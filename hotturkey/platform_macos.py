"""Read processes and invoke a compiled AppKit helper; never shell-interpolate rules."""
import json
import logging
import os
import plistlib
import selectors
import subprocess
import time
from xml.parsers.expat import ExpatError
from pathlib import Path

LOG=logging.getLogger("hotturkey")
ROOT=Path(__file__).resolve().parent.parent
NATIVE_SAMPLE_TIMEOUT=10
NATIVE_COMMAND_TIMEOUT=3
MAX_NATIVE_SAMPLE=4*1024*1024

def native_samples(process, stop, tick):
    """Bound reads by both frame size and time, including partial-line stalls."""
    os.set_blocking(process.stdout.fileno(),False)
    pending=bytearray()
    deadline=time.monotonic()+NATIVE_SAMPLE_TIMEOUT
    next_tick=time.monotonic()+1
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout,selectors.EVENT_READ)
        while not stop.is_set():
            if b"\n" in pending:
                line,_,pending=pending.partition(b"\n")
                if len(line)>MAX_NATIVE_SAMPLE:raise RuntimeError("Native sample exceeds size limit")
                try:sample=json.loads(line)
                except (ValueError,UnicodeError) as exc:raise RuntimeError("Malformed native sample") from exc
                if not isinstance(sample,dict) or not isinstance(sample.get("apps"),list) or not all(isinstance(app,dict) for app in sample["apps"]) or not isinstance(sample.get("front"),dict):
                    raise RuntimeError("Invalid native sample structure")
                yield sample
                deadline=time.monotonic()+NATIVE_SAMPLE_TIMEOUT
                next_tick=time.monotonic()+1
                continue
            if len(pending)>MAX_NATIVE_SAMPLE:raise RuntimeError("Native sample exceeds size limit")
            # Always read ready data first, including the first sample after wake.
            ready=selector.select(max(0,min(.25,deadline-time.monotonic())))
            if ready:
                chunk=os.read(process.stdout.fileno(),65536)
                if not chunk:raise RuntimeError("Native helper closed its output")
                pending.extend(chunk)
                if time.monotonic()>=deadline and b"\n" not in pending:raise TimeoutError("Native helper stopped responding")
                continue
            now=time.monotonic()
            if now>=deadline:raise TimeoutError("Native helper stopped responding")
            if now>=next_tick:
                tick()
                next_tick=now+1

def native_command(process, stop, command):
    """A helper stuck after sampling must not block the worker on a full pipe."""
    os.set_blocking(process.stdin.fileno(),False)
    pending=memoryview(json.dumps(command,ensure_ascii=False).encode()+b"\n")
    deadline=time.monotonic()+NATIVE_COMMAND_TIMEOUT
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdin,selectors.EVENT_WRITE)
        while pending and not stop.is_set():
            if selector.select(max(0,min(.25,deadline-time.monotonic()))):
                try:pending=pending[os.write(process.stdin.fileno(),pending):]
                except BlockingIOError:continue
            elif time.monotonic()>=deadline:raise TimeoutError("Native helper stopped reading commands")
            if pending and time.monotonic()>=deadline:raise TimeoutError("Native helper stopped reading commands")
    return not pending

def stop_native(process):
    """Reap even a suspended helper before starting its replacement."""
    try:
        if process.poll() is None:
            process.terminate()
        try:process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    finally:
        process.stdin.close()
        process.stdout.close()

def boot_id():
    try: return subprocess.check_output(["/usr/sbin/sysctl","-n","kern.boottime"],text=True).strip()
    except (OSError,subprocess.SubprocessError): return "boot-"+str(int(time.time()-time.monotonic()))

def applications():
    from .app_targets import app_info
    result=[]
    for parent in [Path("/Applications"),Path("/System/Applications"),Path.home()/"Applications"]:
        if not parent.exists(): continue
        for path in sorted(parent.glob("*.app")):
            try:
                info=app_info(path)
                if not info:continue
                result.append({"name":info.get("CFBundleDisplayName",path.stem),"path":str(path),"bundle":info.get("CFBundleIdentifier","")})
            except (OSError,plistlib.InvalidFileException,ExpatError,ValueError): continue
    return result

def configure_ui_login(enabled, directory):
    """Save the user's choice for the next login; do not open a new window now."""
    metadata=json.loads((Path(directory)/"installation.json").read_text())
    app=Path(metadata["app_path"])
    if not app.exists(): raise RuntimeError("已安装的桌面应用不存在，请重新安装")
    launch=Path.home()/"Library/LaunchAgents/local.hotturkey.desktop.plist"
    if enabled:
        launch.parent.mkdir(parents=True,exist_ok=True)
        launch.write_bytes(plistlib.dumps({"Label":"local.hotturkey.desktop","ProgramArguments":["/usr/bin/open","-a",str(app),"--args","--login"],"RunAtLoad":True}))
    else:
        subprocess.run(["/bin/launchctl","bootout",f"gui/{os.getuid()}",str(launch)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
        launch.unlink(missing_ok=True)

def enforce_loop(service):
    helper=ROOT/"build/HotTurkeyAgent"
    if not helper.exists(): raise RuntimeError("Build HotTurkeyAgent first: python3 scripts/build.py")
    command=[str(helper)]
    if service.native_session_initialized:command.append("--resume")
    process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,bufsize=0)
    service.agent_process=process
    service.helper_starts+=1
    e=service.engine
    last_sample=None
    previous_states={}
    try:
        # The helper emits one sample per second and applies returned decisions.
        for sample in native_samples(process,service.stop,e.tick):
            if service.stop.is_set(): break
            with service.store.lock:
                e.tick(signin=bool(sample.get("signin")))
                service.native_session_initialized=True
                settings=service.store.state["settings"]
                foreground=sample.get("front",{})
                idle=sample.get("idle",0)
                if foreground and foreground.get("bundle") not in BROWSERS:
                    e.usage({**foreground,"idle":idle},"native")
                kills=[]
                device=None
                notices=service.browser_notices if settings['notifications'] else []
                service.browser_notices=[]
                any_locked=any(e.locked(b) for b in service.store.state["blocks"])
                for app in sample.get("apps",[]):
                    if app.get("pid")==os.getpid() or app.get("bundle")=="local.hotturkey.desktop": continue
                    hit=[]
                    for b in service.store.state["blocks"]:
                        if e.active(b) and not e.break_state(b)["allowed"] and e.app_matches(b,app): hit.append(b["id"])
                    if settings["strict_usage"] and any(e.active(b) and e.app_matches(b,app) for b in service.store.state["blocks"]) and app.get("pid")!=foreground.get("pid"):
                        e.usage({**app,"idle":idle,"active":False},"app:"+str(app["pid"]))
                    strict=False
                    bundle=app.get("bundle","")
                    if any_locked:
                        strict=(settings["block_task_manager"] and bundle=="com.apple.ActivityMonitor") or (settings["block_settings"] and bundle in {"com.apple.systempreferences","com.apple.ScreenTime"}) or (settings["block_installer"] and bundle=="com.apple.installer")
                        if bundle in BROWSERS:
                            browser=BROWSERS[bundle]
                            heartbeat=e.heartbeats.get(browser,{})
                            since=max(e.start_time,heartbeat.get("at",0),app.get("launched",0))
                            missing=e.now()-since>settings["extension_grace"]
                            if settings["require_extension"] and missing: strict=True
                        if settings["block_unsupported"] and (bundle in UNSUPPORTED): strict=True
                    if hit or strict:
                        kills.append(app["pid"])
                        if hit: e.record_block(app.get("application",bundle),hit,"application")
                        if settings["notifications"] and last_sample!=app.get("application"):
                            notices.append("已拦截应用："+app.get("application",bundle))
                            last_sample=app.get("application")
                for b in service.store.state["blocks"]:
                    state=e.status(b)
                    rt=e.runtime(b)
                    if b["device"]!="none" and state["blocking"]:
                        if e.now()-rt.get("last_device",0)>10:
                            device=b["device"]
                            rt["last_device"]=e.now()
                            service.store.save()
                    summary=(state["active"],state["blocking"],state["locked"])
                    old=previous_states.get(b["id"])
                    if old and old!=summary and settings["notifications"]:
                        notices.append(b["name"]+ (" · 拦截生效" if state["blocking"] else " · 可使用"))
                    previous_states[b["id"]]=summary
                    if settings["notifications"]:
                        deadlines=[]
                        if state["locked"] and b["lock"]["type"]=="timer":deadlines.append(("锁定结束",b["lock"]["until"]-e.now()))
                        if b["enabled"] and state["next_start"]:deadlines.append(("日程开始",state["next_start"]-e.now()))
                        bs=state["break_status"]
                        if state["active"] and bs["type"]=="pomodoro":deadlines.append(("休息结束" if bs["allowed"] else "番茄休息开始",bs["remaining"]))
                        if state["active"] and bs["type"]=="allowance" and bs["remaining"]>0:
                            for warning in settings["warning_minutes"]:
                                key="allowance:"+str(e.period_start(b,e.interval(b)[2],e.now()))+":"+str(warning)
                                if 0<bs["remaining"]<=warning*60 and key not in rt.setdefault("warnings",[]):
                                    notices.append(b["name"]+" · 使用额度剩余 "+str(warning)+" 分钟")
                                    rt["warnings"].append(key)
                        for label,remaining in deadlines:
                            for warning in settings["warning_minutes"]:
                                key=label+":"+str(round((e.now()+remaining)/5))+":"+str(warning)
                                if warning*60-2<remaining<=warning*60 and key not in rt.setdefault("warnings",[]):
                                    notices.append(b["name"]+" · "+str(warning)+" 分钟后"+label)
                                    rt["warnings"].append(key)
                        if len(rt.get("warnings",[]))>200:rt["warnings"]=rt["warnings"][-200:]
            if not native_command(process,service.stop,{"kill":kills,"device":device,"notifications":notices}):break
            # Report healthy only after a full sample/decision exchange.
            service.desktop_at=time.monotonic()
            service.worker_error=None
            service.worker_state="running"
    finally:
        service.worker_state="stopped" if service.stop.is_set() else "recovering"
        stop_native(process)
        service.agent_process=None
    if not service.stop.is_set(): raise RuntimeError("Native helper exited")

BROWSERS={"com.microsoft.edgemac":"Edge","com.google.Chrome":"Chrome","com.brave.Browser":"Brave","org.mozilla.firefox":"Firefox","com.operasoftware.Opera":"Opera","com.vivaldi.Vivaldi":"Vivaldi"}
UNSUPPORTED={"com.apple.Safari","org.torproject.torbrowser","company.thebrowser.Browser","company.thebrowser.dia","com.kagi.kagimacOS"}
