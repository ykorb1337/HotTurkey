#!/usr/bin/env python3
"""Transactional per-user installation; policy data is never replaced."""
import argparse
import contextlib
import fcntl
import json
import os
import plistlib
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.runtime import application_python


def ensure_unlocked(directory):
    if not (directory/'hotturkey.sqlite3').exists():return
    from hotturkey.store import Store
    from hotturkey.engine import Engine
    from hotturkey.platform_macos import boot_id
    store=Store(directory)
    try:
        engine=Engine(store,boot_id=boot_id())
        if any(engine.locked(b) for b in store.state['blocks']):raise ValueError('有规则仍处于锁定状态，不能更新或卸载后台')
    finally:store.db.close()


def manual_server(directory):
    try:
        info=json.loads((directory/'connection.json').read_text())
        request=urllib.request.Request(f'http://127.0.0.1:{info["port"]}/api/state',headers={'Authorization':'Bearer '+info['token']})
        with urllib.request.urlopen(request,timeout=1) as response:verified=response.status==200
        command=subprocess.check_output(['/bin/ps','-p',str(info['pid']),'-o','uid=,command='],text=True).strip().split(None,1)
        if verified and int(command[0])==os.getuid() and '-m hotturkey.server' in command[1]:return info['pid']
    except (OSError,ValueError,KeyError,subprocess.SubprocessError):pass
    return None

def restart_old_hosts(directory):
    """Disconnect only our old hosts; browsers reconnect using the new wrapper."""
    if not directory.exists():return 0
    count=0
    try:processes=subprocess.check_output(['/bin/ps','-axo','pid=,uid=,command='],text=True)
    except (OSError,subprocess.SubprocessError):return 0
    for line in processes.splitlines():
        parts=line.strip().split(None,2)
        if len(parts)!=3 or not parts[0].isdigit() or not parts[1].isdigit() or int(parts[1])!=os.getuid():continue
        if not re.search(r'(?:^|\s)-m\s+hotturkey\.native_host(?:\s|$)',parts[2]):continue
        pid=int(parts[0])
        try:
            current=subprocess.check_output(['/usr/sbin/lsof','-a','-p',str(pid),'-d','cwd','-Fn'],text=True,stderr=subprocess.DEVNULL,timeout=2)
            if not any(Path(row[1:]).resolve()==directory.resolve() for row in current.splitlines() if row.startswith('n')):continue
            os.kill(pid,signal.SIGTERM);count+=1
        except (OSError,subprocess.SubprocessError):continue
    return count


@contextlib.contextmanager
def install_lock(target):
    target.mkdir(parents=True,exist_ok=True,mode=0o700)
    with (target/'.install.lock').open('a') as lock:
        os.fchmod(lock.fileno(),0o600)
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('另一个安装或卸载正在进行，请稍后重试') from None
        yield

def install(app_source,target,app_target,launch,browser_files,extension_ids,prepare_only=False):
    with install_lock(target):
        return install_files(app_source,target,app_target,launch,browser_files,extension_ids,prepare_only)

def install_files(app_source,target,app_target,launch,browser_files,extension_ids,prepare_only=False):
    info=plistlib.loads((app_source/'Contents/Info.plist').read_bytes())
    if info.get('CFBundleIdentifier')!='local.hotturkey.desktop':raise ValueError('安装源不是 HotTurkey 桌面应用')
    application_python(app_source)
    ensure_unlocked(target)
    if app_target.exists() and plistlib.loads((app_target/'Contents/Info.plist').read_bytes()).get('CFBundleIdentifier')!='local.hotturkey.desktop':raise ValueError('目标位置存在其他应用，拒绝覆盖')
    for path in browser_files:
        if not path.exists():continue
        for origin in json.loads(path.read_text()).get('allowed_origins',[]):
            match=re.fullmatch(r'chrome-extension://([a-p]{32})/',origin)
            if match:extension_ids.add(match[1])
    loaded=launch.exists() and subprocess.run(['/bin/launchctl','print',f'gui/{os.getuid()}/local.hotturkey.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
    manual=None if loaded else manual_server(target)
    if prepare_only and (loaded or manual):raise ValueError('后台正在运行，请使用正常安装以安全更新')
    target.mkdir(parents=True,exist_ok=True,mode=0o700);target.chmod(0o700)
    app_target.parent.mkdir(parents=True,exist_ok=True)
    runtime=target/'runtime';host=target/'native-host';receipt=target/'installation.json'
    metadata=[launch,host,receipt]+browser_files
    previous={p:(p.read_bytes(),p.stat().st_mode&0o777) if p.exists() else None for p in metadata}
    same_app=app_source.resolve()==app_target.resolve()
    with tempfile.TemporaryDirectory(prefix='.hotturkey-update-',dir=app_target.parent) as temporary:
        stage=Path(temporary);staged_runtime=stage/'runtime';staged_runtime.mkdir()
        for folder in ['hotturkey','web','extension']:
            shutil.copytree(ROOT/folder,staged_runtime/folder,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        (staged_runtime/'build').mkdir()
        for name in ['HotTurkeyAgent','HotTurkeyPeerCheck']:
            if (ROOT/'build'/name).exists():shutil.copy2(ROOT/'build'/name,staged_runtime/'build'/name)
        if not (staged_runtime/'build/HotTurkeyAgent').exists():raise ValueError('先构建 HotTurkey 应用与执行器')
        if not same_app:shutil.copytree(app_source,stage/'new.app',symlinks=True)
        ensure_unlocked(target)
        stopped=False;runtime_moved=False;app_moved=False;new_runtime=False;new_app=False
        try:
            if loaded:
                subprocess.run(['/bin/launchctl','bootout',f'gui/{os.getuid()}',str(launch)],check=True);stopped=True
            elif manual:
                os.kill(manual,signal.SIGTERM);stopped=True
                for _ in range(30):
                    try:os.kill(manual,0)
                    except ProcessLookupError:break
                    time.sleep(.1)
                else:raise ValueError('旧后台尚未停止，未替换运行文件')
            ensure_unlocked(target)
            if runtime.exists():runtime.rename(stage/'old-runtime');runtime_moved=True
            staged_runtime.rename(runtime);new_runtime=True
            if not same_app:
                if app_target.exists():app_target.rename(stage/'old.app');app_moved=True
                (stage/'new.app').rename(app_target);new_app=True
            python=application_python(app_target)
            host.write_text('#!/bin/sh\ncd '+shlex.quote(str(runtime))+'\nexec '+shlex.quote(str(python))+' -E -s -B -m hotturkey.native_host\n');host.chmod(0o700)
            receipt.write_text(json.dumps({'app_path':str(app_target),'python_path':str(python)}))
            for path in browser_files:
                path.parent.mkdir(parents=True,exist_ok=True)
                manifest={'name':'local.hotturkey.bridge','description':'HotTurkey local policy bridge','path':str(host),'type':'stdio'}
                if path.parent.parent.name=='Mozilla':manifest['allowed_extensions']=['hotturkey@local.hotturkey']
                else:manifest['allowed_origins']=['chrome-extension://'+ident+'/' for ident in sorted(extension_ids)]
                path.write_text(json.dumps(manifest,indent=2))
            launch.parent.mkdir(parents=True,exist_ok=True)
            launch.write_bytes(plistlib.dumps({'Label':'local.hotturkey.service','ProgramArguments':[str(python),'-E','-s','-B','-m','hotturkey.server','--enforce'],'WorkingDirectory':str(runtime),'RunAtLoad':True,'KeepAlive':True,'ThrottleInterval':3,'StandardOutPath':str(target/'launch.log'),'StandardErrorPath':str(target/'launch-error.log'),'EnvironmentVariables':{'HOTTURKEY_DATA':str(target),'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'}}))
            if not prepare_only:
                subprocess.run(['/bin/launchctl','bootstrap',f'gui/{os.getuid()}',str(launch)],check=True)
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    if manual_server(target):break
                    time.sleep(.2)
                else:raise ValueError('新后台未能启动，正在恢复旧版本')
            if runtime_moved and not prepare_only:restart_old_hosts(stage/'old-runtime')
        except BaseException:
            if not prepare_only:subprocess.run(['/bin/launchctl','bootout',f'gui/{os.getuid()}',str(launch)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if new_runtime:shutil.rmtree(runtime)
            if runtime_moved:(stage/'old-runtime').rename(runtime)
            if new_app:shutil.rmtree(app_target)
            if app_moved:(stage/'old.app').rename(app_target)
            for path,value in previous.items():
                if value is None:path.unlink(missing_ok=True)
                else:path.write_bytes(value[0]);path.chmod(value[1])
            if stopped:
                if previous[launch]:subprocess.run(['/bin/launchctl','bootstrap',f'gui/{os.getuid()}',str(launch)],check=True)
                elif runtime.exists():subprocess.Popen([sys.executable,'-E','-s','-B','-m','hotturkey.server','--enforce'],cwd=runtime,env={**os.environ,'HOTTURKEY_DATA':str(target)})
            raise
    return python


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--extension-id',action='append',default=[])
    parser.add_argument('--app-source',type=Path,help='作为安装源的 HotTurkey.app')
    parser.add_argument('--uninstall',action='store_true')
    parser.add_argument('--prepare-only',action='store_true',help='只准备首次安装文件，不加载服务')
    args=parser.parse_args()
    for ident in args.extension_id:
        if not re.fullmatch('[a-p]{32}',ident):parser.error('Chromium 扩展 ID 须为 a–p 组成的 32 个字符')
    target=Path.home()/'Library/Application Support/HotTurkey'
    launch=Path.home()/'Library/LaunchAgents/local.hotturkey.service.plist'
    browser_files=[Path.home()/'Library/Application Support'/folder/'NativeMessagingHosts/local.hotturkey.bridge.json' for folder in ['Google/Chrome','Microsoft Edge','BraveSoftware/Brave-Browser','Chromium','Vivaldi','Mozilla']]
    if args.uninstall:
        with install_lock(target):
            ensure_unlocked(target)
            subprocess.run(['/bin/launchctl','bootout',f'gui/{os.getuid()}',str(launch)],check=False)
            launch.unlink(missing_ok=True)
            for path in browser_files:path.unlink(missing_ok=True)
            ui_launch=Path.home()/'Library/LaunchAgents/local.hotturkey.desktop.plist'
            subprocess.run(['/bin/launchctl','bootout',f'gui/{os.getuid()}',str(ui_launch)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False);ui_launch.unlink(missing_ok=True)
        print('已卸载登录启动和浏览器连接；保留本地数据。');return
    source=(args.app_source or ROOT/'build/HotTurkey.app').resolve()
    python=install(source,target,Path.home()/'Applications/HotTurkey.app',launch,browser_files,set(args.extension_id),args.prepare_only)
    print('安装完成：'+str(target/'runtime'));print('运行时：'+str(python))

if __name__=='__main__':
    try:main()
    except (ValueError,OSError,subprocess.SubprocessError) as error:raise SystemExit(str(error)) from None
