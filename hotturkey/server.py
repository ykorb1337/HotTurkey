import argparse
import copy
import json
import logging
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
from .engine import Engine, password_hash, password_ok
from .model import PolicyError, CATEGORIES, DEFAULT_SETTINGS, integer, browser_page
from .store import Store

ROOT=Path(__file__).resolve().parent.parent
LOG=logging.getLogger("hotturkey")

def default_data():
    return Path(os.environ.get("HOTTURKEY_DATA",str(Path.home()/"Library/Application Support/HotTurkey")))

class Service:
    def __init__(self,directory,port=0,enforce=False):
        import fcntl
        directory=Path(directory)
        directory.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.singleton=open(directory/"service.lock","a")
        try:fcntl.flock(self.singleton,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            self.singleton.close()
            raise PolicyError("HotTurkey 服务已在运行") from None
        self.store=Store(directory)
        from .platform_macos import boot_id
        self.engine=Engine(self.store,boot_id=boot_id())
        from .tab_exceptions import TabExceptions
        self.tab_exceptions=TabExceptions(self.engine)
        if enforce:
            from .app_targets import ApplicationTargets
            self.engine.application_targets=ApplicationTargets()
        self.token=secrets.token_urlsafe(32)
        self.auth_sessions={}
        self.auth_retry=0
        self.enforce=enforce
        self.worker_error=None
        self.worker_state="starting" if enforce else "disabled"
        self.helper_starts=0
        self.native_session_initialized=False
        self.agent_process=None
        self.desktop_at=0
        self.browser_notices=[]
        self.browser_notice_at=0
        self.stop=threading.Event()
        try:self.http=ThreadingHTTPServer(("127.0.0.1",port),self.handler())
        except Exception:
            self.singleton.close()
            self.store.db.close()
            raise
        self.http.daemon_threads=True
        self.port=self.http.server_address[1]
        self.origin=f"http://127.0.0.1:{self.port}"
        info={"port":self.port,"token":self.token,"pid":os.getpid(),"enforce":enforce}
        path=self.store.directory/"connection.json"
        # Private directory + atomic replace prevents a partial connection file.
        temp=path.with_suffix(".tmp")
        temp.write_text(json.dumps(info))
        os.chmod(temp,0o600)
        temp.replace(path)

    def handler(self):
        service=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def respond(self,status,value,content_type="application/json; charset=utf-8"):
                payload=value if isinstance(value,bytes) else json.dumps(value,ensure_ascii=False).encode()
                self.send_response(status)
                self.send_header("Content-Type",content_type)
                self.send_header("Content-Length",str(len(payload)))
                self.send_header("Cache-Control","no-store")
                self.send_header("X-Content-Type-Options","nosniff")
                self.send_header("Referrer-Policy","no-referrer")
                self.send_header("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
                self.end_headers()
                try: self.wfile.write(payload)
                except (BrokenPipeError,ConnectionResetError): pass
            def dispatch(self):
                if self.headers.get("Host")!=f"127.0.0.1:{service.port}":
                    return self.respond(403,{"error":"Invalid host"})
                parsed=urlsplit(self.path)
                if parsed.path.startswith("/api/"):
                    origin=self.headers.get("Origin")
                    if origin and origin!=service.origin: return self.respond(403,{"error":"Invalid origin"})
                    token=self.headers.get("Authorization","").removeprefix("Bearer ")
                    if not secrets.compare_digest(token,service.token): return self.respond(401,{"error":"需要本地授权"})
                    data={}
                    if self.command=="POST":
                        if self.headers.get_content_type()!="application/json": raise PolicyError("请求格式须为 JSON")
                        size=int(self.headers.get("Content-Length","0"))
                        if not 0<size<=4*1024*1024: raise PolicyError("请求长度无效")
                        self.connection.settimeout(10)
                        data=json.loads(self.rfile.read(size))
                        if not isinstance(data,dict): raise PolicyError("请求格式无效")
                    value=service.api(parsed.path,self.command,data,parse_qs(parsed.query),self.headers)
                    return self.respond(200,value)
                if self.command!="GET": return self.respond(405,{"error":"Method not allowed"})
                path="index.html" if parsed.path=="/" else parsed.path.lstrip("/")
                allowed={"index.html":"text/html; charset=utf-8","app.js":"application/javascript","text-size.js":"application/javascript","style.css":"text/css","icon.svg":"image/svg+xml"}
                if path not in allowed: return self.respond(404,{"error":"Not found"})
                return self.respond(200,(ROOT/"web"/path).read_bytes(),allowed[path])
            def do_GET(self):
                try: self.dispatch()
                except PolicyError as e: self.respond(400,{"error":str(e)})
                except Exception:
                    LOG.exception("Request failed")
                    self.respond(500,{"error":"本地服务异常，请查看日志"})
            def do_POST(self):
                try: self.dispatch()
                except (PolicyError,ValueError,TypeError,KeyError) as e: self.respond(400,{"error":str(e)})
                except Exception:
                    LOG.exception("Request failed")
                    self.respond(500,{"error":"本地服务异常，请查看日志"})
        return Handler

    def authorized(self,headers):
        return not self.store.state["settings"]["settings_password"] or self.auth_sessions.get(headers.get("X-HotTurkey-Session",""),0)>time.monotonic()

    def api(self,path,method,data,query,headers):
        e=self.engine
        if path in {'/api/extension/add-site-options','/api/extension/add-site'} and method=='POST':
            from .browser_additions import options,add_site
            with self.store.lock:
                hashed=self.store.state['settings']['settings_password']
                if hashed:
                    answer=data.get('password')
                    if answer is None:return {'authentication_required':True}
                    if not isinstance(answer,str) or len(answer)>5000:raise PolicyError('设置密码格式无效')
                    if time.monotonic()<self.auth_retry:raise PolicyError('请稍后重试')
                    if not password_ok(answer,hashed):
                        self.auth_retry=time.monotonic()+2
                        raise PolicyError('设置密码不正确')
                if path.endswith('-options'):return {'blocks':options(e)}
                return add_site(e,data)
        if path=="/api/auth" and method=="POST":
            if time.monotonic()<self.auth_retry: raise PolicyError("请稍后重试")
            hashed=self.store.state["settings"]["settings_password"]
            if hashed and not password_ok(data.get("password",""),hashed):
                self.auth_retry=time.monotonic()+2
                raise PolicyError("设置密码不正确")
            session=secrets.token_urlsafe(32)
            self.auth_sessions[session]=time.monotonic()+900
            return {"session":session}
        if path=="/api/check" and method=="POST":
            url=str(data.get("url",""))[:8192]
            with self.store.lock:
                result=e.evaluate(url,data.get("channels",()),bool(data.get("active",True)),bool(data.get("embedded",False)),self.tab_exceptions.ids(data))
            if result["blocked"] and data.get("record",True): e.record_block(url,[b["id"] for b in result["blocks"]],incognito=data.get("incognito",False))
            return result
        if path=="/api/bridge" and method=="POST":
            browser=str(data.get("browser","unknown"))[:120]
            e.heartbeats[browser]={"at":e.now(),"incognito":bool(data.get("incognito_allowed")),"files":bool(data.get("files_allowed"))}
            for item in data.get("usage",[])[:200]:
                scoped={'context':data['context'],'tab':item.get('tab')} if 'context' in data else {}
                e.usage(item,"browser:"+browser+":"+str(data.get("context","legacy"))+":"+str(item.get("tab",0)),self.tab_exceptions.ids(scoped))
            with self.store.lock:
                blocks=e.snapshot()['blocks']
                for value,block in zip(blocks,self.store.state['blocks']):value['tab_revision']=self.tab_exceptions.revision(block)
                grants=self.tab_exceptions.snapshot(data['context'],data.get('tabs',[])) if 'context' in data else []
            return {"blocks":blocks,"tab_grants":grants,"tab_unblock_supported":True,"settings":{k:self.store.state["settings"][k] for k in ["block_inactive","block_embeds","allow_files","idle_seconds"]},"now":e.now()}
        if path=='/api/extension/tab-unblock' and method=='POST':return self.tab_exceptions.request(data)
        if path=='/api/extension/tab-close' and method=='POST':return self.tab_exceptions.close(data)
        if path=="/api/extension/break" and method=="POST":
            return e.request_break(data["id"],data)
        if path=="/api/extension/closed-tab" and method=="POST":
            url=str(data.get("url",""))[:8192]
            if not browser_page(url):raise PolicyError("只能报告浏览器内部页面")
            with self.store.lock:
                result=e.evaluate(url,active=True)
                if result['blocked']:
                    e.record_block(url,[b['id'] for b in result['blocks']],incognito=bool(data.get('incognito')))
                    if self.store.state['settings']['notifications'] and e.now()-self.browser_notice_at>=2:
                        self.browser_notices=(self.browser_notices+['已关闭拦截的浏览器页面：'+url[:200]])[-8:]
                        self.browser_notice_at=e.now()
                return {'ok':True,'blocked':result['blocked']}
        if path=="/api/native" and method=="POST":
            if data.get("signin"): e.tick(signin=True)
            if data.get("usage"): e.usage(data["usage"],"native")
            return {"blocks":e.snapshot()["blocks"],"settings":e.snapshot()["settings"],"extensions":e.heartbeats,"now":e.now()}
        if path=="/api/state" and method=="GET":
            snapshot=e.snapshot()
            helper=self.agent_process
            snapshot["enforcement"]={"enabled":self.enforce,"worker_error":self.worker_error,"status":self.worker_state,"helper_restarts":max(0,self.helper_starts-1),"desktop_connected":self.worker_state=="running" and helper is not None and helper.poll() is None and self.desktop_at>time.monotonic()-10,"launch_agent":(Path.home()/"Library/LaunchAgents/local.hotturkey.service.plist").exists()}
            snapshot["authenticated"]=self.authorized(headers)
            snapshot['enforcement']['extension_path']=str(ROOT/'extension')
            if not self.authorized(headers) and self.store.state["settings"]["protect_overview"]:
                snapshot["blocks"]=[]
            return snapshot
        if not self.authorized(headers): raise PolicyError("请先输入设置密码")
        with self.store.lock:
            if method=="GET":
                if path=="/api/categories": return CATEGORIES
                if path=="/api/export": return {"format":"hotturkey-blocks-v1","blocks":[{k:v for k,v in b.items() if k!="lock"} for b in self.store.state["blocks"]]}
                if path=="/api/statistics":
                    return self.store.statistics(float(query.get("since",[0])[0]),float(query.get("until",[1e20])[0]),query.get("user",[""])[0],query.get("q",[""])[0],query.get("block",[""])[0],query.get("kind",[""])[0])
                if path=="/api/statistics/export": return self.store.export_statistics()
                if path=="/api/apps":
                    from .platform_macos import applications
                    return applications()
                if path=="/api/users":
                    import pwd
                    return [{"name":p.pw_name,"label":p.pw_gecos} for p in pwd.getpwall() if p.pw_uid>=500 and p.pw_dir.startswith("/Users/") and not p.pw_name.startswith("_")]
            if method=="POST":
                if path=="/api/blocks/save": return e.save_block(data["block"],data.get("id"))
                if path=="/api/blocks/add-targets": return e.add_targets(data["id"],data.get("websites"),data.get("applications"))
                if path=="/api/blocks/reset-pomodoro": return e.reset_pomodoro(data['id'])
                if path=="/api/blocks/delete": e.delete(data["id"]); return {"ok":True}
                if path=="/api/blocks/toggle": return e.toggle(data["id"],data.get("enabled"),data.get("confirm_device",False))
                if path=="/api/blocks/duplicate":
                    b=copy.deepcopy(e.find(data["id"]))
                    b.update(name=data.get("name",b["name"]+" 副本"),enabled=False)
                    return e.save_block(b)
                if path=="/api/blocks/lock": return e.set_lock(data["id"],data)
                if path=="/api/blocks/unlock": return e.unlock(data["id"],data)
                if path=="/api/blocks/break": return e.request_break(data["id"],data)
                if path=="/api/import":
                    incoming=data.get("blocks",[])
                    if not isinstance(incoming,list) or len(incoming)>200: raise PolicyError("导入规则过多")
                    from .model import validate_block
                    # Validate entire import before making any changes.
                    blocks=[validate_block({**b,"enabled":False}) for b in incoming]
                    names=[b["name"] for b in self.store.state["blocks"]]+[b["name"] for b in blocks]
                    if len(set(names))!=len(names): raise PolicyError("导入名称重复，请先重命名")
                    self.store.state["blocks"].extend(blocks)
                    self.store.save()
                    return {"count":len(blocks)}
                if path=="/api/statistics/clear": self.store.clear_statistics(); return {"ok":True}
                if path=="/api/settings":
                    settings=self.store.state["settings"]
                    updated=copy.deepcopy(settings)
                    if "password" in data:
                        updated["settings_password"]=password_hash(data["password"]) if data["password"] else None
                    strict={"require_extension","block_unsupported","block_task_manager","block_settings","block_installer","extension_grace","block_inactive","block_embeds","allow_files","strict_usage","idle_seconds"}
                    any_locked=any(e.locked(b) for b in self.store.state["blocks"])
                    for k,v in data.items():
                        if k not in DEFAULT_SETTINGS or k=="settings_password": continue
                        if any_locked and k in strict and v!=settings[k]: raise PolicyError("锁定期间不能修改拦截严格度")
                        default=DEFAULT_SETTINGS[k]
                        if isinstance(default,bool) and not isinstance(v,bool): raise PolicyError("设置值无效")
                        updated[k]=v
                    if updated["theme"] not in {"light","dark","system"}: raise PolicyError("主题无效")
                    if updated["week_start"] not in {"monday","sunday"}: raise PolicyError("周起始日无效")
                    for k,lo,hi in [("extension_grace",5,600),("idle_seconds",30,3600),("retention_days",1,3650),("text_scale",50,200)]: updated[k]=integer(updated[k],lo,hi,k)
                    if not isinstance(updated["warning_minutes"],list): raise PolicyError("提醒时间无效")
                    updated["warning_minutes"]=[integer(v,1,1440,"提醒分钟") for v in updated["warning_minutes"]]
                    if updated["open_at_login"]!=settings["open_at_login"]:
                        if not self.enforce:raise PolicyError("登录启动设置需从已安装的桌面版本修改")
                        from .platform_macos import configure_ui_login
                        try:configure_ui_login(updated["open_at_login"],self.store.directory)
                        except (OSError,ValueError,RuntimeError) as exc:raise PolicyError(str(exc)) from None
                    self.store.state["settings"]=updated
                    self.store.save()
                    return {"ok":True}
        raise PolicyError("未知操作")

    def supervise_enforcement(self):
        from .platform_macos import enforce_loop
        retry=1
        while not self.stop.is_set():
            started=time.monotonic()
            self.worker_state="starting"
            try:
                enforce_loop(self)
                if not self.stop.is_set():raise RuntimeError("Native enforcement returned unexpectedly")
            except Exception:
                if self.stop.is_set():break
                healthy_at=self.desktop_at
                self.desktop_at=0
                self.worker_state="recovering"
                self.worker_error="macOS 执行层中断，正在自动恢复拦截"
                LOG.exception("macOS enforcement interrupted; retrying")
                if healthy_at-started>=30:retry=1
                until=time.monotonic()+retry
                while not self.stop.is_set() and time.monotonic()<until:
                    if self.stop.wait(min(1,max(0,until-time.monotonic()))):break
                    try:self.engine.tick()
                    except Exception:LOG.exception("Policy tick failed during recovery")
                retry=min(30,retry*2)
        self.desktop_at=0
        self.worker_state="stopped"

    def run(self):
        def worker():
            if self.enforce:
                self.supervise_enforcement()
            else:
                while not self.stop.wait(1): self.engine.tick()
        worker_thread=threading.Thread(target=worker,daemon=True)
        worker_thread.start()
        LOG.info("HotTurkey listening on loopback port %d; enforcement=%s",self.port,self.enforce)
        try: self.http.serve_forever()
        finally:
            self.stop.set()
            self.http.server_close()
            worker_thread.join(timeout=5)
            self.singleton.close()

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--data",type=Path,default=default_data())
    p.add_argument("--port",type=int,default=0)
    p.add_argument("--enforce",action="store_true")
    a=p.parse_args()
    a.data.mkdir(parents=True,exist_ok=True,mode=0o700)
    logging.basicConfig(filename=str(a.data/"service.log"),level=logging.INFO,format="%(asctime)s %(levelname)s %(message)s")
    try:Service(a.data,a.port,a.enforce).run()
    except PolicyError as exc:raise SystemExit(str(exc)) from None

if __name__=="__main__": main()
