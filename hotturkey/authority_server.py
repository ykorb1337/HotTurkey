"""Bounded policy RPC for a future protected macOS installation.

Not registered by the current-user installer. Production startup requires root,
pre-existing protected paths and a root-selected native client requirement.
Process enforcement uses a protected kernel scanner, never a client PID list.
Session usage and browser operations have separately attested native sources.
Production browser deployment and privileged installation remain open.
"""
import errno
import json
import os
import signal
import socket
import stat
import threading
from pathlib import Path

from .authority import PolicyAuthority
from .authority_management import AuthorityManagement,FIELDS as MANAGEMENT_API
from .documents import Documents
from .ipc import (ProtocolError, authenticated_roles, receive, send,
                  trusted_directory, trusted_path)
from .model import PolicyError
from .store import Store

INSTALL=Path('/Library/PrivilegedHelperTools/local.hotturkey')
CONFIG=INSTALL/'authority.json'
DATA=Path('/private/var/db/local.hotturkey')
SOCKET=Path('/private/var/run/local.hotturkey/control.sock')
MANAGEMENT={'save','add-targets','reset-pomodoro','delete','toggle','lock','unlock'}
MANAGEMENT_FIELDS={
    'save':{'id','block'},'add-targets':{'id','websites','applications'},
    'reset-pomodoro':{'id'},'delete':{'id'},'toggle':{'id','enabled','confirm_device'},
    'lock':{'id','type','until','password','text_mode','custom_text','length','minutes','schedule','allow_inside','before_minutes'},
    'unlock':{'id','answer'},
}


def _text(value, limit, label):
    if not isinstance(value,str) or len(value)>limit:raise PolicyError(label+'无效')
    return value


class PolicyRPC:
    def __init__(self, authority, execution=None, sessions=None, browsers=None):
        self.authority=authority;self.execution=execution;self.sessions=sessions;self.browsers=browsers
        self.management=AuthorityManagement(authority)
        self.documents=Documents(authority.clock)

    def dispatch(self, identity, request):
        with self.authority.store.lock:
            if not isinstance(request,dict):raise PolicyError('请求内容无效')
            operation=_text(request.get('op'),32,'操作');session=_text(request.get('session',''),128,'会话')
            active=self.authority.installation_active()
            if operation=='installation-health':
                if (set(request)-{'op','data','session'} or request.get('data',{})!={} or session
                        or identity.role!='client' or identity.uid!=self.authority.controller_uid):raise PolicyError('安装健康检查需要管理账户的原生客户端')
                execution=self.execution.status() if self.execution else {'status':'not-connected'}
                gate=self.authority.installation_gate
                age=execution.get('last_sample_age')
                ready=execution.get('status')=='running' and type(age) in {float,int} and 0<=age<3
                fresh=(gate.session_fresh(identity.uid) if gate and not active else self.sessions is not None and self.sessions.status(identity.uid).get('status')=='running')
                return {'installation_pending':not active,'executor_ready':ready,
                        'session_transport_fresh':fresh}
            if not active and not (identity.role=='session' and operation=='session-sample'):
                raise PolicyError('系统安装尚未提交，请稍后重试')
            if operation in {'document-read','document-cancel','document-start','document-chunk','document-finish'}:
                result=self.document_request(identity,request)
            else:result=self._dispatch(identity,request)
            if identity.role=='session':return result
            return self.documents.pack(identity,operation,session,result)

    def document_access(self,identity,operation,session):
        uid=identity.uid;self.authority._account(uid)
        if identity.role=='browser':
            if operation!='browser-request' or session:raise PolicyError('浏览器传输权限无效')
            return
        if identity.role!='client':raise PolicyError('传输身份无效')
        if operation=='snapshot':
            if self.authority.store.state['settings']['protect_overview'] and not self.authority.authenticated(uid,session):raise PolicyError('规则概览已受保护')
            return
        if operation in MANAGEMENT_API:return self.management.authorize(uid,operation,session)
        if operation in MANAGEMENT:
            if uid!=self.authority.controller_uid or not self.authority.authenticated(uid,session):raise PolicyError('需要管理账户验证')
            return
        if operation not in {'check','break'}:raise PolicyError('传输操作无效')

    def document_request(self,identity,request):
        if set(request)-{'op','data','session'}:raise PolicyError('传输请求无效')
        operation=request['op'];data=request.get('data',{});session=request.get('session','')
        if not isinstance(data,dict) or not isinstance(session,str) or len(session)>128:raise PolicyError('传输内容无效')
        if operation=='document-start':
            if set(data)!={'operation','size','sha256'}:raise PolicyError('上传字段无效')
            target=data['operation']
            allowed={'save','add-targets','import'} if identity.role=='client' else {'browser-request'} if identity.role=='browser' else set()
            if not isinstance(target,str) or target not in allowed:raise PolicyError('上传操作无效')
            self.document_access(identity,target,session)
            return self.documents.start(identity,target,session,data['size'],data['sha256'])
        mode='read' if operation in {'document-read','document-cancel'} else 'write'
        record=self.documents.record(identity,data.get('id'),mode)
        try:self.document_access(identity,record['operation'],record['session'])
        except PolicyError:
            self.documents.records.pop(data.get('id'),None)
            raise
        if session!=record['session']:raise PolicyError('传输验证会话不符')
        if operation=='document-cancel':
            if set(data)!={'id'}:raise PolicyError('取消字段无效')
            del self.documents.records[data['id']]
            return {'ok':True}
        if operation=='document-read':
            if set(data)!={'id','offset'}:raise PolicyError('分页字段无效')
            return self.documents.page(identity,data['id'],data['offset'])
        if operation=='document-chunk':
            if set(data)!={'id','offset','data'}:raise PolicyError('上传字段无效')
            return self.documents.append(identity,data['id'],data['offset'],data['data'])
        if set(data)!={'id'}:raise PolicyError('上传结束字段无效')
        original=self.documents.finish(identity,data['id'])
        result=self._dispatch(identity,original)
        # The result belongs to the actual operation, not the upload wrapper.
        return self.documents.pack(identity,original['op'],original.get('session',''),result)

    def _dispatch(self, identity, request):
        # Peer identity/role always comes from the kernel and code verifier.
        # Separate native roles submit session/browser claims, cross-checked
        # against independent executor inventory before any usage is earned.
        if set(request)-{'op','data','session'}:raise PolicyError('请求字段无效')
        operation=_text(request.get('op'),32,'操作')
        data=request.get('data',{})
        if not isinstance(data,dict):raise PolicyError('请求内容无效')
        session=_text(request.get('session',''),128,'会话')
        uid=identity.uid
        self.authority._account(uid)
        with self.authority.store.lock:
            if identity.role=='browser':
                if operation!='browser-request' or session or self.browsers is None:raise PolicyError('浏览器只可使用扩展接口')
                return self.browsers.consume(identity,data)
            if identity.role=='session':
                if operation!='session-sample' or session or self.sessions is None:raise PolicyError('会话代理只可提交采样')
                return self.sessions.consume(identity,data)
            if identity.role!='client' or operation=='session-sample':raise PolicyError('操作身份无效')
            if operation in MANAGEMENT_API:return self.management.dispatch(uid,operation,data,session)
            if operation=='snapshot':
                value=self.authority.snapshot(uid,session)
                value['system_execution']=self.execution.status() if self.execution else {'status':'not-connected'}
                value['system_session']=self.sessions.status(uid) if self.sessions else {'status':'not-connected'}
                return value
            if operation=='authenticate':
                if set(data)!={'password'}:raise PolicyError('验证字段无效')
                return {'session':self.authority.authenticate(uid,_text(data['password'],5000,'密码'))}
            if operation in MANAGEMENT:
                if set(data)-MANAGEMENT_FIELDS[operation]:raise PolicyError('管理字段无效')
                if operation!='save' or 'id' in data:_text(data.get('id'),128,'规则')
                if operation=='save' and not isinstance(data.get('block'),dict):raise PolicyError('规则内容无效')
                for key in ['enabled','confirm_device','allow_inside']:
                    if key in data and type(data[key]) is not bool:raise PolicyError('管理选项无效')
                for key in ['type','password','text_mode','custom_text','answer']:
                    if key in data:_text(data[key],5000,'管理内容')
                # Engine validation enforces locks and atomic additive edits.
                return self.authority.manage(uid,operation,data,session)
            if operation=='check':
                if set(data)-{'url','channels','active','embedded'}:raise PolicyError('检查字段无效')
                url=_text(data.get('url',''),8192,'网址')
                channels=data.get('channels',[])
                if (not isinstance(channels,list) or len(channels)>64
                        or any(not isinstance(c,str) or len(c)>2048 for c in channels)):
                    raise PolicyError('频道列表无效')
                for key in ['active','embedded']:
                    if key in data and type(data[key]) is not bool:raise PolicyError('页面状态无效')
                return self.authority.engine(uid).evaluate(url,channels,data.get('active',True),data.get('embedded',False))
            if operation=='device-recover':
                if set(data)-{'word','stop_plan'} or 'word' not in data:raise PolicyError('安全词字段无效')
                if type(data.get('stop_plan',False)) is not bool:raise PolicyError('紧急停用选项无效')
                if data.get('stop_plan') and (uid!=self.authority.controller_uid or not self.authority.authenticated(uid,session)):raise PolicyError('紧急停用计划需要管理账户验证；仍可用安全词放行本次时段')
                return self.authority.engine(uid).recover_device(_text(data['word'],256,'安全词'),data.get('stop_plan',False))
            if operation=='break':
                if set(data)-{'id','answer'}:raise PolicyError('休息字段无效')
                ident=_text(data.get('id'),128,'规则')
                if 'answer' in data:_text(data['answer'],5000,'答案')
                return self.authority.engine(uid).request_break(ident,data)
            if operation=='maintenance-status':
                if uid!=self.authority.controller_uid or not self.authority.authenticated(uid,session):
                    raise PolicyError('需要管理账户验证')
                return {'can_uninstall':self.authority.can_uninstall()}
        raise PolicyError('未知操作')


class AuthorityServer:
    """One authenticated request per connection, at most eight active workers.

    A verifier is explicitly injected for isolated tests. Production constructs
    it only after checking root ownership and uses authenticated_roles.
    """
    def __init__(self, authority, path, verifier, *, workers=8, tick_interval=1, execution=None, sessions=None, browsers=None):
        if type(workers) is not int or not 1<=workers<=32:raise ValueError('Invalid worker count')
        self.authority=authority
        self.execution=execution
        self.rpc=PolicyRPC(authority,execution,sessions,browsers)
        self.path=Path(path)
        self.verifier=verifier
        self.slots=threading.BoundedSemaphore(workers)
        self.tick_interval=tick_interval
        self.stopping=threading.Event()
        self.listener=None
        self.workers=set()
        self.worker_lock=threading.Lock()
        self.inode=None
        self.failure=None

    def bind(self):
        if self.listener is not None:raise RuntimeError('Already bound')
        if self.path.exists() or self.path.is_symlink():
            info=self.path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=os.geteuid():
                raise PermissionError('Refusing to replace a non-owned socket')
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as probe:
                probe.settimeout(.2)
                try:probe.connect(str(self.path))
                except OSError as exc:
                    if exc.errno!=errno.ECONNREFUSED:raise
                else:raise RuntimeError('Authority is already running')
            self.path.unlink()
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            listener.bind(str(self.path))
            self.inode=self.path.lstat().st_ino
            self.path.chmod(0o666)
            listener.listen(16)
            listener.settimeout(.2)
            self.listener=listener
        except BaseException:
            listener.close()
            self._unlink()
            raise

    def _unlink(self):
        try:
            if self.inode is not None and self.path.lstat().st_ino==self.inode:self.path.unlink()
        except FileNotFoundError:pass

    def _serve(self, connection):
        try:
            with connection:
                try:
                    identity=self.verifier(connection)
                    request=receive(connection)
                    if request is None:return
                    result=self.rpc.dispatch(identity,request)
                    send(connection,{'ok':True,'result':result})
                except (PermissionError,PolicyError,ProtocolError,KeyError,TypeError,ValueError) as exc:
                    # Do not echo requests, secrets, filesystem paths or tracebacks.
                    message=str(exc) if isinstance(exc,PolicyError) else '请求或身份验证失败'
                    try:send(connection,{'ok':False,'error':message})
                    except (OSError,ValueError):pass
                except (OSError,TimeoutError):pass
                except Exception:
                    # Unexpected policy/storage failure must be visible to the
                    # supervisor instead of silently running a broken authority.
                    self.failure='Policy authority failed'
                    self.stopping.set()
        finally:
            with self.worker_lock:self.workers.discard(threading.current_thread())
            self.slots.release()

    def _tick(self):
        while not self.stopping.wait(self.tick_interval):
            try:
                with self.authority.store.lock:
                    self.rpc.documents.prune()
                    if not self.authority.installation_active():continue
                    # No JSON-provided IDs create ticking account contexts.
                    for engine in list(self.authority.engines.values()):engine.tick()
            except Exception:
                self.failure='Policy clock failed'
                self.stopping.set()

    def _execute(self):
        try:
            self.execution.run(self.stopping)
            if not self.stopping.is_set():raise RuntimeError('Protected executor returned')
        except Exception:
            self.failure='Protected process enforcement failed'
            self.stopping.set()

    def serve_forever(self):
        if self.listener is None:raise RuntimeError('Bind before serving')
        ticker=threading.Thread(target=self._tick,name='policy-clock',daemon=True)
        ticker.start()
        executor=None
        if self.execution:
            executor=threading.Thread(target=self._execute,name='protected-executor',daemon=True)
            executor.start()
        try:
            while not self.stopping.is_set():
                if not self.slots.acquire(timeout=.2):continue
                try:connection,_=self.listener.accept()
                except socket.timeout:self.slots.release();continue
                except OSError:
                    self.slots.release()
                    if self.stopping.is_set():break
                    raise
                worker=threading.Thread(target=self._serve,args=(connection,),daemon=True)
                with self.worker_lock:self.workers.add(worker)
                worker.start()
        finally:
            self.stopping.set()
            self.listener.close()
            ticker.join()
            if executor:executor.join()
            # Each worker has bounded verifier, read and write deadlines.
            with self.worker_lock:workers=list(self.workers)
            for worker in workers:worker.join()
            self._unlink()
        if self.failure:raise RuntimeError(self.failure)

    def stop(self):self.stopping.set()


def production_server():
    if os.geteuid()!=0:raise PermissionError('System authority requires root installation')
    # A root interpreter may not import this service from a user-writable tree.
    package=trusted_directory(INSTALL/'project/hotturkey')
    if Path(__file__).resolve().parent!=package:raise PermissionError('Authority code is outside the protected installation')
    for path in package.glob('*.py'):trusted_path(path)
    config_path=trusted_path(CONFIG)
    if config_path.stat().st_size>16384:raise ValueError('Authority configuration too large')
    config=json.loads(config_path.read_text())
    if set(config)!={'version','controller_uid','requirements'} or config['version']!=3:
        raise ValueError('Unsupported authority configuration')
    requirements=config['requirements']
    # This local unsigned distribution pins a specific hardened native client.
    import re
    if (not isinstance(requirements,dict) or set(requirements)!={'client','session','browser'}
            or any(not isinstance(value,str) or not re.fullmatch(r'cdhash H"[0-9a-f]{40}"',value) for value in requirements.values())
            or len(set(requirements.values()))!=3):
        raise ValueError('Expected distinct pinned native role requirements')
    checker=trusted_path(INSTALL/'HotTurkeyPeerCheck')
    executor=trusted_path(INSTALL/'HotTurkeySystemAgent')
    trusted_path(INSTALL/'HotTurkeySessionAgent')
    trusted_directory(INSTALL/'HotTurkey.app')
    trusted_path(INSTALL/'HotTurkey.app/Contents/MacOS/HotTurkey')
    trusted_path(INSTALL/'HotTurkeyBrowserHost')
    trusted_path(INSTALL/'browsers.json')
    trusted_directory(DATA)
    trusted_directory(SOCKET.parent)
    for path in DATA.iterdir():
        if path.name not in {'hotturkey.sqlite3','hotturkey.sqlite3-wal','hotturkey.sqlite3-shm'}:
            raise PermissionError('Unexpected protected data entry')
        trusted_path(path)
    from .installation_gate import InstallationGate,MARKER
    from .system_package import digest
    manifest=trusted_path(INSTALL/'payload.json')
    if manifest.stat().st_size>8*1024**2:raise ValueError('Installation manifest too large')
    gate=InstallationGate(MARKER,config['controller_uid'],digest(manifest))
    trusted_path(DATA/'hotturkey.sqlite3')
    store=Store(DATA)
    try:
        if store.state.get('authority_version')!=1 or store.state.get('controller_uid')!=config['controller_uid']:
            raise ValueError('Protected data must be migrated by the installer before startup')
        from .platform_macos import boot_id
        authority=PolicyAuthority(store,config['controller_uid'],boot_id=boot_id(),installation_gate=gate)
        authority.engine(authority.controller_uid)
        from .system_enforcement import SystemExecution
        execution=SystemExecution(authority,executor,protected_paths=[INSTALL])
        from .trusted_sessions import TrustedSessions
        sessions=TrustedSessions(authority,execution)
        from .trusted_browsers import TrustedBrowsers
        browsers=TrustedBrowsers(authority,execution,sessions)
        return AuthorityServer(authority,SOCKET,lambda connection:authenticated_roles(connection,checker,requirements),execution=execution,sessions=sessions,browsers=browsers)
    except BaseException:
        store.db.close()
        raise


def main():
    server=production_server()
    try:
        server.bind()
        for number in [signal.SIGTERM,signal.SIGINT]:signal.signal(number,lambda *_:server.stop())
        server.serve_forever()
    finally:server.authority.store.db.close()


if __name__=='__main__':main()
