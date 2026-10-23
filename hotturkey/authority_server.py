"""Bounded policy RPC for a future protected macOS installation.

Not registered by the current-user installer. Production startup requires root,
pre-existing protected paths and a root-selected native client requirement.
Process enforcement uses a protected kernel scanner, never a client PID list.
Session usage, browser integration and privileged installation remain open.
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
from .ipc import (ProtocolError, authenticated_peer, receive, send,
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
    def __init__(self, authority, execution=None):self.authority=authority;self.execution=execution

    def dispatch(self, identity, request):
        # No UID, PID, role, path or executable is ever accepted from the wire.
        if set(request)-{'op','data','session'}:raise PolicyError('请求字段无效')
        operation=_text(request.get('op'),32,'操作')
        data=request.get('data',{})
        if not isinstance(data,dict):raise PolicyError('请求内容无效')
        session=_text(request.get('session',''),128,'会话')
        uid=identity.uid
        self.authority._account(uid)
        with self.authority.store.lock:
            if operation=='snapshot':
                value=self.authority.snapshot(uid,session)
                value['system_execution']=self.execution.status() if self.execution else {'status':'not-connected'}
                return value
            if operation=='authenticate':
                if set(data)!={'password'}:raise PolicyError('验证字段无效')
                return {'session':self.authority.authenticate(uid,_text(data['password'],4096,'密码'))}
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
    it only after checking root ownership and uses authenticated_peer.
    """
    def __init__(self, authority, path, verifier, *, workers=8, tick_interval=1, execution=None):
        if type(workers) is not int or not 1<=workers<=32:raise ValueError('Invalid worker count')
        self.authority=authority
        self.execution=execution
        self.rpc=PolicyRPC(authority,execution)
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
    if set(config)!={'version','controller_uid','client_requirement'} or config['version']!=1:
        raise ValueError('Unsupported authority configuration')
    requirement=config['client_requirement']
    # This local unsigned distribution pins a specific hardened native client.
    import re
    if not isinstance(requirement,str) or not re.fullmatch(r'cdhash H"[0-9a-f]{40}"',requirement):
        raise ValueError('Expected a pinned native client requirement')
    checker=trusted_path(INSTALL/'HotTurkeyPeerCheck')
    executor=trusted_path(INSTALL/'HotTurkeySystemAgent')
    trusted_directory(DATA)
    trusted_directory(SOCKET.parent)
    for path in DATA.iterdir():
        if path.name not in {'hotturkey.sqlite3','hotturkey.sqlite3-wal','hotturkey.sqlite3-shm'}:
            raise PermissionError('Unexpected protected data entry')
        trusted_path(path)
    store=Store(DATA)
    try:
        from .platform_macos import boot_id
        authority=PolicyAuthority(store,config['controller_uid'],boot_id=boot_id())
        authority.engine(authority.controller_uid)
        from .system_enforcement import SystemExecution
        execution=SystemExecution(authority,executor,protected_paths=[INSTALL])
        return AuthorityServer(authority,SOCKET,lambda connection:authenticated_peer(connection,checker,requirement),execution=execution)
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
