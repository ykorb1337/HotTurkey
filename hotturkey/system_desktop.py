"""Unprivileged loopback UI for the protected policy service.

This adapter owns only an ephemeral local connection file. Policy, passwords,
locks, statistics and enforcement remain in the attested authority. No legacy
database is opened and a failed protected request never falls back to it.
"""
import fcntl
import json
import logging
import math
import os
import secrets
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

from .model import PolicyError
from .server import ROOT, Service
from .system_client import SystemClient
from .documents import MAX_DOCUMENT

LOG=logging.getLogger('hotturkey')
GET={'state','categories','export','statistics','statistics/export','users','apps'}
POST={'auth','import','settings','statistics/clear','check','device/recover','device/configure-recovery',
      *('blocks/'+name for name in ['save','add-targets','reset-pomodoro','delete','toggle','lock','unlock','break','duplicate'])}


def desktop_directory(directory):return Path(directory)/'system-desktop'


class SystemDesktopService(Service):
    maximum_body=MAX_DOCUMENT
    def __init__(self,directory,port=0,client_factory=SystemClient):
        self.directory=desktop_directory(directory)
        self.directory.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.singleton=open(self.directory/'service.lock','a')
        try:fcntl.flock(self.singleton,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            self.singleton.close()
            raise PolicyError('系统模式界面服务已在运行') from None
        self.client_factory=client_factory
        self.token=secrets.token_urlsafe(32)
        self.stop=threading.Event()
        self.request_slots=threading.BoundedSemaphore(4)
        self.http=None
        self.connection_file=self.directory/'connection.json'
        try:
            self.http=ThreadingHTTPServer(('127.0.0.1',port),self.handler())
            self.http.daemon_threads=True
            self.port=self.http.server_address[1]
            self.origin=f'http://127.0.0.1:{self.port}'
            info={'mode':'system','port':self.port,'token':self.token,'pid':os.getpid(),'enforce':False}
            temp=self.connection_file.with_suffix('.tmp')
            temp.write_text(json.dumps(info));os.chmod(temp,0o600);temp.replace(self.connection_file)
        except BaseException:
            if self.http is not None:self.http.server_close()
            self.singleton.close()
            raise

    def api(self,path,method,data,query,headers):
        if path=='/api/health' and method=='GET':return {'ok':True,'mode':'system'}
        route=path.removeprefix('/api/')
        if route not in (GET if method=='GET' else POST if method=='POST' else set()):raise PolicyError('系统界面不支持此操作')
        session=headers.get('X-HotTurkey-Session','')
        if not isinstance(session,str) or len(session)>128:raise PolicyError('验证会话无效')
        # Each HTTP request carries its own session. Authentication in one page
        # must not authenticate another page sharing the loopback access token.
        if not self.request_slots.acquire(blocking=False):raise PolicyError('系统后台繁忙，请稍后重试')
        try:
            client=self.client_factory();client.session=session
            if route=='apps':
                state=client.api('state')
                if not state.get('can_manage') or not state.get('authenticated'):raise PolicyError('请使用管理账户并验证设置密码')
                from .platform_macos import applications
                return applications()
            payload=data if method=='POST' else None
            if route=='statistics':
                if set(query)-{'since','until','user','q','block','kind'} or any(len(values)!=1 for values in query.values()):raise PolicyError('统计筛选无效')
                payload={key:values[0] for key,values in query.items()}
                for key in ['since','until']:
                    if key in payload:
                        try:payload[key]=float(payload[key])
                        except (ValueError,TypeError):raise PolicyError('统计时间无效') from None
                        if not math.isfinite(payload[key]):raise PolicyError('统计时间无效')
            value=client.api(route,payload)
            if route=='state':
                execution=value.get('system_execution',{});session_state=value.get('system_session',{})
                age=execution.get('last_sample_age')
                live=execution.get('status')=='running' and type(age) in {float,int} and math.isfinite(age) and 0<=age<=3
                session_live=session_state.get('status')=='running'
                error=None if live and session_live else '系统执行层尚未连接' if not live else '会话代理尚未连接，使用计时暂不可用'
                value['mode']='system'
                value['enforcement']={'enabled':True,'desktop_connected':live and session_live,
                    'status':'running' if live and session_live else 'recovering','worker_error':error,
                    'launch_agent':False,'helper_restarts':0,'extension_path':str(ROOT/'extension')}
            return value
        finally:self.request_slots.release()

    def run(self):
        LOG.info('Protected desktop adapter listening on loopback port %d',self.port)
        try:self.http.serve_forever()
        finally:
            self.stop.set();self.http.server_close()
            try:
                info=json.loads(self.connection_file.read_text())
                if info.get('token')==self.token:self.connection_file.unlink()
            except (OSError,ValueError):pass
            self.singleton.close()
