"""Root-owned activation barrier for a prospective protected installation.

Only the install coordinator may publish this marker. No RPC can create,
commit, remove or select it. A new authority remains passive until its exact
payload/transaction marker has been committed.
"""
import os
import re
import stat
import time
from pathlib import Path

from .ipc import decode_json
from .system_transaction import protected_directory

MARKER=Path('/private/var/db/local.hotturkey-install/activation.json')


class InstallationGate:
    def __init__(self,path,controller_uid,payload_sha256,*,owner_uid=0,anchor=Path('/'),clock=time.monotonic):
        if type(controller_uid) is not int or not 500<=controller_uid<=4294967295:raise ValueError('安装管理账户无效')
        if not isinstance(payload_sha256,str) or not re.fullmatch('[a-f0-9]{64}',payload_sha256):raise ValueError('安装材料摘要无效')
        self.path=Path(path);self.controller_uid=controller_uid;self.payload_sha256=payload_sha256
        self.owner_uid=owner_uid;self.anchor=Path(anchor);self.clock=clock;self.probes={}
        self.transaction=None;self.committed=False
        value=self.read();self.transaction=value['transaction'];self.committed=value['phase']=='committed'

    def read(self):
        protected_directory(self.path.parent,self.owner_uid,self.anchor)
        descriptor=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=self.owner_uid or info.st_nlink!=1
                    or stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=4096):raise PermissionError('系统安装状态文件不可信')
            value=decode_json(os.read(descriptor,4097))
            after=os.fstat(descriptor)
            if (after.st_size,after.st_mtime_ns,after.st_ctime_ns)!=(info.st_size,info.st_mtime_ns,info.st_ctime_ns):raise PermissionError('系统安装状态在读取期间变化')
        finally:os.close(descriptor)
        if (not isinstance(value,dict) or set(value)!={'version','transaction','phase','controller_uid','payload_sha256'}
                or type(value['version']) is not int or value['version']!=1
                or type(value['controller_uid']) is not int or value['controller_uid']!=self.controller_uid
                or value['payload_sha256']!=self.payload_sha256
                or not isinstance(value['transaction'],str) or not re.fullmatch('[a-f0-9]{32}',value['transaction'])
                or not isinstance(value['phase'],str) or value['phase'] not in {'pending','committed'}):raise PermissionError('系统安装状态与当前程序不匹配')
        return value

    def is_open(self):
        value=self.read()
        if value['transaction']!=self.transaction:raise PermissionError('安装事务已变化，必须重新启动后台')
        if self.committed and value['phase']!='committed':raise PermissionError('安装提交状态不能倒退')
        self.committed=value['phase']=='committed'
        return self.committed

    def observe_session(self,uid):
        now=self.clock();self.probes={key:at for key,at in self.probes.items() if now-at<=10}
        if len(self.probes)<256 or uid in self.probes:self.probes[uid]=now

    def session_fresh(self,uid):
        age=self.clock()-self.probes.get(uid,-1e30)
        return 0<=age<=5

    def transport_uids(self):
        now=self.clock()
        return sorted(uid for uid,at in self.probes.items() if 0<=now-at<=5)
