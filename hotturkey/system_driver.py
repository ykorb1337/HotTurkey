"""Fixed-target protected cutover driver; not a public privilege entry point.

A trusted installer must first copy the approved artifact and a consistent
preflight database into the root-owned transaction directory. This module does
not elevate, accept public apply requests or deploy browser/user registrations.
"""
import dataclasses
import fcntl
import hashlib
import json
import math
import os
import pwd
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import time
from pathlib import Path

from .engine import password_ok
from .installation_gate import MARKER
from .ipc import decode_json
from .platform_macos import boot_id
from .service_lease import ServiceLease
from .session_launch import INSTALL,SESSION_PLIST
from .system_cutover import CutoverDriver,CutoverCoordinator,pending_cutover,staging_paths
from .system_jobs import REGISTRY,SystemJobs,human_account,root_only
from .system_migration import ensure_database_unlocked,migrate_database,validate_database
from .system_package import DATA,DAEMON,SOCKET_DIRECTORY,digest,verify_payload
from .system_processes import KernelProcesses
from .system_transaction import FileTransaction,protected_directory,read_private_record,write_private_record,sync_directory


@dataclasses.dataclass(frozen=True)
class _Layout:
    folder:Path
    registry:Path
    program:Path
    database:Path
    marker:Path
    daemon:Path
    session:Path
    runtime:Path
    legacy:Path
    anchor:Path=Path('/')
    owner_uid:int=0

    @property
    def artifact(self):return self.folder/'payload'
    @property
    def targets(self):return {'program':self.program,'database':self.database,'activation':self.marker,'daemon':self.daemon,'session':self.session}
    def source(self,kind):
        if kind=='system':return self.database,self.owner_uid
        if kind=='legacy':return self.legacy,None
        if kind=='fresh':return None,None
        raise ValueError('升级数据来源无效')
    def origin(self):
        file=self.database/'hotturkey.sqlite3'
        if file.exists() or file.is_symlink() or self.database.exists():return 'system'
        file=self.legacy/'hotturkey.sqlite3'
        if file.exists() or file.is_symlink():return 'legacy'
        return 'fresh'


@dataclasses.dataclass(frozen=True)
class _Approval:
    controller_uid:int
    payload_sha256:str
    source:str
    credential_fingerprint:str
    expires:float


def _credential(state):
    value=state.get('settings',{}).get('settings_password','')
    if not isinstance(value,str) or len(value)>1024:raise ValueError('管理验证格式无效')
    return value,hashlib.sha256(value.encode()).hexdigest()


def _private_state(directory,layout):
    protected_directory(directory,layout.owner_uid,layout.anchor)
    path=directory/'hotturkey.sqlite3';info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=layout.owner_uid or info.st_mode&0o077 or info.st_nlink!=1:raise PermissionError('预检数据库不是私有副本')
    db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=2)
    try:return validate_database(db)
    finally:db.close()


def _approve(layout,uid,expected,password):
    if type(uid) is not int or not 500<=uid<=4294967295 or not isinstance(expected,str) or not re.fullmatch('[a-f0-9]{64}',expected):raise ValueError('管理批准绑定无效')
    if not isinstance(password,str) or len(password)>5000:raise ValueError('管理密码格式无效')
    kind=layout.origin()
    if kind=='fresh':fingerprint=_credential({'settings':{}})[1]
    else:
        state=_private_state(layout.folder/'preflight',layout)
        if ('authority_version' in state)!=(kind=='system'):raise ValueError('预检副本来源不匹配')
        if kind=='system' and state.get('controller_uid')!=uid:raise PermissionError('不能更换已有管理账户')
        stored,fingerprint=_credential(state)
        if stored and not password_ok(password,stored):raise PermissionError('设置密码不正确')
        ensure_database_unlocked(layout.folder/'preflight',uid,boot_id(),pwd.getpwuid)
    return _Approval(uid,expected,kind,fingerprint,time.monotonic()+90)


def _owned_tree(directory,layout):
    protected_directory(directory,layout.owner_uid,layout.anchor)
    for parent,folders,files in os.walk(directory,followlinks=False):
        for name in folders+files:
            path=Path(parent)/name;info=path.lstat()
            if info.st_uid!=layout.owner_uid or not stat.S_ISLNK(info.st_mode) and info.st_mode&0o022:raise PermissionError('程序材料含可变或错误所有者项目')
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)):raise PermissionError('程序材料含特殊项目')


def _verify_artifact(layout,expected,uid):
    _owned_tree(layout.artifact,layout)
    manifest=layout.artifact/'payload.json';info=manifest.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>8*1024**2:raise PermissionError('安装清单身份无效')
    if digest(manifest)!=expected:raise PermissionError('安装材料与已批准摘要不符')
    value=verify_payload(layout.artifact)
    if value['controller_uid']!=uid:raise PermissionError('安装材料管理账户不符')
    if not (layout.artifact/'project/hotturkey/service_lease.py').is_file():raise ValueError('安装材料缺少交接锁协议')


def _stage(layout,context,approval):
    uid=context['controller_uid'];expected=context['payload_sha256'];_verify_artifact(layout,expected,uid)
    if layout.origin()!=approval['source']:raise ValueError('预检后数据来源发生变化')
    stages=staging_paths(layout.targets,context['transaction'])
    if any(path.exists() or path.is_symlink() for path in stages.values()):raise FileExistsError('暂存位置已存在')
    shutil.copytree(layout.artifact,stages['program'],symlinks=True)
    if approval['source']=='fresh':
        from .store import Store
        from .authority import PolicyAuthority
        store=Store(stages['database'])
        try:PolicyAuthority(store,uid,boot_id=boot_id()).engine(uid)
        finally:store.db.close()
    else:
        source,source_uid=layout.source(approval['source']);source_uid=uid if source_uid is None else source_uid
        migrate_database(source/'hotturkey.sqlite3',stages['database'],uid,source_uid,boot_id(),pwd.getpwuid)
    state=_private_state(stages['database'],layout)
    if _credential(state)[1]!=approval['credential_fingerprint']:raise PermissionError('预检后管理凭据发生变化')
    with ServiceLease(stages['database']/'service.lock',owner_uid=layout.owner_uid):pass
    for name in ['daemon','session']:
        shutil.copy2(layout.artifact/('authority.plist' if name=='daemon' else 'session.plist'),stages[name]);stages[name].chmod(0o644)
    value={'version':1,'transaction':context['transaction'],'phase':'pending','controller_uid':uid,'payload_sha256':expected}
    # This unpublished stage needs no hard-link publication protocol. A killed
    # writer leaves an ordinary disposable file, never a paired journal link.
    descriptor=os.open(stages['activation'],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'w') as stream:json.dump(value,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
    _owned_tree(stages['program'],layout);verify_payload(stages['program'])
    _sync_stages(stages,layout)
    return stages


def _sync_stages(stages,layout):
    def regular(path):
        descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=layout.owner_uid or info.st_mode&0o022 or info.st_nlink!=1:raise PermissionError('暂存文件身份无效')
            os.fsync(descriptor)
        finally:os.close(descriptor)
    for path in stages.values():
        if path.is_dir():
            for parent,folders,files in os.walk(path,topdown=False,followlinks=False):
                for name in files:
                    file=Path(parent)/name
                    if not file.is_symlink():regular(file)
                sync_directory(parent)
        else:regular(path)
        sync_directory(path.parent)


class _Driver(CutoverDriver):
    """Common orchestration. Alternative paths/identity adapters are test-only."""
    def __init__(self,layout,jobs,uid,expected,approval,*,client,worker=None):
        self.layout=layout;self.jobs=jobs;self.uid=uid;self.expected=expected;self.approval=approval
        self.client=client;self.worker=worker;self.leases=[];self.records=None
        protected_directory(layout.folder,layout.owner_uid,layout.anchor)
        if type(uid) is not int or not 500<=uid<=4294967295 or not isinstance(expected,str) or not re.fullmatch('[a-f0-9]{64}',expected):raise ValueError('安装身份或摘要无效')

    def coordinator(self):return CutoverCoordinator(self.layout.folder,self.layout.targets,self,self.uid,self.expected,
        lock_directory=self.layout.registry,owner_uid=self.layout.owner_uid,anchor=self.layout.anchor,timeout=180)

    def authorize(self):
        approval=self.approval
        if (not isinstance(approval,_Approval) or approval.controller_uid!=self.uid or approval.payload_sha256!=self.expected
                or approval.source!=self.layout.origin() or type(approval.expires) not in {int,float} or not math.isfinite(approval.expires)
                or not isinstance(approval.credential_fingerprint,str) or not re.fullmatch('[a-f0-9]{64}',approval.credential_fingerprint)
                or time.monotonic()>approval.expires):raise PermissionError('缺少本次有效管理批准')
        _verify_artifact(self.layout,self.expected,self.uid)
        if approval.source=='system':
            _owned_tree(self.layout.program,self.layout)
            protected_directory(self.layout.database,self.layout.owner_uid,self.layout.anchor)
            for path in self.layout.database.iterdir():
                if path.name not in {'hotturkey.sqlite3','hotturkey.sqlite3-wal','hotturkey.sqlite3-shm','service.lock'}:raise PermissionError('已有共享数据包含未知项目，拒绝覆盖')
                info=path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=self.layout.owner_uid or info.st_mode&0o077 or info.st_nlink!=1:raise PermissionError('已有共享数据权限或身份无效')
        self.records={'version':1,'source':approval.source,'credential_fingerprint':approval.credential_fingerprint}
        write_private_record(self.layout.folder/'approval.json',self.records,initial=True,owner_uid=self.layout.owner_uid,anchor=self.layout.anchor)

    def capture(self):
        value=self.jobs.capture()
        if self.approval.source=='fresh' and (value['legacy_loaded'] or value['authority_loaded']):raise ValueError('后台运行但源数据库缺失，拒绝新建覆盖')
        if self.approval.source=='system' and value['legacy_loaded']:raise ValueError('已有共享策略与用户后台并行，须先处理重复部署')
        if self.approval.source=='legacy' and not value['legacy_loaded']:raise ValueError('迁移旧版本前请先启动受管理用户后台')
        return value

    def _record(self,context):
        path=self.layout.folder/'processes.json'
        if not path.exists():return {'version':1,'transaction':context['transaction'],'boot':boot_id(),'jobs':{}}
        value=read_private_record(path,owner_uid=self.layout.owner_uid,anchor=self.layout.anchor)
        allowed={'legacy','authority','candidate'}|{'session:'+str(uid) for uid in context['services']['gui_uids']}
        if (not isinstance(value,dict) or set(value)!={'version','transaction','boot','jobs'} or type(value['version']) is not int or value['version']!=1
                or value['transaction']!=context['transaction'] or not isinstance(value['boot'],str) or not 1<=len(value['boot'])<=1024 or not isinstance(value['jobs'],dict)
                or set(value['jobs'])-allowed):raise ValueError('进程交接记录无效')
        for record in value['jobs'].values():
            if (not isinstance(record,dict) or set(record)!={'groups','done'} or type(record['done']) is not bool
                    or not isinstance(record['groups'],list) or not 1<=len(record['groups'])<=1024 or any(type(n) is not int or not 1<n<=2147483647 for n in record['groups'])
                    or len(set(record['groups']))!=len(record['groups'])):raise ValueError('进程组交接记录无效')
        return value

    def _save_record(self,value):
        path=self.layout.folder/'processes.json'
        write_private_record(path,value,initial=not path.exists(),owner_uid=self.layout.owner_uid,anchor=self.layout.anchor)

    def _stop(self,context,key,operation):
        def record(observer):
            value=self._record(context);value['jobs'][key]={'groups':sorted(observer.groups),'done':False};self._save_record(value)
        result=operation(before_unload=record)
        if result:
            value=self._record(context);value['jobs'][key]['done']=True;self._save_record(value)
        return result

    def _hold_file(self,path,owner,*,missing=False,replaced=False):
        for lease in self.leases:
            if lease.path==path:
                try:lease.assert_current()
                except PermissionError:
                    if replaced:continue
                    raise
                if lease.acquired:return
        if not path.exists():
            if missing:return
            raise ValueError('缺少后台交接锁，拒绝猜测写入状态')
        lease=ServiceLease(path,owner_uid=owner,create=False);self.leases.append(lease)
        deadline=time.monotonic()+15
        while not lease.try_acquire():
            if time.monotonic()>=deadline:raise TimeoutError('旧后台或执行器仍持有数据锁')
            time.sleep(.05)

    def stop_previous(self,context):
        if self.approval.source=='legacy':self._hold_file(self.layout.legacy/'.install.lock',self.uid)
        if context['services']['legacy_loaded']:self.jobs.save_legacy()
        for uid in context['services']['session_loaded']:self._stop(context,'session:'+str(uid),lambda **values:self.jobs.stop_session(uid,**values))
        if context['services']['authority_loaded']:self._stop(context,'authority',self.jobs.stop_authority)
        if context['services']['legacy_loaded']:self._stop(context,'legacy',self.jobs.stop_legacy)
        source,owner=self.layout.source(self.approval.source)
        if source is not None:self._hold_file(source/'service.lock',self.uid if owner is None else owner)

    def stage(self,context):
        if self.worker is not None:return self.worker(context)
        return _run_worker(self.layout,context,self.installation_lock_fd,[lease.fileno() for lease in self.leases])

    def start_candidate(self,context):
        if digest(self.layout.program/'payload.json')!=self.expected:raise PermissionError('当前程序不是本次材料')
        _owned_tree(self.layout.program,self.layout)
        if not self.layout.runtime.exists():self.layout.runtime.mkdir(mode=0o755)
        protected_directory(self.layout.runtime,self.layout.owner_uid,self.layout.anchor)
        self.jobs.load_authority()
        for uid in self.jobs.gui_uids():self.jobs.load_session(uid)

    def probe_candidate(self,context,*,timeout):return self.client(timeout)
    def required_sessions(self,context):
        uids=self.jobs.gui_uids()
        for uid in uids:self.jobs.load_session(uid)
        return uids

    def activate(self,context):
        value=read_private_record(self.layout.marker,owner_uid=self.layout.owner_uid,anchor=self.layout.anchor)
        if not isinstance(value,dict) or type(value.get('version')) is not int or value['version']!=1 or not isinstance(value.get('phase'),str):raise PermissionError('激活状态格式无效')
        expected={'version':1,'transaction':context['transaction'],'phase':value.get('phase'),'controller_uid':self.uid,'payload_sha256':self.expected}
        if value!=expected or value['phase'] not in {'pending','committed'}:raise PermissionError('激活状态不属于本次安装')
        if value['phase']=='pending':value['phase']='committed';write_private_record(self.layout.marker,value,owner_uid=self.layout.owner_uid,anchor=self.layout.anchor)

    def stop_candidate(self,context):
        files=FileTransaction(self.layout.folder/'files.json',self.layout.targets,owner_uid=self.layout.owner_uid,anchor=self.layout.anchor,resume=True)
        published=next((step for step in files.value['steps'] if step['key']=='program'),None)
        if published is None or files.identity_at(self.layout.program)!=published['new_identity']:return
        for uid in self.jobs.gui_uids():self.jobs.unload_session(uid)
        self._stop(context,'candidate',self.jobs.stop_authority)
        data=next((step for step in files.value['steps'] if step['key']=='database'),None)
        replaced=data is not None and files.identity_at(self.layout.database)==data['new_identity']
        self._hold_file(self.layout.database/'service.lock',self.layout.owner_uid,missing=True,replaced=replaced)

    def _wait_recorded(self,context,key):
        value=self._record(context);record=value['jobs'].get(key)
        if record is None or record['done'] or value['boot']!=boot_id():return
        kernel=KernelProcesses();deadline=time.monotonic()+30
        while True:
            live=False
            for group in record['groups']:
                for pid in kernel.group(group):
                    process=kernel.process(pid)
                    if process is not None and process.live:live=True
            if not live:return
            if time.monotonic()>=deadline:raise TimeoutError('旧进程组尚未退出，不能重启写入者')
            time.sleep(.05)

    def restore_previous(self,context):
        self.close()
        if context['services']['authority_loaded']:
            if not self.jobs.control.loaded(self.jobs.authority):self._wait_recorded(context,'authority')
            _owned_tree(self.layout.program,self.layout);self.jobs.load_authority();self.jobs.resume_authority()
        if context['services']['legacy_loaded']:
            if not self.jobs.control.loaded(self.jobs.legacy):self._wait_recorded(context,'legacy')
            self.jobs.load_legacy();self.jobs.resume_legacy()
        for uid in context['services']['session_loaded']:self.jobs.load_session(uid);self.jobs.resume_session(uid)

    def close(self):
        for lease in self.leases:lease.close()
        self.leases=[]
    def __enter__(self):return self
    def __exit__(self,*values):self.close()


def _production_layout(uid,job):
    if not isinstance(job,str) or not re.fullmatch('[a-f0-9]{32}',job):raise ValueError('安装作业无效')
    account=human_account(uid)
    return _Layout(REGISTRY/'jobs'/job,REGISTRY,INSTALL,DATA,MARKER,DAEMON,SESSION_PLIST,SOCKET_DIRECTORY,
        Path(account.pw_dir)/'Library/Application Support/HotTurkey')


def approve_private_copy(uid,job,expected,password):
    root_only();return _approve(_production_layout(uid,job),uid,expected,password)


class ProtectedDriver(_Driver):
    def __init__(self,uid,job,expected,approval=None):
        root_only();layout=_production_layout(uid,job);jobs=SystemJobs(uid,job)
        def client(timeout):
            account=human_account(uid)
            result=subprocess.run([str(INSTALL/'HotTurkeyPolicyClient')],input=b'{"op":"installation-health","data":{}}',capture_output=True,
                timeout=timeout,user=uid,group=account.pw_gid,extra_groups=os.getgrouplist(account.pw_name,account.pw_gid),
                cwd='/',env={'PATH':'/usr/bin:/bin','HOME':account.pw_dir})
            if result.returncode or len(result.stdout)>16384:return None
            value=decode_json(result.stdout)
            return value.get('result') if isinstance(value,dict) and value.get('ok') is True else None
        super().__init__(layout,jobs,uid,expected,approval,client=client)


def _run_worker(layout,context,lock_fd,lease_fds):
    if type(lock_fd) is not int:raise RuntimeError('暂存工作进程缺少内核安装锁')
    code='import sys;sys.path.insert(0,'+repr(str(layout.artifact/'project'))+');from hotturkey.system_driver import _worker_main;_worker_main('+repr(layout.folder.name)+')'
    process=subprocess.Popen([str(layout.artifact/'HotTurkey.app/Contents/Resources/python/bin/python3'),'-I','-B','-c',code],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,pass_fds=(lock_fd,*lease_fds),close_fds=True,cwd='/',env={'PATH':'/usr/bin:/bin'})
    try:
        output,_=process.communicate(json.dumps({'context':context,'lock_fd':lock_fd,'lease_fds':lease_fds}).encode(),timeout=45)
        if process.returncode or len(output)>4096:raise RuntimeError('私有暂存验证失败')
        result=decode_json(output)
        if result!={'ok':True}:raise RuntimeError('暂存工作进程返回无效结果')
    except BaseException:
        if process.poll() is None:process.kill();process.wait(timeout=5)
        raise
    return staging_paths(layout.targets,context['transaction'])


def _worker_main(job):
    root_only();signal.alarm(45)
    value=decode_json(__import__('sys').stdin.buffer.read(1024*1024+1))
    if not isinstance(value,dict) or set(value)!={'context','lock_fd','lease_fds'}:raise ValueError('暂存请求无效')
    context=value['context'];layout=_production_layout(context['controller_uid'],job)
    if Path(__file__).resolve().parent!=layout.artifact/'project/hotturkey':raise PermissionError('暂存工作代码不在受保护材料中')
    index=pending_cutover(REGISTRY)
    if index is None or index['directory']!='jobs/'+job or index['transaction']!=context['transaction'] or index['payload_sha256']!=context['payload_sha256'] or index['controller_uid']!=context['controller_uid']:raise PermissionError('暂存请求不属于活动安装')
    descriptor=value['lock_fd'];info=os.fstat(descriptor);expected=(REGISTRY/'install.lock').lstat()
    if info.st_uid!=0 or info.st_ino!=expected.st_ino or info.st_dev!=expected.st_dev or not stat.S_ISREG(info.st_mode):raise PermissionError('继承安装锁不匹配')
    os.set_inheritable(descriptor,False)
    persisted=read_private_record(layout.folder/'services.json')
    if persisted!=context or context['phase']!='staging':raise PermissionError('暂存阶段不匹配')
    coordinator=CutoverCoordinator(layout.folder,layout.targets,None,context['controller_uid'],context['payload_sha256'],lock_directory=REGISTRY)
    coordinator.files=FileTransaction(layout.folder/'files.json',layout.targets,resume=True)
    coordinator.validate_context(context)
    approval=read_private_record(layout.folder/'approval.json')
    if not isinstance(approval,dict) or set(approval)!={'version','source','credential_fingerprint'} or approval['version']!=1 or not re.fullmatch('[a-f0-9]{64}',approval['credential_fingerprint']):raise ValueError('管理批准记录无效')
    descriptors=value['lease_fds']
    if not isinstance(descriptors,list) or len(descriptors)>3 or any(type(fd) is not int or fd<3 for fd in descriptors):raise ValueError('继承后台锁无效')
    source,owner=layout.source(approval['source']);owner=context['controller_uid'] if owner is None else owner
    paths=[] if source is None else [source/'service.lock']+([source/'.install.lock'] if approval['source']=='legacy' else [])
    expected_leases={(path.lstat().st_dev,path.lstat().st_ino) for path in paths}
    actual=set()
    for fd in descriptors:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or info.st_nlink!=1 or info.st_size:raise PermissionError('继承后台锁身份不符')
        actual.add((info.st_dev,info.st_ino));fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);os.set_inheritable(fd,False)
    if actual!=expected_leases:raise PermissionError('暂存前未持有全部后台锁')
    _stage(layout,context,approval)
    print('{"ok":true}',flush=True)
