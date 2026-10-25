"""Fixed launchd registrations for a future privileged installer.

No RPC or CLI is exposed. Unloading confirms removal of the job definition,
not that every process has exited; cutover still needs independent kernel and
signed health checks. Importing or rendering plans changes nothing on disk.
"""
import dataclasses
import contextlib
import math
import os
import plistlib
import pwd
import re
import stat
import subprocess
import time
from pathlib import Path

from .session_launch import SESSION_PLIST,session_launch_agent
from .system_package import DAEMON,LABEL,daemon_plan
from .system_transaction import owned_entry,protected_directory,sync_directory

REGISTRY=Path('/private/var/db/local.hotturkey-install')
SESSION_LABEL='local.hotturkey.session'
LEGACY_LABEL='local.hotturkey.service'


def human_account(uid,resolve=pwd.getpwuid):
    if type(uid) is not int or not 500<=uid<=4294967295:raise ValueError('用户 UID 无效')
    account=resolve(uid);home=Path(account.pw_dir)
    if (account.pw_uid!=uid or not account.pw_name or account.pw_name.startswith('_')
            or not home.is_absolute() or '..' in home.parts or not home.is_relative_to('/Users') or home==Path('/Users')):
        raise ValueError('仅支持真实本机用户的图形会话')
    return account


def legacy_plan(home):
    home=Path(home);data=home/'Library/Application Support/HotTurkey'
    return {'Label':LEGACY_LABEL,'ProgramArguments':[str(home/'Applications/HotTurkey.app/Contents/Resources/python/bin/python3'),
        '-E','-s','-B','-m','hotturkey.server','--enforce'],'WorkingDirectory':str(data/'runtime'),
        'RunAtLoad':True,'KeepAlive':True,'ThrottleInterval':3,
        'StandardOutPath':str(data/'launch.log'),'StandardErrorPath':str(data/'launch-error.log'),
        'EnvironmentVariables':{'HOTTURKEY_DATA':str(data),'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'}}


def root_only():
    if os.geteuid()!=0:raise PermissionError('系统服务操作需要获准的特权安装入口')


def read_plan(path,expected,*,owner_uid=0,anchor=Path('/')):
    path=Path(path);protected_directory(path.parent,owner_uid,anchor)
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=owner_uid or info.st_nlink!=1
                or info.st_mode&0o022 or info.st_size>65536):raise PermissionError('服务启动文件身份、类型或权限无效')
        with os.fdopen(os.dup(descriptor),'rb') as stream:data=stream.read(65537)
        after=os.fstat(descriptor)
        identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
        if len(data)!=info.st_size or identity(info)!=identity(after):raise ValueError('服务启动文件读取期间发生变化')
        if (plistlib.loads(data)!=expected or data not in {plistlib.dumps(expected),plistlib.dumps(expected,fmt=plistlib.FMT_BINARY)}):
            raise ValueError('服务启动计划不是预期的固定配置')
    finally:os.close(descriptor)
    return data


def valid_domain(value):
    return isinstance(value,str) and (value=='system' or bool(re.fullmatch(r'gui/[1-9][0-9]{2,9}',value)) and 500<=int(value[4:])<=4294967295)


@dataclasses.dataclass(frozen=True)
class _Job:
    domain:str
    label:str
    plist:Path
    expected:dict

    def __post_init__(self):
        if not valid_domain(self.domain):raise ValueError('服务域无效')
        if not isinstance(self.label,str) or not re.fullmatch(r'local\.hotturkey\.[a-z0-9.-]{1,100}',self.label):raise ValueError('服务名称无效')
        if not isinstance(self.plist,Path) or not self.plist.is_absolute() or '..' in self.plist.parts or not isinstance(self.expected,dict) or self.expected.get('Label')!=self.label:raise ValueError('服务路径或名称不一致')

    @property
    def target(self):return self.domain+'/'+self.label


class _JobControl:
    """Trusted internal adapter, also exercised with disposable GUI jobs."""
    def __init__(self,permission,validate,*,run=subprocess.run,timeout=10,clock=time.monotonic,sleep=time.sleep):
        if type(timeout) not in {int,float} or not math.isfinite(timeout) or not 1<=timeout<=30:raise ValueError('服务操作时限无效')
        self.permission=permission;self.validate=validate;self.run=run;self.timeout=timeout;self.clock=clock;self.sleep=sleep;self.deadline=None

    def remaining(self):
        value=self.timeout if self.deadline is None else self.deadline-self.clock()
        if value<=0:raise TimeoutError('服务操作超过总时限')
        return value

    @contextlib.contextmanager
    def window(self):
        previous=self.deadline;deadline=self.clock()+self.timeout
        self.deadline=deadline if previous is None else min(previous,deadline)
        try:self.remaining();yield;self.remaining()
        finally:self.deadline=previous

    def command(self,*arguments,query=False):
        # Never parse launchctl print output: its man page explicitly disclaims
        # that interface. Unknown exit codes fail closed instead of meaning off.
        result=self.run(['/bin/launchctl',*arguments],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LC_ALL':'C'},cwd='/',close_fds=True,timeout=min(3 if query else self.timeout,self.remaining()))
        self.remaining()
        if type(result.returncode) is not int:raise RuntimeError('服务控制返回无效状态')
        return result.returncode

    def signal_job(self,job,signal):
        self.permission()
        if signal not in {'SIGSTOP','SIGCONT'}:raise ValueError('安装服务信号无效')
        code=self.command('kill',signal,job.target)
        if code and self.loaded(job):raise RuntimeError('无法调整固定服务状态（代码 '+str(code)+'）')

    def running_pid(self,job):
        self.permission()
        result=self.run(['/bin/launchctl','kickstart','-p',job.target],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LC_ALL':'C'},cwd='/',close_fds=True,timeout=min(3,self.remaining()))
        self.remaining()
        if result.returncode or not isinstance(result.stdout,bytes) or len(result.stdout)>32 or not re.fullmatch(rb'[1-9][0-9]{0,9}\n?',result.stdout):
            raise RuntimeError('无法确认固定作业的内核进程')
        pid=int(result.stdout)
        if not 1<pid<=2147483647:raise ValueError('服务进程编号越界')
        return pid

    def pause_unload(self,job,*,observe=None,before_unload=lambda observer:None):
        """Freeze one job, capture its kernel groups, unload and prove exit.

        The caller persists before_unload evidence before removal. Recovery
        must resume an old job that survived an installer crash while frozen.
        No PID/group is selected for a signal; only fixed launchd jobs are.
        """
        from .system_processes import JobProcesses
        paused=False;removed=False
        try:
            with self.window():
                self.permission()
                if not self.loaded(job):return False
                # A recovery driver must run in its own supervised process,
                # never freeze the authority that is executing this very call.
                if self.running_pid(job) in {os.getpid(),os.getppid()}:raise PermissionError('安装控制不能暂停自身或其父进程')
                self.signal_job(job,'SIGSTOP');paused=True
                pid=self.running_pid(job)
                observer=(observe or JobProcesses)(pid,0 if job.domain=='system' else int(job.domain[4:]))
                observer.confirm_frozen();before_unload(observer);self.remaining()
                self.unload(job);removed=True
                observer.wait(self.remaining)
                return True
        finally:
            if paused and not removed:
                # A failed proof must not leave an otherwise loaded old backend
                # frozen. This cleanup has a fresh, separately bounded budget.
                previous=self.deadline;self.deadline=None
                try:
                    with self.window():
                        if self.loaded(job):self.signal_job(job,'SIGCONT')
                finally:self.deadline=previous

    def domain_exists(self,domain):
        if not valid_domain(domain):raise ValueError('服务域无效')
        code=self.command('print',domain,query=True)
        if code==0:return True
        if code==112 and domain.startswith('gui/'):return False
        raise RuntimeError('无法确认服务域状态（代码 '+str(code)+'）')

    def loaded(self,job):
        code=self.command('print',job.target,query=True)
        if code==0:return True
        if code in {112,113}:
            exists=self.domain_exists(job.domain)
            if code==113 or not exists:return False
        raise RuntimeError('无法确认服务状态（代码 '+str(code)+'）')

    def load(self,job):
        with self.window():
            self.permission();self.validate(job)
            if not self.domain_exists(job.domain):return False
            if self.loaded(job):return True
            code=self.command('bootstrap',job.domain,str(job.plist))
            if code:
                if job.domain.startswith('gui/') and not self.domain_exists(job.domain):return False
                raise RuntimeError('无法加载固定服务（代码 '+str(code)+'）')
            if self.loaded(job):return True
            if job.domain.startswith('gui/') and not self.domain_exists(job.domain):return False
            raise RuntimeError('服务加载后未找到注册')

    def unload(self,job):
        with self.window():
            self.permission()
            if not self.loaded(job):return False
            code=self.command('bootout',job.target)  # Never boot out a whole domain.
            if code and self.loaded(job):raise RuntimeError('无法卸载服务（代码 '+str(code)+'）')
            while self.loaded(job):self.sleep(min(.05,self.remaining()))
            return True


class SystemJobs:
    """Only fixed HotTurkey labels/paths; call from a trusted root entry point.

    This component neither authorizes installation nor signals caller-selected
    PIDs. The full installer must authorize, recheck locks, supervise recovery,
    prove old processes exited and use the cutover commit barrier.
    """
    def __init__(self,controller_uid,transaction):
        root_only()
        if not isinstance(transaction,str) or not re.fullmatch('[a-f0-9]{32}',transaction):raise ValueError('安装事务无效')
        account=human_account(controller_uid)
        self.uid=controller_uid;self.home=Path(account.pw_dir);self.directory=REGISTRY/'jobs'/transaction
        protected_directory(self.directory)
        self.authority=_Job('system',LABEL,DAEMON,daemon_plan())
        plan=legacy_plan(self.home)
        self.legacy=_Job('gui/'+str(self.uid),LEGACY_LABEL,self.home/'Library/LaunchAgents'/str(LEGACY_LABEL+'.plist'),plan)
        self.saved_legacy=_Job(self.legacy.domain,LEGACY_LABEL,self.directory/'legacy.plist',plan)
        self.control=_JobControl(root_only,lambda job:read_plan(job.plist,job.expected),timeout=30)

    def session(self,uid):
        human_account(uid)
        return _Job('gui/'+str(uid),SESSION_LABEL,SESSION_PLIST,session_launch_agent())

    def gui_uids(self):
        with self.control.window():return self._gui_uids()

    def _gui_uids(self):
        result=[];seen=set();accounts=pwd.getpwall()
        if len(accounts)>4096:raise ValueError('本机账户列表超过限制')
        for account in accounts:
            try:human_account(account.pw_uid)
            except (ValueError,KeyError):continue
            if account.pw_uid in seen:continue
            seen.add(account.pw_uid)
            if self.control.domain_exists('gui/'+str(account.pw_uid)):result.append(account.pw_uid)
            if len(result)>256:raise ValueError('图形会话数量超过限制')
        return sorted(result)

    def validate_legacy(self):
        # Validate only ordinary-user ancestors down to the home boundary.
        # A trusted private copy, not this writable path, is used for restore.
        return read_plan(self.legacy.plist,self.legacy.expected,owner_uid=self.uid,anchor=self.home)

    def save_legacy(self):
        root_only();self.validate_legacy();path=self.saved_legacy.plist
        protected_directory(path.parent)
        if path.exists() or path.is_symlink():read_plan(path,self.legacy.expected);return
        temporary=path.with_name(path.name+'.new')
        if temporary.exists() or temporary.is_symlink():
            if not stat.S_ISREG(owned_entry(temporary).st_mode):raise PermissionError('暂存服务计划不是普通文件')
            temporary.unlink();sync_directory(path.parent)
        descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            # Re-serialize trusted fields; never ask privileged launchd to
            # reinterpret raw user XML with duplicate/ambiguous keys.
            with os.fdopen(descriptor,'wb') as stream:
                stream.write(plistlib.dumps(self.saved_legacy.expected,fmt=plistlib.FMT_BINARY));stream.flush();os.fsync(stream.fileno())
            os.replace(temporary,path)
            sync_directory(path.parent)
        finally:
            if temporary.exists():temporary.unlink();sync_directory(path.parent)

    def capture(self):
        with self.control.window():return self._capture()

    def _capture(self):
        uids=self.gui_uids();legacy=self.control.loaded(self.legacy);authority=self.control.loaded(self.authority)
        if legacy:self.validate_legacy()
        if authority:read_plan(self.authority.plist,self.authority.expected)
        sessions=[]
        for uid in uids:
            job=self.session(uid)
            if self.control.loaded(job):read_plan(job.plist,job.expected);sessions.append(uid)
        return {'legacy_loaded':legacy,'authority_loaded':authority,'session_loaded':sessions,'gui_uids':uids}

    def unload_legacy(self):
        # Require an exact protected restore plan before touching the old job.
        root_only();read_plan(self.saved_legacy.plist,self.saved_legacy.expected)
        return self.control.unload(self.legacy)
    def load_legacy(self):return self.control.load(self.saved_legacy)
    def unload_authority(self):return self.control.unload(self.authority)
    def load_authority(self):return self.control.load(self.authority)
    def unload_session(self,uid):return self.control.unload(self.session(uid))
    def load_session(self,uid):return self.control.load(self.session(uid))
    def stop_authority(self,**options):return self.control.pause_unload(self.authority,**options)
    def stop_legacy(self,**options):
        root_only();read_plan(self.saved_legacy.plist,self.saved_legacy.expected)
        return self.control.pause_unload(self.legacy,**options)
    def stop_session(self,uid,**options):return self.control.pause_unload(self.session(uid),**options)
    def resume_authority(self):
        if self.control.loaded(self.authority):self.control.signal_job(self.authority,'SIGCONT')
    def resume_legacy(self):
        if self.control.loaded(self.legacy):self.control.signal_job(self.legacy,'SIGCONT')
    def resume_session(self,uid):
        job=self.session(uid)
        if self.control.loaded(job):self.control.signal_job(job,'SIGCONT')
