"""Read-only Darwin process-group evidence for fixed-job installer handoffs.

The job manager supplies the leader PID through its documented kickstart -p
operation. No signal is sent to a PID/group here, and no identity comes from
an HTTP/JSON client. Unknown kernel results cannot mean a stopped backend.
"""
import ctypes
import dataclasses
import errno
import os
import sys
import time

MAX_PIDS=32768
MAX_TREE=1024


class _BSDInfo(ctypes.Structure):
    _fields_=[(name,ctypes.c_uint32) for name in ['flags','status','xstatus','pid','ppid','uid','gid','ruid','rgid','svuid','svgid','reserved']]+[
        ('comm',ctypes.c_char*16),('name',ctypes.c_char*32)]+[(name,ctypes.c_uint32) for name in ['nfiles','pgid','pjobc','tdev','tpgid']]+[
        ('nice',ctypes.c_int32),('start_sec',ctypes.c_uint64),('start_usec',ctypes.c_uint64)]


@dataclasses.dataclass(frozen=True)
class Process:
    pid:int
    uid:int
    ruid:int
    svuid:int
    pgid:int
    status:int
    start_sec:int
    start_usec:int

    @property
    def identity(self):return self.pid,self.uid,self.ruid,self.svuid,self.pgid,self.start_sec,self.start_usec
    @property
    def live(self):return self.status!=5  # SDK sys/proc.h: SZOMB cannot execute.


class KernelProcesses:
    def __init__(self):
        if sys.platform!='darwin' or ctypes.sizeof(_BSDInfo)!=136:raise NotImplementedError('需要受支持的 macOS 进程接口')
        self.library=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True)
        self.library.proc_pidinfo.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_int]
        self.library.proc_pidinfo.restype=ctypes.c_int
        self.library.proc_listpids.argtypes=[ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_int]
        self.library.proc_listpids.restype=ctypes.c_int

    def process(self,pid):
        if type(pid) is not int or not 1<pid<=2147483647:raise ValueError('内核进程编号无效')
        value=_BSDInfo();ctypes.set_errno(0)
        count=self.library.proc_pidinfo(pid,3,0,ctypes.byref(value),ctypes.sizeof(value))  # PROC_PIDTBSDINFO
        if count!=ctypes.sizeof(value):
            error=ctypes.get_errno()
            if count<=0 and error==errno.ESRCH:return None
            raise OSError(error or errno.EIO,'无法确认内核进程状态')
        if value.pid!=pid or value.status not in {1,2,3,4,5} or value.start_usec>=1000000:raise ValueError('内核进程信息无效')
        return Process(value.pid,value.uid,value.ruid,value.svuid,value.pgid,value.status,value.start_sec,value.start_usec)

    def pids(self,kind,identifier):
        if kind not in {2,6} or type(identifier) is not int or not 1<identifier<=2147483647:raise ValueError('内核进程集合无效')
        values=(ctypes.c_int*MAX_PIDS)();ctypes.set_errno(0)
        count=self.library.proc_listpids(kind,identifier,values,ctypes.sizeof(values))
        error=ctypes.get_errno()
        if count==0 and error in {0,errno.ESRCH}:return []
        if count<=0:raise OSError(error or errno.EIO,'无法确认内核进程集合')
        if count>=ctypes.sizeof(values) or count%ctypes.sizeof(ctypes.c_int):raise ValueError('内核进程集合不完整')
        result=list(values[:count//ctypes.sizeof(ctypes.c_int)])
        if any(pid<=1 for pid in result) or len(set(result))!=len(result):raise ValueError('内核进程集合格式无效')
        return result

    def children(self,pid):return self.pids(6,pid)  # PROC_PPID_ONLY
    def group(self,pgid):return self.pids(2,pgid)  # PROC_PGRP_ONLY


class JobProcesses:
    def __init__(self,pid,uid,*,kernel=None):
        self.kernel=kernel or KernelProcesses();self.root=self.kernel.process(pid)
        if self.root is None or not self.root.live:raise RuntimeError('服务进程已变化，请重新确认')
        if (self.root.status!=4 or self.root.uid!=uid or self.root.ruid!=uid or self.root.svuid!=uid
                or self.root.pgid!=pid or self.root.pgid==os.getpgrp() or pid in {os.getpid(),os.getppid()}):
            raise PermissionError('服务进程不是预期的独立暂停作业')
        self.groups={self.root.pgid};seen={pid};pending=[pid]
        while pending:
            parent=pending.pop()
            for child in self.kernel.children(parent):
                if child in seen:continue
                seen.add(child)
                if len(seen)>MAX_TREE:raise ValueError('服务进程树超过限制')
                value=self.kernel.process(child)
                if value is None or not value.live:continue
                if (value.uid!=uid or value.ruid!=uid or value.svuid!=uid or value.pgid<=1 or value.pgid==os.getpgrp()):
                    raise PermissionError('服务子进程归属异常')
                self.groups.add(value.pgid);pending.append(child)
        self.confirm_frozen()

    def confirm_frozen(self):
        current=self.kernel.process(self.root.pid)
        if current is None or current.identity!=self.root.identity or current.status!=4:raise RuntimeError('暂停的服务进程已变化')

    def live(self):
        for group in self.groups:
            for pid in self.kernel.group(group):
                value=self.kernel.process(pid)
                if value is not None and value.pgid==group and value.live:return True
        return False

    def wait(self,remaining,*,sleep=time.sleep):
        while True:
            remaining()
            if not self.live():remaining();return
            sleep(min(.05,remaining()))
