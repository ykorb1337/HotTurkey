"""A kernel file lock retained by the backend and its native executor.

Close descriptors to release, never LOCK_UN: inherited descriptors share the
same open-file description, so a surviving executor must retain the lock even
after an abrupt backend exit. The installer probes an existing inode and keeps
the exclusive lock during a handoff; it never creates an absent proof file.
"""
import fcntl
import os
import stat
from pathlib import Path


class ServiceLease:
    def __init__(self,path,*,owner_uid=None,create=True):
        self.path=Path(path).absolute();self.owner_uid=os.geteuid() if owner_uid is None else owner_uid
        if type(self.owner_uid) is not int or not 0<=self.owner_uid<=4294967295:raise ValueError('后台锁所有者无效')
        parent=self.path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=self.owner_uid or parent.st_mode&0o022:raise PermissionError('后台锁目录不受保护')
        flags=os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK|(os.O_CREAT if create else 0)
        descriptor=os.open(self.path,flags,0o600);self.stream=None;self.acquired=False
        if descriptor<3:
            previous=descriptor
            try:descriptor=fcntl.fcntl(previous,fcntl.F_DUPFD_CLOEXEC,3)
            finally:os.close(previous)
        try:
            self.identity=self.inspect(descriptor)
            self.stream=os.fdopen(descriptor,'r+b',buffering=0)
            self.assert_current()
            if create:
                os.fchmod(self.fileno(),0o600)
                if not self.try_acquire():raise BlockingIOError('HotTurkey service lease is held')
        except BaseException:
            if self.stream is not None:self.stream.close()
            else:os.close(descriptor)
            raise

    def inspect(self,descriptor):
        info=os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=self.owner_uid or info.st_mode&0o022 or info.st_nlink!=1 or info.st_size!=0):
            raise PermissionError('后台锁身份、类型或权限无效')
        return [info.st_dev,info.st_ino]

    def fileno(self):return self.stream.fileno()

    def assert_current(self):
        info=self.path.lstat()
        if self.inspect(self.fileno())!=self.identity or [info.st_dev,info.st_ino]!=self.identity or not stat.S_ISREG(info.st_mode):
            raise PermissionError('后台锁已被替换')

    def try_acquire(self):
        self.assert_current()
        try:fcntl.flock(self.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return False
        self.acquired=True
        try:self.assert_current()
        except BaseException:self.close();raise
        return True

    def close(self):
        if self.stream is not None:self.stream.close()

    def __enter__(self):return self
    def __exit__(self,*arguments):self.close()
