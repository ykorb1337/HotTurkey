"""Durable filesystem swaps for an installer that has already stopped services.

This module never starts/stops a service and grants no installation authority.
The production coordinator must supply fixed targets, validate the staged
payload/data and hold the installation lock before publishing anything.
"""
import contextlib
import ctypes
import fcntl
import json
import os
import re
import shutil
import stat
import sys
import uuid
from pathlib import Path

from .ipc import decode_json


def sync_directory(path):
    descriptor=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)


def atomic_exchange(left,right):
    """No multi-rename fallback: existing startup paths must never disappear."""
    if sys.platform!='darwin':raise NotImplementedError('原子安装切换仅支持 macOS')
    function=ctypes.CDLL(None,use_errno=True).renamex_np
    function.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_uint];function.restype=ctypes.c_int
    if function(os.fsencode(left),os.fsencode(right),0x00000002)!=0:
        error=ctypes.get_errno();raise OSError(error,os.strerror(error))


def file_identity(info):return [info.st_dev,info.st_ino]


def protected_directory(path,owner_uid=0,anchor=Path('/')):
    path=Path(path);anchor=Path(anchor)
    if not anchor.is_absolute() or '..' in anchor.parts or not path.is_absolute() or '..' in path.parts or not path.is_relative_to(anchor):raise PermissionError('事务路径越过信任边界')
    while True:
        info=path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner_uid or info.st_mode&0o022:raise PermissionError('事务目录不是受保护路径')
        if path==anchor:break
        path=path.parent


def owned_entry(path,owner_uid=0):
    info=Path(path).lstat()
    if (info.st_uid!=owner_uid or info.st_mode&0o022
            or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
            or stat.S_ISREG(info.st_mode) and info.st_nlink!=1):raise PermissionError('事务项目不是受保护的普通文件或目录')
    return info


def read_private_record(path,*,owner_uid=0,anchor=Path('/'),validate=None):
    path=Path(path);protected_directory(path.parent,owner_uid,anchor)
    temporary=path.with_name(path.name+'.new');info=path.lstat()
    # Initial exclusive publication may leave exactly these two hard links.
    if stat.S_ISREG(info.st_mode) and info.st_nlink==2 and temporary.exists() and not temporary.is_symlink():
        other=temporary.lstat()
        if file_identity(info)==file_identity(other) and info.st_uid==owner_uid and not info.st_mode&0o077:
            temporary.unlink();sync_directory(path.parent)
    info=owned_entry(path,owner_uid)
    if not stat.S_ISREG(info.st_mode) or info.st_size>1024*1024:raise ValueError('事务记录大小或类型无效')
    value=decode_json(path.read_bytes())
    if validate is not None:validate(value)
    if temporary.exists() or temporary.is_symlink():
        if not stat.S_ISREG(owned_entry(temporary,owner_uid).st_mode):raise PermissionError('临时事务记录不是普通文件')
        temporary.unlink();sync_directory(path.parent)
    return value


def write_private_record(path,value,*,initial=False,owner_uid=0,anchor=Path('/')):
    path=Path(path);protected_directory(path.parent,owner_uid,anchor)
    if not initial and not stat.S_ISREG(owned_entry(path,owner_uid).st_mode):raise PermissionError('事务记录不是普通文件')
    temporary=path.with_name(path.name+'.new')
    descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(descriptor,'w') as stream:
            json.dump(value,stream,sort_keys=True,allow_nan=False);stream.flush();os.fsync(stream.fileno())
        if initial:os.link(temporary,path,follow_symlinks=False)
        else:os.replace(temporary,path)
        sync_directory(path.parent)
    finally:temporary.unlink(missing_ok=True)


class FileTransaction:
    def __init__(self,journal,targets,*,owner_uid=0,anchor=Path('/'),resume=False):
        self.journal=Path(journal);self.targets={key:Path(path) for key,path in targets.items()}
        self.owner_uid=owner_uid;self.anchor=Path(anchor)
        if not self.anchor.is_absolute() or not self.journal.is_absolute():raise ValueError('事务必须使用绝对路径')
        self.check_directory(self.journal.parent)
        if not self.targets or any(not re.fullmatch('[a-z][a-z0-9_]{0,31}',key) for key in self.targets):raise ValueError('事务目标名称无效')
        paths=list(self.targets.values())
        if len(set(paths))!=len(paths) or any(left!=right and left.is_relative_to(right) for left in paths for right in paths):raise ValueError('事务目标不能重叠')
        for path in self.targets.values():
            if not path.is_absolute() or '..' in path.parts:raise ValueError('事务目标路径无效')
            self.check_directory(path.parent)
            if path==self.anchor or path==self.journal or self.journal.is_relative_to(path):raise ValueError('事务目标覆盖日志或信任边界')
        if resume:
            self.value=read_private_record(self.journal,owner_uid=owner_uid,anchor=anchor,validate=self.validate_journal)
        else:
            self.value={'version':2,'id':uuid.uuid4().hex,'status':'active','targets':{key:str(path) for key,path in self.targets.items()},'steps':[]}
            self.save(initial=True)

    def check_directory(self,path):
        protected_directory(path,self.owner_uid,self.anchor)

    def check_owned(self,path):
        return owned_entry(path,self.owner_uid)

    def validate_journal(self,value):
        if (not isinstance(value,dict) or set(value)!={'version','id','status','targets','steps'} or type(value['version']) is not int or value['version'] not in {1,2}
                or not isinstance(value['id'],str) or not re.fullmatch('[a-f0-9]{32}',value['id'])
                or not isinstance(value['status'],str) or value['status'] not in {'active','committing','committed','rolled-back'}
                or value['targets']!={key:str(path) for key,path in self.targets.items()} or not isinstance(value['steps'],list)):
            raise ValueError('安装事务日志无效')
        keys=set()
        for step in value['steps']:
            fields={'key','stage','had_original','rolled_back'}|({'old_identity','new_identity'} if value['version']==2 else set())
            if (not isinstance(step,dict) or set(step)!=fields or not isinstance(step['key'],str) or step['key'] not in self.targets
                    or step['key'] in keys or not isinstance(step['stage'],str) or not re.fullmatch(r'\.hotturkey-stage-[a-f0-9]{32}',step['stage'])
                    or type(step['had_original']) is not bool or type(step['rolled_back']) is not bool):raise ValueError('安装事务步骤无效')
            if value['version']==2:
                for key in ['old_identity','new_identity']:
                    identity=step[key]
                    if key=='old_identity' and not step['had_original']:
                        if identity is not None:raise ValueError('首次安装不能有旧文件身份')
                    elif not isinstance(identity,list) or len(identity)!=2 or any(type(part) is not int or not 0<=part<2**64 for part in identity):raise ValueError('事务文件身份无效')
                if step['old_identity']==step['new_identity']:raise ValueError('新旧文件身份不能相同')
            keys.add(step['key'])

    def save(self,initial=False):
        write_private_record(self.journal,self.value,initial=initial,owner_uid=self.owner_uid,anchor=self.anchor)

    def paths(self,step):
        target=self.targets[step['key']]
        return target,target.with_name(step['stage']),target.with_name('.hotturkey-backup-'+self.value['id']+'-'+step['key'])

    def publish(self,key,staged):
        if self.value['version']!=2 or self.value['status']!='active' or key not in self.targets or any(step['key']==key or step['rolled_back'] for step in self.value['steps']):raise ValueError('事务步骤不能发布')
        target=self.targets[key];staged=Path(staged)
        self.check_directory(target.parent)
        if staged.parent!=target.parent or not re.fullmatch(r'\.hotturkey-stage-[a-f0-9]{32}',staged.name):raise ValueError('暂存项目必须是目标同目录中的私有项目')
        new_identity=file_identity(self.check_owned(staged))
        exists=target.exists() or target.is_symlink()
        old_identity=file_identity(self.check_owned(target)) if exists else None
        step={'key':key,'stage':staged.name,'had_original':exists,'rolled_back':False,'old_identity':old_identity,'new_identity':new_identity}
        _,_,backup=self.paths(step)
        if backup.exists() or backup.is_symlink():raise FileExistsError('备份位置已被占用')
        self.value['steps'].append(step)
        self.save()  # Write intent before the first rename.
        if exists:
            atomic_exchange(target,staged);sync_directory(target.parent)
            if self.identity_at(target)!=new_identity or self.identity_at(staged)!=old_identity:raise OSError('文件系统未完成原子交换')
            staged.rename(backup);sync_directory(target.parent)
        else:staged.rename(target);sync_directory(target.parent)

    def remove_owned(self,path):
        if not path.exists() and not path.is_symlink():return
        info=self.check_owned(path)
        if stat.S_ISDIR(info.st_mode):shutil.rmtree(path)
        else:path.unlink()
        sync_directory(path.parent)

    def rollback(self):
        if self.value['status']=='rolled-back':return
        if self.value['status']!='active':raise ValueError('提交之后不能恢复旧数据')
        for step in reversed(self.value['steps']):
            if step['rolled_back']:continue
            target,staged,backup=self.paths(step);self.check_directory(target.parent)
            if self.value['version']==2:
                self.rollback_exchange(step,target,staged,backup)
                step['rolled_back']=True;self.save();continue
            if backup.exists() or backup.is_symlink():
                self.check_owned(backup);self.remove_owned(target);backup.rename(target);sync_directory(target.parent)
            elif not step['had_original'] and not staged.exists():self.remove_owned(target)
            self.remove_owned(staged);step['rolled_back']=True;self.save()
        self.value['status']='rolled-back';self.save()

    def identity_at(self,path):
        if not path.exists() and not path.is_symlink():return None
        return file_identity(self.check_owned(path))

    def rollback_exchange(self,step,target,staged,backup):
        old,new=step['old_identity'],step['new_identity']
        locations={path:self.identity_at(path) for path in [target,staged,backup]}
        if any(identity is not None and identity not in [old,new] for identity in locations.values()):raise PermissionError('事务项目已被其他文件替换，拒绝删除')
        current=locations[target]
        if not step['had_original']:
            if locations[backup] is not None or current not in [None,new] or locations[staged] not in [None,new]:raise ValueError('首次安装文件布局异常')
            if current==new:self.remove_owned(target)
        elif current!=old:
            originals=[path for path in [staged,backup] if locations[path]==old]
            if len(originals)!=1 or current not in [None,new]:raise ValueError('旧程序身份或位置不明确')
            if current is None:originals[0].rename(target);sync_directory(target.parent)
            else:
                atomic_exchange(target,originals[0]);sync_directory(target.parent)
                if self.identity_at(target)!=old or self.identity_at(originals[0])!=new:raise OSError('文件系统未完成原子恢复')
        for path in [staged,backup]:
            remaining=self.identity_at(path)
            if remaining is not None:
                if remaining!=new:raise ValueError('恢复后遗留了非暂存文件')
                self.remove_owned(path)

    def commit(self):
        if self.value['status']=='committed':return
        if self.value['status'] not in {'active','committing'}:raise ValueError('已经回退的事务不能提交')
        if self.value['status']=='active':
            if any(step['rolled_back'] for step in self.value['steps']):raise ValueError('已经开始回退的事务不能提交')
            for step in self.value['steps']:
                target,staged,backup=self.paths(step)
                if self.value['version']==2:
                    if (self.identity_at(target)!=step['new_identity'] or self.identity_at(staged) is not None
                            or self.identity_at(backup)!=step['old_identity']):raise ValueError('尚未完整发布的事务不能提交')
                elif not target.exists() or staged.exists() or step['had_original'] and not backup.exists():raise ValueError('旧版事务尚未完整发布')
            self.value['status']='committing';self.save()
        # Once the commit barrier is durable, recovery only completes cleanup.
        for step in self.value['steps']:
            _,staged,backup=self.paths(step);self.remove_owned(backup);self.remove_owned(staged)
        self.value['status']='committed';self.save()

    def recover(self):
        if self.value['status']=='active':self.rollback()
        elif self.value['status']=='committing':self.commit()
        return self.value['status']


@contextlib.contextmanager
def installation_lock(directory,*,owner_uid=0,anchor=Path('/')):
    directory=Path(directory)
    protected_directory(directory,owner_uid,Path(anchor))
    descriptor=os.open(directory/'install.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        info=os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=owner_uid or info.st_mode&0o077 or info.st_nlink!=1:raise PermissionError('安装锁无效')
        try:fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('另一个系统安装事务正在执行') from None
        yield
    finally:os.close(descriptor)
