"""Durable filesystem swaps for an installer that has already stopped services.

This module never starts/stops a service and grants no installation authority.
The production coordinator must supply fixed targets, validate the staged
payload/data and hold the installation lock before publishing anything.
"""
import contextlib
import fcntl
import json
import os
import re
import shutil
import stat
import uuid
from pathlib import Path

from .ipc import decode_json


def sync_directory(path):
    descriptor=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)


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
            info=self.check_owned(self.journal)
            if not stat.S_ISREG(info.st_mode) or info.st_size>1024*1024:raise ValueError('事务日志大小或类型无效')
            self.value=decode_json(self.journal.read_bytes());self.validate_journal()
            self.remove_owned(self.journal.with_name(self.journal.name+'.new'))
        else:
            self.value={'version':1,'id':uuid.uuid4().hex,'status':'active','targets':{key:str(path) for key,path in self.targets.items()},'steps':[]}
            self.save(initial=True)

    def check_directory(self,path):
        if not path.is_absolute() or '..' in path.parts or not path.is_relative_to(self.anchor):raise PermissionError('事务路径越过信任边界')
        while True:
            info=path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=self.owner_uid or info.st_mode&0o022:raise PermissionError('事务目录不是受保护路径')
            if path==self.anchor:break
            path=path.parent

    def check_owned(self,path):
        info=path.lstat()
        if (info.st_uid!=self.owner_uid or info.st_mode&0o022
                or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
                or stat.S_ISREG(info.st_mode) and info.st_nlink!=1):raise PermissionError('事务项目不是受保护的普通文件或目录')
        return info

    def validate_journal(self):
        value=self.value
        if (not isinstance(value,dict) or set(value)!={'version','id','status','targets','steps'} or value['version']!=1
                or not isinstance(value['id'],str) or not re.fullmatch('[a-f0-9]{32}',value['id'])
                or value['status'] not in {'active','committing','committed','rolled-back'}
                or value['targets']!={key:str(path) for key,path in self.targets.items()} or not isinstance(value['steps'],list)):
            raise ValueError('安装事务日志无效')
        keys=set()
        for step in value['steps']:
            if (not isinstance(step,dict) or set(step)!={'key','stage','had_original','rolled_back'} or step['key'] not in self.targets
                    or step['key'] in keys or not isinstance(step['stage'],str) or not re.fullmatch(r'\.hotturkey-stage-[a-f0-9]{32}',step['stage'])
                    or type(step['had_original']) is not bool or type(step['rolled_back']) is not bool):raise ValueError('安装事务步骤无效')
            keys.add(step['key'])

    def save(self,initial=False):
        # A fixed sibling temp is safe only inside the protected journal folder.
        temporary=self.journal.with_name(self.journal.name+'.new')
        descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(descriptor,'w') as stream:
                json.dump(self.value,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
            if initial:os.link(temporary,self.journal,follow_symlinks=False)
            else:os.replace(temporary,self.journal)
            sync_directory(self.journal.parent)
        finally:temporary.unlink(missing_ok=True)

    def paths(self,step):
        target=self.targets[step['key']]
        return target,target.with_name(step['stage']),target.with_name('.hotturkey-backup-'+self.value['id']+'-'+step['key'])

    def publish(self,key,staged):
        if self.value['status']!='active' or key not in self.targets or any(step['key']==key or step['rolled_back'] for step in self.value['steps']):raise ValueError('事务步骤不能发布')
        target=self.targets[key];staged=Path(staged)
        self.check_directory(target.parent)
        if staged.parent!=target.parent or not re.fullmatch(r'\.hotturkey-stage-[a-f0-9]{32}',staged.name):raise ValueError('暂存项目必须是目标同目录中的私有项目')
        self.check_owned(staged)
        exists=target.exists() or target.is_symlink()
        if exists:self.check_owned(target)
        step={'key':key,'stage':staged.name,'had_original':exists,'rolled_back':False}
        _,_,backup=self.paths(step)
        if backup.exists() or backup.is_symlink():raise FileExistsError('备份位置已被占用')
        self.value['steps'].append(step)
        self.save()  # Write intent before the first rename.
        if exists:target.rename(backup);sync_directory(target.parent)
        staged.rename(target);sync_directory(target.parent)

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
            if backup.exists() or backup.is_symlink():
                self.check_owned(backup);self.remove_owned(target);backup.rename(target);sync_directory(target.parent)
            elif not step['had_original'] and not staged.exists():self.remove_owned(target)
            self.remove_owned(staged);step['rolled_back']=True;self.save()
        self.value['status']='rolled-back';self.save()

    def commit(self):
        if self.value['status']=='committed':return
        if self.value['status'] not in {'active','committing'}:raise ValueError('已经回退的事务不能提交')
        if self.value['status']=='active':
            if any(step['rolled_back'] for step in self.value['steps']):raise ValueError('已经开始回退的事务不能提交')
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
    # Reuse ancestor checks without creating a transaction.
    guard=object.__new__(FileTransaction);guard.owner_uid=owner_uid;guard.anchor=Path(anchor);guard.check_directory(directory)
    descriptor=os.open(directory/'install.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        info=os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=owner_uid or info.st_mode&0o077 or info.st_nlink!=1:raise PermissionError('安装锁无效')
        try:fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('另一个系统安装事务正在执行') from None
        yield
    finally:os.close(descriptor)
