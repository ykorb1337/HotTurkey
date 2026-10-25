"""Durable install sequencing; OS operations belong to a separately trusted driver.

There is intentionally no public apply RPC or arbitrary-path CLI. Production
must use fixed targets and a driver that authorizes management, stops the old
services, rechecks locks, validates private stages and bounds every OS call.
"""
import copy
import hashlib
import math
import re
import stat
import time
from pathlib import Path

from .system_transaction import (FileTransaction,installation_lock,protected_directory,
                                 read_private_record,write_private_record)

PHASES={'ready','stopping','staging','publishing','probing','committing','activating','finished','restoring','rolled-back'}
HEALTH_FIELDS={'installation_pending','executor_ready','session_transport_fresh','session_transport_uids',
               'installation_transaction','payload_sha256'}


def valid_uids(values):
    return (isinstance(values,list) and len(values)<=256 and all(type(uid) is int and 500<=uid<=4294967295 for uid in values)
            and len(set(values))==len(values))


def validate_services(value):
    if (not isinstance(value,dict) or set(value)!={'legacy_loaded','authority_loaded','session_loaded','gui_uids'}
            or type(value['legacy_loaded']) is not bool or type(value['authority_loaded']) is not bool
            or not valid_uids(value['session_loaded']) or not valid_uids(value['gui_uids'])
            or not set(value['session_loaded'])<=set(value['gui_uids'])):raise ValueError('旧后台状态记录无效')


def staging_paths(targets,transaction):
    if not isinstance(transaction,str) or not re.fullmatch('[a-f0-9]{32}',transaction):raise ValueError('安装事务标识无效')
    return {key:Path(path).with_name('.hotturkey-stage-'+hashlib.sha256((transaction+':'+key).encode()).hexdigest()[:32]) for key,path in targets.items()}


def validate_index(value):
    if (not isinstance(value,dict) or set(value)!={'version','directory','controller_uid','payload_sha256','transaction'}
            or type(value['version']) is not int or value['version']!=1 or type(value['controller_uid']) is not int
            or not 500<=value['controller_uid']<=4294967295 or not isinstance(value['directory'],str)
            or not 1<=len(Path(value['directory']).parts)<=3 or Path(value['directory']).is_absolute()
            or '/'.join(Path(value['directory']).parts)!=value['directory']
            or any(not re.fullmatch('[a-z0-9][a-z0-9_-]{0,63}',part) for part in Path(value['directory']).parts)
            or not isinstance(value['payload_sha256'],str) or not re.fullmatch('[a-f0-9]{64}',value['payload_sha256'])
            or not isinstance(value['transaction'],str) or not re.fullmatch('[a-f0-9]{32}',value['transaction'])):raise ValueError('活动安装登记无效')


def pending_cutover(directory,*,owner_uid=0,anchor=Path('/')):
    path=Path(directory)/'active.json'
    protected_directory(path.parent,owner_uid,anchor)
    if not path.exists() and not path.is_symlink():
        if path.with_name(path.name+'.new').exists() or path.with_name(path.name+'.new').is_symlink():raise ValueError('安装登记尚未完成，请先恢复原事务')
        return None
    return read_private_record(path,owner_uid=owner_uid,anchor=anchor,validate=validate_index)


def health_matches(value,context,required_uids,pending):
    if not valid_uids(required_uids):raise ValueError('当前登录账户列表无效')
    if not isinstance(value,dict) or set(value)!=HEALTH_FIELDS:return False
    if (value['installation_transaction']!=context['transaction'] or value['payload_sha256']!=context['payload_sha256']
            or type(value['installation_pending']) is not bool or value['executor_ready'] is not True
            or pending is not None and value['installation_pending'] is not pending
            or not valid_uids(value['session_transport_uids']) or type(value['session_transport_fresh']) is not bool):return False
    actual=set(value['session_transport_uids'])
    return set(required_uids)<=actual and value['session_transport_fresh']==(context['controller_uid'] in actual)


class CutoverDriver:
    """Service/activation methods are idempotent; stage exclusively creates once."""
    def authorize(self):raise NotImplementedError
    def capture(self):raise NotImplementedError
    def stop_previous(self,context):raise NotImplementedError
    def stage(self,context):raise NotImplementedError
    def start_candidate(self,context):raise NotImplementedError
    def probe_candidate(self,context,*,timeout):raise NotImplementedError
    def activate(self,context):raise NotImplementedError
    def stop_candidate(self,context):raise NotImplementedError
    def restore_previous(self,context):raise NotImplementedError
    def required_sessions(self,context):return context['services']['gui_uids']


class CutoverCoordinator:
    def __init__(self,directory,targets,driver,controller_uid,payload_sha256,*,lock_directory,owner_uid=0,
                 anchor=Path('/'),timeout=60,clock=time.monotonic,wall=time.time,sleep=time.sleep):
        if type(controller_uid) is not int or not 500<=controller_uid<=4294967295:raise ValueError('安装管理账户无效')
        if not isinstance(payload_sha256,str) or not re.fullmatch('[a-f0-9]{64}',payload_sha256):raise ValueError('安装材料摘要无效')
        if type(timeout) not in {int,float} or not math.isfinite(timeout) or not 1<=timeout<=300:raise ValueError('安装超时无效')
        self.directory=Path(directory);self.lock_directory=Path(lock_directory);self.anchor=Path(anchor);self.owner_uid=owner_uid
        protected_directory(self.lock_directory,owner_uid,self.anchor);protected_directory(self.directory,owner_uid,self.anchor)
        if not self.directory.is_relative_to(self.lock_directory):raise ValueError('安装日志必须位于全局安装锁目录内')
        parts=self.directory.relative_to(self.lock_directory).parts
        if not 1<=len(parts)<=3 or any(not re.fullmatch('[a-z0-9][a-z0-9_-]{0,63}',part) for part in parts):raise ValueError('安装日志目录名称无效')
        self.job_directory='/'.join(parts);self.index=self.lock_directory/'active.json'
        self.targets={key:Path(path) for key,path in targets.items()};self.driver=driver
        self.uid=controller_uid;self.payload=payload_sha256;self.timeout=timeout;self.clock=clock;self.wall=wall;self.sleep=sleep
        self.journal=self.directory/'files.json';self.record=self.directory/'services.json';self.files=None;self.context=None;self.deadline=None

    def validate_context(self,value):
        if (not isinstance(value,dict) or set(value)!={'version','transaction','controller_uid','payload_sha256','services','phase','expires_at','stages_reserved','services_touched'}
                or type(value['version']) is not int or value['version']!=1 or value['controller_uid']!=self.uid or type(value['controller_uid']) is not int
                or value['payload_sha256']!=self.payload or value['transaction']!=self.files.value['id']
                or not isinstance(value['phase'],str) or value['phase'] not in PHASES
                or type(value['stages_reserved']) is not bool or type(value['services_touched']) is not bool
                or type(value['expires_at']) not in {int,float} or not math.isfinite(value['expires_at'])):raise ValueError('安装服务事务记录无效')
        validate_services(value['services'])
        if self.files.value['steps'] and not (value['stages_reserved'] and value['services_touched']):raise ValueError('文件发布早于服务停用记录')
        if value['services_touched'] and not value['stages_reserved']:raise ValueError('服务停用早于暂存空间保留')
        if self.files.value['status'] in {'committing','committed'} and ({step['key'] for step in self.files.value['steps']}!=set(self.targets) or not value['services_touched']):raise ValueError('提交记录未包含全部安装目标')

    def transition(self,phase,initial=False):
        self.context['phase']=phase
        self.validate_context(self.context)
        write_private_record(self.record,self.context,initial=initial,owner_uid=self.owner_uid,anchor=self.anchor)

    def call(self,name,**values):return getattr(self.driver,name)(copy.deepcopy(self.context),**values)

    def index_value(self):
        return {'version':1,'directory':self.job_directory,'controller_uid':self.uid,'payload_sha256':self.payload,'transaction':self.files.value['id']}

    def clear_index(self):
        index=pending_cutover(self.lock_directory,owner_uid=self.owner_uid,anchor=self.anchor)
        if index==self.index_value():self.files.remove_owned(self.index)
        elif index is not None:raise ValueError('活动安装登记属于另一事务，拒绝修改')

    def check_budget(self):
        remaining=min(self.deadline-self.clock(),self.context['expires_at']-self.wall())
        if remaining<=0:raise TimeoutError('安装阶段超过时限')
        return remaining

    def wait_health(self,pending):
        while True:
            remaining=self.check_budget()
            value=self.call('probe_candidate',timeout=min(3,remaining))
            self.check_budget()
            required=self.call('required_sessions')
            if health_matches(value,self.context,required,pending):return
            self.sleep(min(.1,self.check_budget()))

    def apply(self):
        with installation_lock(self.lock_directory,owner_uid=self.owner_uid,anchor=self.anchor):
            if pending_cutover(self.lock_directory,owner_uid=self.owner_uid,anchor=self.anchor) is not None:raise FileExistsError('另一安装事务尚未恢复或完成')
            if self.journal.exists() or self.journal.is_symlink() or self.record.exists() or self.record.is_symlink():raise FileExistsError('请先恢复或归档此前的安装事务')
            self.driver.authorize()
            services=copy.deepcopy(self.driver.capture());validate_services(services)
            self.files=FileTransaction(self.journal,self.targets,owner_uid=self.owner_uid,anchor=self.anchor)
            self.context={'version':1,'transaction':self.files.value['id'],'controller_uid':self.uid,'payload_sha256':self.payload,
                          'services':services,'phase':'ready','expires_at':self.wall()+self.timeout,'stages_reserved':False,'services_touched':False}
            self.deadline=self.clock()+self.timeout;self.transition('ready',initial=True)
            try:
                write_private_record(self.index,self.index_value(),initial=True,owner_uid=self.owner_uid,anchor=self.anchor)
                expected=staging_paths(self.targets,self.context['transaction'])
                if any(path.exists() or path.is_symlink() for path in expected.values()):raise FileExistsError('暂存位置已有文件，拒绝覆盖')
                self.context['stages_reserved']=True;self.transition('ready')
                self.context['services_touched']=True;self.transition('stopping');self.call('stop_previous');self.check_budget()
                self.transition('staging');stages=self.call('stage');self.check_budget()
                if not isinstance(stages,dict) or {key:Path(path) for key,path in stages.items()}!=expected:raise ValueError('安装暂存目标不完整或路径不匹配')
                self.transition('publishing')
                for key in self.targets:
                    self.check_budget();self.files.publish(key,stages[key])
                self.transition('probing');self.call('start_candidate');self.wait_health(True)
                self.transition('committing');self.files.commit()
                self.finish_forward()
            except BaseException:
                # Never restore old data after the durable filesystem barrier.
                if self.files.value['status'] in {'active','rolled-back'}:self.restore_old()
                raise
            return self.result()

    def restore_old(self):
        self.transition('restoring')
        if self.context['services_touched']:self.call('stop_candidate')
        if self.files.value['status']=='active':self.files.rollback()
        self.cleanup_stages()
        if self.context['services_touched']:self.call('restore_previous')
        self.transition('rolled-back')
        self.clear_index()

    def cleanup_stages(self):
        if self.context['stages_reserved']:
            for path in staging_paths(self.targets,self.context['transaction']).values():self.files.remove_owned(path)

    def finish_forward(self):
        self.files.commit()
        self.cleanup_stages()
        # Recovery gets a new bounded window; a stale installer deadline cannot
        # authorize reverting already committed data.
        self.deadline=self.clock()+self.timeout;self.context['expires_at']=self.wall()+self.timeout
        self.transition('activating');self.call('start_candidate')
        self.wait_health(None);self.call('activate');self.wait_health(False)
        self.transition('finished')
        self.clear_index()

    def recover(self):
        with installation_lock(self.lock_directory,owner_uid=self.owner_uid,anchor=self.anchor):
            temporary=self.index.with_name(self.index.name+'.new')
            unpublished=not (self.index.exists() or self.index.is_symlink()) and (temporary.exists() or temporary.is_symlink())
            index=None if unpublished else pending_cutover(self.lock_directory,owner_uid=self.owner_uid,anchor=self.anchor)
            if not self.journal.exists() and not self.journal.is_symlink():
                if index is not None or unpublished:raise ValueError('活动安装缺少文件事务日志，拒绝猜测恢复操作')
                if self.record.exists() or self.record.is_symlink():raise ValueError('服务记录存在但文件事务日志缺失')
                return {'status':'empty','transaction':None}
            self.files=FileTransaction(self.journal,self.targets,owner_uid=self.owner_uid,anchor=self.anchor,resume=True)
            if index is not None and index!=self.index_value():raise ValueError('活动安装登记属于另一事务')
            if not self.record.exists() and not self.record.is_symlink():
                if index is not None or unpublished:raise ValueError('已登记的安装缺少服务状态，拒绝猜测恢复操作')
                if self.files.value['status'] not in {'active','rolled-back'} or self.files.value['steps']:raise ValueError('缺少服务状态，拒绝猜测恢复操作')
                # The service record is synced before stop_previous can run.
                temporary=self.record.with_name(self.record.name+'.new')
                if temporary.exists() or temporary.is_symlink():
                    if not stat.S_ISREG(self.files.check_owned(temporary).st_mode):raise ValueError('临时服务记录类型无效')
                    self.files.remove_owned(temporary)
                self.files.rollback();return {'status':'rolled-back','transaction':self.files.value['id']}
            self.context=read_private_record(self.record,owner_uid=self.owner_uid,anchor=self.anchor,validate=self.validate_context)
            if unpublished:
                # Registration is durable before reserving stages or stopping
                # services. Only this untouched phase can retire a partial
                # initial write; a touched job must never guess what it owns.
                if (self.context['phase']!='ready' or self.context['stages_reserved'] or self.context['services_touched']
                        or self.files.value['status']!='active' or self.files.value['steps']):raise ValueError('未完成登记但服务事务已有变化')
                if not stat.S_ISREG(self.files.check_owned(temporary).st_mode):raise PermissionError('临时安装登记类型无效')
                try:draft=read_private_record(temporary,owner_uid=self.owner_uid,anchor=self.anchor,validate=validate_index)
                except (ValueError,UnicodeError):draft=None
                if draft is not None and draft!=self.index_value():raise ValueError('临时安装登记属于另一事务')
                self.files.remove_owned(temporary)
            phase=self.context['phase'];status=self.files.value['status']
            if phase in {'finished','rolled-back'}:
                expected='committed' if phase=='finished' else 'rolled-back'
                if status!=expected:raise ValueError('文件和服务事务终态不一致')
                if index is not None:self.clear_index()
                return self.result()
            if self.context['services_touched'] and index is None:raise ValueError('服务已变更但活动安装登记缺失')
            if status in {'active','rolled-back'}:self.restore_old()
            else:self.finish_forward()
            return self.result()

    def result(self):return {'status':self.context['phase'],'transaction':self.context['transaction']}
