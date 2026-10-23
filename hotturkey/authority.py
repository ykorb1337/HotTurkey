"""Shared policy authority for the future privileged service.

One protected Store owns policy. Account views share policy and locks, while
usage charges, earned breaks and challenges belong to a numeric account ID.
This module does not install a daemon or grant itself system privileges.
"""
import copy
import pwd
import secrets
import time
from collections.abc import MutableMapping

from .engine import Engine, password_ok
from .model import PolicyError


class AccountState(MutableMapping):
    def __init__(self, core, context):
        self.core=core
        self.context=context

    def __getitem__(self,key):
        return self.context['runtime'] if key=='runtime' else self.core.state[key]

    def __setitem__(self,key,value):
        if key=='runtime':self.context['runtime']=value
        else:self.core.state[key]=value

    def __delitem__(self,key):
        if key=='runtime':self.context['runtime'].clear()
        else:del self.core.state[key]

    def __iter__(self):return iter(self.core.state)
    def __len__(self):return len(self.core.state)


class AccountStore:
    def __init__(self, authority, uid, username):
        self.authority=authority
        self.core=authority.store
        self.uid=uid
        self.username=username
        self.context=self.core.state['accounts'].setdefault(str(uid),{'runtime':{}})
        self.state=AccountState(self.core,self.context)
        self.lock=self.core.lock
        self.directory=self.core.directory
        self.db=self.core.db

    def save(self):self.core.save()

    def runtime_for(self, block, now):
        runtime=self.context['runtime'].setdefault(block['id'],{'started':now})
        start=self.core.state['block_starts'].get(block['id'])
        if start and runtime.get('_start_generation')!=start['generation']:
            runtime.update(started=start['at'],_start_generation=start['generation'])
            if 'device_until' in start:runtime['device_until']=start['device_until']
        # Device timer extensions are shared without resetting other break state.
        if start and 'device_until' in start:runtime['device_until']=start['device_until']
        if start and 'pomodoro_started' in start:
            if runtime.get('pomodoro_started')!=start['pomodoro_started']:runtime.pop('break_until',None)
            runtime['pomodoro_started']=start['pomodoro_started']
        elif start:runtime.pop('pomodoro_started',None)
        return runtime

    def block_started(self, block, now):
        previous=self.core.state['block_starts'].get(block['id'],{})
        start={'at':now,'generation':previous.get('generation',0)+1}
        if block['device']!='none' and block['mode']=='continuous':
            start['device_until']=self.context['runtime'][block['id']]['device_until']
        self.core.state['block_starts'][block['id']]=start

    def device_deadline_changed(self, block, until):
        start=self.core.state['block_starts'].get(block['id'])
        if start is not None:start['device_until']=until

    def pomodoro_reset(self, block, now):
        runtime=self.context['runtime'][block['id']]
        start=self.core.state['block_starts'].setdefault(block['id'],{'at':runtime['started'],'generation':1})
        start['pomodoro_started']=now

    def autostart_runtime(self, block):
        return self.core.state['autostarts'].setdefault(block['id'],{})

    def block_deleted(self, ident):
        self.core.state['block_starts'].pop(ident,None)
        self.core.state['autostarts'].pop(ident,None)
        for context in self.core.state['accounts'].values():context['runtime'].pop(ident,None)

    def charge(self, at, block_id, seconds):
        self.core.charge(at,self._charge_key(block_id),seconds)

    def used(self, block_id, since):return self.core.used(self._charge_key(block_id),since)
    def _charge_key(self, ident):return f'uid:{self.uid}:{ident}'

    def event(self, at, user, kind, target, block_id='', seconds=0, blocked=False, block_ids=None):
        # The identity comes from the account context, never the sample payload.
        self.core.event(at,self.username,kind,target,block_id,seconds,blocked,block_ids)

    def statistics(self, since=0, until=1e20, user='', query='', block='', kind=''):
        if self.uid!=self.authority.controller_uid:user=self.username
        return self.core.statistics(since,until,user,query,block,kind)

    def export_statistics(self):
        if self.uid==self.authority.controller_uid:return self.core.export_statistics()
        with self.lock:
            return [dict(row) for row in self.db.execute('SELECT * FROM events WHERE user=? ORDER BY at',(self.username,))]

    def clear_statistics(self):
        if self.uid!=self.authority.controller_uid:raise PolicyError('只有管理账户可以删除统计')
        self.core.clear_statistics()

    def prune(self, now):self.core.prune(now)


class PolicyAuthority:
    def __init__(self, store, controller_uid, *, resolve_user=pwd.getpwuid, boot_id='test-boot', wall=None, monotonic=None):
        if isinstance(controller_uid,bool) or not isinstance(controller_uid,int) or controller_uid<500:
            raise PolicyError('管理账户 UID 无效')
        self.store=store
        self.controller_uid=controller_uid
        self.resolve_user=resolve_user
        self.boot_id=boot_id
        self.clocks={}
        if wall is not None:self.clocks['wall']=wall
        if monotonic is not None:self.clocks['monotonic']=monotonic
        self.clock=monotonic or time.monotonic
        self.sessions={}
        self.auth_retry=0
        self.engines={}
        self._account(controller_uid)
        self._migrate()

    def _migrate(self):
        """Migrate a copied per-user database in one SQLite transaction."""
        with self.store.lock:
            state=self.store.state
            if state.get('authority_version')==1:
                if state['controller_uid']!=self.controller_uid:raise PolicyError('不能更换既有规则的管理账户')
                return
            if 'authority_version' in state:raise PolicyError('系统规则版本不受支持')
            before=copy.deepcopy(state)
            try:
                legacy=copy.deepcopy(state.get('runtime',{}))
                state.update(authority_version=1,controller_uid=self.controller_uid,
                             accounts={str(self.controller_uid):{'runtime':legacy}},
                             block_starts={},autostarts={})
                for block in state['blocks']:
                    runtime=legacy.get(block['id'],{})
                    if 'started' in runtime:
                        start={'at':runtime['started'],'generation':1}
                        if 'device_until' in runtime:start['device_until']=runtime['device_until']
                        if 'pomodoro_started' in runtime:start['pomodoro_started']=runtime['pomodoro_started']
                        state['block_starts'][block['id']]=start
                    state['autostarts'][block['id']]={key:runtime[key] for key in ['once_fired','daily_fired','schedule_fired'] if key in runtime}
                # Preserve already-spent allowances for the installing account.
                self.store.db.execute('UPDATE charges SET block_id=? || block_id',(f'uid:{self.controller_uid}:',))
                state['runtime']={}
                self.store.save()
            except BaseException:
                self.store.db.rollback()
                self.store.state=before
                raise

    def _account(self, uid):
        if isinstance(uid,bool) or not isinstance(uid,int) or uid<500:raise PolicyError('账户 UID 无效')
        try:account=self.resolve_user(uid)
        except KeyError:raise PolicyError('本机账户不存在') from None
        if account.pw_uid!=uid or not account.pw_dir.startswith('/Users/') or account.pw_name.startswith('_'):
            raise PolicyError('只支持本机用户账户')
        return account

    def engine(self, uid):
        account=self._account(uid)
        with self.store.lock:
            current=self.engines.get(uid)
            if current is None or current.user!=account.pw_name:
                view=AccountStore(self,uid,account.pw_name)
                current=Engine(view,boot_id=self.boot_id,user=account.pw_name,**self.clocks)
                self.engines[uid]=current
            return current

    def authenticated(self, uid, session=''):
        if type(uid) is not int or uid!=self.controller_uid:return False
        if not self.store.state['settings']['settings_password']:return True
        return isinstance(session,str) and self.sessions.get(session,0)>self.clock()

    def verify_password(self, uid, password):
        self._account(uid)
        if uid!=self.controller_uid:raise PolicyError('只有管理账户可以验证管理密码')
        with self.store.lock:
            if self.clock()<self.auth_retry:raise PolicyError('请稍后重试')
            stored=self.store.state['settings']['settings_password']
            if stored and not password_ok(password,stored):
                self.auth_retry=self.clock()+2
                raise PolicyError('设置密码不正确')

    def authenticate(self, uid, password):
        with self.store.lock:
            self.verify_password(uid,password)
            self.sessions={key:until for key,until in self.sessions.items() if until>self.clock()}
            # Bound memory even when the approved manager repeatedly authenticates.
            while len(self.sessions)>=64:self.sessions.pop(next(iter(self.sessions)))
            token=secrets.token_urlsafe(32)
            self.sessions[token]=self.clock()+900
            return token

    def snapshot(self, uid, session=''):
        engine=self.engine(uid)
        with self.store.lock:
            value=engine.snapshot()
            value['can_manage']=uid==self.controller_uid
            value['authenticated']=self.authenticated(uid,session)
            if uid!=self.controller_uid:
                value['blocks']=[b for b in value['blocks'] if not b['users'] or engine.user in b['users']]
            if value['settings']['protect_overview'] and not value['authenticated']:value['blocks']=[]
            return value

    def manage(self, uid, operation, data, session=''):
        if uid!=self.controller_uid:raise PolicyError('只有管理账户可以修改规则')
        engine=self.engine(uid)
        with self.store.lock:
            if not self.authenticated(uid,session):raise PolicyError('请先输入设置密码')
            if operation=='save':return engine.save_block(data['block'],data.get('id'))
            if operation=='add-targets':return engine.add_targets(data['id'],data.get('websites'),data.get('applications'))
            if operation=='reset-pomodoro':return engine.reset_pomodoro(data['id'])
            if operation=='delete':engine.delete(data['id']);return {'ok':True}
            if operation=='toggle':return engine.toggle(data['id'],data.get('enabled'),data.get('confirm_device',False))
            if operation=='lock':return engine.set_lock(data['id'],data)
            if operation=='unlock':return engine.unlock(data['id'],data)
        raise PolicyError('未知规则操作')

    def can_uninstall(self):
        engine=self.engine(self.controller_uid)
        with self.store.lock:return not any(engine.locked(block) for block in self.store.state['blocks'])
