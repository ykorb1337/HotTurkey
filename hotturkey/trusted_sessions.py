"""Usage from a separately attested native GUI agent and kernel inventory.

No caller-supplied elapsed time, UID, application metadata or login identity is
accepted. Missing/stale samples earn no credit and consume no allowance.
"""
import ctypes
import math

from .model import PolicyError
from .platform_macos import BROWSERS
from .session_desktop import SessionDesktop

FIELDS={'front_pid','front_start_sec','front_start_usec','front_executable',
        'idle_seconds','on_console','sample_seq','event_seq'}


def audit_session(identity):
    """Decode the socket's kernel audit token using the system libbsm API."""
    class Token(ctypes.Structure):_fields_=[('val',ctypes.c_uint32*8)]
    if len(identity.audit_token)!=ctypes.sizeof(Token):raise PermissionError('Invalid audit token')
    token=Token.from_buffer_copy(identity.audit_token)
    library=ctypes.CDLL('/usr/lib/libbsm.dylib')
    values={}
    for name in ['pid','euid','ruid','asid']:
        function=getattr(library,'audit_token_to_'+name)
        function.argtypes=[Token];function.restype=ctypes.c_uint32
        values[name]=function(token)
    if values['pid']!=identity.pid or values['euid']!=identity.uid or values['ruid']!=identity.uid:
        raise PermissionError('Inconsistent audit identity')
    return values['asid'] if values['asid'] not in {0,4294967295} else None


class TrustedSessions:
    def __init__(self,authority,execution,session_identity=audit_session):
        self.authority=authority;self.execution=execution;self.session_identity=session_identity
        self.leases={}
        self.external_targets=lambda uid:set()
        self.desktop=SessionDesktop(authority)

    def status(self,uid):
        lease=self.leases.get(uid)
        if not lease:return {'status':'missing','desktop_login':self.desktop.status(uid)}
        age=max(0,self.authority.clock()-lease['at'])
        return {'status':'running' if age<=3 else 'stale','last_sample_age':age,
                'on_console':lease['console'] if age<=3 else False,'desktop_login':self.desktop.status(uid)}

    def activity(self,uid):
        """Private root-side context for browser accounting, never an RPC result."""
        lease=self.leases.get(uid)
        if not lease or self.authority.clock()-lease['at']>3 or not lease['verified_console']:return None
        return {'pid':lease['front_pid'],'idle':lease['idle']}

    @staticmethod
    def validate(data):
        if set(data)-{'desktop_result'}!=FIELDS:raise PolicyError('会话采样字段无效')
        if 'desktop_result' in data:
            if data['desktop_result'] is None:raise PolicyError('桌面启动回执无效')
            SessionDesktop.validate(data['desktop_result'])
        for key,maximum in [('front_pid',2147483647),('front_start_sec',2**53),('front_start_usec',999999),('sample_seq',2**53),('event_seq',2**53)]:
            if type(data[key]) is not int or not 0<=data[key]<=maximum:raise PolicyError('会话采样数值无效')
        if data['sample_seq']==0 or type(data['on_console']) is not bool:raise PolicyError('会话采样状态无效')
        idle=data['idle_seconds']
        if type(idle) not in {int,float} or not math.isfinite(idle) or not 0<=idle<=86400:raise PolicyError('闲置时间无效')
        path=data['front_executable']
        if not isinstance(path,str) or len(path)>4096 or (data['front_pid'] and not path.startswith('/')):raise PolicyError('前台进程无效')
        if not data['front_pid'] and (path or data['front_start_sec'] or data['front_start_usec']):raise PolicyError('空前台进程无效')

    def consume(self,identity,data):
        if identity.role!='session':raise PolicyError('需要可信会话代理')
        self.validate(data)
        uid=identity.uid
        self.authority._account(uid)
        asid=self.session_identity(identity)
        with self.authority.store.lock:
            now=self.authority.clock();old=self.leases.get(uid)
            owner=(identity.pid,identity.audit_token)
            same=old is not None and old['owner']==owner
            if old and not same and now-old['at']<=5:raise PolicyError('已有活动会话代理')
            if same and (data['sample_seq']<=old['seq'] or data['event_seq']<old['event']):raise PolicyError('重复或倒序采样')
            engine=self.authority.engine(uid)
            # A new agent, a sampling gap, console/idle transitions or a missing
            # kernel match cannot retroactively fill the interval with usage.
            continuous=same and 0<=now-old['at']<=3 and old['valid']
            duration=now-old['at'] if continuous else 0
            applications=self.execution.applications(uid)
            front=next((app for app in applications if app['pid']==data['front_pid']
                and app.get('start_sec')==data['front_start_sec'] and app.get('start_usec')==data['front_start_usec']
                and app['executable']==data['front_executable']),None)
            valid=bool(data['on_console'] and front and data['idle_seconds']<=self.authority.store.state['settings']['idle_seconds'])
            signin=False
            marker={'boot':self.authority.boot_id,'audit_session':asid} if asid is not None else None
            previous_login=self.authority.store.state.get('trusted_sessions',{}).get(str(uid))
            if data['on_console'] and asid is not None:
                known=self.authority.store.state.setdefault('trusted_sessions',{})
                signin=known.get(str(uid))!=marker
                known[str(uid)]=marker
                signin=signin or bool(same and data['event_seq']>old['event'])
            engine.tick(signin=signin)
            prefix='system:'
            if not (continuous and valid):
                for source in list(engine.sources):
                    if source.startswith(prefix):engine.sources.pop(source)
            if valid:
                settings=self.authority.store.state['settings']
                rules=self.authority.store.state['blocks']
                background=[]
                if settings['strict_usage']:
                    for app in applications:
                        if app['pid']==front['pid']:continue
                        matched={b['id'] for b in rules if engine.active(b) and engine.app_matches(b,app)}
                        if matched:background.append((app,matched))
                background_ids=set().union(*(matched for _,matched in background))
                if settings['strict_usage']:background_ids.update(self.external_targets(uid))
                ids={b['id'] for b in rules if b['id'] not in background_ids}
                if front.get('bundle') in BROWSERS:ids.intersection_update(b['id'] for b in rules if b['applications'])
                engine.usage({**front,'idle':data['idle_seconds']},'system:foreground',policy_ids=ids,seconds_limit=duration)
                live={'system:foreground'}
                for app,ids in background:
                    source='system:background:'+app['identity'];live.add(source)
                    engine.usage({**app,'idle':data['idle_seconds'],'active':False},source,policy_ids=ids,seconds_limit=duration)
                for source in list(engine.sources):
                    if source.startswith(prefix) and source not in live:engine.sources.pop(source)
            self.leases[uid]={'owner':owner,'seq':data['sample_seq'],'event':data['event_seq'],
                             'at':now,'console':data['on_console'],'valid':valid,
                             'front_pid':data['front_pid'],'idle':data['idle_seconds'],
                             'verified_console':bool(data['on_console'] and front)}
            desktop=self.desktop.consume(uid,owner,marker,data['on_console'],previous_login,data.get('desktop_result'))
            self.authority.store.save()
            result={'accepted':True,'foreground_verified':bool(front)}
            if desktop is not None:result['desktop']=desktop
            return result
