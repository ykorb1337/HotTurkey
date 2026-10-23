"""Restricted Native Messaging operations for an attested browser-host role.

Parent code/origin is verified by the native host, then its UID/start identity
is independently matched to the kernel scanner. Missing session context cannot
invent usage; no management operation is exposed here.
"""
import copy
import hashlib
import math
import re

from .browser_additions import add_site,options
from .model import PolicyError,browser_page,target_matches
from .platform_macos import BROWSERS
from .tab_exceptions import TabExceptions,scope

ENVELOPE={'browser','parent_pid','parent_start_sec','parent_start_usec','channel','sequence','message'}
OPERATIONS={
    'check':{'url','channels','active','embedded','incognito','record','context','tab'},
    'sync':{'browser','incognito_allowed','files_allowed','usage','tabs','context'},
    'break':{'id','answer'},'closed-tab':{'url','incognito'},
    'tab-unblock':{'id','url','channels','context','tab','minutes','answer'},
    'tab-close':{'context','tab'},'add-site-options':{'password'},
    'add-site':{'id','url','scope','password'},
}


def text(value,maximum=8192):
    if not isinstance(value,str) or len(value)>maximum:raise PolicyError('浏览器文本无效')
    return value


def boolean_fields(data,keys):
    for key in keys:
        if key in data and type(data[key]) is not bool:raise PolicyError('浏览器状态无效')


def channels(value):
    if not isinstance(value,list) or len(value)>64:raise PolicyError('频道信息无效')
    for item in value:text(item,2048)


class TrustedBrowsers:
    def __init__(self,authority,execution,sessions,bundles=None):
        self.authority=authority;self.execution=execution;self.sessions=sessions
        self.bundles=bundles if bundles is not None else {name:bundle for bundle,name in BROWSERS.items()}
        self.leases={};self.exceptions={};self.sources={};self.matches={}
        sessions.external_targets=self.targets

    def targets(self,uid):
        now=self.authority.clock()
        return set().union(*(ids for (owner,_,_), (at,ids) in self.matches.items() if owner==uid and 0<=now-at<=8))

    def tabs(self,uid):
        if uid not in self.exceptions:self.exceptions[uid]=TabExceptions(self.authority.engine(uid))
        return self.exceptions[uid]

    @staticmethod
    def validate_message(message):
        if not isinstance(message,dict) or set(message)-{'op','data'}:raise PolicyError('浏览器消息无效')
        operation=message.get('op');data=message.get('data',{})
        if not isinstance(operation,str) or operation not in OPERATIONS or not isinstance(data,dict) or set(data)-OPERATIONS[operation]:raise PolicyError('浏览器操作无效')
        boolean_fields(data,['active','embedded','incognito','record','incognito_allowed','files_allowed'])
        for key in ['url','id','answer','password','context','scope','browser']:
            if key in data:text(data[key],8192 if key=='url' else 5000 if key in {'answer','password'} else 128)
        if 'channels' in data:channels(data['channels'])
        if ('context' in data or 'tab' in data) and operation!='sync':scope(data)
        if operation=='sync':
            if 'context' not in data:raise PolicyError('需要浏览器会话')
            scope({'context':data['context'],'tab':0})
            tabs=data.get('tabs',[]);usage=data.get('usage',[])
            if not isinstance(tabs,list) or len(tabs)>1000 or any(type(t) is not int or not 0<=t<=2147483647 for t in tabs):raise PolicyError('标签页列表无效')
            if not isinstance(usage,list) or len(usage)>200:raise PolicyError('使用采样过多')
            seen=set()
            for item in usage:
                if not isinstance(item,dict) or set(item)-{'tab','url','active','idle','playing','incognito','channels'}:raise PolicyError('使用采样无效')
                scope({'context':data['context'],'tab':item.get('tab')})
                if item['tab'] in seen or item['tab'] not in tabs:raise PolicyError('使用采样标签页无效')
                seen.add(item['tab']);text(item.get('url'));channels(item.get('channels',[]))
                boolean_fields(item,['active','playing','incognito'])
                idle=item.get('idle',0)
                if type(idle) not in {int,float} or not math.isfinite(idle) or idle<0:raise PolicyError('闲置采样无效')
        return operation,data

    def consume(self,identity,envelope):
        if identity.role!='browser' or set(envelope)!=ENVELOPE:raise PolicyError('需要可信浏览器连接')
        browser=envelope['browser'];uid=identity.uid
        if not isinstance(browser,str) or browser not in self.bundles:raise PolicyError('浏览器身份无效')
        for key,maximum in [('parent_pid',2147483647),('parent_start_sec',2**53),('parent_start_usec',999999),('sequence',2**53)]:
            if type(envelope[key]) is not int or not 0<=envelope[key]<=maximum:raise PolicyError('浏览器进程身份无效')
        channel=envelope['channel']
        if not isinstance(channel,str) or not re.fullmatch('[0-9a-fA-F]{64}',channel) or envelope['sequence']==0:raise PolicyError('浏览器连接无效')
        operation,data=self.validate_message(envelope['message'])
        with self.authority.store.lock:
            self.authority._account(uid)
            parent=next((app for app in self.execution.applications(uid) if app['pid']==envelope['parent_pid']
                and app.get('start_sec')==envelope['parent_start_sec'] and app.get('start_usec')==envelope['parent_start_usec']
                and app['bundle']==self.bundles[browser]),None)
            if parent is None:raise PolicyError('浏览器进程尚未验证')
            now=self.authority.clock()
            self.leases={key:value for key,value in self.leases.items() if now-value['at']<=600}
            self.matches={key:value for key,value in self.matches.items() if now-value[0]<=8}
            key=(uid,channel);owner=(identity.pid,identity.audit_token)
            old=self.leases.get(key)
            if old and (old['owner']!=owner or envelope['sequence']<=old['seq']):raise PolicyError('重复或伪造的浏览器连接')
            if old is None and sum(k[0]==uid for k in self.leases)>=128:raise PolicyError('浏览器连接过多')
            self.leases[key]={'owner':owner,'seq':envelope['sequence'],'at':now}
            engine=self.authority.engine(uid);engine.tick()
            # Browser name is attested, even if extension user-agent detection is wrong.
            data=copy.deepcopy(data)
            if 'context' in data:
                namespace=f"{browser}:{parent['pid']}:{parent['start_sec']}:{parent['start_usec']}:"
                data['context']=hashlib.sha256((namespace+data['context']).encode()).hexdigest()
            grants=self.tabs(uid)
            if operation=='sync':return self.sync(uid,browser,parent,engine,grants,data)
            if operation=='check':
                url=data.get('url','');result=engine.evaluate(url,data.get('channels',[]),data.get('active',True),data.get('embedded',False),grants.ids(data))
                if result['blocked'] and data.get('record',True):engine.record_block(url,[b['id'] for b in result['blocks']],incognito=data.get('incognito',False))
                return result
            if operation=='tab-unblock':return grants.request(data)
            if operation=='tab-close':return grants.close(data)
            if operation=='break':return engine.request_break(data.get('id'),data)
            if operation in {'add-site-options','add-site'}:
                if uid!=self.authority.controller_uid:raise PolicyError('只有管理账户可以增加规则目标')
                if self.authority.store.state['settings']['settings_password'] and 'password' not in data:return {'authentication_required':True}
                self.authority.verify_password(uid,data.get('password',''))
                return {'blocks':options(engine)} if operation=='add-site-options' else add_site(engine,data)
            if operation=='closed-tab':
                url=data.get('url','')
                if not browser_page(url):raise PolicyError('只能报告浏览器内部页面')
                result=engine.evaluate(url,active=True)
                if result['blocked']:engine.record_block(url,[b['id'] for b in result['blocks']],incognito=data.get('incognito',False))
                return {'ok':True,'blocked':result['blocked']}
        raise PolicyError('未知浏览器操作')

    def sync(self,uid,browser,parent,engine,grants,data):
        now=self.authority.clock();context=data['context'];activity=self.sessions.activity(uid)
        settings=self.authority.store.state['settings'];rules=self.authority.store.state['blocks']
        engine.heartbeats[browser]={'at':engine.now(),'incognito':data.get('incognito_allowed',False),'files':data.get('files_allowed',False)}
        hit_ids={b['id'] for item in data.get('usage',[]) for b in rules if engine.active(b) and target_matches(b,item['url'],item.get('channels',[]))}
        match_key=(uid,browser,context)
        if match_key not in self.matches and sum(key[0]==uid for key in self.matches)>=256:raise PolicyError('浏览器会话过多')
        for key,value in list(self.sources.items()):
            if now-value['at']>10:
                self.authority.engines[key[0]].sources.pop(key[1],None)
                del self.sources[key]
        incoming={'protected-browser:'+browser+':'+context+':'+str(item['tab']) for item in data.get('usage',[])}
        if len({key[1] for key in self.sources if key[0]==uid}|incoming)>2000:raise PolicyError('网页使用来源过多')
        self.matches[match_key]=(now,hit_ids if settings['strict_usage'] and activity else set())
        excluded=self.targets(uid)
        excluded.update(b['id'] for app in self.execution.applications(uid) for b in rules
                        if (settings['strict_usage'] or activity and app['pid']==activity['pid'])
                        and engine.active(b) and engine.app_matches(b,app))
        for item in data.get('usage',[]):
            source='protected-browser:'+browser+':'+context+':'+str(item['tab']);key=(uid,source)
            previous=self.sources.get(key)
            valid=bool(activity and (activity['idle']<=settings['idle_seconds'] or item.get('playing',False)))
            self.sources[key]={'at':now,'valid':valid}
            delta=max(0,now-previous['at']) if previous else 0
            continuous=previous is not None and previous['valid'] and 0<delta<=8
            if not valid or not continuous:
                engine.sources.pop(source,None)
                if valid:engine.sources[source]=engine.now()
                continue
            # Ignore caller idle and elapsed time; foreground is checked against
            # the actual browser PID. Strict background samples only charge hits.
            active=bool(item.get('active',False) and activity['pid']==parent['pid'])
            own_hits={b['id'] for b in rules if engine.active(b) and target_matches(b,item['url'],item.get('channels',[]))}
            ids=own_hits if not active else {b['id'] for b in rules if b['id'] not in excluded or b['id'] in own_hits}
            engine.usage({**item,'active':active,'idle':activity['idle']},source,grants.ids({'context':context,'tab':item['tab']}),policy_ids=ids,seconds_limit=delta)
        blocks=[]
        for block in rules:
            if block['users'] and engine.user not in block['users']:continue
            value=engine.status(block);value['tab_revision']=grants.revision(block);blocks.append(value)
        return {'blocks':blocks,'tab_grants':grants.snapshot(context,data.get('tabs',[])),
                'tab_unblock_supported':True,'settings':{key:settings[key] for key in ['block_inactive','block_embeds','allow_files','idle_seconds']},'now':engine.now()}
