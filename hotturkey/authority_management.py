"""Complete policy-management operations for attested local clients."""
import copy
import math
import pwd

from .management import duplicate_block,import_blocks,settings_update
from .model import CATEGORIES,DEFAULT_SETTINGS,PolicyError

FIELDS={
    'settings':set(DEFAULT_SETTINGS)-{'settings_password'}|{'password'},
    'duplicate':{'id','name'},'import':{'blocks','allow_autostart','confirm_device'},
    'export':set(),'categories':set(),'users':set(),
    'statistics':{'since','until','user','q','block','kind'},
    'statistics-export':set(),'statistics-clear':set(),
}
MUTATIONS={'settings','duplicate','import','statistics-clear'}


class AuthorityManagement:
    def __init__(self,authority):self.authority=authority

    def authorize(self,uid,operation,session):
        self.authority._account(uid)
        if operation in MUTATIONS and uid!=self.authority.controller_uid:raise PolicyError('只有管理账户可以修改配置')
        if uid==self.authority.controller_uid:
            if not self.authority.authenticated(uid,session):raise PolicyError('请先输入设置密码')
        elif operation=='export' and self.authority.store.state['settings']['protect_overview']:
            raise PolicyError('规则概览已受保护')

    def dispatch(self,uid,operation,data,session=''):
        if set(data)-FIELDS[operation]:raise PolicyError('管理字段无效')
        self.authorize(uid,operation,session)
        engine=self.authority.engine(uid)
        if operation=='settings':
            updated=settings_update(engine,data)
            password_changed=updated['settings_password']!=self.authority.store.state['settings']['settings_password']
            self.authority.store.state['settings']=updated;self.authority.store.save()
            if password_changed:self.authority.sessions.clear()
            return {'ok':True}
        if operation=='duplicate':
            if not isinstance(data.get('id'),str) or len(data['id'])>128:raise PolicyError('规则无效')
            if 'name' in data and (not isinstance(data['name'],str) or len(data['name'])>100):raise PolicyError('规则名称无效')
            return duplicate_block(engine,data['id'],data.get('name'))
        if operation=='import':return import_blocks(engine,data.get('blocks'),data.get('allow_autostart',False),data.get('confirm_device',False))
        if operation=='export':
            blocks=[{key:copy.deepcopy(value) for key,value in block.items() if key!='lock'} for block in self.authority.store.state['blocks']
                    if uid==self.authority.controller_uid or not block['users'] or engine.user in block['users']]
            return {'format':'hotturkey-blocks-v1','blocks':blocks}
        if operation=='categories':return copy.deepcopy(CATEGORIES)
        if operation=='users':
            accounts=pwd.getpwall() if uid==self.authority.controller_uid else [self.authority._account(uid)]
            return [{'name':account.pw_name,'label':getattr(account,'pw_gecos','')[:512]} for account in accounts
                    if account.pw_uid>=500 and account.pw_dir.startswith('/Users/') and not account.pw_name.startswith('_')]
        if operation=='statistics':
            for key in ['since','until']:
                value=data.get(key,0 if key=='since' else 1e20)
                if type(value) not in {int,float} or not math.isfinite(value) or not 0<=value<=1e20:raise PolicyError('统计时间无效')
            for key,maximum in [('user',128),('q',2048),('block',128),('kind',32)]:
                if not isinstance(data.get(key,''),str) or len(data.get(key,''))>maximum:raise PolicyError('统计筛选无效')
            if data.get('kind','') not in {'','website','application'}:raise PolicyError('统计类型无效')
            since,until=data.get('since',0),data.get('until',1e20)
            if since>until:raise PolicyError('统计时间范围无效')
            return engine.store.statistics(since,until,data.get('user',''),data.get('q',''),data.get('block',''),data.get('kind',''))
        if operation=='statistics-export':return engine.store.export_statistics()
        if operation=='statistics-clear':engine.store.clear_statistics();return {'ok':True}
        raise PolicyError('未知管理操作')
