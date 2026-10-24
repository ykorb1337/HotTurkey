"""Bounded login-UI delivery, separate from policy autostarts and wake events.

Callers hold the authority lock. Only a verified session role can supply an
acknowledgement; launch tokens are bound to that kernel process incarnation.
"""
import re
import secrets

from .model import PolicyError


class SessionDesktop:
    def __init__(self,authority):self.authority=authority;self.commands={};self.cooldowns={}

    @staticmethod
    def validate(result):
        if result is None:return
        if (not isinstance(result,dict) or set(result)!={'id','ok'} or type(result['ok']) is not bool
                or not isinstance(result['id'],str) or not re.fullmatch('[0-9a-f]{64}',result['id'])):
            raise PolicyError('桌面启动回执无效')

    def status(self,uid):
        record=self.authority.store.state.get('desktop_logins',{}).get(str(uid),{})
        return {'supported':True,'status':record.get('status','not-requested'),'attempts':record.get('attempts',0)}

    def consume(self,uid,owner,marker,on_console,previous_login,result=None):
        self.validate(result)
        if marker is None:return None
        state=self.authority.store.state;settings=state['settings'];now=self.authority.clock()
        records=state.get('desktop_logins',{});record=records.get(str(uid))
        if record is None or record['login']!=marker:
            if not on_console:return None
            records=state.setdefault('desktop_logins',{})
            enabled=settings['open_at_login'] and previous_login!=marker
            record={'login':marker,'handled':not enabled,'attempts':0,'status':'pending' if enabled else 'disabled'}
            records[str(uid)]=record;self.commands.pop(uid,None);self.cooldowns.pop(uid,None)
        command=self.commands.get(uid)
        if result and command and command['owner']==owner and result['id']==command['id']:
            self.commands.pop(uid,None);command=None
            if result['ok']:record.update(handled=True,status='launched')
            else:
                record['status']='failed' if record['attempts']>=3 else 'retrying'
                self.cooldowns[uid]=now+[10,30,120][min(2,record['attempts']-1)]
        if record['handled']:return None
        # Changing the preference off cancels an outstanding request. Turning
        # it on later must not manufacture a fresh login or pop up a window.
        if not settings['open_at_login']:
            record.update(handled=True,status='disabled');self.commands.pop(uid,None)
            return None
        if not on_console:return None
        if command and now-command['at']<15:
            return {'id':command['id']} if command['owner']==owner else None
        self.commands.pop(uid,None)
        if record['attempts']>=3:record['status']='failed';return None
        if self.cooldowns.get(uid,0)>now:return None
        command={'id':secrets.token_hex(32),'at':now,'owner':owner}
        self.commands[uid]=command;record['attempts']+=1;record['status']='pending'
        return {'id':command['id']}
