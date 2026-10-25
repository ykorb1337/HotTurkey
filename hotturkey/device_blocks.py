"""Deterministic device-rule selection; never performs a device action."""
PRIORITY={'lock':0,'sleep':1,'logout':2,'shutdown':3}


def selected_device(engine,actions=None):
    choices=[]
    for block in engine.store.state['blocks']:
        action=block['device']
        if action not in PRIORITY or actions is not None and action not in actions:continue
        if engine.active(block) and not engine.break_state(block)['allowed']:choices.append(block)
    return max(choices,key=lambda block:(PRIORITY[block['device']],block['id'])) if choices else None


class SleepGate:
    """A recovery countdown before sleep; no OS actions or credential storage."""
    def __init__(self,resolve,actions=frozenset({'sleep'})):self.resolve=resolve;self.actions=actions;self.contexts={};self.console=None

    def update(self,uid,wake=0):
        switched=uid!=self.console;self.console=uid
        if uid<500:return None
        engine=self.resolve(uid);block=selected_device(engine,self.actions)
        if block is None:self.contexts.pop(uid,None);return None
        interval=engine.interval(block)
        end=engine.runtime(block).get('device_until',0) if block['mode']=='continuous' else interval[1]
        key=(block['id'],interval[0],end)
        now=engine.now();old=self.contexts.get(uid)
        gap=old is not None and now-old['at']>3
        if old is None or old['key']!=key or old['wake']!=wake or switched or gap:
            old={'key':key,'grace':now+30,'wake':wake,'at':now,'until':end,'action':block['device']};self.contexts[uid]=old
        old['at']=now
        return self.status(uid)

    def status(self,uid):
        current=self.contexts.get(uid)
        if current is None:return None
        engine=self.resolve(uid)
        if selected_device(engine,self.actions) is None:self.contexts.pop(uid,None);return None
        remaining=max(0,current['grace']-engine.now())
        return {'until':current['until'],'grace_remaining':remaining,'phase':'countdown' if remaining>0 else 'sleep','action':current['action'],
                'recovery_configured':bool(engine.store.state['settings']['device_recovery_hash'])}
