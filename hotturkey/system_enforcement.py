"""Protected process decisions using kernel samples, never client-reported PIDs.

The current-user installer does not enable this service. Fresh inventory can
verify native session/browser identities. Protected browser deployment, device
actions and privileged installation remain separate work.
"""
import os
import re
import subprocess
import time
from pathlib import Path

from .model import PolicyError
from .platform_macos import native_samples, native_command, stop_native
from .platform_macos import BROWSERS,UNSUPPORTED

MAX_PROCESSES=32768
MAX_KILLS=8192


def process_identity(value):
    if not isinstance(value,dict):raise ValueError('Invalid process sample')
    pid,uid,token=(value.get(k) for k in ['pid','uid','identity'])
    if type(pid) is not int or not 1<pid<=2147483647 or type(uid) is not int or not 500<=uid<=4294967295:
        raise ValueError('Invalid kernel process identity')
    if not isinstance(token,str) or not re.fullmatch('[0-9a-f]{64}',token):raise ValueError('Invalid kernel generation')
    return pid,uid,token


class SystemDecisions:
    def __init__(self,authority,protected_paths=()):
        self.authority=authority
        self.protected_paths=tuple(str(Path(p)) for p in protected_paths)
        self.pending={}
        self.recorded={}

    def protected(self,path):
        return any(path==root or path.startswith(root.rstrip('/')+'/') for root in self.protected_paths)

    def configure(self,uid):
        engine=self.authority.engine(uid)
        if engine.application_targets is None:
            from .app_targets import ApplicationTargets
            home=Path(self.authority._account(uid).pw_dir)
            engine.application_targets=ApplicationTargets(steam_root=home/'Library/Application Support/Steam',app_roots=['/Applications','/System/Applications',home/'Applications'])
        return engine

    def consume(self,sample):
        if not isinstance(sample,dict) or set(sample)!={'apps','front','results'} or sample['front']!={}:
            raise ValueError('Invalid protected sample')
        apps,results=sample['apps'],sample['results']
        if not isinstance(apps,list) or len(apps)>MAX_PROCESSES or not isinstance(results,list) or len(results)>MAX_KILLS:
            raise ValueError('Protected sample limit exceeded')
        # Validate an entire frame before changing policy runtime or statistics.
        identities=set();pids=set()
        for app in apps:
            pid,uid,token=process_identity(app)
            if pid in pids or token in identities:raise ValueError('Duplicate kernel process')
            pids.add(pid);identities.add(token)
            for key in ['executable','path','application','bundle']:
                if not isinstance(app.get(key),str) or len(app[key])>4096:raise ValueError('Invalid process metadata')
            if not app['executable'].startswith('/') or not app['path'].startswith('/'):
                raise ValueError('Invalid executable path')
            for key,maximum in [('start_sec',2**53),('start_usec',999999)]:
                if key in app and (type(app[key]) is not int or not 0<=app[key]<=maximum):raise ValueError('Invalid process start time')
        acknowledgements=set()
        for result in results:
            pid,uid,token=process_identity(result)
            if set(result)!={'pid','uid','identity','signal','result'} or token in acknowledgements:
                raise ValueError('Invalid execution acknowledgement')
            if type(result['signal']) is not int or result['signal'] not in {0,15,9} or result['result'] not in {'sent','stale','gone','denied'}:
                raise ValueError('Invalid signal result')
            if result['result']=='sent' and result['signal']==0:raise ValueError('Missing delivered signal')
            expected=self.pending.get(token)
            if expected is None or (pid,uid)!=(expected['pid'],expected['uid']):raise ValueError('Unexpected execution acknowledgement')
            acknowledgements.add(token)
        if acknowledgements!=set(self.pending):raise ValueError('Missing execution acknowledgement')
        with self.authority.store.lock:
            now=self.authority.clock()
            self.recorded={token:until for token,until in self.recorded.items() if until>now}
            for result in results:
                token=result['identity'];pending=self.pending[token]
                if result['result']=='sent' and token not in self.recorded:
                    self.configure(pending['uid']).record_block(pending['application'],pending['blocks'],'application')
                    self.recorded[token]=now+60
            while len(self.recorded)>MAX_PROCESSES:self.recorded.pop(next(iter(self.recorded)))
            engines={}
            # Account contexts are derived only from the root scanner's UID.
            for uid in {app['uid'] for app in apps}|{self.authority.controller_uid}:
                try:engine=self.configure(uid)
                except PolicyError:continue
                engine.tick();engines[uid]=engine
            commands=[];pending={}
            for app in apps:
                if app['uid'] not in engines or app['pid'] in {os.getpid(),os.getppid()} or self.protected(app['executable']):continue
                engine=engines[app['uid']]
                hits=[b['id'] for b in self.authority.store.state['blocks'] if engine.active(b) and not engine.break_state(b)['allowed'] and engine.app_matches(b,app)]
                settings=self.authority.store.state['settings'];bundle=app['bundle']
                locked=[b['id'] for b in self.authority.store.state['blocks'] if engine.locked(b) and (not b['users'] or engine.user in b['users'])]
                if locked:
                    strict=((settings['block_task_manager'] and bundle=='com.apple.ActivityMonitor')
                            or (settings['block_settings'] and bundle in {'com.apple.systempreferences','com.apple.ScreenTime'})
                            or (settings['block_installer'] and bundle=='com.apple.installer')
                            or (settings['block_unsupported'] and bundle in UNSUPPORTED))
                    if bundle in BROWSERS and settings['require_extension']:
                        since=max(engine.start_time,engine.heartbeats.get(BROWSERS[bundle],{}).get('at',0),app.get('start_sec',0))
                        strict=strict or engine.now()-since>settings['extension_grace']
                    if strict:hits=list(dict.fromkeys(hits+locked))
                if hits:
                    if len(commands)>=MAX_KILLS:raise ValueError('Execution command limit exceeded')
                    command={k:app[k] for k in ['pid','uid','identity']};commands.append(command)
                    pending[app['identity']]={**command,'application':app['application'],'blocks':hits}
            self.pending=pending
            return {'kill':commands}


class SystemExecution:
    def __init__(self,authority,executable,protected_paths=()):
        self.authority=authority
        self.executable=Path(executable)
        self.protected_paths=tuple(protected_paths)
        self.process=None
        self.last_sample=None
        self.state='not-started'
        self.inventory={}

    def applications(self,uid):
        with self.authority.store.lock:
            if self.state!='running' or self.last_sample is None or time.monotonic()-self.last_sample>3:return []
            return [dict(app) for app in self.inventory.get(uid,())]

    def status(self):
        with self.authority.store.lock:
            return {'status':self.state,'last_sample_age':None if self.last_sample is None else max(0,time.monotonic()-self.last_sample),'process_source':'kernel'}

    def run(self,stop):
        self.state='starting'
        process=subprocess.Popen([str(self.executable)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,bufsize=0)
        self.process=process
        decisions=SystemDecisions(self.authority,self.protected_paths)
        try:
            for sample in native_samples(process,stop,lambda:None):
                command=decisions.consume(sample)
                if not native_command(process,stop,command):break
                with self.authority.store.lock:
                    self.inventory={}
                    for app in sample['apps']:self.inventory.setdefault(app['uid'],[]).append(dict(app))
                    self.last_sample=time.monotonic();self.state='running'
            if not stop.is_set():raise RuntimeError('Protected executor exited')
        except BaseException:
            self.state='failed'
            raise
        finally:
            stop_native(process);self.process=None
            if stop.is_set():self.state='stopped'
