"""Same cutover coordinator with real disposable legacy and signed QA services.

The driver is a regular-UID test adapter, not the production launchd driver.
No system paths, installed rules, browser registrations or user apps are changed.
"""
import base64
import copy
import dataclasses
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.authority import PolicyAuthority
from hotturkey.authority_server import AuthorityServer
from hotturkey.installation_gate import InstallationGate
from hotturkey.ipc import peer_identity
from hotturkey.platform_macos import boot_id
from hotturkey.server import Service
from hotturkey.store import Store
from hotturkey.system_cutover import CutoverCoordinator,CutoverDriver,staging_paths
from hotturkey.system_enforcement import SystemExecution
from hotturkey.system_migration import migrate_database
from hotturkey.system_package import digest,prepare_payload,verify_payload
from hotturkey.system_transaction import read_private_record,write_private_record
from hotturkey.trusted_sessions import TrustedSessions


class Driver(CutoverDriver):
    def __init__(self,root,template,executable):
        self.root=root;self.template=template;self.executable=executable
        self.registry=root/'registry';self.registry.mkdir(mode=0o700);self.folder=self.registry/'job';self.folder.mkdir(mode=0o700)
        self.targets={'program':root/'program','database':root/'database','activation':self.registry/'activation.json'}
        self.legacy=root/'legacy';self.old=None;self.old_thread=None;self.server=None;self.thread=None;self.store=None;self.agent=None;self.fixture=None;self.errors=[]
        self.fail_precommit=False;self.fail_postcommit=False;self.pending_checked=False;self.uid=os.getuid()
        seed=Store(self.legacy)
        from hotturkey.engine import Engine
        engine=Engine(seed,boot_id=boot_id());block=engine.save_block({'name':'Owned cutover fixture','enabled':True,'applications':['binary:'+str(executable)]})
        self.block=block['id'];seed.state['settings']['statistics']=False;seed.charge(engine.now(),self.block,123);seed.save();seed.db.close()
        self.start_old()

    def old_state(self):
        request=urllib.request.Request(self.old.origin+'/api/state',headers={'Authorization':'Bearer '+self.old.token})
        with urllib.request.urlopen(request,timeout=3) as response:return json.load(response)

    def start_old(self):
        if self.old_thread is not None and self.old_thread.is_alive():return
        self.old=Service(self.legacy,enforce=True);self.old_thread=threading.Thread(target=self.old.run);self.old_thread.start()
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            if self.old_state()['enforcement']['desktop_connected']:return
            time.sleep(.1)
        raise AssertionError('Old private service not healthy')

    def stop_old(self):
        if self.old is None:return
        helper=self.old.agent_process
        self.old.stop.set();self.old.http.shutdown();self.old_thread.join(timeout=10);assert not self.old_thread.is_alive()
        assert helper is None or helper.poll() is not None
        self.old.store.db.close();self.old=None;self.old_thread=None

    def authorize(self):assert not any(block['locked'] for block in self.old_state()['blocks'])
    def capture(self):return {'legacy_loaded':self.old is not None,'authority_loaded':False,'session_loaded':[],'gui_uids':[self.uid]}
    def stop_previous(self,context):self.stop_old()
    def stage(self,context):
        assert self.old is None
        stages=staging_paths(self.targets,context['transaction'])
        shutil.copytree(self.template,stages['program'],symlinks=True);verify_payload(stages['program'])
        import pwd
        migrate_database(self.legacy/'hotturkey.sqlite3',stages['database'],self.uid,self.uid,boot_id(),pwd.getpwuid)
        value={'version':1,'transaction':context['transaction'],'phase':'pending','controller_uid':self.uid,'payload_sha256':context['payload_sha256']}
        write_private_record(stages['activation'],value,initial=True,owner_uid=self.uid,anchor=self.root)
        return stages

    def start_candidate(self,context):
        if self.thread is not None and self.thread.is_alive():return
        assert self.old is None and digest(self.targets['program']/'payload.json')==context['payload_sha256']
        gate=InstallationGate(self.targets['activation'],self.uid,context['payload_sha256'],owner_uid=self.uid,anchor=self.root)
        self.store=Store(self.targets['database']);authority=PolicyAuthority(self.store,self.uid,boot_id=boot_id(),installation_gate=gate)
        self.authority=authority;self.before=copy.deepcopy(self.store.state)
        execution=SystemExecution(authority,ROOT/'build/HotTurkeySystemAgentQA');sessions=TrustedSessions(authority,execution)
        checker=ROOT/'build/HotTurkeyPeerCheck'
        requirements={role:json.loads(subprocess.check_output([str(checker),'--describe',str(binary)]))['requirement']
                      for role,binary in [('client',ROOT/'build/HotTurkeyPolicyClientQA'),('session',ROOT/'build/HotTurkeySessionAgentQA')]}
        def verify(connection):
            identity=peer_identity(connection)
            result=subprocess.run([str(checker),'--audit',base64.b64encode(identity.audit_token).decode(),'--roles',json.dumps(requirements)],capture_output=True,timeout=3)
            if result.returncode:raise PermissionError('Denied')
            return dataclasses.replace(identity,role=json.loads(result.stdout)['role'])
        self.socket=self.root/'candidate.sock';self.server=AuthorityServer(authority,self.socket,verify,execution=execution,sessions=sessions,tick_interval=.1)
        self.server.bind()
        def serve():
            try:self.server.serve_forever()
            except BaseException as error:self.errors.append(type(error).__name__)
        self.thread=threading.Thread(target=serve);self.thread.start()
        self.agent=subprocess.Popen([str(ROOT/'build/HotTurkeySessionAgentQA'),str(self.socket),str(self.uid),'120'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if self.fixture is None:self.fixture=subprocess.Popen([str(self.executable)])

    def request(self,operation,data=None,timeout=3):
        result=subprocess.run([str(ROOT/'build/HotTurkeyPolicyClientQA'),str(self.socket),str(self.uid)],
            input=json.dumps({'op':operation,'data':{} if data is None else data}).encode(),capture_output=True,timeout=timeout)
        if result.returncode:return None
        value=json.loads(result.stdout)
        return value['result'] if value.get('ok') is True else None

    def probe_candidate(self,context,*,timeout):
        health=self.request('installation-health',timeout=timeout)
        summary={'health_available':health is not None,'pending':health.get('installation_pending') if health else None,
                 'executor_ready':health.get('executor_ready') if health else None,'session_fresh':health.get('session_transport_fresh') if health else None,
                 'candidate_running':self.thread is not None and self.thread.is_alive(),'session_exit':self.agent.poll() if self.agent else None,'errors':self.errors}
        if summary!=getattr(self,'last_probe',None):
            print(json.dumps({'probe':summary}),flush=True);self.last_probe=copy.deepcopy(summary)
        if health and health['installation_pending'] and health['executor_ready'] and health['session_transport_fresh'] and not self.pending_checked:
            time.sleep(1.1)
            assert self.fixture.poll() is None and self.store.state==self.before
            assert self.authority.engine(self.uid).store.used(self.block,0)==123
            self.pending_checked=True
            if self.fail_precommit:raise OSError('Test installer failed before commit')
        return health

    def activate(self,context):
        marker=read_private_record(self.targets['activation'],owner_uid=self.uid,anchor=self.root)
        if marker['phase']!='committed':
            marker['phase']='committed';write_private_record(self.targets['activation'],marker,owner_uid=self.uid,anchor=self.root)
        if self.fail_postcommit:
            assert self.request('add-targets',{'id':self.block,'websites':['after-commit.invalid']}) is not None
            raise OSError('Test installer failed after commit')

    def stop_candidate(self,context):
        if self.agent is not None:
            self.agent.terminate();self.agent.wait(timeout=5);self.agent=None
        if self.server is not None:
            self.server.stop();self.thread.join(timeout=15);assert not self.thread.is_alive();self.server=None;self.thread=None
            self.store.db.close();self.store=None
        assert not self.errors,self.errors

    def restore_previous(self,context):
        if context['services']['legacy_loaded']:self.start_old()
    def coordinator(self):return CutoverCoordinator(self.folder,self.targets,self,self.uid,digest(self.template/'payload.json'),
        lock_directory=self.registry,owner_uid=self.uid,anchor=self.root,timeout=45)
    def close(self):
        self.stop_candidate(None);self.stop_old()
        if self.fixture is not None:
            if self.fixture.poll() is None:self.fixture.kill()
            self.fixture.wait(timeout=5)


def main():
    proof={'root_installed':False,'system_files_written':False,'installed_rules_read_or_changed':False,'production_service_driver_tested':False,
           'qa_native_transport':True,'physical_sleep_invoked':False}
    with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-cutover-') as temporary:
        root=Path(temporary);source=root/'fixture.c';source.write_text('#include <unistd.h>\nint main(void){sleep(180);return 0;}\n')
        executable=root/'owned-cutover-fixture';subprocess.run(['/usr/bin/clang',str(source),'-o',str(executable)],check=True,capture_output=True)
        template=root/'payload';prepare_payload(ROOT/'build/HotTurkey.app',template,os.getuid(),{'Edge':{'requirement':'identifier "com.microsoft.edgemac"','origins':['chrome-extension://'+'a'*32+'/']}})
        for mode in ['success','before-commit','after-commit']:
            case=root/mode;case.mkdir(mode=0o700);driver=Driver(case,template,executable)
            try:
                driver.fail_precommit=mode=='before-commit';driver.fail_postcommit=mode=='after-commit'
                coordinator=driver.coordinator()
                if mode=='success':assert coordinator.apply()['status']=='finished'
                else:
                    try:coordinator.apply()
                    except OSError:pass
                    else:raise AssertionError('Expected injected installer failure')
                assert driver.pending_checked
                if mode=='before-commit':
                    assert driver.old is not None and driver.server is None
                    assert not driver.targets['database'].exists() and not driver.targets['program'].exists()
                    assert driver.old.store.used(driver.block,0)==123
                    driver.fixture.wait(timeout=10);assert driver.fixture.returncode<0
                    assert driver.coordinator().recover()['status']=='rolled-back'
                    proof['failed_candidate_restores_real_legacy_enforcement_and_quota']=True
                else:
                    assert driver.old is None
                    driver.fixture.wait(timeout=10);assert driver.fixture.returncode==-15
                    assert driver.authority.engine(driver.uid).store.used(driver.block,0)==123
                    if mode=='after-commit':
                        assert driver.request('add-targets',{'id':driver.block,'websites':['retained.invalid']}) is not None
                        driver.fail_postcommit=False;assert driver.coordinator().recover()['status']=='finished'
                        websites=driver.authority.engine(driver.uid).find(driver.block)['websites']
                        assert 'after-commit.invalid' in websites and 'retained.invalid' in websites
                        proof['post_commit_recovery_keeps_real_accepted_policy_changes']=True
                    else:proof['real_signed_candidate_activates_after_legacy_stop_and_migration']=True
            finally:driver.close()
    (ROOT/'build/system-cutover-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof))


if __name__=='__main__':main()
