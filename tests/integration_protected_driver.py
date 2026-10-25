"""Shared protected driver with real disposable launchd and signed peers.

The layout, GUI job definitions and native client identity are test adapters.
The production root factory/elevation entry is not run. Staging, credential
recheck, kernel exit barriers, leases, migration, cutover and recovery use the
actual driver code. No installed rules or production jobs are touched.
"""
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.authority import PolicyAuthority
from hotturkey.engine import Engine,password_hash
from hotturkey.service_lease import ServiceLease
from hotturkey.store import Store
from hotturkey.system_driver import _Driver,_Layout,_approve,_stage
from hotturkey.system_jobs import _Job,_JobControl,read_plan
from hotturkey.system_migration import snapshot_database
from hotturkey.system_package import digest,prepare_payload


class Jobs:
    def __init__(self,layout,configuration,binary):
        self.layout=layout;self.uid=os.getuid();self.domain='gui/'+str(self.uid);self.fixture=None;self.binary=binary
        self.directory=layout.folder/'fixture-jobs';self.directory.mkdir(mode=0o700,exist_ok=True)
        python=ROOT/'build/HotTurkey.app/Contents/Resources/python/bin/python3';entry=ROOT/'tests/driver_authority_fixture.py'
        self.jobs={};self.plans={}
        for name in ['legacy','authority','session']:
            path=self.directory/(name+'.plist')
            if path.exists():
                plan=plistlib.loads(path.read_bytes());label=plan['Label']
                assert label.startswith('local.hotturkey.driver.qa.'+name+'.')
                self.jobs[name]=_Job(self.domain,label,path,plan);continue
            label='local.hotturkey.driver.qa.'+name+'.'+uuid.uuid4().hex
            args=[str(ROOT/'build/HotTurkeySessionAgentQA'),configuration['socket'],str(self.uid),'120'] if name=='session' else [str(python),'-I','-B',str(entry),name,str(configuration['file'])]
            plan={'Label':label,'ProgramArguments':args,'RunAtLoad':True,'KeepAlive':True,'ThrottleInterval':1,'ExitTimeOut':1,
                'StandardOutPath':str(self.directory/(name+'.log')),'StandardErrorPath':str(self.directory/(name+'.log'))}
            path.write_bytes(plistlib.dumps(plan));self.jobs[name]=_Job(self.domain,label,path,plan)
        self.legacy=self.jobs['legacy'];self.authority=self.jobs['authority']
        self.control=_JobControl(lambda:None,lambda job:read_plan(job.plist,job.expected,owner_uid=self.uid,anchor=layout.anchor),timeout=12)
    def gui_uids(self):return [self.uid] if self.control.domain_exists(self.domain) else []
    def capture(self):return {'legacy_loaded':self.control.loaded(self.legacy),'authority_loaded':self.control.loaded(self.authority),
        'session_loaded':[self.uid] if self.control.loaded(self.jobs['session']) else [],'gui_uids':self.gui_uids()}
    def save_legacy(self):
        read_plan(self.legacy.plist,self.legacy.expected,owner_uid=self.uid,anchor=self.layout.anchor)
        path=self.layout.folder/'saved-legacy.plist';path.write_bytes(plistlib.dumps(self.legacy.expected));path.chmod(0o600)
    def load_legacy(self):
        path=self.layout.folder/'saved-legacy.plist'
        return self.control.load(_Job(self.domain,self.legacy.label,path,self.legacy.expected) if path.exists() else self.legacy)
    def stop_legacy(self,**values):
        result=self.control.pause_unload(self.legacy,**values)
        if result and self.fixture is None:self.fixture=subprocess.Popen([str(self.binary)])
        return result
    def stop_authority(self,**values):return self.control.pause_unload(self.authority,**values)
    def stop_session(self,uid,**values):assert uid==self.uid;return self.control.pause_unload(self.jobs['session'],**values)
    def load_authority(self):return self.control.load(self.authority)
    def load_session(self,uid):assert uid==self.uid;return self.control.load(self.jobs['session'])
    def unload_session(self,uid):assert uid==self.uid;return self.control.unload(self.jobs['session'])
    def resume_legacy(self):self.control.signal_job(self.legacy,'SIGCONT')
    def resume_authority(self):self.control.signal_job(self.authority,'SIGCONT')
    def resume_session(self,uid):assert uid==self.uid;self.control.signal_job(self.jobs['session'],'SIGCONT')
    def close(self):
        errors=[]
        for job in [self.jobs['session'],self.authority,self.legacy]:
            try:self.control.pause_unload(job)
            except Exception as error:errors.append(type(error).__name__)
            finally:
                try:subprocess.run(['/bin/launchctl','bootout',job.target],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
                except Exception as error:errors.append(type(error).__name__)
        if self.fixture is not None:
            if self.fixture.poll() is None:self.fixture.kill()
            self.fixture.wait(timeout=5)
        if errors:raise RuntimeError('Fixture job cleanup errors: '+','.join(errors))


def legacy_ready(layout):
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        try:
            value=json.loads((layout.legacy/'connection.json').read_text());request=urllib.request.Request('http://127.0.0.1:'+str(value['port'])+'/api/state',headers={'Authorization':'Bearer '+value['token']})
            with urllib.request.urlopen(request,timeout=2) as response:state=json.load(response)
            if state.get('enforcement',{}).get('desktop_connected'):return
        except (OSError,ValueError,KeyError):pass
        time.sleep(.1)
    raise AssertionError('Disposable legacy backend did not become ready')


def main():
    uid=os.getuid();proof={'root_installed':False,'system_files_written':False,'installed_rules_read_or_changed':False,
        'production_elevation_or_fixed_paths_tested':False,'qa_identity_and_job_definitions':True,'physical_sleep_invoked':False}
    proof['gui_domain_available']=_JobControl(lambda:None,lambda job:None).domain_exists('gui/'+str(uid))
    if not proof['gui_domain_available']:
        proof['native_driver_exercised']=False
        (ROOT/'build/protected-driver-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof));return
    with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-protected-driver-') as temporary:
        root=Path(temporary);source=root/'fixture.c';source.write_text('#include <unistd.h>\nint main(void){sleep(180);return 0;}\n');binary=root/'owned-fixture'
        subprocess.run(['/usr/bin/clang',str(source),'-o',str(binary)],check=True,capture_output=True)
        template=root/'template';prepare_payload(ROOT/'build/HotTurkey.app',template,uid,{'Edge':{'requirement':'identifier "com.microsoft.edgemac"','origins':['chrome-extension://'+'a'*32+'/']}})
        expected=digest(template/'payload.json')
        for mode in ['success','before-commit','after-commit']:
            case=root/mode;case.mkdir(mode=0o700);registry=case/'registry';folder=registry/'jobs'/uuid.uuid4().hex;folder.mkdir(mode=0o700,parents=True)
            layout=_Layout(folder,registry,case/'program',case/'database',registry/'activation.json',case/'daemon.plist',case/'session.plist',case/'runtime',case/'legacy',case,uid)
            shutil.copytree(template,layout.artifact,symlinks=True)
            store=Store(layout.legacy);engine=Engine(store);block=engine.save_block({'name':'Owned protected cutover fixture','enabled':True,'applications':['binary:'+str(binary)]});ident=block['id']
            store.state['settings'].update(statistics=False,open_at_login=False,settings_password=password_hash('fixture password'));store.charge(time.time(),ident,123);store.save();store.db.close()
            with ServiceLease(layout.legacy/'.install.lock'):pass
            (folder/'preflight').mkdir(mode=0o700);snapshot_database(layout.legacy/'hotturkey.sqlite3',folder/'preflight/hotturkey.sqlite3',uid)
            approval=_approve(layout,uid,expected,'fixture password')
            configuration={'root':str(case),'program':str(layout.program),'database':str(layout.database),'marker':str(layout.marker),
                'legacy':str(layout.legacy),'socket':str(case/'control.sock'),'file':str(folder/'fixture.json')}
            Path(configuration['file']).write_text(json.dumps(configuration));jobs=Jobs(layout,configuration,binary)
            client_command=[str(ROOT/'build/HotTurkeyPolicyClientQA'),configuration['socket'],str(uid)]
            def request(op,data=None,session=''):
                result=subprocess.run(client_command,input=json.dumps({'op':op,'data':{} if data is None else data,'session':session}).encode(),capture_output=True,timeout=3)
                if result.returncode:return None
                value=json.loads(result.stdout)
                return value.get('result') if value.get('ok') is True else None
            def client(timeout):return request('installation-health')
            driver=_Driver(layout,jobs,uid,expected,approval,client=client)
            def stage(context):
                assert jobs.fixture is not None and jobs.fixture.poll() is None
                result=_stage(layout,context,driver.records)
                assert jobs.fixture.poll() is None
                return result
            driver.worker=stage
            try:
                assert jobs.load_legacy();legacy_ready(layout)
                if mode=='before-commit':
                    driver.client=lambda timeout:None
                    stop_candidate=driver.stop_candidate
                    def pending_stop(context):
                        assert jobs.fixture is not None and jobs.fixture.poll() is None
                        health=request('installation-health')
                        assert health is not None and health['installation_pending'] is True and health['executor_ready'] is True and health['session_transport_fresh'] is True
                        stop_candidate(context)
                    driver.stop_candidate=pending_stop
                if mode=='after-commit':
                    activate=driver.activate
                    def fail(context):activate(context);raise OSError('Injected after durable activation')
                    driver.activate=fail
                coordinator=driver.coordinator();coordinator.timeout=18
                try:result=coordinator.apply()
                except (OSError,TimeoutError):
                    assert mode!='success'
                else:assert mode=='success' and result['status']=='finished'
                if mode=='before-commit':
                    legacy_ready(layout);assert jobs.control.loaded(jobs.legacy);assert not layout.database.exists() and not layout.program.exists()
                    assert jobs.fixture is not None;jobs.fixture.wait(timeout=10);assert jobs.fixture.returncode<0
                    source_store=Store(layout.legacy)
                    try:assert source_store.used(ident,0)==123
                    finally:source_store.db.close()
                    proof['actual_driver_restores_legacy_job_enforcement_and_quota']=True
                else:
                    assert jobs.fixture is not None;jobs.fixture.wait(timeout=10);assert jobs.fixture.returncode==-15
                    if mode=='after-commit':
                        session=request('authenticate',{'password':'fixture password'})['session']
                        assert request('add-targets',{'id':ident,'websites':['kept-after-commit.invalid']},session) is not None
                        with _Driver(layout,jobs,uid,expected,None,client=client) as recovery:assert recovery.coordinator().recover()['status']=='finished'
                        exported=request('export',session=session);assert 'kept-after-commit.invalid' in exported['blocks'][0]['websites']
                        proof['actual_driver_forward_recovery_keeps_accepted_changes']=True
                    else:proof['actual_driver_activates_signed_backend_after_kernel_exit_and_migration']=True
                    check=Store(layout.database)
                    try:assert PolicyAuthority(check,uid).engine(uid).store.used(ident,0)==123
                    finally:check.db.close()
            except BaseException:
                diagnostics={}
                for name in ['legacy','authority','session']:
                    path=jobs.directory/(name+'.log')
                    diagnostics[name]=path.read_text(errors='replace')[-6000:] if path.exists() else 'no log'
                path=layout.legacy/'service.log';diagnostics['service']=path.read_text(errors='replace')[-6000:] if path.exists() else 'no log'
                path=ROOT/'build/protected-driver-debug.json';path.write_text(json.dumps(diagnostics,indent=2));path.chmod(0o600)
                raise
            finally:driver.close();jobs.close()
    proof['native_driver_exercised']=True
    (ROOT/'build/protected-driver-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof))


if __name__=='__main__':main()
