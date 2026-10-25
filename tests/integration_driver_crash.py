"""SIGKILL the actual driver coordinator; disposable launchd jobs survive.

Recovery exercises a frozen old job, published-but-pending files and committed
policy changes. All paths, jobs and identity overrides are test fixtures, not
the privileged production entry point. No physical power loss is simulated.
"""
import dataclasses
import json
import os
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from integration_protected_driver import Jobs,legacy_ready
from hotturkey.engine import Engine,password_hash
from hotturkey.service_lease import ServiceLease
from hotturkey.store import Store
from hotturkey.system_driver import _Driver,_Layout,_approve
from hotturkey.system_migration import snapshot_database
from hotturkey.system_package import digest,prepare_payload
from hotturkey.system_processes import KernelProcesses
from hotturkey.system_jobs import _JobControl

CHILD=r'''
import dataclasses,json,os,sys,subprocess
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root));sys.path.insert(0,str(root/'tests'))
from integration_protected_driver import Jobs
from hotturkey.system_driver import _Driver,_Layout,_Approval,_stage
from hotturkey.system_cutover import CutoverCoordinator
value=json.loads(sys.stdin.readline());layout=_Layout(**{key:(item if key=='owner_uid' else Path(item)) for key,item in value['layout'].items()})
jobs=Jobs(layout,value['configuration'],Path(value['binary']));mode=value['mode']
def checkpoint():
 print(json.dumps({'checkpoint':mode,'fixture':None if jobs.fixture is None else jobs.fixture.pid}),flush=True);sys.stdin.readline()
def client(timeout):
 command=[str(root/'build/HotTurkeyPolicyClientQA'),value['configuration']['socket'],str(os.getuid())]
 result=subprocess.run(command,input=b'{"op":"installation-health","data":{}}',capture_output=True,timeout=timeout)
 if result.returncode:return None
 answer=json.loads(result.stdout);return answer.get('result') if answer.get('ok') is True else None
class Driver(_Driver):
 def _stop(self,context,key,operation):
  if mode=='frozen' and key=='legacy':
   original=operation
   def operation(**values):
    before=values['before_unload']
    def frozen(observer):before(observer);checkpoint()
    return original(before_unload=frozen)
  return super()._stop(context,key,operation)
 def activate(self,context):
  super().activate(context)
  if mode=='committed':checkpoint()
class Coordinator(CutoverCoordinator):
 def transition(self,phase,initial=False):
  super().transition(phase,initial)
  if mode=='published' and phase=='probing':checkpoint()
driver=Driver(layout,jobs,os.getuid(),value['expected'],_Approval(**value['approval']),client=client)
driver.worker=lambda context:_stage(layout,context,driver.records)
coordinator=Coordinator(layout.folder,layout.targets,driver,os.getuid(),value['expected'],lock_directory=layout.registry,owner_uid=os.getuid(),anchor=layout.anchor,timeout=60)
coordinator.apply()
'''


def main():
    uid=os.getuid();kernel=KernelProcesses();proof={'root_installed':False,'system_files_written':False,'installed_rules_changed':False,
        'production_elevation_or_fixed_paths_tested':False,'physical_power_loss_tested':False}
    proof['gui_domain_available']=_JobControl(lambda:None,lambda job:None).domain_exists('gui/'+str(uid))
    if not proof['gui_domain_available']:
        proof['native_driver_crash_exercised']=False
        (ROOT/'build/driver-crash-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof));return
    with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-driver-crash-') as temporary:
        root=Path(temporary);source=root/'fixture.c';source.write_text('#include <unistd.h>\nint main(void){sleep(180);return 0;}\n');binary=root/'owned-fixture'
        subprocess.run(['/usr/bin/clang',str(source),'-o',str(binary)],check=True,capture_output=True)
        template=root/'template';prepare_payload(ROOT/'build/HotTurkey.app',template,uid,{'Edge':{'requirement':'identifier "com.microsoft.edgemac"','origins':['chrome-extension://'+'a'*32+'/']}});expected=digest(template/'payload.json')
        for mode in ['frozen','published','committed']:
            case=root/mode;case.mkdir(mode=0o700);registry=case/'registry';folder=registry/'jobs'/('a'*32);folder.mkdir(parents=True,mode=0o700)
            layout=_Layout(folder,registry,case/'program',case/'database',registry/'activation.json',case/'daemon.plist',case/'session.plist',case/'runtime',case/'legacy',case,uid)
            shutil.copytree(template,layout.artifact,symlinks=True)
            store=Store(layout.legacy);engine=Engine(store);block=engine.save_block({'name':'Owned crash fixture','enabled':True,'applications':['binary:'+str(binary)]});ident=block['id']
            store.state['settings'].update(statistics=False,open_at_login=False,settings_password=password_hash('fixture password'));store.charge(time.time(),ident,123);store.save();store.db.close()
            with ServiceLease(layout.legacy/'.install.lock'):pass
            (folder/'preflight').mkdir(mode=0o700);snapshot_database(layout.legacy/'hotturkey.sqlite3',folder/'preflight/hotturkey.sqlite3',uid)
            approval=_approve(layout,uid,expected,'fixture password')
            configuration={'root':str(case),'program':str(layout.program),'database':str(layout.database),'marker':str(layout.marker),'legacy':str(layout.legacy),'socket':str(case/'control.sock'),'file':str(folder/'fixture.json')}
            Path(configuration['file']).write_text(json.dumps(configuration));jobs=Jobs(layout,configuration,binary)
            command=[str(ROOT/'build/HotTurkeyPolicyClientQA'),configuration['socket'],str(uid)]
            def request(op,data=None,session=''):
                result=subprocess.run(command,input=json.dumps({'op':op,'data':{} if data is None else data,'session':session}).encode(),capture_output=True,timeout=3)
                if result.returncode:return None
                value=json.loads(result.stdout);return value.get('result') if value.get('ok') is True else None
            client=lambda timeout:request('installation-health')
            process=None;fixture=None;fixture_identity=None
            try:
                assert jobs.load_legacy();legacy_ready(layout)
                data={'layout':{key:(item if key=='owner_uid' else str(item)) for key,item in dataclasses.asdict(layout).items()},'configuration':configuration,
                    'binary':str(binary),'mode':mode,'expected':expected,'approval':dataclasses.asdict(approval)}
                process=subprocess.Popen([sys.executable,'-E','-s','-B','-c',CHILD,str(ROOT)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                process.stdin.write((json.dumps(data)+'\n').encode());process.stdin.flush()
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout,selectors.EVENT_READ);assert selector.select(60),'No durable checkpoint'
                    message=json.loads(process.stdout.readline());assert message['checkpoint']==mode
                fixture=message['fixture'];fixture_identity=None if fixture is None else kernel.process(fixture)
                session=''
                if mode=='committed':
                    session=request('authenticate',{'password':'fixture password'})['session']
                    assert request('add-targets',{'id':ident,'websites':['survives-controller-crash.invalid']},session) is not None
                process.kill();process.wait(timeout=5);assert process.returncode==-9
                with _Driver(layout,jobs,uid,expected,None,client=client) as recovery:result=recovery.coordinator().recover()
                if mode=='committed':
                    assert result['status']=='finished';assert 'survives-controller-crash.invalid' in request('export',session=session)['blocks'][0]['websites']
                else:
                    assert result['status']=='rolled-back';legacy_ready(layout)
                    if fixture_identity is not None:
                        until=time.monotonic()+10
                        while time.monotonic()<until:
                            current=kernel.process(fixture)
                            if current is None or current.identity!=fixture_identity.identity or not current.live:break
                            time.sleep(.05)
                        else:raise AssertionError('Restored legacy job did not enforce its retained rule')
                    store=Store(layout.legacy)
                    try:assert store.used(ident,0)==123
                    finally:store.db.close()
                with _Driver(layout,jobs,uid,expected,None,client=client) as recovery:assert recovery.coordinator().recover()==result
                proof['actual_driver_SIGKILL_'+mode]='PASS'
            finally:
                if process is not None:
                    if process.poll() is None:process.kill();process.wait(timeout=5)
                    process.stdin.close();process.stdout.close();process.stderr.close()
                if fixture_identity is not None:
                    current=kernel.process(fixture)
                    if current is not None and current.identity==fixture_identity.identity and current.live:os.kill(fixture,signal.SIGKILL)
                jobs.close()
    proof['native_driver_crash_exercised']=True
    (ROOT/'build/driver-crash-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof))


if __name__=='__main__':main()
