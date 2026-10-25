"""Abrupt coordinator-process death while real disposable services survive.

A socketpair test adapter keeps the regular-UID service manager in the parent;
the child runs the actual cutover coordinator/file transaction code. The
production launchd driver and root installation are not exercised here.
"""
import json
import os
import selectors
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.ipc import receive,send
from hotturkey.system_package import prepare_payload,digest
from integration_system_cutover import Driver

CHILD=r'''
import json,os,socket,sys
from pathlib import Path
from hotturkey.ipc import receive,send
from hotturkey.system_cutover import CutoverCoordinator
configuration=json.loads(sys.argv[1]);connection=socket.socket(fileno=int(sys.argv[2]))
class RemoteDriver:
    def __getattr__(self,name):
        def invoke(*args,**values):
            send(connection,{'method':name,'args':list(args),'values':values})
            result=receive(connection)
            if result is None or not result.get('ok'):raise OSError('Test service adapter failed')
            return result.get('result')
        return invoke
class InterruptedCoordinator(CutoverCoordinator):
    def checkpoint(self):print('CHECKPOINT',flush=True);sys.stdin.readline()
    def transition(self,phase,initial=False):
        super().transition(phase,initial)
        if configuration['mode']=='precommit' and phase=='probing':self.checkpoint()
    def call(self,name,**values):
        result=super().call(name,**values)
        if configuration['mode']=='postcommit' and name=='activate':self.checkpoint()
        return result
coordinator=InterruptedCoordinator(Path(configuration['folder']),{key:Path(value) for key,value in configuration['targets'].items()},RemoteDriver(),os.getuid(),configuration['payload'],
    lock_directory=Path(configuration['registry']),owner_uid=os.getuid(),anchor=Path(configuration['root']),timeout=45)
coordinator.apply()
'''


def interrupt(driver,mode):
    parent,child=socket.socketpair();errors=[]
    allowed={'authorize','capture','stop_previous','stage','start_candidate','probe_candidate','activate','stop_candidate','restore_previous','required_sessions'}
    def manage():
        try:
            with parent:
                while True:
                    message=receive(parent)
                    if message is None:return
                    assert isinstance(message,dict) and set(message)=={'method','args','values'} and message['method'] in allowed
                    result=getattr(driver,message['method'])(*message['args'],**message['values'])
                    if message['method']=='stage':result={key:str(path) for key,path in result.items()}
                    send(parent,{'ok':True,'result':result})
        except BaseException as error:errors.append(type(error).__name__)
    manager=threading.Thread(target=manage);manager.start()
    configuration={'folder':str(driver.folder),'targets':{key:str(path) for key,path in driver.targets.items()},'payload':digest(driver.template/'payload.json'),
                   'registry':str(driver.registry),'root':str(driver.root),'mode':mode}
    process=subprocess.Popen([sys.executable,'-E','-s','-B','-c',CHILD,json.dumps(configuration),str(child.fileno())],
        pass_fds=(child.fileno(),),cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    child.close()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout,selectors.EVENT_READ)
            assert selector.select(50),'Coordinator did not reach durable interruption point'
            assert process.stdout.readline()==b'CHECKPOINT\n','Unexpected coordinator output'
        assert driver.old is None
        if mode=='precommit':
            assert driver.server is None
            driver.fixture=subprocess.Popen([str(driver.executable)])
            assert driver.fixture.poll() is None
        else:
            assert driver.server is not None
            assert driver.request('add-targets',{'id':driver.block,'websites':['survives-installer-crash.invalid']}) is not None
        process.kill();process.wait(timeout=5);assert process.returncode==-9
        manager.join(timeout=10);assert not manager.is_alive();assert not errors,errors
        result=driver.coordinator().recover()
        if mode=='precommit':
            assert result['status']=='rolled-back' and driver.old is not None and driver.server is None
            assert driver.old.store.used(driver.block,0)==123
            driver.fixture.wait(timeout=10);assert driver.fixture.returncode<0
        else:
            assert result['status']=='finished' and driver.old is None
            assert driver.authority.engine(driver.uid).store.used(driver.block,0)==123
            assert 'survives-installer-crash.invalid' in driver.authority.engine(driver.uid).find(driver.block)['websites']
            driver.fixture.wait(timeout=10);assert driver.fixture.returncode==-15
        assert driver.coordinator().recover()==result
    finally:
        if process.poll() is None:process.kill();process.wait(timeout=5)
        process.stdin.close();process.stdout.close();process.stderr.close()
        parent.close();manager.join(timeout=10);assert not manager.is_alive()


def main():
    proof={'root_installed':False,'system_files_written':False,'installed_rules_read_or_changed':False,'production_service_driver_tested':False,
           'qa_native_transport':True,'physical_power_loss_tested':False}
    with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-cutover-crash-') as temporary:
        root=Path(temporary);source=root/'fixture.c';source.write_text('#include <unistd.h>\nint main(void){sleep(180);return 0;}\n')
        executable=root/'owned-crash-fixture';subprocess.run(['/usr/bin/clang',str(source),'-o',str(executable)],check=True,capture_output=True)
        template=root/'payload';prepare_payload(ROOT/'build/HotTurkey.app',template,os.getuid(),{'Edge':{'requirement':'identifier "com.microsoft.edgemac"','origins':['chrome-extension://'+'a'*32+'/']}})
        for mode in ['precommit','postcommit']:
            case=root/mode;case.mkdir(mode=0o700);driver=Driver(case,template,executable)
            try:interrupt(driver,mode)
            finally:driver.close()
            proof['actual_coordinator_SIGKILL_'+mode]='PASS'
    (ROOT/'build/cutover-crash-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof))


if __name__=='__main__':main()
