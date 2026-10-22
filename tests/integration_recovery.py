"""Fault injection against an isolated service and its disposable native child.

No installed service, user rule, browser, or user application is terminated.
"""
import json
import logging
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.server import Service


def wait_for(predicate, description, timeout=20):
    until=time.monotonic()+timeout
    while time.monotonic()<until:
        result=predicate()
        if result:return result
        time.sleep(.05)
    raise AssertionError('Timed out: '+description)


def main():
    build=ROOT/'build'
    build.mkdir(exist_ok=True)
    log=logging.FileHandler(build/'recovery-integration.log',mode='w')
    logging.getLogger('hotturkey').addHandler(log)
    results={}
    with tempfile.TemporaryDirectory(prefix='recovery-',dir=build) as temporary:
        directory=Path(temporary)
        source=directory/'fixture.c'
        source.write_text('#include <unistd.h>\nint main(void) { sleep(90); return 0; }\n')
        fixture=directory/'HotTurkeyRecoveryFixture'
        subprocess.run(['/usr/bin/clang',str(source),'-o',str(fixture)],check=True)
        service=Service(directory/'data',enforce=True)
        thread=threading.Thread(target=service.run,daemon=True)
        thread.start()

        def call(path,data=None):
            request=urllib.request.Request(service.origin+'/api/'+path,data=json.dumps(data).encode() if data is not None else None,headers={'Authorization':'Bearer '+service.token,'Content-Type':'application/json'})
            with urllib.request.urlopen(request,timeout=5) as response:return json.load(response)

        def healthy():
            state=call('state')
            return state if state['enforcement']['desktop_connected'] and not state['enforcement']['worker_error'] else None

        def assert_preserved():
            state=call('state')
            protected=next(b for b in state['blocks'] if b['id']==block['id'])
            paused=next(b for b in state['blocks'] if b['id']==signin['id'])
            assert protected['locked'] and protected['enabled'],'Recovery changed a locked rule'
            assert not paused['enabled'],'Helper recovery was incorrectly treated as a login'

        def assert_enforced():
            process=subprocess.Popen([str(fixture)])
            try:
                wait_for(lambda:process.poll() is not None,'disposable executable blocked',timeout=5)
                assert process.returncode<0,'Expected signal termination of fixture'
                return process.returncode
            finally:
                if process.poll() is None:process.kill()
                process.wait()

        try:
            wait_for(healthy,'initial helper heartbeat')
            block=call('blocks/save',{'block':{'name':'QA recovery protected fixture','enabled':True,'applications':['binary:'+str(fixture)],'websites':['recovery.invalid']}})
            call('blocks/lock',{'id':block['id'],'type':'timer','until':time.time()+300})
            signin=call('blocks/save',{'block':{'name':'QA paused login rule','enabled':False,'autostart':{'type':'signin'}}})
            results['initial_enforcement_signal']=assert_enforced()

            previous=service.agent_process
            started=time.monotonic()
            previous.kill()
            wait_for(lambda:not call('state')['enforcement']['desktop_connected'],'dead helper reported offline',timeout=3)
            wait_for(lambda:service.agent_process is not None and service.agent_process.pid!=previous.pid and healthy(),'restart after helper exit')
            assert previous.poll() is not None,'Exited child was not reaped'
            assert_preserved()
            results['exit_recovery_seconds']=round(time.monotonic()-started,2)
            results['after_exit_enforcement_signal']=assert_enforced()

            once=call('blocks/save',{'block':{'name':'QA clock during stalled helper','enabled':False,'autostart':{'type':'once','at':time.time()+1}}})
            previous=service.agent_process
            started=time.monotonic()
            previous.send_signal(signal.SIGSTOP)
            _,status=os.waitpid(previous.pid,os.WUNTRACED)
            assert os.WIFSTOPPED(status),'Fixture helper did not suspend'
            wait_for(lambda:next(b for b in call('state')['blocks'] if b['id']==once['id'])['enabled'],'scheduled autostart while helper stalled',timeout=4)
            assert service.agent_process is previous,'Helper was replaced before the clock check'
            results['clock_during_stall']='PASS'
            wait_for(lambda:not call('state')['enforcement']['desktop_connected'],'stalled helper reported offline',timeout=13)
            wait_for(lambda:service.agent_process is not None and service.agent_process.pid!=previous.pid and healthy(),'replacement of suspended helper')
            assert previous.poll() in (-signal.SIGTERM,-signal.SIGKILL),'Suspended helper was not terminated and reaped'
            assert_preserved()
            results['stalled_recovery_seconds']=round(time.monotonic()-started,2)
            results['after_stall_enforcement_signal']=assert_enforced()
            results['helper_restarts']=call('state')['enforcement']['helper_restarts']
            results['locked_rule_preserved']='PASS'
            results['no_false_signin']='PASS'

            previous=service.agent_process
            previous.send_signal(signal.SIGSTOP)
            _,status=os.waitpid(previous.pid,os.WUNTRACED)
            assert os.WIFSTOPPED(status),'Shutdown fixture helper did not suspend'
            started=time.monotonic()
            service.http.shutdown()
            thread.join(timeout=7)
            assert not thread.is_alive(),'Service shutdown did not finish'
            assert previous.poll() in (-signal.SIGTERM,-signal.SIGKILL),'Shutdown left a suspended helper behind'
            results['shutdown_seconds']=round(time.monotonic()-started,2)
            assert results['shutdown_seconds']<6,'Shutdown exceeded its bound'
            results['clean_shutdown']='PASS'
        finally:
            service.stop.set()
            if thread.is_alive():service.http.shutdown();thread.join(timeout=7)
            if service.agent_process is not None and service.agent_process.poll() is None:
                service.agent_process.kill();service.agent_process.wait(timeout=3)
            service.store.db.close()
            logging.getLogger('hotturkey').removeHandler(log)
            log.close()
    (build/'recovery-proof.json').write_text(json.dumps(results,indent=2))
    print(json.dumps(results,ensure_ascii=False))


if __name__=='__main__':main()
