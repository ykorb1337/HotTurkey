"""Actual signed policy RPC + console scanner; QA never invokes physical sleep."""
import base64
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.authority import PolicyAuthority
from hotturkey.authority_server import AuthorityServer
from hotturkey.ipc import peer_identity
from hotturkey.platform_macos import native_samples,native_command,stop_native
from hotturkey.store import Store
from hotturkey.system_client import SystemClient
from hotturkey.system_enforcement import SystemExecution


def main():
    checker=ROOT/'build/HotTurkeyPeerCheck';client=ROOT/'build/HotTurkeyPolicyClientQA';actuator=ROOT/'build/HotTurkeySystemAgentQA'
    requirement=json.loads(subprocess.check_output([str(checker),'--describe',str(client)]))['requirement']
    proof={'root_installed':False,'physical_sleep_invoked':False,'installed_rules_changed':False}
    # A stalled parent cannot indefinitely freeze the native recovery run loop.
    helper=subprocess.Popen([str(ROOT/'build/HotTurkeyAgent'),'--resume'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,bufsize=0)
    try:
        started=time.monotonic();samples=native_samples(helper,threading.Event(),lambda:None)
        next(samples)  # No command is ever sent; no overlay or OS action requested.
        helper.wait(timeout=15)
        assert helper.returncode==0 and 9<=time.monotonic()-started<=15
        proof['native_recovery_helper_exits_after_parent_stall']='PASS'
    finally:stop_native(helper)
    stop=threading.Event();process=subprocess.Popen([str(actuator)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,bufsize=0)
    try:
        samples=native_samples(process,stop,lambda:None);initial=next(samples);console=initial['console_uid']
        command={'id':'a'*64,'uid':os.getuid(),'action':'sleep'}
        native_command(process,stop,{'kill':[],'device':command})
        result=next(samples)['device_result'];assert result=={**command,'result':'simulated' if console==os.getuid() else 'stale'}
        proof['native_power_protocol_simulation_and_console_recheck']='PASS'
    finally:stop.set();stop_native(process)
    # Invalid power commands are rejected before even a valid owned test kill.
    fixture=subprocess.Popen([sys.executable,'-B','-c','import time; time.sleep(90)'])
    stop=threading.Event();process=subprocess.Popen([str(actuator)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,bufsize=0)
    try:
        samples=native_samples(process,stop,lambda:None);initial=next(samples)
        owned=next(app for app in initial['apps'] if app['pid']==fixture.pid)
        native_command(process,stop,{'kill':[{k:owned[k] for k in ['pid','uid','identity']}],'device':{'id':'a'*64,'uid':os.getuid(),'action':'unsupported'}})
        process.wait(timeout=5);assert process.returncode==65 and fixture.poll() is None
        proof['malformed_device_command_rejected_before_signals']='PASS'
    finally:
        stop.set();stop_native(process)
        if fixture.poll() is None:fixture.terminate()
        fixture.wait(timeout=5)
    with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-device-gate-') as temporary:
        path=Path(temporary)/'socket';store=Store(Path(temporary)/'data')
        store.state['settings']['statistics']=False
        authority=PolicyAuthority(store,os.getuid());execution=SystemExecution(authority,actuator,simulate_devices=True)
        def verify(connection):
            identity=peer_identity(connection)
            result=subprocess.run([str(checker),'--audit',base64.b64encode(identity.audit_token).decode(),'--requirement',requirement],capture_output=True,timeout=3)
            if result.returncode:raise PermissionError('Denied')
            return identity
        server=AuthorityServer(authority,path,verify,execution=execution);server.bind();errors=[]
        def serve():
            try:server.serve_forever()
            except BaseException as error:errors.append(type(error).__name__)
        thread=threading.Thread(target=serve);thread.start()
        api=SystemClient(command=[str(client),str(path),str(os.getuid())])
        try:
            api.api('device/configure-recovery',{'word':'fixture-escape'})
            block=api.api('blocks/save',{'block':{'name':'Sleep fixture','device':'sleep','enabled':True,'device_minutes':5,'confirm_device':True}})
            assert block['locked'] and api.api('state')['settings']['device_recovery_hash'] is True
            if console==os.getuid():
                deadline=time.monotonic()+45
                while execution.device_result is None and time.monotonic()<deadline:time.sleep(.1)
                assert execution.device_result and execution.device_result['result']=='simulated',execution.status()
                assert execution.device_gate.status(os.getuid())['phase']=='sleep'
                proof['real_console_countdown_to_simulated_sleep']='PASS'
            else:proof['real_console_countdown_to_simulated_sleep']='NO_CONSOLE_USER'
            api.api('settings',{'password':'manager-only','protect_overview':True})
            assert api.api('state')['blocks']==[]
            result=api.api('device/recover',{'word':'fixture-escape'});assert result['ok'] and result['count']==1
            time.sleep(2.2)
            assert execution.device_gate.status(os.getuid()) is None
            engine=authority.engine(os.getuid());assert not engine.active(engine.find(block['id']))
            assert engine.find(block['id'])['enabled'] and engine.locked(engine.find(block['id']))
            proof['emergency_works_without_settings_auth_and_stops_further_requests']='PASS'
            assert 'fixture-escape' not in json.dumps(store.state)
            proof['safety_word_not_persisted_in_plaintext']='PASS'
        finally:
            server.stop();thread.join(timeout=15);assert not thread.is_alive();assert not errors,errors;store.db.close()
    (ROOT/'build/device-gate-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof))


if __name__=='__main__':main()
