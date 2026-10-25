"""Signed health/session probes and real process enforcement across commit.

All policy/activation files and the target executable are disposable. No
system installation is performed and the executor is current-UID-only QA.
"""
import base64
import copy
import dataclasses
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
from hotturkey.installation_gate import InstallationGate
from hotturkey.ipc import peer_identity
from hotturkey.model import PolicyError
from hotturkey.store import Store
from hotturkey.system_client import SystemClient
from hotturkey.system_enforcement import SystemExecution
from hotturkey.trusted_sessions import TrustedSessions


def main():
    checker=ROOT/'build/HotTurkeyPeerCheck';client=ROOT/'build/HotTurkeyPolicyClientQA';session=ROOT/'build/HotTurkeySessionAgentQA'
    requirements={role:json.loads(subprocess.check_output([str(checker),'--describe',str(binary)]))['requirement'] for role,binary in [('client',client),('session',session)]}
    proof={'root_installed':False,'system_files_written':False,'installed_rules_read_or_changed':False,'physical_sleep_invoked':False}
    with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-install-gate-') as temporary:
        root=Path(temporary);marker=root/'activation.json';path=root/'socket'
        def publish(phase):
            staged=root/'marker.new';staged.write_text(json.dumps({'version':1,'transaction':'b'*32,'phase':phase,'controller_uid':os.getuid(),'payload_sha256':'a'*64}));staged.chmod(0o600);staged.replace(marker)
        publish('pending');gate=InstallationGate(marker,os.getuid(),'a'*64,owner_uid=os.getuid(),anchor=root)
        source=root/'fixture.c';source.write_text('#include <unistd.h>\nint main(void){sleep(90);return 0;}\n')
        executable=root/'fixture';subprocess.run(['/usr/bin/clang',str(source),'-o',str(executable)],check=True,capture_output=True)
        fixture=subprocess.Popen([str(executable)]);agent=None
        store=Store(root/'data');store.state['settings']['statistics']=False
        authority=PolicyAuthority(store,os.getuid(),installation_gate=gate);engine=authority.engine(os.getuid())
        engine.save_block({'name':'Owned fixture','enabled':True,'applications':['binary:'+str(executable)]})
        before=copy.deepcopy(store.state)
        execution=SystemExecution(authority,ROOT/'build/HotTurkeySystemAgentQA');sessions=TrustedSessions(authority,execution)
        def verify(connection):
            identity=peer_identity(connection)
            result=subprocess.run([str(checker),'--audit',base64.b64encode(identity.audit_token).decode(),'--roles',json.dumps(requirements)],capture_output=True,timeout=3)
            if result.returncode:raise PermissionError('Denied')
            return dataclasses.replace(identity,role=json.loads(result.stdout)['role'])
        server=AuthorityServer(authority,path,verify,execution=execution,sessions=sessions,tick_interval=.1);server.bind();errors=[]
        def serve():
            try:server.serve_forever()
            except BaseException as error:errors.append(type(error).__name__)
        thread=threading.Thread(target=serve);thread.start();api=SystemClient(command=[str(client),str(path),str(os.getuid())])
        try:
            agent=subprocess.Popen([str(session),str(path),str(os.getuid()),'90'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                health=api.request('installation-health')
                if health['executor_ready'] and health['session_transport_fresh']:break
                time.sleep(.1)
            else:raise AssertionError('No attested passive health')
            assert health['installation_pending'] and fixture.poll() is None
            for operation,data in [('snapshot',{}),('save',{'block':{'name':'Denied'}}),('installation-health',{'phase':'committed'})]:
                try:api.request(operation,data)
                except PolicyError:pass
                else:raise AssertionError('Uncommitted policy operation succeeded')
            time.sleep(2.2);assert fixture.poll() is None and store.state==before and store.export_statistics()==[]
            proof['signed_health_and_session_probes_without_policy_mutation']=True
            proof['enabled_target_not_signaled_before_commit']=True
            publish('committed');fixture.wait(timeout=10);assert fixture.returncode==-15
            assert not api.request('installation-health')['installation_pending']
            deadline=time.monotonic()+8
            while sessions.status(os.getuid())['status']!='running' and time.monotonic()<deadline:time.sleep(.1)
            assert sessions.status(os.getuid())['status']=='running'
            assert str(os.getuid()) in store.state['trusted_sessions']
            proof['same_runtime_activates_only_after_matching_commit']=True
            proof['real_owned_process_terminated_after_commit']=True
            marker.unlink();deadline=time.monotonic()+8
            while not server.stopping.is_set() and time.monotonic()<deadline:time.sleep(.1)
            assert server.stopping.is_set()
            proof['missing_activation_marker_stops_authority']=True
        finally:
            if agent is not None:
                agent.terminate();agent.wait(timeout=5)
            if fixture.poll() is None:fixture.terminate();fixture.wait(timeout=5)
            server.stop();thread.join(timeout=15);assert not thread.is_alive();store.db.close()
        assert errors==['RuntimeError'],errors
    (ROOT/'build/installation-gate-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof))


if __name__=='__main__':main()
