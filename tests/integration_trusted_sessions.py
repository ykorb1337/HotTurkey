"""Real passive native session sampling; no installed policy or GUI changes."""
import base64
import dataclasses
import json
import os
import socket
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
from hotturkey.ipc import peer_identity,receive
from hotturkey.store import Store
from hotturkey.system_enforcement import SystemExecution
from hotturkey.trusted_sessions import TrustedSessions,audit_session


def main():
    checker=ROOT/'build/HotTurkeyPeerCheck'
    client=ROOT/'build/HotTurkeyPolicyClientQA'
    agent=ROOT/'build/HotTurkeySessionAgentQA'
    requirements={role:json.loads(subprocess.check_output([str(checker),'--describe',str(binary)]))['requirement']
                  for role,binary in [('client',client),('session',agent)]}
    assert len(set(requirements.values()))==2
    proof={}
    with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-session-') as temporary:
        store=Store(Path(temporary)/'data');store.state['settings']['statistics']=False
        authority=PolicyAuthority(store,os.getuid(),boot_id='session-integration')
        execution=SystemExecution(authority,ROOT/'build/HotTurkeySystemAgentQA')
        sessions=TrustedSessions(authority,execution)
        verified=[]
        consume=sessions.consume
        def observe_sample(identity,data):
            result=consume(identity,data);verified.append(result['foreground_verified']);return result
        sessions.consume=observe_sample
        observed=[]
        def verify(connection):
            identity=peer_identity(connection)
            result=subprocess.run([str(checker),'--audit',base64.b64encode(identity.audit_token).decode(),
                                   '--roles',json.dumps(requirements)],capture_output=True,text=True,timeout=3)
            if result.returncode:raise PermissionError('Denied')
            value=json.loads(result.stdout)
            if value.get('ok') is not True or value.get('role') not in requirements:raise PermissionError('Denied')
            identity=dataclasses.replace(identity,role=value['role'])
            observed.append(identity)
            return identity
        path=Path(temporary)/'socket'
        server=AuthorityServer(authority,path,verify,execution=execution,sessions=sessions,tick_interval=.2)
        server.bind();errors=[]
        def serve():
            try:server.serve_forever()
            except BaseException as error:errors.append(type(error).__name__)
        thread=threading.Thread(target=serve);thread.start()
        def call(operation,data=None):
            result=subprocess.run([str(client),str(path),str(os.getuid())],input=json.dumps({'op':operation,'data':data or {}}).encode(),capture_output=True,timeout=8)
            assert result.returncode==0
            return json.loads(result.stdout)
        def run_agent(count=3):
            result=subprocess.run([str(agent),str(path),str(os.getuid()),str(count)],stdin=subprocess.DEVNULL,capture_output=True,timeout=count*7+5)
            assert result.returncode==0,result.stderr.decode()
            value=json.loads(result.stdout);assert value['accepted']==count
            return value
        try:
            deadline=time.monotonic()+5
            while execution.status()['status']!='running' and time.monotonic()<deadline:time.sleep(.05)
            assert execution.status()['status']=='running'
            assert not call('session-sample',{'idle_seconds':0})['ok']
            proof['signed_management_client_cannot_report_usage']='PASS'
            # Native agent reads actual session/front/idle; test supplies no samples.
            values=run_agent()
            agent_peers=[p for p in observed if p.role=='session']
            assert len(agent_peers)==3 and len({p.pid for p in agent_peers})==1
            assert all(p.uid==os.getuid() for p in agent_peers)
            asid=audit_session(agent_peers[0])
            marker=store.state.get('trusted_sessions',{}).get(str(os.getuid()))
            if values['on_console'] and asid is not None:
                assert marker['audit_session']==asid
            else:assert marker is None
            proof.update(distinct_native_code_roles='PASS',real_kernel_uid_pid_audit_session='PASS',native_passive_samples_accepted='PASS')
            # Freshly launched same-session agent must wait for the old lease,
            # then reuse the persisted login marker rather than creating a login.
            time.sleep(5.1);run_agent(2)
            assert store.state.get('trusted_sessions',{}).get(str(os.getuid()))==marker
            assert call('snapshot')['result']['system_session']['status']=='running'
            proof['agent_restart_preserves_login_marker']='PASS' if marker else 'NO_CONSOLE_LOGIN'
            proof['actual_console_samples']=values['on_console']
            proof['actual_foreground_samples']=values['front_present']
            proof['kernel_verified_foreground_samples']=sum(verified)
            if values['front_present']:assert any(verified)
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as unauthorized:
                unauthorized.connect(str(path));assert receive(unauthorized)['ok'] is False
            proof['unsigned_same_uid_process_rejected']='PASS'
            production=ROOT/'build/HotTurkeySessionAgent'
            assert subprocess.run([str(production),str(path),str(os.getuid()),'1'],capture_output=True,timeout=5).returncode==64
            assert subprocess.run([str(agent),str(path),str(os.getuid()),'1','--front-pid','1'],capture_output=True,timeout=5).returncode==64
            proof['no_production_override_or_fake_sample_flags']='PASS'
        finally:
            server.stop();thread.join(timeout=15);assert not thread.is_alive()
            assert not errors,errors
            store.db.close()
        # Server identity is checked before even passive activity is transmitted.
        fake_path=Path(temporary)/'fake'
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as fake:
            fake.bind(str(fake_path));fake.listen(1);fake.settimeout(5)
            process=subprocess.Popen([str(agent),str(fake_path),'0','1'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                with fake.accept()[0] as connection:
                    connection.settimeout(5);assert connection.recv(1)==b''
                output,error=process.communicate(timeout=8)
                assert process.returncode==1 and json.loads(output)['accepted']==0
            finally:
                if process.poll() is None:process.kill();process.wait()
        proof['wrong_server_uid_receives_no_activity']='PASS'
    proof.update(root_installed=False,separate_accounts_tested=False,real_sleep_wake_tested=False)
    (ROOT/'build/trusted-session-proof.json').write_text(json.dumps(proof,indent=2))
    print(json.dumps(proof))


if __name__=='__main__':main()
