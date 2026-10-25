"""Disposable current-GUI launchd service with actual signed passive sampling.

The production plist is rendered then copied under a unique QA label with a
QA executable/socket. No system files or persistent login items are written.
"""
import base64
import copy
import dataclasses
import json
import os
import plistlib
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.authority import PolicyAuthority
from hotturkey.authority_server import AuthorityServer
from hotturkey.ipc import peer_identity
from hotturkey.session_launch import session_launch_agent
from hotturkey.system_jobs import _Job,_JobControl,read_plan
from hotturkey.store import Store
from hotturkey.system_enforcement import SystemExecution
from hotturkey.trusted_sessions import TrustedSessions


def main():
    domain=f'gui/{os.getuid()}';proof={'root_installed':False,'persistent_login_item_installed':False,'installed_rules_changed':False}
    if subprocess.run(['/bin/launchctl','print',domain],capture_output=True).returncode:
        proof.update(gui_domain_available=False,native_supervision_exercised=False)
    else:
        proof['gui_domain_available']=True
        checker=ROOT/'build/HotTurkeyPeerCheck';agent=ROOT/'build/HotTurkeySessionAgentQA'
        requirement=json.loads(subprocess.check_output([str(checker),'--describe',str(agent)]))['requirement']
        with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-supervise-') as temporary:
            directory=Path(temporary);path=directory/'socket';store=Store(directory/'data')
            store.state['settings']['statistics']=False
            authority=PolicyAuthority(store,os.getuid());execution=SystemExecution(authority,ROOT/'build/HotTurkeySystemAgentQA')
            sessions=TrustedSessions(authority,execution);observed=[];consume=sessions.consume
            def sample(identity,data):
                result=consume(identity,data);observed.append(identity);return result
            sessions.consume=sample
            def verify(connection):
                identity=peer_identity(connection)
                result=subprocess.run([str(checker),'--audit',base64.b64encode(identity.audit_token).decode(),'--requirement',requirement],capture_output=True,timeout=3)
                if result.returncode:raise PermissionError('Denied')
                return dataclasses.replace(identity,role='session')
            server=AuthorityServer(authority,path,verify,execution=execution,sessions=sessions,tick_interval=.2)
            server.bind();errors=[]
            def serve():
                try:server.serve_forever()
                except BaseException as error:errors.append(type(error).__name__)
            thread=threading.Thread(target=serve);thread.start()
            label='local.hotturkey.session.qa.'+uuid.uuid4().hex;target=domain+'/'+label
            plan=session_launch_agent();plan.update(Label=label,ProgramArguments=[str(agent),str(path),str(os.getuid()),'120'])
            plist=directory/'agent.plist';plist.write_bytes(plistlib.dumps(plan));loaded=False;commands=[]
            job=_Job(domain,label,plist,plan)
            def run(arguments,**values):
                assert arguments[:2] in [['/bin/launchctl','print'],['/bin/launchctl','bootstrap'],['/bin/launchctl','bootout']]
                if arguments[1]=='bootstrap':assert arguments[2:]==[domain,str(plist)]
                elif arguments[1]=='bootout':assert arguments[2:]==[target]
                else:assert arguments[2:] in [[domain],[target]]
                commands.append(arguments);return subprocess.run(arguments,**values)
            control=_JobControl(lambda:None,lambda candidate:read_plan(candidate.plist,candidate.expected,owner_uid=os.getuid(),anchor=directory),run=run)
            try:
                assert control.load(job);loaded=True
                assert control.load(job)
                assert sum(command[1]=='bootstrap' for command in commands)==1
                deadline=time.monotonic()+20
                while not observed and time.monotonic()<deadline:time.sleep(.1)
                assert observed,'launchd did not deliver an accepted native sample'
                first=observed[-1];assert first.uid==os.getuid() and first.role=='session'
                marker=copy.deepcopy(store.state.get('trusted_sessions',{}))
                result=subprocess.run(['/bin/launchctl','kill','SIGKILL',target],capture_output=True,timeout=10)
                assert result.returncode==0,result.stderr.decode()
                deadline=time.monotonic()+35
                while not any(item.pid!=first.pid for item in observed) and time.monotonic()<deadline:time.sleep(.1)
                assert any(item.pid!=first.pid for item in observed),'launchd did not restart the exact QA service'
                assert all(item.uid==os.getuid() for item in observed)
                assert store.state.get('trusted_sessions',{})==marker
                assert sessions.status(os.getuid())['status']=='running'
                assert store.state['blocks']==[]
                proof.update(native_supervision_exercised=True,accepted_signed_agent_before_and_after_crash='PASS',audit_login_preserved='PASS',new_kernel_process_identity='PASS',
                             shared_bounded_job_control_exercised=True,idempotent_load='PASS',production_system_driver_tested=False)
            finally:
                try:
                    if loaded:assert control.unload(job)
                    assert not control.unload(job)
                finally:
                    # Also clean an uncertain registration if a query timed out
                    # after bootstrap. This fallback is confined to this test's
                    # exact random QA label, never a production service/domain.
                    subprocess.run(['/bin/launchctl','bootout',target],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
                    server.stop();thread.join(timeout=15);assert not thread.is_alive();assert not errors,errors
                    store.db.close()
            assert not control.loaded(job)
            assert sum(command[1]=='bootout' for command in commands)==1
            proof['idempotent_unload']='PASS'
            proof['temporary_launchd_service_removed']='PASS'
    (ROOT/'build/session-supervision-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof))


if __name__=='__main__':main()
