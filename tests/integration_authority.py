"""Real signed policy RPC, isolated from installed rules and system paths."""
import base64
import copy
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.authority import PolicyAuthority
from hotturkey.authority_server import AuthorityServer
from hotturkey.engine import password_hash
from hotturkey.ipc import peer_identity, receive, send
from hotturkey.store import Store


def main():
    checker=ROOT/'build/HotTurkeyPeerCheck'
    client=ROOT/'build/HotTurkeyPolicyClientQA'
    production=ROOT/'build/HotTurkeyPolicyClient'
    approved=json.loads(subprocess.check_output([str(checker),'--describe',str(client)]))['requirement']
    proof={}
    with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-authority-') as temporary:
        data=Path(temporary)/'data';path=Path(temporary)/'socket'
        observed=[]
        def verify(connection):
            # Isolated QA uses a workspace checker; production requires a root-
            # protected checker and configuration with no verifier override.
            identity=peer_identity(connection)
            result=subprocess.run([str(checker),'--audit',base64.b64encode(identity.audit_token).decode(),
                                   '--requirement',approved],capture_output=True,text=True,timeout=3)
            if result.returncode or json.loads(result.stdout).get('ok') is not True:raise PermissionError('Denied')
            observed.append(identity)
            return identity

        def start():
            store=Store(data)
            authority=PolicyAuthority(store,os.getuid(),boot_id='integration-boot')
            authority.engine(os.getuid())
            server=AuthorityServer(authority,path,verify,tick_interval=.2)
            server.bind()
            thread=threading.Thread(target=server.serve_forever);thread.start()
            return store,authority,server,thread

        def call(operation,data=None,session='',**extra):
            payload={'op':operation,'data':data or {},'session':session,**extra}
            process=subprocess.Popen([str(client),str(path),str(os.getuid())],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            output,error=process.communicate(json.dumps(payload).encode(),timeout=8)
            assert process.returncode==0,(process.returncode,error.decode())
            value=json.loads(output)
            if value['ok']:assert observed[-1].pid==process.pid
            return value

        store,authority,server,thread=start()
        try:
            result=call('save',{'block':{'name':'RPC locked append','enabled':True,'websites':['example.invalid']}})
            assert result['ok'];ident=result['result']['id']
            now=authority.engine(os.getuid()).now()
            assert call('lock',{'id':ident,'type':'timer','until':now+3600})['ok']
            before=copy.deepcopy(store.state['blocks'][0]['lock'])
            assert call('add-targets',{'id':ident,'websites':['new.invalid'],'applications':['local.hotturkey.fixture']})['ok']
            assert store.state['blocks'][0]['lock']==before
            assert call('check',{'url':'https://new.invalid'})['result']['blocked']
            assert not call('delete',{'id':ident})['ok']
            assert not call('toggle',{'id':ident,'enabled':False})['ok']
            assert not call('snapshot',uid=0)['ok']
            proof.update(real_signed_client='PASS',kernel_uid_pid='PASS',locked_atomic_addition='PASS',locked_removal_rejected='PASS',claimed_uid_rejected='PASS')
            # Same UID Python can open the socket, but cannot satisfy native code identity.
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as unauthorized:
                unauthorized.connect(str(path))
                denial=receive(unauthorized)
                assert denial['ok'] is False
            proof['unapproved_same_uid_code_rejected']='PASS'
            with store.lock:
                store.state['settings'].update(settings_password=password_hash('integration secret'),protect_overview=True)
                store.save()
            assert call('snapshot')['result']['blocks']==[]
            assert not call('add-targets',{'id':ident,'websites':['denied.invalid']})['ok']
            session=call('authenticate',{'password':'integration secret'})['result']['session']
            assert call('add-targets',{'id':ident,'websites':['authenticated.invalid']},session)['ok']
            assert call('check',{'url':'https://authenticated.invalid'})['result']['blocked']
            proof['settings_password_and_protected_overview']='PASS'
            assert not call('maintenance-status',session=session)['result']['can_uninstall']
            # Packaged client cannot be repointed at a caller-selected socket/UID.
            invalid=subprocess.run([str(production),str(path),str(os.getuid())],input=b'{}',capture_output=True,timeout=5)
            assert invalid.returncode!=0
            proof['production_has_no_test_path_or_uid_flags']='PASS'
        finally:
            server.stop();thread.join(timeout=15)
            assert not thread.is_alive();store.db.close()
        store,authority,server,thread=start()
        try:
            assert call('snapshot')['result']['blocks']==[]
            assert not call('add-targets',{'id':ident,'websites':['stale.invalid']},session)['ok']
            session=call('authenticate',{'password':'integration secret'})['result']['session']
            block=call('snapshot',session=session)['result']['blocks'][0]
            assert block['lock']['type']=='timer'
            assert set(block['websites'])=={'example.invalid','new.invalid','authenticated.invalid'}
            assert call('check',{'url':'https://authenticated.invalid'})['result']['blocked']
            proof['restart_preserves_policy_locks_and_additions']='PASS'
            proof['restart_invalidates_old_management_sessions']='PASS'
        finally:
            server.stop();thread.join(timeout=15)
            assert not thread.is_alive();store.db.close()
        # A server with the wrong kernel UID receives no credential bytes.
        fake_path=Path(temporary)/'fake'
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as fake:
            fake.bind(str(fake_path));fake.listen(1);fake.settimeout(5)
            process=subprocess.Popen([str(client),str(fake_path),'0'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            process.stdin.write(b'{"op":"authenticate","data":{"password":"must not cross"}}');process.stdin.close()
            with fake.accept()[0] as connection:
                connection.settimeout(5);assert connection.recv(1)==b''
            process.wait(timeout=5)
            assert process.returncode!=0
            process.stdout.close();process.stderr.close()
        proof['wrong_server_uid_rejected_before_credentials']='PASS'
    (ROOT/'build/authority-rpc-proof.json').write_text(json.dumps(proof,indent=2))
    print(json.dumps(proof))


if __name__=='__main__':main()
