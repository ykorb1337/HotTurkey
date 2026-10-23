"""Real signed, multi-frame management with large UTF-8 policy and exports."""
import base64
import collections
import hashlib
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
from hotturkey.documents import CHUNK,MARKER
from hotturkey.ipc import peer_identity,receive,send
from hotturkey.model import PolicyError
from hotturkey.store import Store
from hotturkey.system_client import SystemClient


def main():
    checker=ROOT/'build/HotTurkeyPeerCheck';native=ROOT/'build/HotTurkeyPolicyClientQA'
    approved=json.loads(subprocess.check_output([str(checker),'--describe',str(native)]))['requirement']
    proof={}
    with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-management-') as temporary:
        directory=Path(temporary);path=directory/'socket';store=Store(directory/'data')
        authority=PolicyAuthority(store,os.getuid());observed=[];counts=collections.Counter()
        def verify(connection):
            identity=peer_identity(connection)
            result=subprocess.run([str(checker),'--audit',base64.b64encode(identity.audit_token).decode(),'--requirement',approved],capture_output=True,text=True,timeout=3)
            if result.returncode:raise PermissionError('Denied')
            return identity
        server=AuthorityServer(authority,path,verify,tick_interval=.2)
        original=server.rpc.dispatch
        def dispatch(identity,request):
            counts[request.get('op')]+=1;observed.append((identity.pid,identity.uid))
            return original(identity,request)
        server.rpc.dispatch=dispatch;server.bind();errors=[]
        def serve():
            try:server.serve_forever()
            except BaseException as error:errors.append(type(error).__name__)
        thread=threading.Thread(target=serve);thread.start()
        client=SystemClient(command=[str(native),str(path),str(os.getuid())])
        try:
            targets=[f'https://bulk.invalid/{i}/'+'星'*110 for i in range(4000)]
            payload={'block':{'name':'Large signed rule','websites':targets}}
            assert len(json.dumps(payload,ensure_ascii=False).encode())>1024*1024
            block=client.api('blocks/save',payload)
            assert block['websites']==targets and len(set(observed))==1
            assert counts['document-start']==1 and counts['document-chunk']>1 and counts['document-read']>1
            assert not server.rpc.documents.records
            proof.update(real_signed_large_upload='PASS',real_signed_paged_result='PASS',unicode_preserved='PASS',all_frames_same_kernel_process='PASS')
            client.api('settings',{'password':'management-fixture','protect_overview':True})
            assert client.api('state')['blocks']==[]
            try:client.api('export');raise AssertionError('Unauthenticated export was accepted')
            except PolicyError:pass
            client.api('auth',{'password':'management-fixture'})
            state=client.api('state');assert state['blocks'][0]['websites']==targets
            until=state['now']+600
            locked=client.api('blocks/lock',{'id':block['id'],'type':'timer','until':until})
            assert locked['lock']['until']==until
            added=client.api('blocks/add-targets',{'id':block['id'],'websites':['new.invalid']})
            assert added['lock']==locked['lock'] and added['websites']==targets+['new.invalid']
            try:client.api('blocks/delete',{'id':block['id']});raise AssertionError('Locked delete was accepted')
            except PolicyError:pass
            exported=client.api('export');assert 'lock' not in exported['blocks'][0]
            exported['blocks'][0]['name']='Imported signed rule'
            assert client.api('import',{'blocks':exported['blocks']})['count']==1
            duplicate=client.api('blocks/duplicate',{'id':block['id'],'name':'Duplicated signed rule'})
            assert not duplicate['enabled'] and not duplicate['locked']
            proof.update(settings_password_and_overview='PASS',large_locked_append_preserves_lock='PASS',large_import_export_and_duplicate='PASS')
            engine=authority.engine(os.getuid())
            with store.lock:
                engine.store.charge(engine.now(),block['id'],20)
                store.db.executemany('INSERT INTO events(at,user,kind,target,block_id,seconds,blocked) VALUES(?,?,?,?,?,?,?)',
                    [(engine.now(),engine.user,'website','统计-'+str(i)+'x'*500,block['id'],1,0) for i in range(1500)])
                store.db.commit()
            rows=client.api('statistics/export');assert len(rows)==1500 and rows[0]['target'].startswith('统计-')
            assert client.api('statistics')['totals']['seconds']==1500
            client.api('statistics/clear');assert client.api('statistics/export')==[]
            assert engine.store.used(block['id'],0)==20
            proof['paged_statistics_clear_keeps_allowance']='PASS'
            before=len(store.state['blocks'])
            body=json.dumps({'op':'import','data':{'blocks':[{'name':'Never committed'}]},'session':client.session}).encode()
            token=client.request('document-start',{'operation':'import','size':len(body),'sha256':hashlib.sha256(body).hexdigest()})['id']
            try:client.request('document-chunk',{'id':token,'offset':0,'data':base64.b64encode(body).decode()});raise AssertionError('New process took over upload')
            except PolicyError:pass
            assert len(store.state['blocks'])==before
            proof['abandoned_upload_has_no_partial_policy']='PASS'
        finally:
            server.stop();thread.join(timeout=15);assert not thread.is_alive();assert not errors,errors;store.db.close()
        # An otherwise reachable QA server cannot pass a corrupt page to stdout.
        fake_path=directory/'corrupt'
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as fake:
            fake.bind(str(fake_path));fake.listen(1);fake.settimeout(5)
            process=subprocess.Popen([str(native),str(fake_path),str(os.getuid())],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            process.stdin.write(b'{"op":"snapshot"}');process.stdin.close()
            with fake.accept()[0] as connection:
                assert receive(connection)['op']=='snapshot'
                body=b'{"blocks":["tampered"]}'
                send(connection,{'ok':True,'result':{MARKER:{'id':'a'*43,'size':len(body),'sha256':'0'*64},
                    'offset':0,'data':base64.b64encode(body).decode(),'next':None}})
            output=process.stdout.read();process.wait(timeout=8);assert process.returncode==1
            assert json.loads(output)['ok'] is False and b'tampered' not in output
            process.stdout.close();process.stderr.close()
        proof['native_integrity_failure_never_exposes_partial_result']='PASS'
    proof.update(root_installed=False,installed_rules_changed=False)
    (ROOT/'build/management-transfer-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof))


if __name__=='__main__':main()
