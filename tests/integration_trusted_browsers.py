"""Real signed parent/host/RPC with disposable data, never a user's browser."""
import base64
import dataclasses
import json
import os
import selectors
import socket
import struct
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
from hotturkey.store import Store
from hotturkey.system_enforcement import SystemExecution
from hotturkey.trusted_browsers import TrustedBrowsers
from hotturkey.trusted_sessions import TrustedSessions


def exact(stream,count):
    result=b'';deadline=time.monotonic()+10
    with selectors.DefaultSelector() as selector:
        selector.register(stream,selectors.EVENT_READ)
        while len(result)<count:
            assert time.monotonic()<deadline,'Native response deadline'
            if selector.select(max(0,deadline-time.monotonic())):
                part=os.read(stream.fileno(),count-len(result));assert part,'Native host exited'
                result+=part
    return result


def main():
    build=ROOT/'build';checker=build/'HotTurkeyPeerCheck';fixture=build/'HotTurkeyBrowserFixture';host=build/'HotTurkeyBrowserHostQA'
    def requirement(binary):return json.loads(subprocess.check_output([str(checker),'--describe',str(binary)]))['requirement']
    requirements={role:requirement(build/binary) for role,binary in [('client','HotTurkeyPolicyClientQA'),('session','HotTurkeySessionAgentQA'),('browser','HotTurkeyBrowserHostQA')]}
    origin='chrome-extension://'+'a'*32+'/'
    proof={};observed=[]
    with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-browser-') as temporary:
        directory=Path(temporary);config=directory/'browsers.json';path=directory/'socket'
        config.write_text(json.dumps({'version':1,'browsers':{
            'Edge':{'requirement':requirement(fixture),'origins':[origin]},
            'Firefox':{'requirement':requirement(fixture),'origins':['hotturkey@local.hotturkey']}}}))
        store=Store(directory/'data');store.state['settings']['statistics']=False
        authority=PolicyAuthority(store,os.getuid(),boot_id='browser-integration')
        execution=SystemExecution(authority,build/'HotTurkeySystemAgentQA')
        sessions=TrustedSessions(authority,execution)
        browsers=TrustedBrowsers(authority,execution,sessions,bundles={'Edge':'','Firefox':''})
        def verify(connection):
            identity=peer_identity(connection)
            result=subprocess.run([str(checker),'--audit',base64.b64encode(identity.audit_token).decode(),'--roles',json.dumps(requirements)],capture_output=True,text=True,timeout=3)
            if result.returncode:raise PermissionError('Denied')
            role=json.loads(result.stdout)['role'];identity=dataclasses.replace(identity,role=role);observed.append(identity)
            return identity
        server=AuthorityServer(authority,path,verify,execution=execution,sessions=sessions,browsers=browsers,tick_interval=.2)
        server.bind();errors=[]
        def serve():
            try:server.serve_forever()
            except BaseException as error:errors.append(type(error).__name__)
        thread=threading.Thread(target=serve);thread.start()
        processes=[]
        def start(origins=None,socket_path=None,uid=None):
            process=subprocess.Popen([str(fixture),str(host),str(config),str(socket_path or path),str(os.getuid() if uid is None else uid),*(origins or [origin])],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
            processes.append(process)
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                if any(p['pid']==process.pid for p in execution.applications(os.getuid())):return process
                if process.poll() is not None:return process
                time.sleep(.05)
            raise AssertionError('Fixture not in kernel inventory')
        def call(process,op,data=None):
            value=json.dumps({'op':op,'data':data or {}}).encode()
            process.stdin.write(struct.pack('<I',len(value))+value);process.stdin.flush()
            length=struct.unpack('<I',exact(process.stdout,4))[0];assert 0<length<=1024*1024
            return json.loads(exact(process.stdout,length))
        try:
            deadline=time.monotonic()+5
            while execution.status()['status']!='running' and time.monotonic()<deadline:time.sleep(.05)
            b=authority.manage(os.getuid(),'save',{'block':{'name':'Signed browser fixture','enabled':True,'websites':['blocked.invalid']}})
            authority.manage(os.getuid(),'lock',{'id':b['id'],'type':'text','custom_text':'browser-fixture'})
            lock=dict(store.state['blocks'][0]['lock']);context='c'*48
            process=start();result=call(process,'sync',{'browser':'forged','context':context,'tabs':[1,2],'usage':[{'tab':1,'url':'https://blocked.invalid','active':True}]})
            assert not result.get('error'),result
            assert result['blocks'][0]['locked'] and result['tab_unblock_supported']
            assert set(authority.engine(os.getuid()).heartbeats)=={'Edge'}
            assert browsers.sources and authority.engine(os.getuid()).sources=={},'No session agent must mean no usage'
            assert all(peer.role=='browser' and peer.uid==os.getuid() for peer in observed)
            proof.update(real_parent_code_and_origin='PASS',real_kernel_parent_identity='PASS',distinct_browser_role='PASS',missing_session_cannot_invent_usage='PASS')
            check={'context':context,'tab':1,'url':'https://blocked.invalid'}
            assert call(process,'check',check)['blocked']
            assert 'error' in call(process,'tab-unblock',{**check,'id':b['id'],'answer':'wrong'})
            assert call(process,'tab-unblock',{**check,'id':b['id'],'answer':'browser-fixture'})['granted']
            assert not call(process,'check',check)['blocked']
            assert call(process,'check',{**check,'tab':2})['blocked']
            assert call(process,'add-site',{'id':b['id'],'url':'https://new.invalid/private?token=not-saved','scope':'domain'})['added']
            assert store.state['blocks'][0]['lock']==lock
            assert store.state['blocks'][0]['websites']==['blocked.invalid','new.invalid']
            assert 'error' in call(process,'delete',{'id':b['id']})
            assert 'error' in call(process,'sync',{'context':context,'tabs':[1],'usage':[{'tab':1,'url':'https://a','seconds':999}]})
            proof.update(locked_append_preserves_lock='PASS',tab_grants_keep_other_tabs_blocked='PASS',no_management_or_elapsed_time_escape='PASS')
            # The alternate native invocation shape is tested explicitly; this
            # signed fixture is not claimed to be a real Firefox application.
            firefox=start(['/not-read/manifest.json','hotturkey@local.hotturkey'])
            result=call(firefox,'sync',{'context':context,'tabs':[1],'usage':[]})
            assert not result.get('error') and 'Firefox' in authority.engine(os.getuid()).heartbeats
            proof['firefox_argument_shape']='PASS'
            invalid=start(['chrome-extension://'+'b'*32+'/']);invalid.wait(timeout=5);assert invalid.returncode!=0
            direct=subprocess.run([str(host),str(config),str(path),str(os.getuid()),origin],input=b'',capture_output=True,timeout=5)
            assert direct.returncode!=0
            assert subprocess.run([str(build/'HotTurkeyBrowserHost'),'--config',str(config)],capture_output=True,timeout=5).returncode!=0
            proof.update(unapproved_origin_rejected='PASS',ordinary_parent_cannot_launch_host='PASS',production_override_flags_rejected='PASS')
            fake_path=directory/'fake'
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as fake:
                fake.bind(str(fake_path));fake.listen(1);fake.settimeout(5)
                wrong=start(socket_path=fake_path,uid=0)
                payload=json.dumps({'op':'add-site','data':{'password':'never-cross'}}).encode()
                wrong.stdin.write(struct.pack('<I',len(payload))+payload);wrong.stdin.flush()
                with fake.accept()[0] as connection:
                    connection.settimeout(5);assert connection.recv(1)==b''
                length=struct.unpack('<I',exact(wrong.stdout,4))[0]
                assert 'error' in json.loads(exact(wrong.stdout,length))
            proof['wrong_server_uid_receives_no_password']='PASS'
        finally:
            for process in processes:
                if process.stdin and not process.stdin.closed:process.stdin.close()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()
                process.stdout.close();process.stderr.close()
            server.stop();thread.join(timeout=15);assert not thread.is_alive();assert not errors,errors;store.db.close()
    proof.update(root_installed=False,real_browser_tested=False,extension_tamper_resistance_tested=False)
    (build/'trusted-browser-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof))


if __name__=='__main__':main()
