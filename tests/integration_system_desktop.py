"""Actual HTTP UI -> hardened native client -> attested policy authority.

All policy and connection files are disposable. --ui keeps the fixture alive
for browser inspection until Enter is received; it does not install anything.
"""
import argparse
import base64
import dataclasses
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.authority import PolicyAuthority
from hotturkey.authority_server import AuthorityServer
from hotturkey.ipc import peer_identity
from hotturkey.store import Store
from hotturkey.system_client import SystemClient
from hotturkey.system_desktop import SystemDesktopService
from hotturkey.system_enforcement import SystemExecution
from hotturkey.trusted_sessions import TrustedSessions


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--ui',action='store_true');args=parser.parse_args()
    checker=ROOT/'build/HotTurkeyPeerCheck';native=ROOT/'build/HotTurkeyPolicyClientQA';agent=ROOT/'build/HotTurkeySessionAgentQA'
    requirements={role:json.loads(subprocess.check_output([str(checker),'--describe',str(binary)]))['requirement']
                  for role,binary in [('client',native),('session',agent)]}
    proof={};observed=[]
    with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-desktop-') as temporary:
        directory=Path(temporary);path=directory/'socket';store=Store(directory/'authority')
        store.state['settings']['statistics']=False
        authority=PolicyAuthority(store,os.getuid())
        execution=SystemExecution(authority,ROOT/'build/HotTurkeySystemAgentQA')
        sessions=TrustedSessions(authority,execution)
        def verify(connection):
            identity=peer_identity(connection)
            result=subprocess.run([str(checker),'--audit',base64.b64encode(identity.audit_token).decode(),
                '--roles',json.dumps(requirements)],capture_output=True,text=True,timeout=3)
            if result.returncode:raise PermissionError('Denied')
            value=json.loads(result.stdout)
            if value.get('ok') is not True or value.get('role') not in requirements:raise PermissionError('Denied')
            observed.append((identity.uid,value['role']))
            return dataclasses.replace(identity,role=value['role'])
        server=AuthorityServer(authority,path,verify,execution=execution,sessions=sessions,tick_interval=.2)
        server.bind();errors=[]
        def run_authority():
            try:server.serve_forever()
            except BaseException as error:errors.append(type(error).__name__)
        thread=threading.Thread(target=run_authority);thread.start()
        desktop=SystemDesktopService(directory/'desktop',client_factory=lambda:SystemClient(command=[str(native),str(path),str(os.getuid())]))
        web_thread=threading.Thread(target=desktop.run);web_thread.start()
        def call(route,data=None,session='',expected=200,token=None):
            request=urllib.request.Request(desktop.origin+'/api/'+route,data=None if data is None else json.dumps(data,ensure_ascii=False).encode(),
                headers={'Authorization':'Bearer '+(desktop.token if token is None else token),'Content-Type':'application/json','X-HotTurkey-Session':session})
            try:
                with urllib.request.urlopen(request,timeout=180) as response:code,value=response.status,json.load(response)
            except urllib.error.HTTPError as error:code,value=error.code,json.load(error)
            assert code==expected,(route,code,value)
            return value
        try:
            call('state',expected=401,token='wrong')
            assert call('health')['mode']=='system'
            state=call('state');assert state['mode']=='system' and not state['enforcement']['desktop_connected']
            value=subprocess.run([str(agent),str(path),str(os.getuid()),'3'],capture_output=True,timeout=25)
            assert value.returncode==0,value.stderr.decode()
            assert json.loads(value.stdout)['accepted']==3
            state=call('state');assert state['enforcement']['desktop_connected'],state['enforcement']
            proof['native_executor_and_session_status']='PASS'
            block=call('blocks/save',{'block':{'name':'Shared focus fixture','websites':['fixture.invalid'],'applications':['bundle:local.hotturkey.fixture.nonexistent'],'enabled':True}})
            lock=call('blocks/lock',{'id':block['id'],'type':'timer','until':state['now']+600})['lock']
            added=call('blocks/add-targets',{'id':block['id'],'websites':['追加.invalid']})
            assert added['lock']==lock and added['locked']
            call('blocks/delete',{'id':block['id']},expected=400)
            assert call('check',{'url':'https://fixture.invalid'})['blocked']
            proof['desktop_locked_additions_and_delete_guard']='PASS'
            call('settings',{'password':'desktop-fixture','protect_overview':True})
            assert call('state')['blocks']==[]
            token=call('auth',{'password':'desktop-fixture'})['session']
            assert call('state',session=token)['authenticated']
            assert not call('state')['authenticated']
            call('export',expected=400)
            assert call('export',session=token)['blocks'][0]['websites']==added['websites']
            assert call('statistics?since=0&kind=website',session=token)['totals']['seconds']==0
            proof['per_request_password_and_statistics']='PASS'
            call('settings',{'password':'','protect_overview':False},token)
            # Exercise the HTTP body's large-document path and actual native
            # paging in both directions; these targets cannot match user apps.
            targets=[f'https://large.invalid/{i}/'+'星'*360 for i in range(4000)]
            payload={'blocks':[{'name':'Large desktop import','websites':targets}]}
            assert len(json.dumps(payload,ensure_ascii=False).encode())>4*1024*1024
            assert call('import',payload)['count']==1
            exported=call('export')['blocks'];assert exported[-1]['websites']==targets and not exported[-1]['enabled']
            call('blocks/delete',{'id':exported[-1]['id']})
            proof['large_http_native_upload_and_readback']='PASS'
            assert not list((directory/'desktop').glob('*.sqlite3'))
            assert not (directory/'desktop/connection.json').exists()
            assert (desktop.directory/'connection.json').exists()
            assert {uid for uid,_ in observed}=={os.getuid()} and {'client','session'}<={role for _,role in observed}
            proof['separate_adapter_no_legacy_database']='PASS'
            if args.ui:
                (ROOT/'build/system-desktop-ui.json').write_text(json.dumps({'url':desktop.origin+'/#token='+desktop.token,'id':block['id'],'isolated':True}))
                print('Disposable protected desktop UI ready; press Enter to finish.',flush=True)
                input()
            server.stop();thread.join(timeout=15);assert not thread.is_alive()
            call('state',expected=400)
            assert call('health')['mode']=='system'
            assert not list((directory/'desktop').glob('*.sqlite3'))
            proof['authority_disconnect_never_falls_back']='PASS'
        finally:
            desktop.http.shutdown();web_thread.join(timeout=10)
            server.stop();thread.join(timeout=15);assert not thread.is_alive() and not web_thread.is_alive()
            assert not errors,errors
            assert not (desktop.directory/'connection.json').exists()
            store.db.close()
    proof.update(root_installed=False,installed_rules_changed=False,native_window_tested=False)
    (ROOT/'build/system-desktop-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof))


if __name__=='__main__':main()
