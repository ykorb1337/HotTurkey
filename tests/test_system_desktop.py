import copy
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from hotturkey.authority import PolicyAuthority
from hotturkey.authority_server import PolicyRPC
from hotturkey.ipc import PeerIdentity
from hotturkey.model import PolicyError
from hotturkey.store import Store
from hotturkey.system_desktop import SystemDesktopService


class DesktopTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.directory=Path(self.temporary.name)
        self.store=Store(self.directory/'authority')
        self.authority=PolicyAuthority(self.store,os.getuid())
        self.rpc=PolicyRPC(self.authority);self.requests=[];owner=self
        class Client:
            session=''
            def api(self,route,data=None):
                from hotturkey.system_client import ROUTES
                owner.requests.append((route,self.session,copy.deepcopy(data)))
                return owner.rpc.dispatch(PeerIdentity(os.getuid(),os.getgid(),1,b'x'*32),
                    {'op':ROUTES[route],'data':{} if data is None else data,'session':self.session})
        self.service=SystemDesktopService(self.directory,client_factory=Client)
        self.thread=threading.Thread(target=self.service.run);self.thread.start()
    def tearDown(self):
        self.service.http.shutdown();self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive());self.store.db.close();self.temporary.cleanup()
    def request(self,path,data=None,session='',token=True,origin=None,host=None):
        headers={'Content-Type':'application/json','X-HotTurkey-Session':session}
        if token:headers['Authorization']='Bearer '+self.service.token
        if origin:headers['Origin']=origin
        if host:headers['Host']=host
        request=urllib.request.Request(self.service.origin+'/api/'+path,
            data=json.dumps(data).encode() if data is not None else None,headers=headers)
        try:
            with urllib.request.urlopen(request,timeout=5) as response:return response.status,json.load(response)
        except urllib.error.HTTPError as error:return error.code,json.load(error)
    def call(self,path,data=None,session=''):
        code,value=self.request(path,data,session);self.assertEqual(code,200,value);return value
    def test_only_ephemeral_system_connection_and_no_legacy_database(self):
        self.assertFalse((self.directory/'hotturkey.sqlite3').exists())
        self.assertFalse((self.directory/'connection.json').exists())
        path=self.directory/'system-desktop/connection.json'
        self.assertEqual(json.loads(path.read_text())['mode'],'system')
        self.assertEqual(path.stat().st_mode&0o777,0o600)
        self.assertEqual(self.call('health'),{'ok':True,'mode':'system'})
        self.assertEqual(self.requests,[])
        with self.assertRaises(PolicyError):SystemDesktopService(self.directory)
    def test_loopback_token_origin_and_host_are_still_required(self):
        self.assertEqual(self.request('health',token=False)[0],401)
        self.assertEqual(self.request('state',origin='https://untrusted.invalid')[0],403)
        self.assertEqual(self.request('state',host='untrusted.invalid')[0],403)
        self.assertEqual(self.requests,[])
    def test_authority_owns_locks_and_additions_not_the_adapter(self):
        b=self.call('blocks/save',{'block':{'name':'Shared','websites':['one.invalid'],'enabled':True}})
        locked=self.call('blocks/lock',{'id':b['id'],'type':'timer','until':self.authority.engine(os.getuid()).now()+600})
        added=self.call('blocks/add-targets',{'id':b['id'],'websites':['two.invalid']})
        self.assertEqual(added['lock'],locked['lock']);self.assertEqual(added['websites'],['one.invalid','two.invalid'])
        self.assertEqual(self.request('blocks/delete',{'id':b['id']})[0],400)
        self.assertTrue(self.call('check',{'url':'https://two.invalid'})['blocked'])
        self.assertFalse(hasattr(self.service,'engine'));self.assertFalse(hasattr(self.service,'store'))
    def test_authentication_never_leaks_between_http_sessions(self):
        self.call('settings',{'password':'fixture','protect_overview':True})
        token=self.call('auth',{'password':'fixture'})['session']
        self.call('blocks/save',{'block':{'name':'Private'}},token)
        self.assertTrue(self.call('state',session=token)['authenticated'])
        self.assertFalse(self.call('state')['authenticated']);self.assertEqual(self.call('state')['blocks'],[])
        self.assertEqual(self.request('export')[0],400)
        self.assertEqual(len(self.call('export',session=token)['blocks']),1)
        self.call('settings',{'password':'new'},token)
        self.assertEqual(self.request('export',session=token)[0],400)
    def test_reports_actual_executor_and_session_liveness(self):
        class Status:
            def __init__(self,value):self.value=value
            def status(self,*args):return self.value
        self.rpc.execution=Status({'status':'running','last_sample_age':.1})
        self.rpc.sessions=Status({'status':'running','last_sample_age':.2,'on_console':True})
        state=self.call('state');self.assertTrue(state['enforcement']['desktop_connected']);self.assertEqual(state['mode'],'system')
        self.rpc.execution.value['last_sample_age']=10
        self.assertFalse(self.call('state')['enforcement']['desktop_connected'])
        self.rpc.execution.value['last_sample_age']=.1;self.rpc.sessions.value={'status':'missing'}
        self.assertIn('会话',self.call('state')['enforcement']['worker_error'])
        self.rpc.execution.value['last_sample_age']=True
        self.assertFalse(self.call('state')['enforcement']['desktop_connected'])
    def test_forbidden_browser_native_and_filesystem_operations_do_not_forward(self):
        for route,data in [('native',{'usage':{'seconds':60}}),('bridge',{'usage':[]}),('extension/add-site',{'id':'x'}),('state',{}),('settings',None),('document-start',{'operation':'save'}),('maintenance-status',{})]:
            with self.subTest(route=route):self.assertEqual(self.request(route,data)[0],400)
        self.assertEqual(self.requests,[])
    def test_statistics_query_conversion_and_bad_filters(self):
        value=self.call('statistics?since=0&until=200&kind=website&q=hello')
        self.assertEqual(value['totals']['seconds'],0)
        self.assertEqual(self.requests[-1][2],{'since':0.0,'until':200.0,'kind':'website','q':'hello'})
        before=len(self.requests)
        for query in ['since=nan','since=inf','since=no','since=1&since=2','uid=501']:
            self.assertEqual(self.request('statistics?'+query)[0],400)
        self.assertEqual(len(self.requests),before)
    def test_protected_failure_has_no_local_fallback_and_adapter_stays_reachable(self):
        def unavailable():raise PolicyError('Protected offline')
        self.service.client_factory=unavailable
        before=copy.deepcopy(self.store.state)
        self.assertEqual(self.request('blocks/save',{'block':{'name':'Never local'}})[0],400)
        self.assertEqual(self.store.state,before);self.assertFalse((self.directory/'hotturkey.sqlite3').exists())
        self.assertEqual(self.call('health')['mode'],'system')
    def test_local_app_catalog_requires_authenticated_manager(self):
        self.call('settings',{'password':'fixture'})
        with patch('hotturkey.platform_macos.applications',return_value=[{'value':'bundle:fixture.app','label':'Fixture'}]) as catalog:
            self.assertEqual(self.request('apps')[0],400);catalog.assert_not_called()
            session=self.call('auth',{'password':'fixture'})['session']
            self.assertEqual(self.call('apps',session=session)[0]['label'],'Fixture')
    def test_busy_adapter_does_not_spawn_more_native_clients(self):
        for _ in range(4):self.service.request_slots.acquire()
        try:self.assertEqual(self.request('state')[0],400);self.assertEqual(self.requests,[])
        finally:
            for _ in range(4):self.service.request_slots.release()
        self.assertEqual(self.call('state')['mode'],'system')


if __name__=='__main__':unittest.main()
