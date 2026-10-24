import copy
import tempfile
import unittest
from unittest.mock import patch

from hotturkey.authority import PolicyAuthority
from hotturkey.authority_server import PolicyRPC
from hotturkey.ipc import PeerIdentity
from hotturkey.model import PolicyError
from hotturkey.store import Store
from test_authority import Clock,account


class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=Store(self.temp.name);self.clock=Clock()
        self.authority=PolicyAuthority(self.store,501,resolve_user=account,wall=self.clock.wall,monotonic=self.clock.monotonic)
        self.rpc=PolicyRPC(self.authority);self.session=''
    def tearDown(self):self.store.db.close();self.temp.cleanup()
    def call(self,op,data=None,uid=501):return self.rpc.dispatch(PeerIdentity(uid,20,123,b'a'*32),{'op':op,'data':{} if data is None else data,'session':self.session})
    def block(self,**values):return self.call('save',{'block':{'name':'Rule','enabled':True,'websites':['example.invalid'],**values}})
    def test_all_mutations_require_controller_and_settings_authorization(self):
        self.block()
        for op,data in [('settings',{'theme':'dark'}),('duplicate',{'id':self.store.state['blocks'][0]['id']}),('import',{'blocks':[]}),('statistics-clear',{})]:
            with self.subTest(op=op),self.assertRaises(PolicyError):self.call(op,data,uid=502)
        self.call('settings',{'password':'secret','protect_overview':True})
        for op in ['export','statistics','statistics-export','categories','users','settings']:
            with self.subTest(op=op),self.assertRaises(PolicyError):self.call(op)
        self.session=self.call('authenticate',{'password':'secret'})['session']
        self.assertTrue(self.call('export')['blocks'])
    def test_settings_are_atomic_and_strictness_remains_locked(self):
        b=self.block();self.call('lock',{'id':b['id'],'type':'timer','until':self.clock.now+600})
        self.call('settings',{'theme':'dark','text_scale':150,'open_at_login':True})
        before=copy.deepcopy(self.store.state)
        for data in [{'statistics':False,'idle_seconds':-1},{'block_embeds':False},{'settings_password':'forged'},{'uid':0},{'password':True}]:
            with self.subTest(data=data),self.assertRaises(PolicyError):self.call('settings',data)
            self.assertEqual(self.store.state,before)
        self.assertEqual(self.store.state['settings']['text_scale'],150)
    def test_password_rotation_invalidates_existing_tokens(self):
        self.call('settings',{'password':'one'});self.session=self.call('authenticate',{'password':'one'})['session']
        old=self.session;self.call('settings',{'password':'two'})
        with self.assertRaises(PolicyError):self.call('settings',{'theme':'dark'})
        self.assertNotIn(old,self.authority.sessions)
        self.session=self.call('authenticate',{'password':'two'})['session'];self.call('settings',{'theme':'dark'})
        # Any password accepted by settings must also be accepted by login.
        long_password='星'*5000
        self.call('settings',{'password':long_password})
        self.session=self.call('authenticate',{'password':long_password})['session']
        self.assertTrue(self.call('snapshot')['authenticated'])
        with self.assertRaises(PolicyError):self.call('authenticate',{'password':long_password+'x'})
    def test_import_is_atomic_new_ids_unlocked_and_inert_by_default(self):
        b=self.block();before=copy.deepcopy(self.store.state)
        with self.assertRaises(PolicyError):self.call('import',{'blocks':[{'name':'Good'},{'name':''}]})
        self.assertEqual(self.store.state,before)
        incoming={**b,'name':'Imported','device':'shutdown','autostart':{'type':'once','at':self.clock.now-1}}
        result=self.call('import',{'blocks':[incoming]});self.assertEqual(result,{'count':1,'disabled_autostart':1})
        imported=self.store.state['blocks'][1];self.authority.engine(501).tick()
        self.assertNotEqual(imported['id'],b['id']);self.assertFalse(imported['enabled']);self.assertEqual(imported['lock'],{'type':'none'})
        self.assertEqual(imported['autostart'],{'type':'none'})
    def test_retaining_imported_device_autostart_requires_explicit_confirmation(self):
        incoming={'name':'Device','device':'shutdown','autostart':{'type':'once','at':self.clock.now+60}}
        with self.assertRaises(PolicyError):self.call('import',{'blocks':[incoming],'allow_autostart':True})
        self.assertEqual(self.store.state['blocks'],[])
        self.call('import',{'blocks':[incoming],'allow_autostart':True,'confirm_device':True})
        self.assertEqual(self.store.state['blocks'][0]['autostart'],incoming['autostart'])
    def test_duplicate_does_not_copy_lock_or_start_automatic_device_action(self):
        b=self.block(autostart={'type':'once','at':self.clock.now+60});self.call('lock',{'id':b['id'],'type':'password','password':'lock secret'})
        before=copy.deepcopy(self.store.state['blocks'][0]);duplicate=self.call('duplicate',{'id':b['id'],'name':'Copy'})
        self.assertFalse(duplicate['enabled']);self.assertFalse(duplicate['locked']);self.assertEqual(duplicate['autostart'],{'type':'none'})
        self.assertEqual(self.store.state['blocks'][0],before)
    def test_exports_do_not_expose_lock_hashes_and_obey_account_scope(self):
        a=self.block(users=['alice']);self.call('lock',{'id':a['id'],'type':'password','password':'lock secret'})
        self.call('save',{'block':{'name':'Bob only','users':['bob']}})
        exported=self.call('export');self.assertTrue(all('lock' not in b for b in exported['blocks']))
        self.assertEqual([b['name'] for b in self.call('export',uid=502)['blocks']],['Bob only'])
        self.call('settings',{'protect_overview':True})
        with self.assertRaises(PolicyError):self.call('export',uid=502)
    def test_statistics_force_noncontroller_identity_and_clear_preserves_charges(self):
        b=self.block();self.authority.engine(501).store.charge(self.clock.now,b['id'],20)
        self.store.event(self.clock.now,'alice','website','alice.invalid',seconds=5)
        self.store.event(self.clock.now,'bob','website','bob.invalid',seconds=7)
        value=self.call('statistics',{'user':'alice'},uid=502)
        self.assertEqual([row['target'] for row in value['items']],['bob.invalid'])
        self.assertEqual([row['user'] for row in self.call('statistics-export',uid=502)],['bob'])
        for data in [{'since':float('nan')},{'since':True},{'since':2,'until':1},{'kind':'all'},{'uid':501}]:
            with self.subTest(data=data),self.assertRaises(PolicyError):self.call('statistics',data)
        self.call('statistics-clear');self.assertEqual(self.call('statistics-export'),[])
        self.assertEqual(self.authority.engine(501).store.used(b['id'],0),20)
    def test_user_catalog_does_not_expose_other_accounts_to_noncontroller(self):
        with patch('hotturkey.authority_management.pwd.getpwall',return_value=[account(501),account(502)]):
            self.assertEqual([p['name'] for p in self.call('users')],['alice','bob'])
        self.assertEqual([p['name'] for p in self.call('users',uid=502)],['bob'])


if __name__=='__main__':unittest.main()
