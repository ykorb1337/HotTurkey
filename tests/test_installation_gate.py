import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import contextlib

from hotturkey import authority_server as production
from hotturkey.authority import PolicyAuthority
from hotturkey.authority_server import AuthorityServer,PolicyRPC
from hotturkey.installation_gate import InstallationGate
from hotturkey.ipc import PeerIdentity
from hotturkey.model import PolicyError
from hotturkey.store import Store
from hotturkey.system_enforcement import SystemDecisions
from hotturkey.trusted_sessions import TrustedSessions
from test_authority import Clock,account


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/private/tmp');self.root=Path(self.temp.name);self.marker=self.root/'activation.json'
        self.clock=Clock();self.write('pending');self.gate=self.make_gate()
        self.store=Store(self.root/'data');self.authority=PolicyAuthority(self.store,501,resolve_user=account,wall=self.clock.wall,monotonic=self.clock.monotonic,installation_gate=self.gate)
        self.engine=self.authority.engine(501);self.rpc=PolicyRPC(self.authority)
        self.peer=PeerIdentity(501,20,123,b'x'*32)
    def tearDown(self):self.store.db.close();self.temp.cleanup()
    def write(self,phase_value,**values):
        value={'version':1,'transaction':'b'*32,'phase':phase_value,'controller_uid':501,'payload_sha256':'a'*64,**values}
        temporary=self.root/'new-marker';temporary.write_text(json.dumps(value));temporary.chmod(0o600);temporary.replace(self.marker)
    def make_gate(self,**values):return InstallationGate(self.marker,501,'a'*64,owner_uid=os.getuid(),anchor=self.root,clock=self.clock.monotonic,**values)
    def call(self,op,data=None,peer=None,**values):return self.rpc.dispatch(peer or self.peer,{'op':op,'data':{} if data is None else data,**values})
    def test_pending_marker_only_opens_for_the_same_committed_transaction(self):
        self.assertFalse(self.gate.is_open());self.write('committed');self.assertTrue(self.gate.is_open())
        self.write('pending')
        with self.assertRaises(PermissionError):self.gate.is_open()
        self.write('committed',transaction='c'*32)
        with self.assertRaises(PermissionError):self.gate.is_open()
    def test_payload_controller_version_and_unknown_fields_cannot_match(self):
        for uid in [True,0,499]:
            with self.assertRaises(ValueError):InstallationGate(self.marker,uid,'a'*64,owner_uid=os.getuid(),anchor=self.root)
        for values in [{'payload_sha256':'c'*64},{'controller_uid':502},{'version':True},{'extra':'ignored'},{'phase':'unknown'}]:
            self.write('pending',**values)
            with self.assertRaises(PermissionError):self.make_gate()
    def test_links_missing_marker_wrong_permissions_owner_and_fifo_are_rejected(self):
        self.marker.chmod(0o644)
        with self.assertRaises(PermissionError):self.make_gate()
        self.write('pending');target=self.root/'outside';self.marker.rename(target);self.marker.symlink_to(target)
        with self.assertRaises(OSError):self.make_gate()
        self.marker.unlink();os.mkfifo(self.marker)
        with self.assertRaises(PermissionError):self.make_gate()
        self.marker.unlink()
        with self.assertRaises(OSError):self.make_gate()
        self.write('pending')
        with self.assertRaises(PermissionError):InstallationGate(self.marker,501,'a'*64,owner_uid=os.getuid()+1,anchor=self.root)
    def test_health_is_scoped_minimal_and_does_not_require_settings_credentials(self):
        self.store.state['settings']['protect_overview']=True
        self.assertEqual(self.call('installation-health'),{'installation_pending':True,'executor_ready':False,'session_transport_fresh':False,
            'session_transport_uids':[],'installation_transaction':'b'*32,'payload_sha256':'a'*64})
        for peer in [PeerIdentity(502,20,124,b'y'*32),PeerIdentity(501,20,124,b'y'*32,'session'),PeerIdentity(501,20,124,b'y'*32,'browser')]:
            with self.assertRaises(PolicyError):self.call('installation-health',peer=peer)
        for values in [{'data':{'uid':502}},{'session':'copied-session'},{'path':'/tmp/marker'}]:
            request={'op':'installation-health','data':{},**values}
            with self.assertRaises(PolicyError):self.rpc.dispatch(self.peer,request)
    def test_every_client_and_document_operation_is_blocked_without_mutating_state(self):
        before=copy.deepcopy(self.store.state)
        requests=[('snapshot',{}),('save',{'block':{'name':'Denied'}}),('authenticate',{'password':'secret'}),('settings',{'theme':'dark'}),
                  ('document-start',{'operation':'import','size':1,'sha256':'a'*64}),('document-read',{'id':'x'}),('device-recover',{'word':'anything'}),('check',{'url':'https://example.invalid'})]
        for op,data in requests:
            with self.subTest(op=op),self.assertRaises(PolicyError):self.call(op,data)
        self.assertEqual(self.store.state,before);self.assertEqual(self.authority.sessions,{})
        self.write('committed');self.assertTrue(self.call('snapshot')['can_manage'])
    def test_pending_executor_keeps_kernel_inventory_passive_then_enforces_after_commit(self):
        self.engine.save_block({'name':'Application','enabled':True,'applications':['bundle:local.fixture']})
        before=copy.deepcopy(self.store.state);decisions=SystemDecisions(self.authority)
        app={'pid':991,'uid':501,'identity':'d'*64,'executable':'/tmp/fixture','path':'/tmp/fixture','bundle':'local.fixture','application':'fixture'}
        sample={'apps':[app],'front':{},'results':[]}
        self.assertEqual(decisions.consume(sample),{'kill':[]});self.assertEqual(self.store.state,before)
        self.write('committed');self.assertEqual(decisions.consume(sample)['kill'][0]['pid'],991)
    def test_pending_session_proves_transport_without_login_usage_or_desktop_mutation(self):
        class Inventory:
            def applications(self,uid):return []
        sessions=TrustedSessions(self.authority,Inventory(),session_identity=lambda _:1)
        peer=PeerIdentity(501,20,10,b'z'*32,'session')
        sample={'front_pid':0,'front_start_sec':0,'front_start_usec':0,'front_executable':'','on_console':True,'idle_seconds':0,'sample_seq':1,'event_seq':0}
        before=copy.deepcopy(self.store.state)
        self.assertEqual(sessions.consume(peer,sample),{'accepted':False,'installation_pending':True})
        self.assertEqual(self.store.state,before);self.assertEqual(sessions.leases,{})
        self.assertTrue(self.call('installation-health')['session_transport_fresh'])
        self.clock.advance(6);self.assertFalse(self.call('installation-health')['session_transport_fresh'])
        self.write('committed');self.assertTrue(sessions.consume(peer,sample)['accepted'])
        self.assertIn('501',self.store.state['trusted_sessions'])
    def test_clock_does_not_trigger_autostart_until_commit(self):
        block=self.engine.save_block({'name':'Later','enabled':False,'autostart':{'type':'once','at':self.clock.now+1}})
        self.clock.advance(2);server=AuthorityServer(self.authority,self.root/'unused',lambda _:None)
        with patch.object(server.stopping,'wait',side_effect=[False,True]):server._tick()
        self.assertFalse(self.engine.find(block['id'])['enabled'])
        self.write('committed')
        with patch.object(server.stopping,'wait',side_effect=[False,True]):server._tick()
        self.assertTrue(self.engine.find(block['id'])['enabled'])
    def test_device_countdown_starts_at_commit_not_during_passive_installation(self):
        self.engine.configure_device_recovery('fixture-escape')
        self.engine.save_block({'name':'Sleep','enabled':False,'device':'sleep','confirm_device':True,'autostart':{'type':'once','at':self.clock.now+1}})
        decisions=SystemDecisions(self.authority);sample={'apps':[],'front':{},'results':[],'console_uid':501,'device_result':None,'wake_seq':0}
        self.clock.advance(31);self.assertEqual(decisions.consume(sample),{'kill':[]})
        self.assertEqual(decisions.gate.contexts,{})
        self.write('committed');self.assertEqual(decisions.consume(sample),{'kill':[]})
        self.assertEqual(decisions.gate.status(501)['grace_remaining'],30)
    def test_production_startup_does_not_implicitly_migrate_legacy_data(self):
        install=self.root/'program';package=install/'project/hotturkey';package.mkdir(parents=True)
        (install/'payload.json').write_text('{"fixture":true}')
        config=install/'authority.json';config.write_text(json.dumps({'version':3,'controller_uid':501,
            'requirements':{role:'cdhash H"'+char*40+'"' for role,char in [('client','a'),('session','b'),('browser','c')]}}))
        self.store.state.pop('authority_version');self.store.state.pop('controller_uid');self.store.save()
        before=self.store.db.execute('SELECT value FROM state').fetchone()[0]
        with contextlib.ExitStack() as stack:
            for name,value in [('INSTALL',install),('CONFIG',config),('DATA',self.store.directory),('SOCKET',self.root/'socket'),('__file__',str(package/'authority_server.py'))]:stack.enter_context(patch.object(production,name,value))
            stack.enter_context(patch.object(production.os,'geteuid',return_value=0))
            stack.enter_context(patch.object(production,'trusted_directory',side_effect=Path))
            stack.enter_context(patch.object(production,'trusted_path',side_effect=Path))
            stack.enter_context(patch('hotturkey.installation_gate.InstallationGate'))
            stack.enter_context(patch('hotturkey.service_lease.ServiceLease'))
            migrate=stack.enter_context(patch.object(production,'PolicyAuthority',side_effect=AssertionError('Implicit migration')))
            with self.assertRaisesRegex(ValueError,'must be migrated'):production.production_server()
            migrate.assert_not_called()
        self.assertEqual(self.store.db.execute('SELECT value FROM state').fetchone()[0],before)


if __name__=='__main__':unittest.main()
