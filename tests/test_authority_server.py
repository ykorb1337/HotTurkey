import copy
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from hotturkey.authority import PolicyAuthority
from hotturkey.authority_server import AuthorityServer, PolicyRPC, production_server
from hotturkey.engine import password_hash
from hotturkey.ipc import PeerIdentity, receive, send, trusted_directory
from hotturkey.model import PolicyError
from hotturkey.store import Store
from test_authority import Clock, account


class RPCTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-rpc-')
        self.store=Store(Path(self.temp.name)/'data')
        self.clock=Clock()
        self.authority=PolicyAuthority(self.store,501,resolve_user=account,wall=self.clock.wall,monotonic=self.clock.monotonic)
        self.rpc=PolicyRPC(self.authority)
        self.server=None;self.thread=None

    def tearDown(self):
        if self.server:
            self.server.stop();self.thread.join(timeout=10)
            self.assertFalse(self.thread.is_alive())
        self.store.db.close();self.temp.cleanup()

    def call(self,op,data=None,uid=501,session=''):
        return self.rpc.dispatch(PeerIdentity(uid,20,123,b'x'*32),{'op':op,'data':data or {},'session':session})

    def block(self):return self.call('save',{'block':{'name':'Locked','enabled':True,'websites':['example.com']}})

    def start(self,verifier=None,workers=8):
        self.server=AuthorityServer(self.authority,Path(self.temp.name)/'socket',verifier or (lambda _:PeerIdentity(501,20,123,b'x'*32)),workers=workers,tick_interval=.05)
        self.server.bind()
        self.thread=threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def wire(self,request):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.connect(str(self.server.path));send(client,request)
            return receive(client)

    def test_uid_role_and_filesystem_fields_are_rejected(self):
        for key in ['uid','pid','role','path','command']:
            with self.subTest(key=key),self.assertRaises(PolicyError):
                self.rpc.dispatch(PeerIdentity(502,20,123,b'x'*32),{'op':'snapshot',key:501})

    def test_noncontroller_cannot_modify_or_inspect_maintenance(self):
        block=self.block()
        for op,data in [('delete',{'id':block['id']}),('add-targets',{'id':block['id'],'websites':['new.example']}),('maintenance-status',{}),('authenticate',{'password':''})]:
            with self.subTest(op=op),self.assertRaises(PolicyError):self.call(op,data,uid=502)
        self.assertFalse(self.call('snapshot',uid=502)['can_manage'])

    def test_lock_allows_atomic_addition_but_not_replacement(self):
        ident=self.block()['id']
        self.call('lock',{'id':ident,'type':'timer','until':self.clock.now+3600})
        before=copy.deepcopy(self.store.state['blocks'][0])
        self.call('add-targets',{'id':ident,'websites':['new.example'],'applications':['com.test.fixture']})
        after=self.store.state['blocks'][0]
        self.assertEqual(after['websites'],['example.com','new.example'])
        self.assertEqual(after['lock'],before['lock'])
        for op,data in [('delete',{'id':ident}),('toggle',{'id':ident,'enabled':False}),('save',{'id':ident,'block':{'name':'Replacement'}})]:
            with self.subTest(op=op),self.assertRaises(PolicyError):self.call(op,data)
        self.assertTrue(self.call('check',{'url':'https://new.example'})['blocked'])
        self.assertFalse(self.call('maintenance-status')['can_uninstall'])

    def test_settings_authentication_and_session_isolation(self):
        ident=self.block()['id']
        self.store.state['settings'].update(settings_password=password_hash('secret'),protect_overview=True)
        self.assertEqual(self.call('snapshot')['blocks'],[])
        with self.assertRaises(PolicyError):self.call('delete',{'id':ident})
        session=self.call('authenticate',{'password':'secret'})['session']
        self.assertEqual(len(self.call('snapshot',session=session)['blocks']),1)
        with self.assertRaises(PolicyError):self.call('delete',{'id':ident},uid=502,session=session)
        self.clock.advance(900)
        with self.assertRaises(PolicyError):self.call('delete',{'id':ident},session=session)

    def test_sessions_have_bounded_memory(self):
        for _ in range(100):self.call('authenticate',{'password':''})
        self.assertEqual(len(self.authority.sessions),64)
        self.clock.advance(900);self.call('authenticate',{'password':''})
        self.assertEqual(len(self.authority.sessions),1)

    def test_checks_validate_channels_and_booleans(self):
        for data in [{'url':[]},{'channels':'forged'},{'channels':['x']*65},{'active':1},{'embedded':'false'},{'uid':501}]:
            with self.subTest(data=data),self.assertRaises(PolicyError):self.call('check',data)

    def test_unknown_operations_and_payload_types_do_not_mutate(self):
        for request in [{'op':'usage','data':{'seconds':999}},{'op':'execute','data':{}},{'op':'snapshot','data':[]},{'op':[]},{'op':'snapshot','session':[]}, {'op':'authenticate','data':{'password':[]}}]:
            with self.subTest(request=request),self.assertRaises(PolicyError):
                self.rpc.dispatch(PeerIdentity(501,20,123,b'x'*32),request)
        self.assertEqual(self.store.state['blocks'],[])

    def test_malformed_management_cannot_override_identity_or_lock_fields(self):
        ident=self.block()['id']
        for op,data in [('save',{'block':[]}),('save',{'block':None}),('toggle',{'id':ident,'enabled':'false'}),('add-targets',{'id':ident,'websites':['x.invalid'],'lock':{'type':'none'}}),('unlock',{'id':ident,'answer':[]}),('lock',{'id':ident,'type':[]})]:
            with self.subTest(op=op,data=data),self.assertRaises(PolicyError):self.call(op,data)

    def test_real_socket_roundtrip_and_rejection_recover(self):
        self.start()
        self.assertTrue(self.wire({'op':'snapshot'})['ok'])
        self.assertFalse(self.wire({'op':'delete','data':{'id':'missing'}})['ok'])
        self.assertFalse(self.wire({'op':'snapshot','uid':0})['ok'])
        self.assertTrue(self.wire({'op':'snapshot'})['ok'])

    def test_verifier_denial_is_before_policy_dispatch(self):
        def deny(_):raise PermissionError('secret path must not leak')
        self.start(deny)
        # A rejected peer receives no policy details, even without sending data.
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.connect(str(self.server.path));value=receive(client)
        self.assertFalse(value['ok']);self.assertNotIn('secret',json.dumps(value))
        self.assertEqual(self.authority.engines,{})

    def test_slow_connection_cannot_monopolize_all_workers(self):
        self.start(workers=2)
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as slow:
            slow.connect(str(self.server.path));slow.sendall(b'\x00')
            self.assertTrue(self.wire({'op':'snapshot'})['ok'])

    def test_malformed_frame_recovery_and_socket_cleanup(self):
        self.start()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.connect(str(self.server.path));client.sendall(b'\xff'*4)
            self.assertFalse(receive(client)['ok'])
        self.assertTrue(self.wire({'op':'snapshot'})['ok'])
        self.server.stop();self.thread.join(timeout=10)
        self.assertFalse(self.server.path.exists())

    def test_no_replacement_of_active_socket_regular_file_or_link(self):
        self.start()
        second=AuthorityServer(self.authority,self.server.path,lambda _:None)
        with self.assertRaises(RuntimeError):second.bind()
        for name in ['file','link']:
            path=Path(self.temp.name)/name
            if name=='link':path.symlink_to(self.server.path)
            else:path.write_text('keep')
            with self.subTest(name=name),self.assertRaises(PermissionError):
                AuthorityServer(self.authority,path,lambda _:None).bind()
            self.assertTrue(path.exists())

    def test_ticker_error_stops_authority_for_supervisor_recovery(self):
        self.authority.engine(501)
        def fail():raise RuntimeError('storage failed')
        self.authority.engine(501).tick=fail
        errors=[]
        server=AuthorityServer(self.authority,Path(self.temp.name)/'failure',lambda _:None,tick_interval=.02)
        server.bind()
        def run():
            try:server.serve_forever()
            except RuntimeError as exc:errors.append(str(exc))
        thread=threading.Thread(target=run);thread.start();thread.join(timeout=3)
        self.assertFalse(thread.is_alive());self.assertEqual(errors,['Policy clock failed'])
        self.assertFalse(server.path.exists())

    def test_production_entry_requires_root_and_directory_trust(self):
        with patch('hotturkey.authority_server.os.geteuid',return_value=501):
            with self.assertRaises(PermissionError):production_server()
        with self.assertRaises(PermissionError):trusted_directory(self.temp.name)
        self.assertEqual(trusted_directory('/usr/bin'),Path('/usr/bin'))


if __name__=='__main__':unittest.main()
