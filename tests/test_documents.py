import base64
import copy
import dataclasses
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch

from hotturkey import documents
from hotturkey.authority import PolicyAuthority
from hotturkey.authority_server import PolicyRPC
from hotturkey.ipc import PeerIdentity
from hotturkey.model import PolicyError
from hotturkey.store import Store
from test_authority import Clock,account


class DocumentTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=Store(self.temp.name);self.clock=Clock()
        self.authority=PolicyAuthority(self.store,501,resolve_user=account,wall=self.clock.wall,monotonic=self.clock.monotonic)
        self.rpc=PolicyRPC(self.authority);self.peer=PeerIdentity(501,20,123,b'a'*32);self.session=''
        self.limits=patch.multiple(documents,INLINE_LIMIT=1024,CHUNK=256,MAX_DOCUMENT=8192,MAX_TOTAL=16384);self.limits.start()
    def tearDown(self):self.limits.stop();self.store.db.close();self.temp.cleanup()
    def call(self,op,data=None,peer=None):return self.rpc.dispatch(peer or self.peer,{'op':op,'data':{} if data is None else data,'session':self.session})
    def large_block(self):return {'name':'Large','websites':[f'https://fixture.invalid/{i}/'+'星'*30 for i in range(45)]}
    def upload(self,value):
        data=json.dumps(value,ensure_ascii=False).encode();start=self.call('document-start',{'operation':value['op'],'size':len(data),'sha256':hashlib.sha256(data).hexdigest()})
        return data,start['id']
    def append(self,token,data,offset=0):return self.call('document-chunk',{'id':token,'offset':offset,'data':base64.b64encode(data).decode()})
    def drain(self,page):
        meta=page[documents.MARKER];data=base64.b64decode(page['data'])
        while page['next'] is not None:
            page=self.call('document-read',{'id':meta['id'],'offset':page['next']});data+=base64.b64decode(page['data'])
        self.assertEqual(hashlib.sha256(data).hexdigest(),meta['sha256']);self.assertEqual(len(data),meta['size'])
        return json.loads(data)
    def test_unicode_snapshot_is_immutable_and_pages_reassemble_exactly(self):
        self.authority.manage(501,'save',{'block':self.large_block()})
        first=self.call('snapshot');self.assertIn(documents.MARKER,first)
        self.authority.manage(501,'save',{'block':{'name':'Later'}})
        value=self.drain(first);self.assertEqual([b['name'] for b in value['blocks']],['Large'])
        self.assertEqual(self.rpc.documents.records,{})
    def test_read_cursor_is_bound_to_uid_role_pid_and_kernel_incarnation(self):
        self.authority.manage(501,'save',{'block':self.large_block()});page=self.call('export');token=page[documents.MARKER]['id']
        for changes in [{'uid':502},{'role':'browser'},{'pid':124},{'audit_token':b'b'*32}]:
            with self.subTest(changes=changes),self.assertRaises(PolicyError):self.call('document-read',{'id':token,'offset':page['next']},dataclasses.replace(self.peer,**changes))
            with self.subTest(changes=changes),self.assertRaises(PolicyError):self.call('document-cancel',{'id':token},dataclasses.replace(self.peer,**changes))
        self.assertTrue(self.drain(page)['blocks'])
    def test_expiry_order_and_overview_changes_revoke_pages(self):
        self.authority.manage(501,'save',{'block':self.large_block()});page=self.call('snapshot');token=page[documents.MARKER]['id']
        with self.assertRaises(PolicyError):self.call('document-read',{'id':token,'offset':0})
        self.clock.advance(121)
        self.rpc.documents.pack(self.peer,'snapshot','',{})
        self.assertNotIn(token,self.rpc.documents.records)
        with self.assertRaises(PolicyError):self.call('document-read',{'id':token,'offset':page['next']})
        page=self.call('snapshot');token=page[documents.MARKER]['id']
        self.authority.store.state['settings'].update(protect_overview=True,settings_password='locked')
        with self.assertRaises(PolicyError):self.call('document-read',{'id':token,'offset':page['next']})
        self.assertNotIn(token,self.rpc.documents.records)
    def test_completed_upload_dispatches_once_and_never_partially_mutates(self):
        value={'op':'import','data':{'blocks':[self.large_block()]}}
        data,token=self.upload(value);before=copy.deepcopy(self.store.state)
        for offset in range(0,len(data),256):
            self.append(token,data[offset:offset+256],offset);self.assertEqual(self.store.state,before)
        self.assertEqual(self.call('document-finish',{'id':token})['count'],1)
        with self.assertRaises(PolicyError):self.call('document-finish',{'id':token})
        self.assertEqual(len(self.store.state['blocks']),1)
    def test_incomplete_hash_mismatch_and_changed_operation_never_commit(self):
        value={'op':'import','data':{'blocks':[{'name':'Not committed'}]}}
        for mode in ['missing','hash','operation']:
            with self.subTest(mode=mode):
                data,token=self.upload(value)
                if mode=='hash':data=data.replace(b'Not committed',b'Bad committed')
                if mode=='operation':self.rpc.documents.records[token]['operation']='save'
                if mode!='missing':self.append(token,data)
                with self.assertRaises(PolicyError):self.call('document-finish',{'id':token})
                self.assertEqual(self.store.state['blocks'],[])
    def test_upload_rejects_duplicate_json_identity_fields_and_nonfinite_values(self):
        for raw in [b'{"op":"import","op":"import","data":{"blocks":[]}}',b'{"op":"import","uid":0,"data":{"blocks":[]}}',b'{"op":"import","data":{"blocks":[],"value":NaN}}',b'{"op":"import","data":{"blocks":[{"name":"bad\\ud800"}]}}']:
            token=self.call('document-start',{'operation':'import','size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})['id'];self.append(token,raw)
            with self.subTest(raw=raw),self.assertRaises(PolicyError):self.call('document-finish',{'id':token})
        self.assertEqual(self.store.state['blocks'],[])
    def test_password_change_revokes_inflight_upload_and_read(self):
        self.call('settings',{'password':'one'});self.session=self.call('authenticate',{'password':'one'})['session']
        data,token=self.upload({'op':'import','session':self.session,'data':{'blocks':[{'name':'Not committed'}]}})
        self.call('settings',{'password':'two'})
        with self.assertRaises(PolicyError):self.append(token,data)
        self.assertNotIn(token,self.rpc.documents.records);self.assertEqual(self.store.state['blocks'],[])
    def test_memory_size_and_role_limits_do_not_change_policy(self):
        for changes in [{'role':'session'},{'uid':502}]:
            with self.assertRaises(PolicyError):self.call('document-start',{'operation':'import','size':1,'sha256':'a'*64},dataclasses.replace(self.peer,**changes))
        for size in [0,True,8193]:
            with self.assertRaises(PolicyError):self.call('document-start',{'operation':'import','size':size,'sha256':'a'*64})
        self.call('document-start',{'operation':'import','size':8192,'sha256':'a'*64});self.call('document-start',{'operation':'import','size':8192,'sha256':'a'*64})
        with self.assertRaises(PolicyError):self.call('document-start',{'operation':'import','size':1,'sha256':'a'*64})
        self.clock.advance(121);self.call('document-start',{'operation':'import','size':1,'sha256':'a'*64})
        self.assertEqual(self.store.state['blocks'],[])


if __name__=='__main__':unittest.main()
