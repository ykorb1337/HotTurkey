import copy
import json
import os
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from pathlib import Path
from hotturkey.server import Service

class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.service=Service(self.temp.name);self.thread=threading.Thread(target=self.service.http.serve_forever,daemon=True);self.thread.start();self.session=""
    def tearDown(self):self.service.http.shutdown();self.service.http.server_close();self.service.store.db.close();self.service.singleton.close();self.temp.cleanup()
    def request(self,path,data=None,token=True,origin=None,host=None):
        headers={"Content-Type":"application/json","X-HotTurkey-Session":self.session}
        if token:headers["Authorization"]="Bearer "+self.service.token
        if origin:headers["Origin"]=origin
        if host:headers["Host"]=host
        req=urllib.request.Request(self.service.origin+path,data=json.dumps(data).encode() if data is not None else None,headers=headers)
        try:
            with urllib.request.urlopen(req,timeout=5) as response:return response.status,json.load(response)
        except urllib.error.HTTPError as error:return error.code,json.load(error)
    def call(self,path,data=None):
        code,value=self.request('/api/'+path,data);self.assertEqual(code,200,value);return value
    def block(self,**kw):return self.call('blocks/save',{'block':{'name':'Work','websites':['example.com'],'enabled':True,**kw}})
    def test_no_token_rejected(self):self.assertEqual(self.request('/api/state',token=False)[0],401)
    def test_single_instance(self):
        from hotturkey.model import PolicyError
        with self.assertRaises(PolicyError):Service(self.temp.name)
    def test_foreign_origin_rejected(self):self.assertEqual(self.request('/api/state',origin='https://evil.com')[0],403)
    def test_dns_rebinding_host_rejected(self):self.assertEqual(self.request('/api/state',host='evil.com')[0],403)
    def test_full_crud(self):
        b=self.block();self.assertTrue(self.call('check',{'url':'https://example.com'})['blocked']);self.call('blocks/toggle',{'id':b['id'],'enabled':False});self.assertFalse(self.call('check',{'url':'https://example.com'})['blocked']);self.call('blocks/delete',{'id':b['id']});self.assertEqual(self.call('state')['blocks'],[])
    def test_export_import_disables(self):
        b=self.block();value=self.call('export');self.call('blocks/delete',{'id':b['id']});self.call('import',value);self.assertFalse(self.call('state')['blocks'][0]['enabled'])
    def test_import_atomic(self):
        code,_=self.request('/api/import',{'blocks':[{'name':'Good'},{'name':''}]});self.assertEqual(code,400);self.assertEqual(self.call('state')['blocks'],[])
    def test_lock_mutation_rejected_and_extension_break_available(self):
        b=self.block(**{'break':{'type':'text','custom_text':'focus'}});self.call('blocks/lock',{'id':b['id'],'type':'timer','until':self.service.engine.now()+60});self.assertEqual(self.request('/api/blocks/delete',{'id':b['id']})[0],400);self.assertEqual(self.call('extension/break',{'id':b['id']})['challenge'],'focus')
    def test_settings_password(self):
        self.call('settings',{'password':'secret'});self.assertEqual(self.request('/api/blocks/save',{'block':{'name':'No'}})[0],400);result=self.call('auth',{'password':'secret'});self.session=result['session'];self.block();self.assertTrue(self.call('state')['authenticated'])
    def test_pomodoro_reset_and_text_extension_require_management_auth(self):
        b=self.block(**{'break':{'type':'pomodoro'}})
        old=self.call('blocks/lock',{'id':b['id'],'type':'text','length':10})['lock']['text']
        self.call('settings',{'password':'secret'})
        for path,data in [('blocks/reset-pomodoro',{'id':b['id']}),('blocks/lock',{'id':b['id'],'type':'text','length':20})]:
            self.assertEqual(self.request('/api/'+path,data)[0],400)
        self.session=self.call('auth',{'password':'secret'})['session']
        reset=self.call('blocks/reset-pomodoro',{'id':b['id']});self.assertTrue(reset['locked']);self.assertTrue(reset['blocking'])
        extended=self.call('blocks/lock',{'id':b['id'],'type':'text','length':20})
        self.assertTrue(extended['lock']['text'].startswith(old));self.assertEqual(len(extended['lock']['text']),20)
    def test_locked_additions_enforced_and_cannot_change_other_fields(self):
        b=self.block();lock=self.call('blocks/lock',{'id':b['id'],'type':'timer','until':self.service.engine.now()+60})['lock']
        result=self.call('blocks/add-targets',{'id':b['id'],'websites':['new.example'],'applications':['bundle:new.app'],'exceptions':['*.*'],'enabled':False,'lock':{'type':'none'}})
        self.assertEqual(result['websites'],['example.com','new.example']);self.assertEqual(result['applications'],['bundle:new.app'])
        self.assertEqual(result['exceptions'],b['exceptions']);self.assertEqual(result['lock'],lock);self.assertTrue(result['enabled']);self.assertTrue(result['locked'])
        self.assertTrue(self.call('check',{'url':'https://new.example'})['blocked'])
        self.assertEqual(self.request('/api/blocks/save',{'id':b['id'],'block':{**result,'websites':['new.example']}})[0],400)
        self.assertEqual(self.call('bridge',{'browser':'Edge','usage':[]})['blocks'][0]['websites'],result['websites'])
    def test_additions_require_management_authentication(self):
        b=self.block();self.call('settings',{'password':'secret'})
        self.assertEqual(self.request('/api/blocks/add-targets',{'id':b['id'],'websites':['denied.example']})[0],400)
        self.assertEqual(self.service.engine.find(b['id'])['websites'],['example.com'])
        self.session=self.call('auth',{'password':'secret'})['session']
        self.assertIn('allowed.example',self.call('blocks/add-targets',{'id':b['id'],'websites':['allowed.example']})['websites'])
    def test_overview_privacy(self):
        self.block();self.call('settings',{'password':'secret','protect_overview':True});self.assertEqual(self.call('state')['blocks'],[])
    def test_strictness_protected(self):
        b=self.block();self.call('blocks/lock',{'id':b['id'],'type':'timer','until':self.service.engine.now()+60});self.assertEqual(self.request('/api/settings',{'block_embeds':False})[0],400);self.assertTrue(self.call('state')['settings']['block_embeds'])
    def test_settings_update_atomic(self):
        self.assertEqual(self.request('/api/settings',{'statistics':False,'extension_grace':-1})[0],400);self.assertTrue(self.call('state')['settings']['statistics'])
    def test_unknown_settings_ignored(self):self.call('settings',{'settings_password':'injected'});self.assertFalse(self.call('state')['settings']['settings_password'])
    def test_native_bridge_sync(self):
        self.block();value=self.call('bridge',{'browser':'Edge','incognito_allowed':True,'files_allowed':False,'usage':[]});self.assertEqual(len(value['blocks']),1);self.assertTrue(value['tab_unblock_supported']);self.assertTrue(self.call('state')['extensions']['Edge']['incognito'])
    def test_tab_grant_does_not_disable_rule_or_other_tab(self):
        b=self.block();scope={'context':'a'*48,'tab':7}
        value=self.call('extension/tab-unblock',{**scope,'id':b['id'],'minutes':5,'url':'https://example.com'})
        self.assertTrue(value['granted'])
        self.assertFalse(self.call('check',{**scope,'url':'https://example.com'})['blocked'])
        self.assertTrue(self.call('check',{**scope,'tab':8,'url':'https://example.com'})['blocked'])
        self.assertTrue(self.call('check',{'url':'https://example.com','exemptions':[b['id']]})['blocked'])
        self.assertTrue(self.call('state')['blocks'][0]['blocking'])
    def test_tab_grant_remains_separate_from_settings_authentication(self):
        b=self.block();self.call('settings',{'password':'manager secret'})
        self.assertTrue(self.call('extension/tab-unblock',{'context':'a'*48,'tab':7,'id':b['id'],'url':'https://example.com'})['granted'])
        self.assertEqual(self.request('/api/blocks/delete',{'id':b['id']})[0],400)
    def test_bridge_returns_only_current_instance_tab_grants(self):
        b=self.block();scope={'context':'a'*48,'tab':7}
        self.call('extension/tab-unblock',{**scope,'id':b['id'],'url':'https://example.com'})
        value=self.call('bridge',{'browser':'Edge','context':scope['context'],'tabs':[7,8],'usage':[]})
        self.assertEqual([g['tab'] for g in value['tab_grants']],[7])
        self.assertEqual(value['tab_grants'][0]['revision'],value['blocks'][0]['tab_revision'])
        self.assertEqual(self.call('bridge',{'browser':'Edge','context':'b'*48,'tabs':[7],'usage':[]})['tab_grants'],[])
        self.call('extension/tab-close',scope)
        self.assertTrue(self.call('check',{**scope,'url':'https://example.com'})['blocked'])
    def test_tab_grant_still_obeys_other_matching_rules(self):
        b=self.block();other=self.call('blocks/save',{'block':{'name':'Other','enabled':True,'websites':['example.com']}})
        scope={'context':'a'*48,'tab':7}
        self.call('extension/tab-unblock',{**scope,'id':b['id'],'url':'https://example.com'})
        self.assertEqual([b['id'] for b in self.call('check',{**scope,'url':'https://example.com'})['blocks']],[other['id']])
    def test_locked_tab_grant_requires_validation_and_is_revoked_on_append(self):
        b=self.block();self.call('blocks/lock',{'id':b['id'],'type':'text','custom_text':'focus'})
        data={'context':'a'*48,'tab':7,'id':b['id'],'url':'https://example.com'}
        self.assertEqual(self.call('extension/tab-unblock',data)['challenge'],'focus')
        self.assertEqual(self.request('/api/extension/tab-unblock',{**data,'answer':'wrong'})[0],400)
        self.assertTrue(self.call('extension/tab-unblock',{**data,'answer':'focus'})['granted'])
        self.call('blocks/add-targets',{'id':b['id'],'websites':['new.example']})
        self.assertTrue(self.call('check',data)['blocked']);self.assertTrue(self.call('state')['blocks'][0]['locked'])
    def test_native_host_preserves_tab_validation_errors(self):
        b=self.block();self.call('blocks/lock',{'id':b['id'],'type':'timer','until':self.service.engine.now()+60})
        env={**os.environ,'HOTTURKEY_DATA':self.temp.name,'PYTHONDONTWRITEBYTECODE':'1'}
        value={'op':'tab-unblock','data':{'context':'a'*48,'tab':7,'id':b['id'],'url':'https://example.com'}}
        payload=json.dumps(value).encode();process=subprocess.run([sys.executable,'-m','hotturkey.native_host'],input=struct.pack('<I',len(payload))+payload,capture_output=True,env=env,check=True)
        length=struct.unpack('<I',process.stdout[:4])[0];result=json.loads(process.stdout[4:4+length])
        self.assertTrue(result['policy']);self.assertIn('锁定条件',result['error'])
    def test_closed_internal_tab_reports_stats_and_bounded_notifications(self):
        b=self.block(websites=['edge://settings'])
        self.assertFalse(self.call('check',{'url':'edge://extensions/','record':False})['blocked'])
        self.assertFalse(self.call('extension/closed-tab',{'url':'edge://extensions/'})['blocked'])
        self.assertEqual(self.service.browser_notices,[])
        self.assertTrue(self.call('extension/closed-tab',{'url':'edge://settings/privacy'})['blocked'])
        self.assertEqual(len(self.service.browser_notices),1)
        self.call('extension/closed-tab',{'url':'edge://settings/privacy'})
        self.assertEqual(len(self.service.browser_notices),1)
        result=self.call('statistics?block='+b['id'])
        self.assertEqual(result['totals']['blocked'],1)
        self.assertEqual(self.request('/api/extension/closed-tab',{'url':'https://example.com'})[0],400)
    def test_closed_tab_reporting_respects_notification_and_private_statistics_settings(self):
        b=self.block(websites=['about:preferences'])
        self.call('settings',{'notifications':False,'incognito_statistics':False})
        self.assertTrue(self.call('extension/closed-tab',{'url':'about:preferences','incognito':True})['blocked'])
        self.assertEqual(self.service.browser_notices,[])
        self.assertEqual(self.call('statistics?block='+b['id'])['totals']['blocked'],0)
    def test_statistics_deletion_preserves_charges(self):
        self.service.store.charge(self.service.engine.now(),'a',30);self.call('statistics/clear',{});self.assertEqual(self.service.store.used('a',0),30)
    def test_duplicate_disabled(self):
        b=self.block();other=self.call('blocks/duplicate',{'id':b['id']});self.assertFalse(other['enabled']);self.assertEqual(other['lock'],{'type':'none'})
    def test_native_host_framing_and_privilege_boundary(self):
        block=self.block(websites=['edge://settings'])
        env={**os.environ,'HOTTURKEY_DATA':self.temp.name,'PYTHONDONTWRITEBYTECODE':'1'}
        messages=[{'op':'check','data':{'url':'https://example.com'}},{'op':'delete','data':{}},{'op':'blocks/add-targets','data':{'id':'any','websites':['injected.example']}},{'op':'closed-tab','data':{'url':'edge://settings/privacy'}}]
        wire=b''.join(struct.pack('<I',len(blob))+blob for blob in [json.dumps(m).encode() for m in messages])
        process=subprocess.run([sys.executable,'-m','hotturkey.native_host'],input=wire,capture_output=True,env=env,check=True)
        offset=0;results=[]
        while offset<len(process.stdout):
            size=struct.unpack('<I',process.stdout[offset:offset+4])[0];offset+=4;results.append(json.loads(process.stdout[offset:offset+size]));offset+=size
        self.assertFalse(results[0]['blocked']);self.assertIn('error',results[1]);self.assertIn('error',results[2]);self.assertTrue(results[3]['blocked']);self.assertEqual(len(results),4)
        self.assertEqual(self.call('statistics?block='+block['id'])['totals']['blocked'],1)
        self.assertEqual(self.service.engine.find(block['id'])['websites'],['edge://settings'])
    def test_connection_private(self):self.assertEqual((Path(self.temp.name)/'connection.json').stat().st_mode&0o777,0o600)
    def test_static_resources_and_csp(self):
        with urllib.request.urlopen(self.service.origin+'/') as response:self.assertIn("script-src 'self'",response.headers['Content-Security-Policy']);self.assertIn(b'HotTurkey',response.read())
        self.assertEqual(self.request('/hotturkey/store.py')[0],404)

if __name__=='__main__':unittest.main()
