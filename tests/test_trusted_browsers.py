import copy
import dataclasses
import tempfile
import unittest

from hotturkey.authority import PolicyAuthority
from hotturkey.authority_server import PolicyRPC
from hotturkey.engine import password_hash
from hotturkey.ipc import PeerIdentity
from hotturkey.model import PolicyError
from hotturkey.store import Store
from hotturkey.trusted_browsers import TrustedBrowsers
from test_authority import Clock,account
from test_system_enforcement import process


class Inventory:
    def __init__(self):self.apps=[]
    def applications(self,uid):return [a for a in self.apps if a['uid']==uid]


class Sessions:
    def __init__(self):self.value={'pid':900001,'idle':0}
    def activity(self,uid):return self.value


class BrowserTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=Store(self.temp.name);self.clock=Clock()
        self.authority=PolicyAuthority(self.store,501,resolve_user=account,wall=self.clock.wall,monotonic=self.clock.monotonic)
        self.execution=Inventory();self.parent={**process(),'bundle':'com.microsoft.edgemac','start_sec':123,'start_usec':456}
        self.execution.apps=[self.parent];self.sessions=Sessions()
        self.browser=TrustedBrowsers(self.authority,self.execution,self.sessions)
        self.peer=PeerIdentity(501,20,12345,b'a'*32,'browser');self.sequence=0;self.context='c'*48
    def tearDown(self):self.store.db.close();self.temp.cleanup()
    def envelope(self,op,data=None,**extra):
        self.sequence+=1
        return {'browser':'Edge','parent_pid':900001,'parent_start_sec':123,'parent_start_usec':456,
                'channel':'a'*64,'sequence':self.sequence,'message':{'op':op,'data':data or {}},**extra}
    def call(self,op,data=None,**extra):return self.browser.consume(self.peer,self.envelope(op,data,**extra))
    def sync(self,usage=None,**values):
        if usage is None:usage=[{'tab':1,'url':'https://blocked.example','active':True}]
        return self.call('sync',{'browser':'forged-UA-name','context':self.context,'tabs':[1,2],'usage':usage,**values})
    def block(self,**values):
        saved=self.authority.manage(501,'save',{'block':{'name':'Web '+str(len(self.store.state['blocks'])),'enabled':True,
            'websites':['blocked.example'],'break':{'type':'allowance','allowance_minutes':1},**values}})
        return self.authority.engine(501).find(saved['id'])
    def used(self,b,uid=501):return self.authority.engine(uid).store.used(b['id'],0)
    def test_roles_cannot_cross_browser_session_and_management_interfaces(self):
        rpc=PolicyRPC(self.authority,self.execution,browsers=self.browser)
        for op in ['snapshot','authenticate','save','session-sample','break']:
            with self.assertRaises(PolicyError):rpc.dispatch(self.peer,{'op':op})
        for role in ['client','session','unknown']:
            with self.assertRaises(PolicyError):rpc.dispatch(dataclasses.replace(self.peer,role=role),{'op':'browser-request','data':self.envelope('sync')})
        with self.assertRaises(PolicyError):self.call('delete',{'id':'x'})
    def test_kernel_parent_uid_bundle_and_start_are_required(self):
        self.block()
        for extra in [{'parent_pid':900002},{'parent_start_sec':124},{'parent_start_usec':457},{'browser':'Firefox'},{'parent_pid':True}]:
            with self.subTest(extra=extra),self.assertRaises(PolicyError):self.call('check',{'url':'https://blocked.example'},**extra)
        self.parent['uid']=502
        with self.assertRaises(PolicyError):self.call('sync',{})
        self.assertEqual(self.browser.leases,{})
    def test_sync_uses_attested_browser_name_and_server_clock(self):
        b=self.block();self.sync(incognito_allowed=True,files_allowed=False)
        self.clock.advance(5);result=self.sync()
        self.assertEqual(self.used(b),5)
        self.assertEqual(set(self.authority.engine(501).heartbeats),{'Edge'})
        self.assertEqual(result['blocks'][0]['id'],b['id'])
        self.assertTrue(result['tab_unblock_supported'])
    def test_native_foreground_idle_and_missing_activity_override_claimed_active(self):
        b=self.block();self.sync()
        self.sessions.value={'pid':900002,'idle':0};self.clock.advance(5);self.sync();self.assertEqual(self.used(b),0)
        self.sessions.value={'pid':900001,'idle':1000};self.clock.advance(5);self.sync();self.assertEqual(self.used(b),0)
        self.sessions.value=None;self.clock.advance(5);self.sync();self.assertEqual(self.used(b),0)
        self.sessions.value={'pid':900001,'idle':0};self.clock.advance(5);self.sync();self.assertEqual(self.used(b),0)
        self.clock.advance(5);self.sync();self.assertEqual(self.used(b),5)
    def test_audible_tab_can_count_idle_time_only_with_verified_console(self):
        b=self.block();self.sessions.value={'pid':900001,'idle':1000}
        usage=[{'tab':1,'url':'https://blocked.example','active':True,'playing':True}]
        self.sync(usage);self.clock.advance(5);self.sync(usage);self.assertEqual(self.used(b),5)
        self.sessions.value=None;self.clock.advance(5);self.sync(usage);self.assertEqual(self.used(b),5)
    def test_gaps_and_wall_clock_jumps_cannot_inflate_usage(self):
        b=self.block();self.sync();self.clock.advance(30);self.sync();self.assertEqual(self.used(b),0)
        self.clock.now+=3600;self.clock.mono+=1;self.sync();self.assertEqual(self.used(b),1)
    def test_replay_channel_takeover_and_malformed_batches_are_atomic(self):
        data=self.envelope('sync',{'context':self.context,'tabs':[1],'usage':[]});self.browser.consume(self.peer,data)
        before=copy.deepcopy(self.store.state)
        with self.assertRaises(PolicyError):self.browser.consume(self.peer,data)
        with self.assertRaises(PolicyError):self.browser.consume(dataclasses.replace(self.peer,pid=9),self.envelope('check'))
        for values in [{'usage':[{'tab':1,'url':'https://a'}, {'tab':2,'url':'x','active':1}]},
                       {'usage':[{'tab':1,'url':'https://a','seconds':999}]}, {'tabs':[True]}, {'context':'invalid'},
                       {'usage':[{'tab':1,'url':'https://a','idle':float('nan')}]}, {'usage':[{'tab':1,'url':'a'},{'tab':1,'url':'b'}]}]:
            with self.subTest(values=values),self.assertRaises(PolicyError):self.sync(**values)
            self.assertEqual(self.store.state,before)
    def test_tab_grants_are_account_and_browser_scoped_and_keep_the_lock(self):
        b=self.block(**{'break':{'type':'none'}});self.authority.manage(501,'lock',{'id':b['id'],'type':'text','custom_text':'fixture'})
        data={'id':b['id'],'context':self.context,'tab':1,'url':'https://blocked.example','answer':'fixture'}
        self.assertTrue(self.call('tab-unblock',data)['granted'])
        check={'url':'https://blocked.example','context':self.context,'tab':1}
        self.assertFalse(self.call('check',check)['blocked'])
        self.assertTrue(self.call('check',{**check,'tab':2})['blocked'])
        self.assertTrue(self.authority.engine(501).locked(b))
        self.call('tab-close',{'context':self.context,'tab':1});self.assertTrue(self.call('check',check)['blocked'])
    def test_popup_addition_respects_password_and_controller_without_session_tokens(self):
        b=self.block();self.authority.manage(501,'lock',{'id':b['id'],'type':'timer','until':self.clock.now+600})
        lock=copy.deepcopy(b['lock']);self.store.state['settings']['settings_password']=password_hash('secret')
        self.assertTrue(self.call('add-site-options')['authentication_required'])
        with self.assertRaises(PolicyError):self.call('add-site',{'id':b['id'],'url':'https://new.example','password':'wrong'})
        self.clock.advance(3)
        result=self.call('add-site',{'id':b['id'],'url':'https://new.example/private?token=secret','password':'secret'})
        self.assertTrue(result['added']);self.assertEqual(b['lock'],lock);self.assertEqual(self.authority.sessions,{})
        self.assertIn('new.example',b['websites']);self.assertNotIn('secret',str(b['websites']))
        self.peer=dataclasses.replace(self.peer,uid=502);self.parent['uid']=502
        with self.assertRaises(PolicyError):self.call('add-site-options',{'password':'secret'})
    def test_sync_filters_rules_for_other_accounts(self):
        a=self.block(users=['alice']);b=self.block(users=['bob'])
        result=self.sync();self.assertEqual([v['id'] for v in result['blocks']],[a['id']])
        self.assertNotIn(b['id'],[v['id'] for v in result['blocks']])
    def test_strict_background_only_charges_matching_targets_and_deduplicates_tabs(self):
        self.store.state['settings']['strict_usage']=True
        b=self.block();reward=self.block(websites=['other.example'],**{'break':{'type':'reward','work_minutes':1,'break_minutes':1}})
        usage=[{'tab':1,'url':'https://blocked.example','active':False},{'tab':2,'url':'https://blocked.example','active':False}]
        self.sync(usage);self.clock.advance(5);self.sync(usage)
        self.assertEqual(self.used(b),5);self.assertEqual(self.authority.engine(501).runtime(reward).get('focus_seconds',0),0)
        self.assertIn(b['id'],self.sessions.external_targets(501))
    def test_strict_background_target_cannot_earn_focus_from_a_clean_front_tab(self):
        self.store.state['settings']['strict_usage']=True
        b=self.block(**{'break':{'type':'reward','work_minutes':1,'break_minutes':1}})
        usage=[{'tab':1,'url':'https://clean.example','active':True},{'tab':2,'url':'https://blocked.example','active':False}]
        self.sync(usage);self.clock.advance(5);self.sync(usage)
        self.assertEqual(self.authority.engine(501).runtime(b).get('focus_seconds',0),0)
    def test_host_leases_and_usage_sources_are_bounded(self):
        for i in range(128):self.call('check',{'url':'https://a'},channel=f'{i:064x}')
        with self.assertRaises(PolicyError):self.call('check',channel=f'{128:064x}')
        self.clock.advance(601);self.assertFalse(self.call('check',{'url':'https://a'})['blocked'])
    def test_targeted_browser_application_does_not_earn_focus_from_clean_url(self):
        b=self.block(applications=['Game'],websites=[],**{'break':{'type':'reward','work_minutes':1,'break_minutes':1}})
        usage=[{'tab':1,'url':'https://clean.example','active':True}]
        self.sync(usage);self.clock.advance(5);self.sync(usage)
        self.assertEqual(self.authority.engine(501).runtime(b).get('focus_seconds',0),0)
    def test_expired_tab_sources_are_removed_from_engine_memory(self):
        self.block();self.sync();self.clock.advance(5);self.sync()
        engine=self.authority.engine(501);self.assertTrue(any(k.startswith('protected-browser:') for k in engine.sources))
        self.clock.advance(11);self.context='d'*48;self.sync([])
        self.assertFalse(any(k.startswith('protected-browser:') for k in engine.sources))


if __name__=='__main__':unittest.main()
