import copy
import dataclasses
import tempfile
import unittest

from hotturkey.authority import PolicyAuthority
from hotturkey.authority_server import PolicyRPC
from hotturkey.ipc import PeerIdentity
from hotturkey.model import PolicyError
from hotturkey.store import Store
from hotturkey.trusted_sessions import TrustedSessions
from test_authority import Clock,account
from test_system_enforcement import process


class Inventory:
    def __init__(self):self.apps=[]
    def applications(self,uid):return [a for a in self.apps if a['uid']==uid]


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=Store(self.temp.name);self.clock=Clock()
        self.authority=PolicyAuthority(self.store,501,resolve_user=account,wall=self.clock.wall,monotonic=self.clock.monotonic)
        self.execution=Inventory();self.app={**process(),'start_sec':123,'start_usec':456}
        self.execution.apps=[self.app]
        self.sessions=TrustedSessions(self.authority,self.execution,session_identity=lambda _:10)
        self.peer=PeerIdentity(501,20,1234,b'a'*32,'session');self.seq=0
    def tearDown(self):self.store.db.close();self.temp.cleanup()
    def sample(self,**values):
        self.seq+=1
        return {'front_pid':self.app['pid'],'front_start_sec':123,'front_start_usec':456,
                'front_executable':self.app['executable'],'idle_seconds':0,'on_console':True,
                'sample_seq':self.seq,'event_seq':0,**values}
    def consume(self,**values):return self.sessions.consume(self.peer,self.sample(**values))
    def block(self,**values):
        saved=self.authority.manage(501,'save',{'block':{'name':'Usage '+str(len(self.store.state['blocks'])),'enabled':True,'applications':['Game'],
            'break':{'type':'allowance','allowance_minutes':1},**values}})
        return self.authority.engine(501).find(saved['id'])
    def used(self,b,uid=501):return self.authority.engine(uid).store.used(b['id'],0)
    def test_only_attested_session_role_can_sample_and_cannot_manage(self):
        rpc=PolicyRPC(self.authority,self.execution,self.sessions)
        for role in ['client','unknown']:
            with self.assertRaises(PolicyError):rpc.dispatch(dataclasses.replace(self.peer,role=role),{'op':'session-sample','data':self.sample()})
        for op in ['snapshot','authenticate','save','break','check','maintenance-status']:
            with self.assertRaises(PolicyError):rpc.dispatch(self.peer,{'op':op})
        with self.assertRaises(PolicyError):rpc.dispatch(self.peer,{'op':'session-sample','data':self.sample(),'session':'manager'})
        self.assertTrue(rpc.dispatch(self.peer,{'op':'session-sample','data':self.sample()})['accepted'])
    def test_root_elapsed_time_charges_only_the_owned_verified_foreground(self):
        b=self.block();self.consume();self.assertEqual(self.used(b),0)
        self.clock.advance(2);self.consume();self.assertEqual(self.used(b),2)
        self.clock.advance(1);self.consume(front_start_usec=457);self.assertEqual(self.used(b),2)
        self.clock.advance(1);self.consume();self.assertEqual(self.used(b),2)
        self.clock.advance(1);self.consume();self.assertEqual(self.used(b),3)
    def test_stale_samples_idle_console_and_missing_inventory_never_fill_gaps(self):
        b=self.block();self.consume()
        for fields in [{'idle_seconds':86400},{'on_console':False}]:
            self.clock.advance(9);self.consume(**fields)
            self.clock.advance(1);self.consume()
        self.assertEqual(self.used(b),0)
        self.clock.advance(9);self.consume();self.assertEqual(self.used(b),0)
        self.execution.apps=[];self.clock.advance(1);self.consume();self.assertEqual(self.used(b),0)
        self.assertEqual(self.sessions.status(501)['status'],'running')
        self.clock.advance(4);self.assertEqual(self.sessions.status(501)['status'],'stale')
    def test_wrong_uid_path_or_generation_does_not_charge(self):
        b=self.block();self.consume()
        for fields in [{'front_executable':'/tmp/forged'},{'front_start_sec':999}]:
            self.clock.advance(1);self.consume(**fields)
        self.execution.apps=[{**self.app,'uid':502}];self.clock.advance(1);self.consume()
        self.assertEqual(self.used(b),0)
    def test_duplicate_reversed_and_concurrent_agent_samples_rejected(self):
        b=self.block();data=self.sample();self.sessions.consume(self.peer,data)
        before=copy.deepcopy(self.store.state)
        with self.assertRaises(PolicyError):self.sessions.consume(self.peer,data)
        with self.assertRaises(PolicyError):self.sessions.consume(dataclasses.replace(self.peer,pid=5678),self.sample())
        self.assertEqual(self.store.state,before)
        self.clock.advance(6);self.peer=dataclasses.replace(self.peer,pid=5678,audit_token=b'b'*32)
        self.consume();self.assertEqual(self.used(b),0)
        self.clock.advance(1);self.consume();self.assertEqual(self.used(b),1)
    def test_malformed_sample_rejected_before_any_state_change(self):
        before=copy.deepcopy(self.store.state)
        for fields in [{'uid':501},{'seconds':1000},{'on_console':1},{'idle_seconds':float('nan')},{'idle_seconds':True},
                       {'sample_seq':0},{'front_pid':True},{'front_start_usec':1000000},{'front_executable':'relative'},
                       {'front_pid':0},{'event_seq':-1}]:
            with self.subTest(fields=fields),self.assertRaises(PolicyError):self.consume(**fields)
            self.assertEqual(self.store.state,before)
    def test_signin_and_wake_fire_once_not_on_agent_or_authority_restart(self):
        b=self.block(enabled=False,autostart={'type':'signin'})
        self.consume();self.assertTrue(b['enabled'])
        self.authority.manage(501,'toggle',{'id':b['id'],'enabled':False})
        self.sessions=TrustedSessions(self.authority,self.execution,session_identity=lambda _:10)
        self.consume();self.assertFalse(b['enabled'])
        self.clock.advance(1);self.consume(event_seq=1);self.assertTrue(b['enabled'])
        self.authority.manage(501,'toggle',{'id':b['id'],'enabled':False})
        self.clock.advance(1);self.consume(event_seq=1);self.assertFalse(b['enabled'])
        with self.assertRaises(PolicyError):self.consume(event_seq=0)
        self.sessions=TrustedSessions(self.authority,self.execution,session_identity=lambda _:11)
        self.consume();self.assertTrue(b['enabled'])
    def test_unknown_audit_session_does_not_invent_login(self):
        b=self.block(enabled=False,autostart={'type':'signin'})
        self.sessions.session_identity=lambda _:None;self.consume();self.assertFalse(b['enabled'])
    def test_allowance_is_account_scoped(self):
        b=self.block();self.consume();self.clock.advance(2);self.consume()
        self.assertEqual(self.used(b),2);self.assertEqual(self.used(b,502),0)
    def test_strict_background_counts_matching_rules_without_reward_credit(self):
        self.store.state['settings']['strict_usage']=True
        front={**self.app,'application':'Editor','executable':'/tmp/editor'}
        self.execution.apps=[front,{**process(900002,token='b'),'start_sec':1,'start_usec':0}]
        self.app=front
        b=self.block();reward=self.block(applications=['Other'],**{'break':{'type':'reward','work_minutes':1,'break_minutes':1}})
        self.consume();self.clock.advance(2);self.consume()
        self.assertEqual(self.used(b),2)
        self.assertEqual(self.authority.engine(501).runtime(reward)['focus_seconds'],2)
    def test_browser_foreground_does_not_earn_web_only_focus_rewards(self):
        self.execution.apps[0]['bundle']='com.microsoft.edgemac'
        b=self.block(applications=[],websites=['example.com'],**{'break':{'type':'reward','work_minutes':1,'break_minutes':1}})
        self.consume();self.clock.advance(2);self.consume()
        self.assertEqual(self.authority.engine(501).runtime(b).get('focus_seconds',0),0)
    def test_strict_background_target_cannot_earn_focus_from_foreground_editor(self):
        self.store.state['settings']['strict_usage']=True
        front={**self.app,'application':'Editor','executable':'/tmp/editor'}
        self.execution.apps=[front,{**process(900002,token='b'),'start_sec':1,'start_usec':0}];self.app=front
        b=self.block(**{'break':{'type':'reward','work_minutes':1,'break_minutes':1}})
        self.consume();self.clock.advance(2);self.consume()
        self.assertEqual(self.authority.engine(501).runtime(b).get('focus_seconds',0),0)
    def test_wall_clock_jump_does_not_overcharge_monotonic_interval(self):
        b=self.block();self.consume();self.clock.now+=3600;self.clock.mono+=1;self.consume()
        self.assertEqual(self.used(b),1)


if __name__=='__main__':unittest.main()
