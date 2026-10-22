import copy
import tempfile
import unittest
from pathlib import Path

from hotturkey.engine import Engine
from hotturkey.model import PolicyError
from hotturkey.store import Store
from hotturkey.tab_exceptions import TabExceptions,scope
from test_authority import Clock


class TabExceptionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=Store(self.temp.name);self.clock=Clock()
        self.engine=Engine(self.store,wall=self.clock.wall,monotonic=self.clock.monotonic,user='alice',boot_id='test')
        self.tabs=TabExceptions(self.engine)
        self.context='a'*48
        self.block=self.engine.save_block({'name':'Web','enabled':True,'websites':['example.com'],'applications':['bundle:test.app']})
        self.data={'context':self.context,'tab':7,'id':self.block['id'],'minutes':1,'url':'https://example.com/a'}

    def tearDown(self):self.store.db.close();self.temp.cleanup()
    def request(self,**extra):return self.tabs.request({**self.data,**extra})
    def check(self,**extra):return self.engine.evaluate('https://example.com/a',exemptions=self.tabs.ids({**self.data,**extra}))

    def test_unlocked_grant_is_scoped_to_instance_tab_and_rule(self):
        before=copy.deepcopy(self.store.state)
        self.assertTrue(self.request()['granted']);self.assertFalse(self.check()['blocked'])
        self.assertTrue(self.check(tab=8)['blocked']);self.assertTrue(self.check(context='b'*48)['blocked'])
        self.assertTrue(self.engine.evaluate('https://example.com/a')['blocked'])
        self.assertTrue(self.engine.app_matches(self.engine.find(self.block['id']),{'bundle':'test.app'}))
        self.assertEqual(self.store.state,before)

    def test_other_overlapping_rule_still_blocks(self):
        other=self.engine.save_block({'name':'Other','enabled':True,'websites':['example.com']})
        self.request()
        self.assertEqual([b['id'] for b in self.check()['blocks']],[other['id']])

    def test_text_validation_does_not_unlock_or_reset_any_break_state(self):
        self.engine.set_lock(self.block['id'],{'type':'text','custom_text':'focus careful'})
        before=copy.deepcopy(self.store.state)
        self.assertEqual(self.request()['challenge'],'focus careful')
        with self.assertRaises(PolicyError):self.request(answer='wrong')
        self.assertTrue(self.request(answer='focus careful')['granted'])
        self.assertEqual(self.store.state,before);self.assertTrue(self.engine.locked(self.engine.find(self.block['id'])))

    def test_password_validation_uses_shared_rate_limit_and_retains_lock(self):
        self.engine.set_lock(self.block['id'],{'type':'password','password':'secret'})
        self.assertEqual(self.request()['method'],'password')
        with self.assertRaisesRegex(PolicyError,'密码不正确'):self.request(answer='wrong')
        with self.assertRaisesRegex(PolicyError,'稍后'):self.request(answer='secret')
        self.clock.advance(2);self.assertTrue(self.request(answer='secret')['granted'])
        self.assertTrue(self.engine.locked(self.engine.find(self.block['id'])))

    def test_time_delay_restart_and_schedule_locks_cannot_be_bypassed(self):
        for lock in [{'type':'timer','until':self.clock.now+3600},{'type':'delay','minutes':1},{'type':'restart'},{'type':'range','schedule':[{'days':[0],'start':540,'end':600}]}]:
            with self.subTest(lock=lock):
                self.engine.find(self.block['id'])['lock']={'type':'none'}
                self.engine.set_lock(self.block['id'],lock)
                with self.assertRaises(PolicyError):self.request(answer='anything')
        self.engine.find(self.block['id'])['lock']={'type':'none'}
        self.engine.save_block({**self.engine.find(self.block['id']),'mode':'scheduled','schedule':[{'days':[0],'start':540,'end':600}]},self.block['id'])
        self.engine.set_lock(self.block['id'],{'type':'schedule'})
        with self.assertRaises(PolicyError):self.request()

    def test_expired_lock_can_grant_without_mutating_old_lock(self):
        self.engine.set_lock(self.block['id'],{'type':'timer','until':self.clock.now+60})
        self.clock.advance(60);before=copy.deepcopy(self.engine.find(self.block['id'])['lock'])
        self.assertTrue(self.request()['granted']);self.assertEqual(self.engine.find(self.block['id'])['lock'],before)

    def test_expiry_uses_monotonic_clock_even_if_wall_clock_moves_back(self):
        self.request();self.clock.now-=3600;self.clock.mono+=59
        self.assertFalse(self.check()['blocked']);self.clock.mono+=1
        self.assertTrue(self.check()['blocked']);self.assertEqual(self.tabs.grants,{})

    def test_close_and_backend_restart_revoke_grants(self):
        self.request();self.tabs.close(self.data);self.assertTrue(self.check()['blocked'])
        self.request();fresh=TabExceptions(self.engine);self.assertEqual(fresh.ids(self.data),set())
        self.assertNotIn('tab_grants',self.store.state)

    def test_adding_targets_or_changing_lock_revokes_existing_grant(self):
        self.request();self.engine.add_targets(self.block['id'],['new.example']);self.assertTrue(self.check()['blocked'])
        self.request();self.engine.set_lock(self.block['id'],{'type':'text','custom_text':'original'})
        self.assertTrue(self.check()['blocked']);self.request(answer='original')
        self.engine.set_lock(self.block['id'],{'type':'text','length':20});self.assertTrue(self.check()['blocked'])
        with self.assertRaises(PolicyError):self.request(answer='original')

    def test_reenable_next_schedule_and_deleted_rule_invalidate(self):
        self.request();self.engine.toggle(self.block['id'],False);self.clock.advance(1);self.engine.toggle(self.block['id'],True)
        self.assertTrue(self.check()['blocked'])
        self.request();self.engine.delete(self.block['id']);self.assertEqual(self.tabs.ids(self.data),set())

    def test_invalid_scope_duration_target_and_answer_are_rejected(self):
        for patch in [{'context':'short'},{'context':[]},{'tab':True},{'tab':-1},{'minutes':0},{'minutes':1441},{'url':'file:///tmp/test'},{'url':'edge://settings'},{'url':'https://[invalid'},{'answer':[]},{'channels':'x'}]:
            with self.subTest(patch=patch),self.assertRaises(PolicyError):self.request(**patch)
        self.assertEqual(self.tabs.grants,{})

    def test_unrelated_and_inactive_rule_cannot_be_granted(self):
        with self.assertRaises(PolicyError):self.request(url='https://other.example')
        self.engine.toggle(self.block['id'],False)
        with self.assertRaises(PolicyError):self.request()

    def test_snapshot_filters_other_contexts_tabs_and_does_not_return_secrets(self):
        self.request();value=self.tabs.snapshot(self.context,[7])[0]
        self.assertEqual(value['tab'],7);self.assertEqual(value['remaining'],60)
        self.assertNotIn('context',value);self.assertNotIn('hash',value)
        self.assertEqual(self.tabs.snapshot('b'*48,[7]),[]);self.assertEqual(self.tabs.snapshot(self.context,[8]),[])

    def test_grant_limit_is_bounded_and_expiry_releases_capacity(self):
        for tab in range(512):self.request(tab=tab)
        with self.assertRaisesRegex(PolicyError,'上限'):self.request(tab=512)
        self.assertFalse(self.check(tab=511)['blocked'])
        self.clock.advance(60);self.assertTrue(self.request(tab=512)['granted'])
        self.assertEqual(len(self.tabs.grants),1)

    def test_usage_keeps_statistics_without_spending_other_allowances(self):
        self.engine.save_block({**self.engine.find(self.block['id']),'break':{'type':'allowance','allowance_minutes':1}},self.block['id'])
        self.store.charge(self.clock.now,self.block['id'],60)
        self.request()
        for _ in range(2):
            self.engine.usage({'url':'https://example.com','active':True},'tab',self.tabs.ids(self.data));self.clock.advance(10)
        self.assertEqual(self.store.used(self.block['id'],0),60)
        self.assertEqual(self.store.statistics(block=self.block['id'])['totals']['seconds'],10)


if __name__=='__main__':unittest.main()
