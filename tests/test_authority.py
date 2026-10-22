import datetime as dt
import tempfile
import unittest
from types import SimpleNamespace

from hotturkey.authority import PolicyAuthority
from hotturkey.engine import Engine, password_hash
from hotturkey.model import PolicyError
from hotturkey.store import Store


class Clock:
    def __init__(self):self.now=dt.datetime(2026,10,19,9).timestamp();self.mono=1000
    def wall(self):return self.now
    def monotonic(self):return self.mono
    def advance(self,seconds):self.now+=seconds;self.mono+=seconds


def account(uid):
    names={501:'alice',502:'bob',503:'carol'}
    return SimpleNamespace(pw_uid=uid,pw_name=names[uid],pw_dir='/Users/'+names[uid])


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.store=Store(self.temp.name)
        self.clock=Clock()
        self.authority=self.make_authority()
        self.alice=self.authority.engine(501)
        self.bob=self.authority.engine(502)

    def make_authority(self):
        return PolicyAuthority(self.store,501,resolve_user=account,boot_id='boot-1',wall=self.clock.wall,monotonic=self.clock.monotonic)

    def tearDown(self):self.store.db.close();self.temp.cleanup()

    def block(self,**options):
        value={'name':'Shared','enabled':True,'websites':['example.com'],**options}
        result=self.authority.manage(501,'save',{'block':value})
        return self.alice.find(result['id'])

    def test_selected_account_only(self):
        self.block(users=['bob'])
        self.assertFalse(self.alice.evaluate('https://example.com')['blocked'])
        self.assertTrue(self.bob.evaluate('https://example.com')['blocked'])
        self.assertEqual(self.authority.snapshot(503)['blocks'],[])

    def test_noncontroller_cannot_manage_even_with_password(self):
        block=self.block()
        for operation,data in [('delete',{'id':block['id']}),('toggle',{'id':block['id']}),('save',{'block':{'name':'Injected'}}),('add-targets',{'id':block['id'],'websites':['injected.example']})]:
            with self.subTest(operation=operation),self.assertRaises(PolicyError):self.authority.manage(502,operation,data)
        with self.assertRaises(PolicyError):self.authority.authenticate(502,'secret')
        self.assertFalse(self.authority.snapshot(502)['can_manage'])

    def test_password_and_overview_protection(self):
        block=self.block()
        self.store.state['settings'].update(settings_password=password_hash('secret'),protect_overview=True)
        self.assertEqual(self.authority.snapshot(501)['blocks'],[])
        with self.assertRaises(PolicyError):self.authority.manage(501,'delete',{'id':block['id']})
        with self.assertRaises(PolicyError):self.authority.authenticate(501,'wrong')
        with self.assertRaises(PolicyError):self.authority.authenticate(501,'secret')
        self.clock.advance(2)
        token=self.authority.authenticate(501,'secret')
        self.assertEqual(len(self.authority.snapshot(501,token)['blocks']),1)
        self.clock.advance(900)
        with self.assertRaises(PolicyError):self.authority.manage(501,'toggle',{'id':block['id']},token)

    def test_locked_rule_remains_protected_in_every_account(self):
        block=self.block(users=['bob'])
        self.authority.manage(501,'lock',{'id':block['id'],'type':'timer','until':self.clock.now+60})
        self.assertTrue(self.bob.locked(block))
        self.assertFalse(self.authority.can_uninstall())
        with self.assertRaises(PolicyError):self.authority.manage(501,'delete',{'id':block['id']})
        self.clock.advance(60)
        self.assertTrue(self.authority.can_uninstall())

    def test_usage_allowances_are_independent(self):
        block=self.block(**{'break':{'type':'allowance','allowance_minutes':1}})
        for engine in [self.alice,self.bob]:engine.usage({'url':'https://example.com'},'tab')
        for _ in range(6):
            self.clock.advance(10)
            self.bob.usage({'url':'https://example.com'},'tab')
        self.assertTrue(self.bob.evaluate('https://example.com')['blocked'])
        self.assertFalse(self.alice.evaluate('https://example.com')['blocked'])
        self.assertEqual(self.bob.store.used(block['id'],0),60)
        self.assertEqual(self.alice.store.used(block['id'],0),0)

    def test_break_challenges_and_grants_are_independent(self):
        block=self.block(**{'break':{'type':'text','text_length':50}})
        alice=self.alice.request_break(block['id'],{})['challenge']
        bob=self.bob.request_break(block['id'],{})['challenge']
        self.assertNotEqual(alice,bob)
        with self.assertRaises(PolicyError):self.bob.request_break(block['id'],{'answer':alice})
        self.bob.request_break(block['id'],{'answer':bob})
        self.assertFalse(self.bob.evaluate('https://example.com')['blocked'])
        self.assertTrue(self.alice.evaluate('https://example.com')['blocked'])

    def test_reward_credit_does_not_cross_accounts(self):
        block=self.block(**{'break':{'type':'reward','work_minutes':1,'break_minutes':1}})
        self.bob.usage({'url':'https://work.invalid'},'tab')
        for _ in range(6):self.clock.advance(10);self.bob.usage({'url':'https://work.invalid'},'tab')
        self.assertEqual(self.bob.break_state(block)['remaining'],60)
        self.assertEqual(self.alice.break_state(block)['remaining'],0)

    def test_sessions_do_not_cross_accounts(self):
        block=self.block(**{'break':{'type':'sessions','sessions':1}})
        self.bob.usage({'url':'https://example.com'},'tab')
        self.clock.advance(121)
        self.assertFalse(self.bob.break_state(block)['allowed'])
        self.assertTrue(self.alice.break_state(block)['allowed'])

    def test_pomodoro_anchor_is_shared_and_reenable_updates_all_accounts(self):
        block=self.block(**{'break':{'type':'pomodoro','work_minutes':1,'break_minutes':1}})
        self.clock.advance(70)
        self.assertTrue(self.bob.break_state(block)['allowed'])
        self.authority.manage(501,'toggle',{'id':block['id'],'enabled':False})
        self.authority.manage(501,'toggle',{'id':block['id'],'enabled':True})
        self.assertFalse(self.bob.break_state(block)['allowed'])
        self.assertEqual(self.bob.runtime(block)['started'],self.alice.runtime(block)['started'])
    def test_pomodoro_reset_is_shared_and_cannot_be_requested_by_noncontroller(self):
        block=self.block(**{'break':{'type':'pomodoro','work_minutes':1,'break_minutes':1}})
        self.clock.advance(70);self.assertTrue(self.bob.break_state(block)['allowed'])
        with self.assertRaises(PolicyError):self.authority.manage(502,'reset-pomodoro',{'id':block['id']})
        self.authority.manage(501,'reset-pomodoro',{'id':block['id']})
        self.assertFalse(self.bob.break_state(block)['allowed'])
        self.assertEqual(self.bob.break_state(block)['remaining'],60)
        self.authority.manage(501,'toggle',{'id':block['id'],'enabled':False})
        self.authority.manage(501,'toggle',{'id':block['id'],'enabled':True})
        self.assertNotIn('pomodoro_started',self.bob.runtime(block))

    def test_daily_autostart_occurs_once_across_accounts(self):
        block=self.block(enabled=False,autostart={'type':'daily','minute':540,'days':[0]})
        self.alice.tick()
        self.assertTrue(block['enabled'])
        self.authority.manage(501,'toggle',{'id':block['id'],'enabled':False})
        self.bob.tick()
        self.assertFalse(block['enabled'])
        self.clock.advance(7*86400)
        self.bob.tick()
        self.assertTrue(block['enabled'])

    def test_login_autostart_respects_user_selection(self):
        block=self.block(enabled=False,users=['bob'],autostart={'type':'signin'})
        self.alice.tick(signin=True)
        self.assertFalse(block['enabled'])
        self.bob.tick(signin=True)
        self.assertTrue(block['enabled'])

    def test_device_duration_extension_is_shared(self):
        block=self.block(device='lock',device_minutes=1,confirm_device=True)
        self.assertTrue(self.bob.active(block))
        self.authority.manage(501,'lock',{'id':block['id'],'type':'timer','until':self.clock.now+120})
        self.clock.advance(61)
        self.bob.tick()
        self.assertTrue(block['enabled'])
        self.assertTrue(self.bob.active(block))
        self.clock.advance(59)
        self.bob.tick()
        self.assertFalse(block['enabled'])

    def test_statistics_force_account_identity_and_privacy(self):
        self.alice.store.event(self.clock.now,'bob','website','alice.invalid',seconds=12)
        self.bob.store.event(self.clock.now,'alice','website','bob.invalid',seconds=30)
        self.assertEqual(self.bob.store.statistics(user='alice')['totals']['seconds'],30)
        self.assertEqual([row['user'] for row in self.bob.store.export_statistics()],['bob'])
        self.assertEqual(self.alice.store.statistics()['totals']['seconds'],42)
        with self.assertRaises(PolicyError):self.bob.store.clear_statistics()

    def test_deletion_cleans_all_account_runtime(self):
        block=self.block()
        self.bob.runtime(block)['break_until']=self.clock.now+30
        self.authority.manage(501,'delete',{'id':block['id']})
        self.assertNotIn(block['id'],self.bob.store.state['runtime'])
        self.assertNotIn(block['id'],self.store.state['block_starts'])

    def test_persistence_and_idempotent_migration(self):
        block=self.block()
        self.bob.store.charge(self.clock.now,block['id'],45)
        self.bob.runtime(block)['reward_credit']=30
        self.store.save()
        self.store.db.close()
        self.store=Store(self.temp.name)
        authority=self.make_authority()
        self.assertEqual(authority.engine(502).store.used(block['id'],0),45)
        self.assertEqual(authority.engine(502).runtime(block)['reward_credit'],30)
        with self.assertRaises(PolicyError):PolicyAuthority(self.store,502,resolve_user=account)

    def test_legacy_allowance_is_preserved_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            legacy=Store(temporary)
            try:
                engine=Engine(legacy,self.clock.wall,self.clock.monotonic,'boot-1','alice')
                block=engine.save_block({'name':'Legacy','enabled':True,'websites':['example.com'],'break':{'type':'allowance','allowance_minutes':1}})
                legacy.charge(self.clock.now,block['id'],60)
                authority=PolicyAuthority(legacy,501,resolve_user=account,wall=self.clock.wall,monotonic=self.clock.monotonic)
                self.assertTrue(authority.engine(501).evaluate('https://example.com')['blocked'])
                self.assertFalse(authority.engine(502).evaluate('https://example.com')['blocked'])
                PolicyAuthority(legacy,501,resolve_user=account)
                self.assertEqual(authority.engine(501).store.used(block['id'],0),60)
            finally:legacy.db.close()

    def test_invalid_or_unknown_uid_is_rejected(self):
        for uid in [0,True,'501',501.0,999]:
            with self.subTest(uid=uid),self.assertRaises(PolicyError):self.authority.engine(uid)


if __name__=='__main__':unittest.main()
