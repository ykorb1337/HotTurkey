import copy
import tempfile
import unittest

from hotturkey.authority import PolicyAuthority
from hotturkey.device_blocks import SleepGate,selected_device
from hotturkey.engine import Engine
from hotturkey.management import import_blocks,settings_update
from hotturkey.model import PolicyError
from hotturkey.store import Store
from hotturkey.system_enforcement import SystemDecisions
from hotturkey.ipc import PeerIdentity
from hotturkey.trusted_sessions import TrustedSessions
from test_authority import Clock,account

WORD='fixture-safe-word'


class DeviceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=Store(self.temp.name);self.clock=Clock()
        self.engine=Engine(self.store,self.clock.wall,self.clock.monotonic,'boot-1','alice')
    def tearDown(self):self.store.db.close();self.temp.cleanup()
    def plan(self,**values):
        self.engine.configure_device_recovery(WORD)
        return self.engine.save_block({'name':'Sleep','device':'sleep','mode':'scheduled','enabled':True,'confirm_device':True,
            'schedule':[{'days':[0,1,2,3,4,5,6],'start':540,'end':600}],**values})
    def test_high_risk_enable_requires_recovery_and_explicit_device_confirmation(self):
        for action in ['lock','sleep','logout','shutdown']:
            with self.subTest(action=action),self.assertRaises(PolicyError):
                self.engine.save_block({'name':'Denied','device':action,'enabled':True,'confirm_device':True})
        block=self.engine.save_block({'name':'Inactive','device':'sleep','enabled':False,'confirm_device':True})
        with self.assertRaises(PolicyError):self.engine.toggle(block['id'],True,True)
        self.engine.configure_device_recovery(WORD)
        for enabled in ['false',1,0]:
            with self.assertRaises(PolicyError):self.engine.save_block({'name':'Invalid','device':'sleep','enabled':enabled,'confirm_device':True})
            with self.assertRaises(PolicyError):self.engine.toggle(block['id'],enabled,True)
        with self.assertRaises(PolicyError):self.engine.toggle(block['id'],True)
        self.assertTrue(self.engine.toggle(block['id'],True,True)['active'])
    def test_safety_word_is_hashed_redacted_and_not_writable_through_generic_settings(self):
        self.engine.configure_device_recovery(WORD)
        hashed=self.store.state['settings']['device_recovery_hash'];self.assertNotEqual(hashed,WORD)
        self.assertIs(self.engine.snapshot()['settings']['device_recovery_hash'],True)
        self.assertEqual(settings_update(self.engine,{'device_recovery_hash':'forged'})['device_recovery_hash'],hashed)
        for bad in [None,True,'short','x'*257,'      ',' word-escape ']:
            with self.assertRaises(PolicyError):self.engine.configure_device_recovery(bad)
            self.assertEqual(self.store.state['settings']['device_recovery_hash'],hashed)
    def test_scheduled_device_is_automatically_locked_during_its_window(self):
        block=self.plan();self.assertTrue(block['lock']['automatic_device'])
        for call in [lambda:self.engine.delete(block['id']),lambda:self.engine.toggle(block['id'],False),lambda:self.engine.unlock(block['id'],{}),
                     lambda:self.engine.save_block({**block,'device':'none'},block['id'])]:
            with self.assertRaises(PolicyError):call()
        self.clock.advance(3600);self.assertFalse(self.engine.locked(self.engine.find(block['id'])))
    def test_emergency_releases_this_window_and_preserves_next_day_and_rule(self):
        block=self.plan();before=copy.deepcopy(self.engine.find(block['id']))
        result=self.engine.recover_device(WORD);self.assertEqual(result['count'],1)
        self.assertFalse(self.engine.active(self.engine.find(block['id'])))
        self.assertEqual(self.engine.find(block['id']),before)
        self.clock.advance(86400);self.assertTrue(self.engine.active(self.engine.find(block['id'])))
    def test_emergency_survives_service_restart_without_changing_the_end(self):
        block=self.plan(mode='continuous',device_minutes=5);end=self.engine.recover_device(WORD)['until']
        second=Store(self.temp.name)
        try:
            engine=Engine(second,self.clock.wall,self.clock.monotonic,'boot-2','alice')
            self.assertFalse(engine.active(engine.find(block['id'])))
            self.assertEqual(engine.runtime(engine.find(block['id']))['device_emergency_until'],end)
        finally:second.db.close()
    def test_wrong_word_is_rate_limited_and_does_not_extend_or_weaken_device_rule(self):
        block=self.plan();before=copy.deepcopy(self.store.state)
        with self.assertRaises(PolicyError):self.engine.recover_device('wrong-word')
        with self.assertRaises(PolicyError):self.engine.recover_device(WORD)
        self.assertEqual(self.store.state,before)
        self.clock.advance(3);self.assertTrue(self.engine.recover_device(WORD)['ok'])
        self.assertTrue(self.engine.find(block['id'])['enabled'])
    def test_wake_during_release_cannot_extend_original_continuous_deadline(self):
        block=self.plan(mode='continuous',device_minutes=5,autostart={'type':'signin'})
        end=self.engine.recover_device(WORD)['until']
        self.clock.advance(1);self.engine.tick(signin=True)
        self.assertEqual(self.engine.runtime(self.engine.find(block['id']))['device_until'],end)
        self.clock.advance(300);self.engine.tick()
        self.assertFalse(self.engine.find(block['id'])['enabled'])
        self.engine.tick(signin=True)
        self.assertTrue(self.engine.active(self.engine.find(block['id'])))
    def test_replacing_word_during_lock_requires_old_word(self):
        self.plan()
        with self.assertRaises(PolicyError):self.engine.configure_device_recovery('new-safe-word')
        with self.assertRaises(PolicyError):self.engine.configure_device_recovery('new-safe-word','wrong')
        self.engine.configure_device_recovery('new-safe-word',WORD)
        self.assertTrue(self.engine.recover_device('new-safe-word')['ok'])
    def test_sleep_gate_has_recovery_countdown_and_reopens_on_real_wake_or_gap(self):
        self.plan();gate=SleepGate(lambda _:self.engine)
        self.assertEqual(gate.update(501)['grace_remaining'],30)
        for _ in range(30):self.clock.advance(1);state=gate.update(501)
        self.assertEqual(state['phase'],'sleep')
        self.assertEqual(gate.update(501,1)['phase'],'countdown')
        self.clock.advance(60);self.assertEqual(gate.update(501,1)['grace_remaining'],30)
        self.engine.recover_device(WORD);self.assertIsNone(gate.status(501))
    def test_device_selection_is_deterministic_and_does_not_let_lock_override_sleep(self):
        self.plan();self.engine.save_block({'name':'Lock','enabled':True,'device':'lock','device_minutes':5,'confirm_device':True})
        self.assertEqual(selected_device(self.engine)['device'],'sleep')
    def test_emergency_stop_cancels_automatic_restart_and_keeps_website_rules(self):
        block=self.plan(autostart={'type':'daily','minute':540,'days':[0]})
        web=self.engine.save_block({'name':'Website','enabled':True,'websites':['example.invalid']})
        self.engine.set_lock(web['id'],{'type':'password','password':'website-only'})
        before=copy.deepcopy(self.engine.find(web['id']))
        self.engine.recover_device(WORD)
        result=self.engine.recover_device(WORD,True);self.assertTrue(result['stopped'])
        saved=self.engine.find(block['id']);self.assertFalse(saved['enabled']);self.assertEqual(saved['autostart'],{'type':'none'})
        self.engine.tick(signin=True);self.assertFalse(saved['enabled'])
        self.assertEqual(self.engine.find(web['id']),before)
    def test_import_retaining_device_autostart_needs_word_even_when_confirmation_is_given(self):
        incoming=[{'name':'Imported','device':'sleep','autostart':{'type':'once','at':self.clock.now+600}}]
        with self.assertRaises(PolicyError):import_blocks(self.engine,incoming,True,True)
        self.assertEqual(self.store.state['blocks'],[])
        self.assertEqual(import_blocks(self.engine,incoming)['count'],1)
        self.assertEqual(self.store.state['blocks'][0]['autostart'],{'type':'none'})


class ProtectedDeviceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=Store(self.temp.name);self.clock=Clock()
        self.authority=PolicyAuthority(self.store,501,resolve_user=account,wall=self.clock.wall,monotonic=self.clock.monotonic)
        self.alice=self.authority.engine(501);self.alice.configure_device_recovery(WORD)
        self.block=self.authority.manage(501,'save',{'block':{'name':'Device','device':'sleep','enabled':True,'confirm_device':True,
            'mode':'scheduled','schedule':[{'days':[0,1,2,3,4,5,6],'start':540,'end':600}]}})
        self.decisions=SystemDecisions(self.authority,simulate_devices=True)
    def tearDown(self):self.store.db.close();self.temp.cleanup()
    def sample(self,uid=501,wake=0,**values):
        pending=self.decisions.pending_device
        ack={**pending,'result':'simulated'} if pending else None
        return {'apps':[],'front':{},'results':[],'console_uid':uid,'device_result':ack,'wake_seq':wake,**values}
    def advance(self,seconds,uid=501,wake=0):
        for _ in range(seconds):
            self.clock.advance(1);command=self.decisions.consume(self.sample(uid,wake))
        return command
    def test_recovery_is_account_scoped_and_persists_across_authority_restart(self):
        bob=self.authority.engine(502);bob.recover_device(WORD)
        self.assertFalse(bob.active(bob.find(self.block['id'])));self.assertTrue(self.alice.active(self.alice.find(self.block['id'])))
        restarted=PolicyAuthority(self.store,501,resolve_user=account,wall=self.clock.wall,monotonic=self.clock.monotonic)
        self.assertFalse(restarted.engine(502).active(restarted.engine(502).find(self.block['id'])))
    def test_only_active_console_uid_can_trigger_sleep_and_grace_is_respected(self):
        self.assertNotIn('device',self.decisions.consume(self.sample()))
        self.assertEqual(self.advance(30)['device']['uid'],501)
        self.assertNotIn('device',self.decisions.consume(self.sample(wake=1)))
        self.assertEqual(self.advance(30,wake=1)['device']['action'],'sleep')
        self.assertNotIn('device',self.decisions.consume(self.sample(uid=0)))
    def test_correct_emergency_word_cancels_further_sleep_requests(self):
        self.decisions.consume(self.sample());self.advance(30)
        self.alice.recover_device(WORD)
        self.assertNotIn('device',self.decisions.consume(self.sample()))
        self.assertNotIn('device',self.advance(3))
    def test_wrong_or_missing_device_receipt_is_rejected_before_state_changes(self):
        self.decisions.consume(self.sample());self.advance(30)
        before=copy.deepcopy(self.store.state)
        for result in [None,{**self.decisions.pending_device,'uid':502,'result':'simulated'},{**self.decisions.pending_device,'result':[]}]:
            with self.assertRaises(ValueError):self.decisions.consume(self.sample(device_result=result))
            self.assertEqual(self.store.state,before)
    def test_simulation_receipt_is_not_accepted_by_production_decisions(self):
        self.decisions.consume(self.sample());self.advance(30);self.decisions.simulate_devices=False
        with self.assertRaises(ValueError):self.decisions.consume(self.sample())
    def test_clock_expiry_stops_sleeping_without_requiring_a_receipt_to_be_erased(self):
        self.decisions.consume(self.sample());self.advance(30)
        self.clock.advance(3600)
        self.assertNotIn('device',self.decisions.consume(self.sample()))
    def test_login_autostart_cannot_erase_emergency_release_in_the_same_or_next_sample(self):
        class Inventory:
            def applications(self,uid):return []
        self.authority.manage(501,'save',{'block':{'name':'On login','device':'sleep','device_minutes':5,'enabled':False,'confirm_device':True,'autostart':{'type':'signin'}}})
        sessions=TrustedSessions(self.authority,Inventory(),session_identity=lambda _:1)
        peer=PeerIdentity(501,20,123,b'a'*32,'session')
        sample={'front_pid':0,'front_start_sec':0,'front_start_usec':0,'front_executable':'','on_console':True,'idle_seconds':0,'sample_seq':1,'event_seq':0,'recovery_word':WORD}
        result=sessions.consume(peer,sample);self.assertTrue(result['recovery_result']['ok'])
        end=result['recovery_result']['until']
        self.clock.advance(1);sample.update(sample_seq=2,event_seq=1);sample.pop('recovery_word')
        sessions.consume(peer,sample)
        for block in self.store.state['blocks']:
            self.assertFalse(self.alice.active(block));self.assertEqual(self.alice.runtime(block)['device_emergency_until'],end)


if __name__=='__main__':unittest.main()
