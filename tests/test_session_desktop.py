import copy
import dataclasses
import plistlib
import tempfile
import unittest

from hotturkey.authority import PolicyAuthority
from hotturkey.ipc import PeerIdentity
from hotturkey.model import PolicyError
from hotturkey.session_launch import session_launch_agent
from hotturkey.store import Store
from hotturkey.trusted_sessions import TrustedSessions
from test_authority import Clock,account
from test_trusted_sessions import Inventory


class DesktopLoginTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=Store(self.temp.name);self.clock=Clock()
        self.authority=PolicyAuthority(self.store,501,resolve_user=account,wall=self.clock.wall,monotonic=self.clock.monotonic)
        self.store.state['settings']['open_at_login']=True
        self.sessions=TrustedSessions(self.authority,Inventory(),session_identity=lambda _:10)
        self.peer=PeerIdentity(501,20,1234,b'a'*32,'session');self.seq=0
    def tearDown(self):self.store.db.close();self.temp.cleanup()
    def sample(self,**values):
        self.seq+=1
        return {'front_pid':0,'front_start_sec':0,'front_start_usec':0,'front_executable':'',
                'idle_seconds':0,'on_console':True,'sample_seq':self.seq,'event_seq':0,**values}
    def consume(self,**values):return self.sessions.consume(self.peer,self.sample(**values))
    def test_first_login_delivers_only_an_opaque_ticket_not_paths_or_settings(self):
        result=self.consume();self.assertEqual(set(result['desktop']),{'id'});self.assertEqual(len(result['desktop']['id']),64)
        self.assertEqual(self.consume()['desktop'],result['desktop'])
        self.assertEqual(self.sessions.desktop.status(501)['attempts'],1)
    def test_successful_receipt_survives_agent_and_authority_restart(self):
        ticket=self.consume()['desktop']
        self.consume(desktop_result={**ticket,'ok':True})
        self.assertNotIn('desktop',self.consume(event_seq=1))
        self.assertEqual(self.sessions.status(501)['desktop_login']['status'],'launched')
        self.sessions=TrustedSessions(self.authority,Inventory(),session_identity=lambda _:10)
        self.assertNotIn('desktop',self.consume())
        self.store.save();reopened=Store(self.temp.name)
        try:
            authority=PolicyAuthority(reopened,501,resolve_user=account,wall=self.clock.wall,monotonic=self.clock.monotonic)
            self.assertEqual(authority.store.state['desktop_logins']['501']['status'],'launched')
        finally:reopened.db.close()
    def test_wake_and_front_changes_never_reopen_the_acknowledged_ui(self):
        ticket=self.consume()['desktop'];self.consume(desktop_result={**ticket,'ok':True})
        self.clock.advance(1);self.assertNotIn('desktop',self.consume(event_seq=2))
        self.clock.advance(60);self.assertNotIn('desktop',self.consume(on_console=False,event_seq=2))
        self.assertNotIn('desktop',self.consume(event_seq=3))
    def test_a_new_audit_login_or_boot_gets_its_own_launch(self):
        first=self.consume()['desktop'];self.consume(desktop_result={**first,'ok':True})
        self.sessions.session_identity=lambda _:11
        second=self.consume()['desktop'];self.assertNotEqual(second,first)
        self.consume(desktop_result={**second,'ok':True})
        self.authority.boot_id='next-boot'
        self.assertNotEqual(self.consume()['desktop'],second)
    def test_no_console_or_unknown_audit_session_invents_a_login(self):
        self.assertNotIn('desktop',self.consume(on_console=False))
        self.assertNotIn('desktop_logins',self.store.state)
        self.sessions.session_identity=lambda _:None
        self.assertNotIn('desktop',self.consume());self.assertNotIn('desktop_logins',self.store.state)
    def test_enabling_mid_session_does_not_open_a_window_and_disabling_cancels(self):
        self.store.state['settings']['open_at_login']=False
        self.assertNotIn('desktop',self.consume())
        self.store.state['settings']['open_at_login']=True
        self.assertNotIn('desktop',self.consume())
        self.sessions.session_identity=lambda _:11;self.assertIn('desktop',self.consume())
        self.store.state['settings']['open_at_login']=False;self.assertNotIn('desktop',self.consume())
        self.store.state['settings']['open_at_login']=True;self.assertNotIn('desktop',self.consume())
    def test_upgrade_in_an_existing_login_does_not_manufacture_another_login(self):
        self.store.state['trusted_sessions']={'501':{'boot':self.authority.boot_id,'audit_session':10}}
        self.assertNotIn('desktop',self.consume())
    def test_failed_delivery_retries_with_backoff_but_at_most_three_times(self):
        first=self.consume()['desktop'];self.consume(desktop_result={**first,'ok':False})
        self.clock.advance(9);self.assertNotIn('desktop',self.consume())
        self.clock.advance(1);second=self.consume()['desktop'];self.assertNotEqual(first,second)
        self.consume(desktop_result={**second,'ok':False});self.clock.advance(30)
        third=self.consume()['desktop'];self.consume(desktop_result={**third,'ok':False})
        self.sessions=TrustedSessions(self.authority,Inventory(),session_identity=lambda _:10)
        self.clock.advance(300);self.assertNotIn('desktop',self.consume())
        self.assertEqual(self.sessions.desktop.status(501),{'supported':True,'status':'failed','attempts':3})
    def test_missing_ack_is_bounded_and_stale_owner_cannot_complete_another_ticket(self):
        first=self.consume()['desktop'];self.clock.advance(6)
        self.peer=dataclasses.replace(self.peer,pid=5678,audit_token=b'b'*32)
        self.assertNotIn('desktop',self.consume(desktop_result={**first,'ok':True}))
        self.assertEqual(self.sessions.desktop.status(501)['status'],'pending')
        self.clock.advance(10);second=self.consume()['desktop'];self.assertNotEqual(first,second)
        self.consume(desktop_result={**first,'ok':True})
        self.assertEqual(self.sessions.desktop.status(501)['status'],'pending')
        self.consume(desktop_result={**second,'ok':True})
        self.assertEqual(self.sessions.desktop.status(501)['status'],'launched')
    def test_acks_do_not_cross_uid_boundaries(self):
        first=self.consume()['desktop']
        other=dataclasses.replace(self.peer,uid=502,pid=2222,audit_token=b'b'*32)
        result=self.sessions.consume(other,self.sample(desktop_result={**first,'ok':True}))
        self.assertNotEqual(result['desktop'],first)
        self.assertEqual(self.sessions.desktop.status(501)['status'],'pending')
    def test_malformed_receipts_rejected_before_any_accounting_or_policy_change(self):
        self.consume();before=copy.deepcopy(self.store.state)
        for value in [None,False,{'id':'a'*64,'ok':1},{'id':'a'*63,'ok':True},{'id':'a'*64,'ok':True,'path':'/tmp/anything'}]:
            with self.subTest(value=value),self.assertRaises(PolicyError):self.consume(desktop_result=value)
            self.assertEqual(self.store.state,before)
    def test_supervision_plan_uses_fixed_program_and_no_selected_user_or_shell(self):
        plan=plistlib.loads(plistlib.dumps(session_launch_agent()))
        self.assertEqual(plan['ProgramArguments'],['/Library/PrivilegedHelperTools/local.hotturkey/HotTurkeySessionAgent'])
        self.assertEqual(plan['LimitLoadToSessionType'],'Aqua');self.assertTrue(plan['KeepAlive'])
        self.assertTrue(plan['AbandonProcessGroup']);self.assertNotIn('UserName',plan)
        self.assertNotIn('SessionCreate',plan);self.assertNotIn('WorkingDirectory',plan)


if __name__=='__main__':unittest.main()
