import copy
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from hotturkey.authority import PolicyAuthority
from hotturkey.authority_server import AuthorityServer
from hotturkey.store import Store
from hotturkey.system_enforcement import SystemDecisions,SystemExecution
from test_authority import Clock,account


def process(pid=900001,uid=501,token='a',path='/tmp/game'):
    return {'pid':pid,'uid':uid,'identity':token*64,'executable':path,'path':path,'application':'Game','bundle':'local.fixture'}

def sample(apps=(),results=()):return {'apps':list(apps),'front':{},'results':list(results)}

def ack(app,result='sent',signal=15):
    return {**{k:app[k] for k in ['pid','uid','identity']},'result':result,'signal':signal}


class SystemDecisionsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=Store(self.temp.name);self.clock=Clock()
        self.authority=PolicyAuthority(self.store,501,resolve_user=account,wall=self.clock.wall,monotonic=self.clock.monotonic)
        self.decisions=SystemDecisions(self.authority,protected_paths=['/protected/install'])
    def tearDown(self):self.store.db.close();self.temp.cleanup()
    def block(self,**values):
        return self.authority.manage(501,'save',{'block':{'name':'Process rule','enabled':True,'applications':['binary:/tmp/game'],**values}})
    def test_account_discovered_from_kernel_sample_without_rpc(self):
        self.block(users=['bob'])
        self.assertNotIn(502,self.authority.engines)
        alice=process();bob=process(900002,502,'b')
        value=self.decisions.consume(sample([alice,bob]))
        self.assertEqual(value['kill'],[{k:bob[k] for k in ['pid','uid','identity']}]);self.assertIn(502,self.authority.engines)
        self.assertEqual(self.authority.engines[502].user,'bob')
    def test_empty_users_affects_both_accounts_but_unmatched_apps_survive(self):
        self.block();apps=[process(),process(900002,502,'b'),process(900003,503,'c',path='/tmp/unrelated')]
        self.assertEqual([x['uid'] for x in self.decisions.consume(sample(apps))['kill']],[501,502])
    def test_protected_paths_and_authority_pids_are_never_targets(self):
        self.block(applications=['Game'])
        apps=[process(os.getpid()),process(os.getppid(),token='b'),process(900003,token='c',path='/protected/install/client'),process(900004,token='d',path='/protected/install-other/game')]
        self.assertEqual([x['pid'] for x in self.decisions.consume(sample(apps))['kill']],[900004])
    def test_statistics_require_successful_matching_ack_and_do_not_double_count_force(self):
        b=self.block();app=process();self.decisions.consume(sample([app]))
        self.assertEqual(self.store.statistics()['totals']['blocked'],0)
        self.decisions.consume(sample([app],[ack(app,'stale',0)]));self.assertEqual(self.store.statistics()['totals']['blocked'],0)
        self.decisions.consume(sample([app],[ack(app)]));self.assertEqual(self.store.statistics()['totals']['blocked'],1)
        self.decisions.consume(sample([app],[ack(app,signal=9)]));self.assertEqual(self.store.statistics()['totals']['blocked'],1)
    def test_denied_kill_not_reported_as_blocked(self):
        self.block();app=process();self.decisions.consume(sample([app]));self.decisions.consume(sample([], [ack(app,'denied')]))
        self.assertEqual(self.store.statistics()['totals']['blocked'],0)
    def test_process_identity_change_does_not_reuse_old_decision(self):
        self.block();old=process();new=process(token='b',path='/tmp/unrelated')
        self.decisions.consume(sample([old]));self.assertEqual(self.decisions.consume(sample([new],[ack(old,'stale',0)]))['kill'],[])
        self.assertEqual(self.store.statistics()['totals']['blocked'],0)
    def test_locked_addition_preserves_deadline_and_runtime(self):
        b=self.block(applications=[]);until=self.clock.now+600
        self.authority.manage(501,'lock',{'id':b['id'],'type':'timer','until':until})
        started=self.authority.engine(501).runtime(b)['started']
        self.assertEqual(self.decisions.consume(sample([process()]))['kill'],[])
        self.authority.manage(501,'add-targets',{'id':b['id'],'applications':['binary:/tmp/game']})
        self.assertEqual(len(self.decisions.consume(sample([process()]))['kill']),1)
        self.assertEqual(self.store.state['blocks'][0]['lock']['until'],until)
        self.assertEqual(self.authority.engine(501).runtime(b)['started'],started)
    def test_account_allowance_ledger_respected_independently(self):
        b=self.block(**{'break':{'type':'allowance','allowance_minutes':1}})
        bob=self.authority.engine(502);bob.store.charge(self.clock.now,b['id'],60)
        result=self.decisions.consume(sample([process(),process(900002,502,'b')]))
        self.assertEqual([x['uid'] for x in result['kill']],[502])
    def test_expired_rule_stops_targeting(self):
        b=self.block();self.authority.manage(501,'lock',{'id':b['id'],'type':'timer','until':self.clock.now+1})
        self.clock.advance(2);self.authority.manage(501,'toggle',{'id':b['id'],'enabled':False})
        self.assertEqual(self.decisions.consume(sample([process()]))['kill'],[])
    def test_invalid_frame_is_rejected_before_runtime_or_statistics_changes(self):
        self.block();before=copy.deepcopy(self.store.state)
        cases=[sample([{**process(),'pid':True}]),sample([{**process(),'uid':0}]),sample([{**process(),'identity':'forged'}]),sample([{**process(),'executable':'relative'}]),sample([process(),process(token='b')]),sample([process(),process(900002)]),sample([process()], [ack(process())]),{**sample(),'front':process()},sample([{**process(),'bundle':[]}])]
        for value in cases:
            with self.subTest(value=value),self.assertRaises(ValueError):self.decisions.consume(value)
            self.assertEqual(self.store.state,before)
    def test_ack_cannot_claim_a_different_uid_or_omit_an_action(self):
        self.block();app=process();self.decisions.consume(sample([app]))
        for results in [[],[{**ack(app),'uid':502}],[ack(app),ack(app)],[{**ack(app),'signal':0}]]:
            with self.subTest(results=results),self.assertRaises(ValueError):self.decisions.consume(sample([],results))
        self.assertEqual(self.store.statistics()['totals']['blocked'],0)
    def test_unknown_account_is_not_created(self):
        self.block();self.assertEqual(self.decisions.consume(sample([process(uid=999)]))['kill'],[])
        self.assertNotIn(999,self.authority.engines)
    def test_frame_and_command_limits(self):
        self.block()
        with patch('hotturkey.system_enforcement.MAX_PROCESSES',0),self.assertRaises(ValueError):self.decisions.consume(sample([process()]))
        with patch('hotturkey.system_enforcement.MAX_KILLS',1),self.assertRaises(ValueError):self.decisions.consume(sample([process(),process(900002,token='b')]))
    def test_session_inventory_is_fresh_account_scoped_and_copied(self):
        execution=SystemExecution(self.authority,'unused')
        execution.inventory={501:[process()],502:[process(900002,502,'b')]}
        self.assertEqual(execution.applications(501),[])
        execution.state='running';execution.last_sample=100
        with patch('hotturkey.system_enforcement.time.monotonic',return_value=102):
            apps=execution.applications(501);self.assertEqual([a['uid'] for a in apps],[501])
            apps[0]['uid']=0;self.assertEqual(execution.applications(501)[0]['uid'],501)
        with patch('hotturkey.system_enforcement.time.monotonic',return_value=104):self.assertEqual(execution.applications(501),[])
    def test_invalid_start_fields_rejected_before_policy_changes(self):
        self.block();before=copy.deepcopy(self.store.state)
        for fields in [{'start_sec':True},{'start_usec':1000000},{'start_sec':-1}]:
            with self.subTest(fields=fields),self.assertRaises(ValueError):self.decisions.consume(sample([{**process(),**fields}]))
            self.assertEqual(self.store.state,before)
    def test_extension_heartbeat_grace_and_expiry_drive_browser_enforcement(self):
        b=self.block(applications=[]);self.authority.manage(501,'lock',{'id':b['id'],'type':'timer','until':self.clock.now+600})
        self.store.state['settings']['require_extension']=True
        browser={**process(),'bundle':'com.microsoft.edgemac','start_sec':int(self.clock.now),'start_usec':0}
        self.assertEqual(self.decisions.consume(sample([browser]))['kill'],[])
        self.clock.advance(61);self.assertEqual(len(self.decisions.consume(sample([browser]))['kill']),1)
        self.authority.engine(501).heartbeats['Edge']={'at':self.clock.now}
        self.assertEqual(self.decisions.consume(sample([browser],[ack(browser,'stale',0)]))['kill'],[])
        self.clock.advance(61);self.assertEqual(len(self.decisions.consume(sample([browser]))['kill']),1)
    def test_strictness_is_limited_to_locked_accounts_and_protected_paths(self):
        b=self.block(applications=[],users=['alice']);self.authority.manage(501,'lock',{'id':b['id'],'type':'timer','until':self.clock.now+600})
        self.store.state['settings']['block_task_manager']=True
        apps=[{**process(),'bundle':'com.apple.ActivityMonitor'},{**process(900002,502,'b'),'bundle':'com.apple.ActivityMonitor'},
              {**process(900003,token='c',path='/protected/install/monitor'),'bundle':'com.apple.ActivityMonitor'}]
        self.assertEqual([v['uid'] for v in self.decisions.consume(sample(apps))['kill']],[501])
    def test_executor_failure_stops_server_and_cleans_socket(self):
        class Failed:
            def run(self,stop):raise RuntimeError('Do not expose executable paths')
            def status(self):return {'status':'failed'}
        path=Path(self.temp.name)/'control';server=AuthorityServer(self.authority,path,lambda _:None,execution=Failed());server.bind();errors=[]
        def run():
            try:server.serve_forever()
            except RuntimeError as e:errors.append(str(e))
        thread=threading.Thread(target=run);thread.start();thread.join(timeout=3)
        self.assertFalse(thread.is_alive());self.assertFalse(path.exists());self.assertEqual(errors,['Protected process enforcement failed'])


if __name__=='__main__':unittest.main()
