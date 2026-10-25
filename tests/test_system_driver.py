import dataclasses
import hashlib
import json
import os
import plistlib
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch

from hotturkey import system_driver as module
from hotturkey.engine import Engine,password_hash
from hotturkey.service_lease import ServiceLease
from hotturkey.store import Store
from hotturkey.system_cutover import CutoverCoordinator
from hotturkey.system_migration import snapshot_database,migrate_database


class Jobs:
    def __init__(self,uid):
        self.uid=uid;self.loaded={'legacy'};self.events=[];self.fail_load=False;self.fail_stop=False;self.frozen=False
        self.authority=SimpleNamespace(name='authority');self.legacy=SimpleNamespace(name='legacy');self.control=SimpleNamespace(loaded=lambda job:job.name in self.loaded)
    def capture(self):return {'legacy_loaded':'legacy' in self.loaded,'authority_loaded':'authority' in self.loaded,'session_loaded':[],'gui_uids':[self.uid]}
    def gui_uids(self):return [self.uid]
    def save_legacy(self):self.events.append('save_legacy')
    def stop(self,name,before_unload):
        if name not in self.loaded:return False
        self.events.append('stop_'+name);self.frozen=True;before_unload(SimpleNamespace(groups={100001}))
        if self.fail_stop:raise OSError('Injected stop failure')
        self.loaded.remove(name);self.frozen=False;return True
    def stop_legacy(self,**values):return self.stop('legacy',**values)
    def stop_authority(self,**values):return self.stop('authority',**values)
    def stop_session(self,uid,**values):return False
    def load_authority(self):
        self.events.append('load_authority');self.loaded.add('authority')
        if self.fail_load:raise OSError('Injected candidate start failure')
    def load_legacy(self):self.events.append('load_legacy');self.loaded.add('legacy')
    def load_session(self,uid):self.loaded.add('session')
    def unload_session(self,uid):self.loaded.discard('session')
    def resume_legacy(self):self.events.append('resume_legacy');self.frozen=False
    def resume_authority(self):self.events.append('resume_authority');self.frozen=False
    def resume_session(self,uid):pass


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/private/tmp');self.root=Path(self.temp.name);self.uid=os.getuid()
        registry=self.root/'registry';folder=registry/'jobs'/('a'*32);folder.mkdir(parents=True,mode=0o700)
        self.layout=module._Layout(folder,registry,self.root/'program',self.root/'database',registry/'activation.json',self.root/'daemon.plist',self.root/'session.plist',self.root/'runtime',self.root/'legacy',self.root,self.uid)
        artifact=self.layout.artifact;(artifact/'project/hotturkey').mkdir(parents=True)
        (artifact/'project/hotturkey/service_lease.py').write_text('fixture')
        (artifact/'payload.json').write_text('{}')
        for name in ['authority.plist','session.plist']:(artifact/name).write_bytes(plistlib.dumps({'Label':'fixture'}))
        self.expected=hashlib.sha256(b'{}').hexdigest();self.jobs=Jobs(self.uid);self.drivers=[]
        store=Store(self.layout.legacy);engine=Engine(store,boot_id='fixture-boot');block=engine.save_block({'name':'Owned upgrade','enabled':True,'websites':['example.invalid']});self.ident=block['id']
        store.state['settings']['settings_password']=password_hash('fixture password');store.charge(time.time(),self.ident,123);store.save();store.db.close()
        with ServiceLease(self.layout.legacy/'.install.lock'):pass
        with ServiceLease(self.layout.legacy/'service.lock'):pass
        (folder/'preflight').mkdir(mode=0o700);snapshot_database(self.layout.legacy/'hotturkey.sqlite3',folder/'preflight/hotturkey.sqlite3',self.uid)
        self.boot=patch.object(module,'boot_id',return_value='fixture-boot');self.boot.start()
        self.verify=patch.object(module,'verify_payload',return_value={'controller_uid':self.uid});self.verifier=self.verify.start()
        self.approval=module._approve(self.layout,self.uid,self.expected,'fixture password')
    def tearDown(self):
        for driver in self.drivers:driver.close()
        self.verify.stop();self.boot.stop();self.temp.cleanup()
    def driver(self,approval=True):
        def client(timeout):
            if 'authority' not in self.jobs.loaded:return None
            marker=json.loads(self.layout.marker.read_text())
            return {'installation_pending':marker['phase']=='pending','executor_ready':True,'session_transport_fresh':True,
                'session_transport_uids':[self.uid],'installation_transaction':marker['transaction'],'payload_sha256':self.expected}
        driver=module._Driver(self.layout,self.jobs,self.uid,self.expected,self.approval if approval else None,client=client)
        driver.worker=lambda context:module._stage(self.layout,context,driver.records);self.drivers.append(driver);return driver
    def used(self,directory,ident):
        store=Store(directory)
        try:
            if 'authority_version' in store.state:
                from hotturkey.authority import PolicyAuthority
                return PolicyAuthority(store,self.uid,boot_id='fixture-boot').engine(self.uid).store.used(ident,0)
            return store.used(ident,0)
        finally:store.db.close()
    def test_source_password_and_private_owner_checked_before_services(self):
        with self.assertRaises(PermissionError):module._approve(self.layout,self.uid,self.expected,'wrong')
        self.assertEqual(self.jobs.events,[])
        path=self.layout.folder/'preflight/hotturkey.sqlite3';path.chmod(0o644)
        with self.assertRaises(PermissionError):module._approve(self.layout,self.uid,self.expected,'fixture password')
    def test_missing_stale_foreign_and_invalid_approval_cannot_start_cutover(self):
        for approval in [None,dataclasses.replace(self.approval,expires=0),dataclasses.replace(self.approval,payload_sha256='b'*64),dataclasses.replace(self.approval,expires=float('nan'))]:
            driver=self.driver();driver.approval=approval
            with self.subTest(approval=approval),self.assertRaises(PermissionError):driver.coordinator().apply()
        self.assertEqual(self.jobs.events,[]);self.assertFalse(self.layout.program.exists())
    def test_full_driver_stages_migration_then_activation_without_changing_source(self):
        driver=self.driver();result=driver.coordinator().apply();self.assertEqual(result['status'],'finished')
        self.assertNotIn('legacy',self.jobs.loaded);self.assertIn('authority',self.jobs.loaded)
        self.assertEqual(self.used(self.layout.legacy,self.ident),123);self.assertEqual(self.used(self.layout.database,self.ident),123)
        self.assertEqual(json.loads(self.layout.marker.read_text())['phase'],'committed')
        self.assertIsNone(driver.installation_lock_fd)
        calls=list(self.jobs.events);self.assertEqual(self.driver(False).coordinator().recover(),result);self.assertEqual(self.jobs.events,calls)
    def test_failed_candidate_rolls_back_files_and_resumes_legacy(self):
        self.jobs.fail_load=True;driver=self.driver()
        with self.assertRaises(OSError):driver.coordinator().apply()
        self.assertEqual(self.jobs.loaded,{'legacy'});self.assertIn('resume_legacy',self.jobs.events)
        self.assertFalse(self.layout.program.exists());self.assertFalse(self.layout.database.exists())
        self.assertEqual(self.used(self.layout.legacy,self.ident),123)
    def test_failed_old_stop_resumes_frozen_job_without_publishing(self):
        self.jobs.fail_stop=True
        with self.assertRaises(OSError):self.driver().coordinator().apply()
        self.assertFalse(self.jobs.frozen);self.assertEqual(self.jobs.loaded,{'legacy'});self.assertFalse(self.layout.program.exists())
    def test_failed_durability_flush_restores_old_without_publishing(self):
        with patch.object(module,'_sync_stages',side_effect=OSError('Flush failed')):
            with self.assertRaises(OSError):self.driver().coordinator().apply()
        self.assertEqual(self.jobs.loaded,{'legacy'});self.assertFalse(self.layout.program.exists())
        self.assertFalse(list(self.root.glob('.hotturkey-stage-*')));self.assertEqual(self.used(self.layout.legacy,self.ident),123)
    def test_unapproved_manifest_is_rejected_before_executing_payload_verifiers(self):
        (self.layout.artifact/'payload.json').write_text('{"changed":true}')
        with self.assertRaises(PermissionError):self.driver().coordinator().apply()
        self.verifier.assert_not_called();self.assertEqual(self.jobs.events,[])
    def test_credential_rotation_after_approval_is_not_ignored(self):
        store=Store(self.layout.legacy);store.state['settings']['settings_password']=password_hash('new password');store.save();store.db.close()
        with self.assertRaises(PermissionError):self.driver().coordinator().apply()
        self.assertEqual(self.jobs.loaded,{'legacy'});self.assertFalse(self.layout.database.exists())
        store=Store(self.layout.legacy)
        try:self.assertNotEqual(module._credential(store.state)[1],self.approval.credential_fingerprint)
        finally:store.db.close()
    def test_new_lock_after_approval_prevents_migration_and_is_preserved(self):
        store=Store(self.layout.legacy);engine=Engine(store,boot_id='fixture-boot');engine.set_lock(self.ident,{'type':'timer','until':time.time()+3600});before=store.state['blocks'][0]['lock'];store.db.close()
        with self.assertRaises(ValueError):self.driver().coordinator().apply()
        self.assertEqual(self.jobs.loaded,{'legacy'});store=Store(self.layout.legacy)
        try:self.assertEqual(store.state['blocks'][0]['lock'],before)
        finally:store.db.close()
    def test_after_commit_recovery_keeps_new_policy_and_never_restarts_old(self):
        driver=self.driver();activate=driver.activate
        def interrupted(context):activate(context);raise OSError('After activation')
        driver.activate=interrupted
        with self.assertRaises(OSError):driver.coordinator().apply()
        store=Store(self.layout.database);store.state['blocks'][0]['websites'].append('kept.invalid');store.save();store.db.close()
        self.assertEqual(self.driver(False).coordinator().recover()['status'],'finished');self.assertNotIn('legacy',self.jobs.loaded)
        store=Store(self.layout.database)
        try:self.assertIn('kept.invalid',store.state['blocks'][0]['websites'])
        finally:store.db.close()
    def test_existing_system_data_swap_does_not_confuse_old_and_candidate_locks(self):
        shutil.copytree(self.layout.artifact,self.layout.program)
        migrate_database(self.layout.legacy/'hotturkey.sqlite3',self.layout.database,self.uid,self.uid,'fixture-boot',__import__('pwd').getpwuid)
        with ServiceLease(self.layout.database/'service.lock'):pass
        shutil.rmtree(self.layout.folder/'preflight');(self.layout.folder/'preflight').mkdir(mode=0o700)
        snapshot_database(self.layout.database/'hotturkey.sqlite3',self.layout.folder/'preflight/hotturkey.sqlite3',self.uid)
        self.approval=module._approve(self.layout,self.uid,self.expected,'fixture password');self.jobs.loaded={'authority'}
        self.jobs.fail_load=True
        with self.assertRaises(OSError):self.driver().coordinator().apply()
        # First restoration failure is retryable with the unchanged old data.
        self.jobs.fail_load=False
        self.assertEqual(self.driver(False).coordinator().recover()['status'],'rolled-back')
        self.assertEqual(self.used(self.layout.database,self.ident),123)
    def test_production_factory_and_approval_entry_refuse_current_user(self):
        with patch.object(module.os,'geteuid',return_value=501):
            with self.assertRaises(PermissionError):module.ProtectedDriver(501,'a'*32,self.expected)
            with self.assertRaises(PermissionError):module.approve_private_copy(501,'a'*32,self.expected,'')


class WorkerContractTests(unittest.TestCase):
    def setUp(self):
        self.layout=SimpleNamespace(artifact=Path('/private/tmp/owned-payload'),folder=Path('/private/tmp/jobs/'+'a'*32),targets={})
        self.context={'transaction':'b'*32,'controller_uid':501,'payload_sha256':'c'*64}

    def test_bounded_isolated_worker_inherits_all_handoff_descriptors(self):
        process=Mock(returncode=0);process.communicate.return_value=(b'{"ok":true}',None)
        with patch.object(module.subprocess,'Popen',return_value=process) as spawn:
            self.assertEqual(module._run_worker(self.layout,self.context,10,[11,12]),{})
        args,options=spawn.call_args
        self.assertEqual(args[0][1:4],['-I','-B','-c'])
        self.assertEqual(args[0][0],str(self.layout.artifact/'HotTurkey.app/Contents/Resources/python/bin/python3'))
        self.assertEqual(options['pass_fds'],(10,11,12));self.assertTrue(options['close_fds'])
        self.assertEqual(options['cwd'],'/');self.assertEqual(options['env'],{'PATH':'/usr/bin:/bin'})
        request=json.loads(process.communicate.call_args.args[0]);self.assertEqual(request,{'context':self.context,'lock_fd':10,'lease_fds':[11,12]})
        self.assertEqual(process.communicate.call_args.kwargs['timeout'],45);process.kill.assert_not_called()

    def test_timed_out_worker_is_reaped_before_recovery_can_continue(self):
        import subprocess
        process=Mock();process.communicate.side_effect=subprocess.TimeoutExpired('private worker',45);process.poll.return_value=None
        with patch.object(module.subprocess,'Popen',return_value=process),self.assertRaises(subprocess.TimeoutExpired):
            module._run_worker(self.layout,self.context,10,[])
        process.kill.assert_called_once_with();process.wait.assert_called_once_with(timeout=5)

    def test_missing_lock_or_noncanonical_result_cannot_publish_stages(self):
        with patch.object(module.subprocess,'Popen') as spawn,self.assertRaises(RuntimeError):
            module._run_worker(self.layout,self.context,None,[])
        spawn.assert_not_called()
        for result in [b'{"ok":false}',b'{"ok":true,"extra":1}',b'x'*4097]:
            process=Mock(returncode=0);process.communicate.return_value=(result,None);process.poll.return_value=0
            with self.subTest(result=result[:50]),patch.object(module.subprocess,'Popen',return_value=process),self.assertRaises(RuntimeError):
                module._run_worker(self.layout,self.context,10,[])
            process.kill.assert_not_called()


if __name__=='__main__':unittest.main()
