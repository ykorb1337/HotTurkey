import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from hotturkey.system_cutover import CutoverCoordinator,CutoverDriver,health_matches,pending_cutover,staging_paths
from hotturkey.system_transaction import FileTransaction,installation_lock,write_private_record


class Clock:
    def __init__(self):self.value=0
    def mono(self):return self.value
    def wall(self):return 1000+self.value
    def sleep(self,seconds):self.value+=seconds


class Driver(CutoverDriver):
    def __init__(self,targets,clock):
        self.targets=targets;self.clock=clock;self.calls=[];self.fail=None;self.restore_fails=False;self.state='old'
        self.services={'legacy_loaded':True,'authority_loaded':False,'session_loaded':[],'gui_uids':[501]}
        self.uids=[501];self.required=None;self.bad_epoch=False;self.never_healthy=False;self.slow_stage=False;self.mutate=False;self.after_activate_fails=False
    def event(self,name):
        self.calls.append(name)
        if self.fail==name:raise OSError('fixture '+name)
    def authorize(self):self.event('authorize')
    def capture(self):self.event('capture');return copy.deepcopy(self.services)
    def stop_previous(self,context):
        self.state=None;self.event('stop_previous')
        if self.mutate:context['controller_uid']=999
    def stage(self,context):
        self.calls.append('stage');stages=staging_paths(self.targets,context['transaction'])
        for key,path in stages.items():
            value={'program':'new','data':self.targets['data'].read_text(),'activation':'pending'}[key]
            path.write_text(value);path.chmod(0o600)
            if self.fail=='stage':raise OSError('fixture partial stage')
        if self.slow_stage:self.clock.sleep(5)
        return stages
    def start_candidate(self,context):
        self.event('start_candidate')
        if self.state not in {'pending','committed'}:self.state=self.targets['activation'].read_text()
    def probe_candidate(self,context,*,timeout):
        self.event('probe_candidate')
        if self.never_healthy or self.state not in {'pending','committed'}:return None
        return {'installation_pending':self.state=='pending','executor_ready':True,'session_transport_fresh':501 in self.uids,
                'session_transport_uids':self.uids,'installation_transaction':'f'*32 if self.bad_epoch else context['transaction'],'payload_sha256':context['payload_sha256']}
    def required_sessions(self,context):return self.required if self.required is not None else super().required_sessions(context)
    def activate(self,context):
        self.event('activate')
        if self.state!='committed':
            self.state='committed';self.targets['activation'].write_text('committed');self.targets['data'].write_text('77')
        if self.after_activate_fails:raise OSError('fixture after activation')
    def stop_candidate(self,context):self.state=None;self.event('stop_candidate')
    def restore_previous(self,context):
        self.event('restore_previous')
        if self.restore_fails:raise OSError('fixture restoring services')
        self.state='old' if context['services']['legacy_loaded'] or context['services']['authority_loaded'] else None


class CutoverTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/private/tmp');self.root=Path(self.temp.name)
        self.registry=self.root/'registry';self.registry.mkdir(mode=0o700);self.folder=self.registry/'job';self.folder.mkdir(mode=0o700)
        self.targets={name:self.root/name for name in ['program','data','activation']}
        for name,value in [('program','old'),('data','42'),('activation','old')]:self.targets[name].write_text(value);self.targets[name].chmod(0o600)
        self.clock=Clock();self.driver=Driver(self.targets,self.clock)
    def tearDown(self):self.temp.cleanup()
    def coordinator(self,**values):return CutoverCoordinator(self.folder,self.targets,self.driver,501,values.pop('payload','a'*64),lock_directory=self.registry,
        owner_uid=os.getuid(),anchor=self.root,timeout=1,clock=self.clock.mono,wall=self.clock.wall,sleep=self.clock.sleep,**values)
    def original(self):
        self.assertEqual(self.targets['program'].read_text(),'old');self.assertEqual(self.targets['data'].read_text(),'42');self.assertEqual(self.targets['activation'].read_text(),'old')
    def no_stages(self):self.assertFalse(list(self.root.glob('.hotturkey-stage-*')))
    def untouched(self):
        coordinator=self.coordinator()
        coordinator.files=FileTransaction(coordinator.journal,self.targets,owner_uid=os.getuid(),anchor=self.root)
        coordinator.context={'version':1,'transaction':coordinator.files.value['id'],'controller_uid':501,'payload_sha256':'a'*64,
            'services':copy.deepcopy(self.driver.services),'phase':'ready','expires_at':1001,'stages_reserved':False,'services_touched':False}
        coordinator.transition('ready',initial=True)
        return coordinator
    def test_success_has_durable_commit_then_activation_and_idempotent_recovery(self):
        coordinator=self.coordinator();self.assertEqual(coordinator.apply()['status'],'finished')
        self.assertEqual(self.targets['program'].read_text(),'new');self.assertEqual(self.targets['data'].read_text(),'77')
        self.assertEqual(coordinator.files.value['status'],'committed');self.assertEqual(self.driver.state,'committed');self.no_stages()
        calls=list(self.driver.calls);self.assertEqual(self.coordinator().recover()['status'],'finished');self.assertEqual(self.driver.calls,calls)
        self.assertLess(calls.index('stop_previous'),calls.index('stage'));self.assertLess(calls.index('probe_candidate'),calls.index('activate'))
    def test_authorization_failure_never_stops_services_or_creates_a_transaction(self):
        self.driver.fail='authorize'
        with self.assertRaises(OSError):self.coordinator().apply()
        self.original();self.assertEqual(self.driver.state,'old');self.assertFalse((self.folder/'files.json').exists())
    def test_partial_old_service_stop_is_restored(self):
        self.driver.fail='stop_previous'
        with self.assertRaises(OSError):self.coordinator().apply()
        self.original();self.assertEqual(self.driver.state,'old');self.assertEqual(json.loads((self.folder/'services.json').read_text())['phase'],'rolled-back')
    def test_failed_staging_cleans_reserved_orphans_and_restores_services(self):
        self.driver.fail='stage'
        with self.assertRaises(OSError):self.coordinator().apply()
        self.original();self.no_stages();self.assertEqual(self.driver.state,'old')
    def test_partial_publication_is_reverted_before_old_services_start(self):
        publish=FileTransaction.publish
        def interrupted(transaction,key,stage):
            publish(transaction,key,stage)
            if key=='program':raise OSError('fixture after first swap')
        with patch.object(FileTransaction,'publish',interrupted):
            with self.assertRaises(OSError):self.coordinator().apply()
        self.original();self.no_stages();self.assertEqual(self.driver.state,'old')
    def test_health_from_another_transaction_cannot_authorize_commit(self):
        self.driver.bad_epoch=True
        with self.assertRaises(TimeoutError):self.coordinator().apply()
        self.original();self.assertEqual(self.driver.state,'old')
    def test_missing_required_session_times_out_without_committing(self):
        self.driver.services['gui_uids']=[501,502]
        with self.assertRaises(TimeoutError):self.coordinator().apply()
        self.original();self.assertEqual(self.driver.state,'old')
    def test_current_session_set_can_handle_a_logout_during_installation(self):
        self.driver.services['gui_uids']=[501,502];self.driver.required=[501]
        self.assertEqual(self.coordinator().apply()['status'],'finished')
    def test_install_deadline_does_not_hold_old_rules_off_indefinitely(self):
        self.driver.slow_stage=True
        with self.assertRaises(TimeoutError):self.coordinator().apply()
        self.original();self.no_stages();self.assertEqual(self.driver.state,'old')
    def test_driver_cannot_mutate_the_persisted_controller_context(self):
        self.driver.mutate=True;self.coordinator().apply()
        self.assertEqual(json.loads((self.folder/'services.json').read_text())['controller_uid'],501)
    def test_committed_failure_must_finish_forward_and_keep_new_usage(self):
        self.driver.after_activate_fails=True;coordinator=self.coordinator()
        with self.assertRaises(OSError):coordinator.apply()
        self.assertEqual(coordinator.files.value['status'],'committed');self.assertNotIn('restore_previous',self.driver.calls)
        self.targets['data'].write_text('99');self.driver.after_activate_fails=False
        self.assertEqual(self.coordinator().recover()['status'],'finished');self.assertEqual(self.targets['data'].read_text(),'99')
    def test_interrupted_service_restoration_is_retried_without_republishing_data(self):
        self.driver.fail='stage';self.driver.restore_fails=True
        with self.assertRaises(OSError):self.coordinator().apply()
        self.original();self.driver.fail=None;self.driver.restore_fails=False
        self.assertEqual(self.coordinator().recover()['status'],'rolled-back');self.assertEqual(self.driver.state,'old')
        self.original();self.no_stages()
    def test_capture_cannot_smuggle_commands_passwords_or_claimed_uid_types(self):
        self.driver.services['command']='arbitrary'
        with self.assertRaises(ValueError):self.coordinator().apply()
        self.original();self.assertEqual(self.driver.calls,['authorize','capture'])
    def test_stage_collision_is_not_deleted_and_does_not_restart_old_services(self):
        path=staging_paths(self.targets,'b'*32)['program'];path.write_text('unrelated');path.chmod(0o600)
        with patch('hotturkey.system_transaction.uuid.uuid4',return_value=SimpleNamespace(hex='b'*32)):
            with self.assertRaises(FileExistsError):self.coordinator().apply()
        self.original();self.assertEqual(path.read_text(),'unrelated');self.assertEqual(self.driver.calls,['authorize','capture'])
    def test_empty_or_initially_interrupted_records_have_idempotent_no_service_recovery(self):
        self.assertEqual(self.coordinator().recover()['status'],'empty')
        FileTransaction(self.folder/'files.json',self.targets,owner_uid=os.getuid(),anchor=self.root)
        temporary=self.folder/'services.json.new';temporary.write_text('partial');temporary.chmod(0o600)
        self.assertEqual(self.coordinator().recover()['status'],'rolled-back')
        self.assertEqual(self.coordinator().recover()['status'],'rolled-back');self.assertFalse(temporary.exists());self.assertEqual(self.driver.calls,[])
    def test_wrong_payload_context_is_rejected_before_any_service_action(self):
        self.driver.after_activate_fails=True
        with self.assertRaises(OSError):self.coordinator().apply()
        calls=list(self.driver.calls)
        with self.assertRaises(ValueError):self.coordinator(payload='c'*64).recover()
        self.assertEqual(self.driver.calls,calls)
    def test_global_installation_lock_covers_the_entire_cutover(self):
        with installation_lock(self.registry,owner_uid=os.getuid(),anchor=self.root):
            with self.assertRaises(RuntimeError):self.coordinator().apply()
        self.assertEqual(self.driver.calls,[]);self.original()
    def test_pending_transaction_blocks_a_different_job_before_authorization(self):
        self.driver.after_activate_fails=True
        with self.assertRaises(OSError):self.coordinator().apply()
        active=pending_cutover(self.registry,owner_uid=os.getuid(),anchor=self.root)
        self.assertEqual(active['directory'],'job')
        calls=list(self.driver.calls);self.folder=self.registry/'another';self.folder.mkdir(mode=0o700)
        with self.assertRaises(FileExistsError):self.coordinator().apply()
        self.assertEqual(self.driver.calls,calls);self.assertFalse((self.folder/'files.json').exists())
        with self.assertRaises(ValueError):self.coordinator().recover()
        self.assertEqual(self.driver.calls,calls)
    def test_unpublished_registration_recovers_without_stopping_services(self):
        coordinator=self.untouched();temporary=self.registry/'active.json.new'
        for complete in [False,True]:
            content=json.dumps(coordinator.index_value()) if complete else '{'
            with self.subTest(complete=complete):
                temporary.write_text(content);temporary.chmod(0o600)
                with self.assertRaises(ValueError):pending_cutover(self.registry,owner_uid=os.getuid(),anchor=self.root)
                self.assertEqual(self.coordinator().recover()['status'],'rolled-back')
                self.assertFalse(temporary.exists());self.assertEqual(self.driver.calls,[]);self.original()
                # Recreate only the untouched fixture for the next interruption.
                (self.folder/'files.json').unlink();(self.folder/'services.json').unlink();coordinator=self.untouched()
    def test_unpublished_foreign_registration_is_preserved(self):
        coordinator=self.untouched();value=coordinator.index_value();value['directory']='another'
        temporary=self.registry/'active.json.new';temporary.write_text(json.dumps(value));temporary.chmod(0o600)
        with self.assertRaises(ValueError):self.coordinator().recover()
        self.assertEqual(json.loads(temporary.read_text()),value);self.assertEqual(self.driver.calls,[]);self.original()
    def test_touched_transaction_cannot_recover_with_a_missing_or_partial_index(self):
        self.driver.after_activate_fails=True
        with self.assertRaises(OSError):self.coordinator().apply()
        index=self.registry/'active.json';index.unlink();calls=list(self.driver.calls)
        with self.assertRaises(ValueError):self.coordinator().recover()
        temporary=index.with_name('active.json.new');temporary.write_text('{');temporary.chmod(0o600)
        with self.assertRaises(ValueError):self.coordinator().recover()
        self.assertEqual(self.driver.calls,calls);self.assertEqual(temporary.read_text(),'{')
    def test_terminal_index_cleanup_does_not_restart_services(self):
        coordinator=self.coordinator()
        with patch.object(coordinator,'clear_index',side_effect=OSError('fixture terminal cleanup')):
            with self.assertRaises(OSError):coordinator.apply()
        self.assertEqual(coordinator.context['phase'],'finished');calls=list(self.driver.calls)
        self.assertEqual(self.coordinator().recover()['status'],'finished');self.assertEqual(self.driver.calls,calls)
        self.assertIsNone(pending_cutover(self.registry,owner_uid=os.getuid(),anchor=self.root))
    def test_initial_index_hardlink_publication_is_recoverable(self):
        self.driver.after_activate_fails=True;coordinator=self.coordinator()
        with self.assertRaises(OSError):coordinator.apply()
        os.link(self.registry/'active.json',self.registry/'active.json.new');self.driver.after_activate_fails=False
        self.assertEqual(self.coordinator().recover()['status'],'finished')
        self.assertFalse((self.registry/'active.json.new').exists());self.assertFalse((self.registry/'active.json').exists())
    def test_index_cannot_choose_a_different_or_ambiguous_job_path(self):
        coordinator=self.untouched();calls=list(self.driver.calls)
        for directory in ['../job','/job','./job','job/','job//child','job/./child']:
            value=coordinator.index_value();value['directory']=directory
            write_private_record(self.registry/'active.json',value,initial=True,owner_uid=os.getuid(),anchor=self.root)
            with self.subTest(directory=directory),self.assertRaises(ValueError):self.coordinator().recover()
            (self.registry/'active.json').unlink()
        self.assertEqual(self.driver.calls,calls);self.original()


if __name__=='__main__':unittest.main()
