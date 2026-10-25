import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from hotturkey.system_transaction import FileTransaction,installation_lock


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/private/tmp');self.root=Path(self.temp.name)
        self.journals=self.root/'journals';self.journals.mkdir(mode=0o700)
        self.targets={'program':self.root/'program','database':self.root/'database','daemon':self.root/'daemon.plist'}
        self.journal=self.journals/'transaction.json'
    def tearDown(self):self.temp.cleanup()
    def transaction(self,resume=False):return FileTransaction(self.journal,self.targets,owner_uid=os.getuid(),anchor=self.root,resume=resume)
    def stage(self,text):
        path=self.root/('.hotturkey-stage-'+uuid.uuid4().hex);path.write_text(text);path.chmod(0o600);return path
    def test_multiple_swaps_roll_back_in_reverse_order_with_original_bytes(self):
        self.targets['program'].write_text('old-program');self.targets['database'].mkdir();(self.targets['database']/'db').write_text('old-data')
        transaction=self.transaction();transaction.publish('program',self.stage('new-program'))
        staged=self.root/('.hotturkey-stage-'+uuid.uuid4().hex);staged.mkdir();(staged/'db').write_text('new-data')
        transaction.publish('database',staged);transaction.publish('daemon',self.stage('new-plist'))
        transaction.rollback();transaction.rollback()
        self.assertEqual(self.targets['program'].read_text(),'old-program');self.assertEqual((self.targets['database']/'db').read_text(),'old-data')
        self.assertFalse(self.targets['daemon'].exists());self.assertEqual(self.transaction(True).recover(),'rolled-back')
    def test_commit_barrier_preserves_new_data_and_removes_backups(self):
        self.targets['program'].write_text('old');transaction=self.transaction();transaction.publish('program',self.stage('new'))
        transaction.commit();transaction.commit()
        self.assertEqual(self.targets['program'].read_text(),'new');self.assertFalse(list(self.root.glob('.hotturkey-backup-*')))
        with self.assertRaises(ValueError):transaction.rollback()
    def test_interruption_between_renames_is_recovered_from_intent(self):
        self.targets['program'].write_text('old');transaction=self.transaction();staged=self.stage('new');rename=Path.rename
        def fail_new(path,target):
            if path==staged:raise OSError('simulated power loss')
            return rename(path,target)
        with patch.object(Path,'rename',fail_new):
            with self.assertRaises(OSError):transaction.publish('program',staged)
        self.assertFalse(self.targets['program'].exists())
        self.assertEqual(self.transaction(True).recover(),'rolled-back');self.assertEqual(self.targets['program'].read_text(),'old')
    def test_interruption_after_publish_before_commit_restores_original(self):
        transaction=self.transaction();transaction.publish('program',self.stage('new'));self.assertTrue(self.targets['program'].exists())
        self.assertEqual(self.transaction(True).recover(),'rolled-back');self.assertFalse(self.targets['program'].exists())
    def test_interruption_during_commit_only_finishes_cleanup(self):
        self.targets['program'].write_text('old');transaction=self.transaction();transaction.publish('program',self.stage('new'))
        with patch.object(transaction,'remove_owned',side_effect=OSError('interrupted cleanup')):
            with self.assertRaises(OSError):transaction.commit()
        self.assertEqual(self.transaction(True).recover(),'committed');self.assertEqual(self.targets['program'].read_text(),'new')
    def test_atomic_journal_temp_left_after_crash_is_removed_on_resume(self):
        transaction=self.transaction();transaction.publish('program',self.stage('new'))
        temporary=self.journal.with_name(self.journal.name+'.new');temporary.write_text('partial uncommitted journal')
        self.assertEqual(self.transaction(True).recover(),'rolled-back');self.assertFalse(temporary.exists())
    def test_existing_journal_cannot_be_overwritten(self):
        self.transaction();before=self.journal.read_bytes()
        with self.assertRaises(FileExistsError):self.transaction()
        self.assertEqual(self.journal.read_bytes(),before)
    def test_backup_collision_cannot_be_mistaken_for_our_old_program(self):
        self.targets['program'].write_text('old');transaction=self.transaction()
        backup=self.root/('.hotturkey-backup-'+transaction.value['id']+'-program');backup.write_text('unrelated')
        with self.assertRaises(FileExistsError):transaction.publish('program',self.stage('new'))
        transaction.rollback();self.assertEqual(self.targets['program'].read_text(),'old');self.assertEqual(backup.read_text(),'unrelated')
    def test_journal_cannot_redirect_paths_or_recover_unknown_steps(self):
        self.transaction();value=json.loads(self.journal.read_text());value['targets']['program']='/etc/hosts';self.journal.write_text(json.dumps(value))
        with self.assertRaises(ValueError):self.transaction(True)
        value['targets']['program']=str(self.targets['program']);value['steps']=[{'key':'program','stage':'../../etc/hosts','had_original':False,'rolled_back':False}]
        self.journal.write_text(json.dumps(value))
        with self.assertRaises(ValueError):self.transaction(True)
    def test_links_writable_targets_and_foreign_stages_are_rejected(self):
        transaction=self.transaction();external=self.root/'outside';external.write_text('keep');self.targets['program'].symlink_to(external)
        with self.assertRaises(PermissionError):transaction.publish('program',self.stage('new'))
        self.targets['program'].unlink();self.targets['program'].write_text('keep');self.targets['program'].chmod(0o666)
        with self.assertRaises(PermissionError):transaction.publish('program',self.stage('new'))
        self.targets['program'].chmod(0o644)
        with self.assertRaises(ValueError):transaction.publish('program',external)
        self.assertEqual(external.read_text(),'keep');self.assertEqual(transaction.value['steps'],[])
    def test_trust_boundary_symlink_directory_and_overlapping_targets_rejected(self):
        with self.assertRaises(PermissionError):FileTransaction(self.journal,{'outside':self.root.parent/'outside'},owner_uid=os.getuid(),anchor=self.root)
        linked=self.root/'linked';linked.symlink_to(self.journals)
        with self.assertRaises(PermissionError):FileTransaction(linked/'new.json',self.targets,owner_uid=os.getuid(),anchor=self.root)
        with self.assertRaises(ValueError):FileTransaction(self.journal,{'one':self.root/'tree','two':self.root/'tree/child'},owner_uid=os.getuid(),anchor=self.root)
    def test_install_lock_excludes_other_operations_and_rejects_symlinks(self):
        with installation_lock(self.journals,owner_uid=os.getuid(),anchor=self.root):
            with self.assertRaises(RuntimeError):
                with installation_lock(self.journals,owner_uid=os.getuid(),anchor=self.root):pass
        lock=self.journals/'install.lock';lock.unlink();lock.symlink_to(self.root/'unexpected')
        with self.assertRaises(OSError):
            with installation_lock(self.journals,owner_uid=os.getuid(),anchor=self.root):pass


if __name__=='__main__':unittest.main()
