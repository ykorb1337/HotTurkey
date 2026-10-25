import copy
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hotturkey.authority import PolicyAuthority
from hotturkey.engine import Engine,password_hash
from hotturkey.model import PolicyError
from hotturkey.store import Store
from hotturkey.system_migration import migrate_database,snapshot_database
from test_authority import account


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.store=Store(self.root/'legacy')
        self.engine=Engine(self.store,boot_id='real-boot',user='alice');self.destination=self.root/'protected'
        self.block=self.engine.save_block({'name':'Focus','enabled':True,'websites':['example.invalid'],'break':{'type':'allowance','allowance_minutes':5}})
        self.store.charge(self.engine.now(),self.block['id'],123);self.store.event(self.engine.now(),'alice','website','example.invalid',seconds=42)
        self.engine.runtime(self.engine.find(self.block['id'])).update(reward_credit=30,break_until=self.engine.now()+60)
        self.store.state['settings'].update(settings_password=password_hash('fixture-settings'),device_recovery_hash=password_hash('fixture-recovery'))
        self.store.save();self.source=self.store.directory/'hotturkey.sqlite3'
    def tearDown(self):self.store.db.close();self.temp.cleanup()
    def migrate(self,**values):return migrate_database(self.source,self.destination,501,os.getuid(),'real-boot',account,**values)
    def test_private_migration_keeps_policy_credentials_statistics_charges_and_breaks(self):
        before=copy.deepcopy(self.store.state);events=self.store.export_statistics()
        result=self.migrate();self.assertEqual(result['rules'],1)
        migrated=Store(self.destination)
        try:
            authority=PolicyAuthority(migrated,501,resolve_user=account,boot_id='real-boot');engine=authority.engine(501)
            self.assertEqual(migrated.state['blocks'],before['blocks']);self.assertEqual(migrated.state['settings'],before['settings'])
            self.assertEqual(engine.store.used(self.block['id'],0),123);self.assertEqual(engine.runtime(engine.find(self.block['id']))['reward_credit'],30)
            self.assertEqual(migrated.export_statistics(),events)
            self.assertEqual(json.loads(self.store.db.execute('SELECT value FROM state').fetchone()[0]),before)
        finally:migrated.db.close()
    def test_repeated_protected_copy_does_not_double_prefix_charges(self):
        self.migrate();second=self.root/'second'
        migrate_database(self.destination/'hotturkey.sqlite3',second,501,os.getuid(),'real-boot',account)
        migrated=Store(second)
        try:
            authority=PolicyAuthority(migrated,501,resolve_user=account,boot_id='real-boot')
            self.assertEqual(authority.engine(501).store.used(self.block['id'],0),123)
            self.assertEqual(migrated.db.execute('SELECT block_id FROM charges').fetchone()[0],'uid:501:'+self.block['id'])
        finally:migrated.db.close()
    def test_wrong_controller_fails_without_touching_source(self):
        self.migrate();second=self.root/'second'
        with self.assertRaises(PolicyError):migrate_database(self.destination/'hotturkey.sqlite3',second,502,os.getuid(),'real-boot',account)
        self.assertFalse(second.exists());self.assertTrue(self.destination.exists())
    def test_timer_restart_and_device_schedule_locks_block_migration(self):
        block=self.engine.find(self.block['id'])
        for lock in [{'type':'timer','until':self.engine.now()+3600},{'type':'restart','boot_id':'real-boot'}]:
            block['lock']=lock;self.store.save()
            with self.assertRaises(PolicyError):self.migrate()
            self.assertFalse(self.destination.exists());self.assertEqual(self.engine.find(block['id'])['lock'],lock)
        block['lock']={'type':'none'};block.update(device='sleep',mode='scheduled',schedule=[{'days':list(range(7)),'start':0,'end':1440}]);self.store.save()
        with self.assertRaises(PolicyError):self.migrate()
    def test_wal_snapshot_includes_committed_records_without_mutating_source(self):
        self.store.db.execute('PRAGMA wal_autocheckpoint=0');self.store.save()
        self.store.charge(self.engine.now(),self.block['id'],2)
        destination=self.root/'copy.sqlite3';snapshot_database(self.source,destination,os.getuid())
        copied=sqlite3.connect(str(destination))
        try:self.assertEqual(copied.execute('SELECT SUM(seconds) FROM charges').fetchone()[0],125)
        finally:copied.close()
    def test_symlink_hardlink_permissions_wrong_uid_and_fifo_fail_safely(self):
        self.store.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        link=self.root/'link';link.symlink_to(self.source)
        with self.assertRaises(OSError):snapshot_database(link,self.root/'denied',os.getuid())
        link.unlink();os.link(self.source,link)
        with self.assertRaises(PermissionError):snapshot_database(link,self.root/'denied',os.getuid())
        link.unlink();self.source.chmod(0o644)
        with self.assertRaises(PermissionError):snapshot_database(self.source,self.root/'denied',os.getuid())
        self.source.chmod(0o600)
        with self.assertRaises(PermissionError):snapshot_database(self.source,self.root/'denied',os.getuid()+1)
        os.mkfifo(link)
        with self.assertRaises(PermissionError):snapshot_database(link,self.root/'denied',os.getuid())
        self.assertFalse((self.root/'denied').exists())
    def test_extra_sql_structures_fail_before_policy_interpretation(self):
        self.store.db.execute('CREATE TABLE injected (value TEXT)');self.store.db.commit()
        with self.assertRaises(ValueError):self.migrate()
        self.assertFalse(self.destination.exists())
    def test_hot_rollback_journal_is_not_silently_dropped(self):
        journal=self.source.with_name(self.source.name+'-journal');journal.write_bytes(b'pending rollback')
        with self.assertRaises(ValueError):self.migrate()
        self.assertFalse(self.destination.exists());self.assertEqual(journal.read_bytes(),b'pending rollback')
    def test_invalid_json_and_executable_triggers_are_rejected(self):
        self.store.db.execute('UPDATE state SET value=?',('{"version":1,"version":2}',));self.store.db.commit()
        with self.assertRaises(ValueError):self.migrate()
        self.store.save();self.store.db.execute('CREATE TRIGGER injected AFTER UPDATE ON state BEGIN DELETE FROM charges; END;');self.store.db.commit()
        with self.assertRaises(ValueError):self.migrate()
        self.assertEqual(self.store.used(self.block['id'],0),123)
    def test_failed_migration_cleans_staging_and_keeps_existing_destination(self):
        with patch('hotturkey.system_migration.PolicyAuthority',side_effect=RuntimeError('fixture failure')):
            with self.assertRaises(RuntimeError):self.migrate()
        self.assertFalse(self.destination.exists())
        self.destination.mkdir();(self.destination/'keep').write_text('keep')
        with self.assertRaises(FileExistsError):self.migrate()
        self.assertEqual((self.destination/'keep').read_text(),'keep')


if __name__=='__main__':unittest.main()
