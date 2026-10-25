import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from hotturkey.service_lease import ServiceLease


class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/private/tmp');self.root=Path(self.temp.name);self.path=self.root/'service.lock'
    def tearDown(self):self.temp.cleanup()

    def test_exclusive_probe_is_retained_until_handoff_closes(self):
        with ServiceLease(self.path) as backend,ServiceLease(self.path,create=False) as probe:
            self.assertFalse(probe.try_acquire());backend.close();self.assertTrue(probe.try_acquire())
            with self.assertRaises(BlockingIOError):ServiceLease(self.path)
        with ServiceLease(self.path):pass
        self.assertEqual(self.path.stat().st_mode&0o777,0o600)

    def test_surviving_child_retains_lock_after_backend_closes_its_descriptor(self):
        backend=ServiceLease(self.path);child=subprocess.Popen([sys.executable,'-B','-c','import time;time.sleep(30)'],pass_fds=(backend.fileno(),))
        try:
            with ServiceLease(self.path,create=False) as probe:
                backend.close();self.assertFalse(probe.try_acquire());child.terminate();child.wait(timeout=5);self.assertTrue(probe.try_acquire())
        finally:
            backend.close()
            if child.poll() is None:child.kill();child.wait(timeout=5)

    def test_probe_never_creates_missing_proof(self):
        with self.assertRaises(FileNotFoundError):ServiceLease(self.path,create=False)
        self.assertFalse(self.path.exists())
    def test_closed_standard_input_cannot_turn_inherited_lease_into_protocol_stdin(self):
        code='import os,sys;from pathlib import Path;from hotturkey.service_lease import ServiceLease;os.close(0);lease=ServiceLease(Path(sys.argv[1]));assert lease.fileno()>=3;lease.close()'
        subprocess.run([sys.executable,'-B','-c',code,str(self.path)],check=True,timeout=5)

    def test_replaced_or_unlinked_inode_cannot_prove_quiescence(self):
        with ServiceLease(self.path) as backend,ServiceLease(self.path,create=False) as probe:
            self.path.unlink();self.path.touch(mode=0o600)
            with self.assertRaises(PermissionError):probe.try_acquire()
            with self.assertRaises(PermissionError):backend.assert_current()

    def test_legacy_readable_empty_lock_is_hardened_without_replacing_inode(self):
        self.path.touch(mode=0o644);before=self.path.stat().st_ino
        with ServiceLease(self.path):self.assertEqual(self.path.stat().st_ino,before)
        self.assertEqual(self.path.stat().st_mode&0o777,0o600)

    def test_links_writable_owner_mismatches_and_nonempty_files_rejected(self):
        other=self.root/'other';other.touch(mode=0o600);self.path.symlink_to(other)
        with self.assertRaises(OSError):ServiceLease(self.path)
        self.path.unlink();os.link(other,self.path)
        with self.assertRaises(PermissionError):ServiceLease(self.path)
        self.path.unlink();self.path.touch(mode=0o600);self.path.chmod(0o666)
        with self.assertRaises(PermissionError):ServiceLease(self.path)
        self.path.chmod(0o600)
        with self.assertRaises(PermissionError):ServiceLease(self.path,owner_uid=os.getuid()+1)
        self.path.write_text('not a service lock')
        with self.assertRaises(PermissionError):ServiceLease(self.path)

    def test_fifo_and_writable_parent_rejected_without_blocking(self):
        os.mkfifo(self.path,0o600)
        with self.assertRaises(PermissionError):ServiceLease(self.path)
        self.path.unlink();self.root.chmod(0o777)
        try:
            with self.assertRaises(PermissionError):ServiceLease(self.path)
        finally:self.root.chmod(0o700)


if __name__=='__main__':unittest.main()
