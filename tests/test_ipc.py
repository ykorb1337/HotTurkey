import os
import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from hotturkey.ipc import ProtocolError, peer_identity, receive, send, trusted_path


class IPCTests(unittest.TestCase):
    def setUp(self):self.left,self.right=socket.socketpair()
    def tearDown(self):self.left.close();self.right.close()

    def wire(self,payload):self.left.sendall(struct.pack('!I',len(payload))+payload)

    def test_unicode_and_multiple_frames(self):
        send(self.left,{'op':'示例','value':'你好'})
        send(self.left,{'op':'second'})
        self.assertEqual(receive(self.right),{'op':'示例','value':'你好'})
        self.assertEqual(receive(self.right),{'op':'second'})

    def test_clean_eof_and_truncation_are_distinguished(self):
        self.left.shutdown(socket.SHUT_WR)
        self.assertIsNone(receive(self.right))

    def test_partial_header_eof_is_rejected(self):
        self.left.sendall(b'\x00\x00');self.left.shutdown(socket.SHUT_WR)
        with self.assertRaises(ProtocolError):receive(self.right)

    def test_partial_body_eof_is_rejected(self):
        self.left.sendall(struct.pack('!I',5)+b'{}');self.left.shutdown(socket.SHUT_WR)
        with self.assertRaises(ProtocolError):receive(self.right)

    def test_invalid_lengths_are_rejected_before_reading_body(self):
        for size in [0,2**32-1]:
            self.left.sendall(struct.pack('!I',size))
            with self.assertRaises(ProtocolError):receive(self.right)

    def test_invalid_json_scalars_nan_and_encoding_are_rejected(self):
        for value in [b'[]',b'42',b'{',b'{"x":NaN}',b'{"x":Infinity}',b'{"x":1e999}',b'{"x":-1e999}',b'{"x":1,"x":2}',b'{"x":'+b'9'*65+b'}',b'\xff']:
            with self.subTest(value=value):
                self.wire(value)
                with self.assertRaises(ProtocolError):receive(self.right)

    def test_slow_header_has_one_total_deadline(self):
        self.left.settimeout(1)
        def trickle():
            try:
                for byte in struct.pack('!I',2)+b'{}':
                    self.left.send(bytes([byte]));time.sleep(.06)
            except OSError:pass
        thread=threading.Thread(target=trickle);thread.start()
        try:
            with patch('hotturkey.ipc.FRAME_TIMEOUT',.15):
                started=time.monotonic()
                with self.assertRaises(TimeoutError):receive(self.right)
                self.assertLess(time.monotonic()-started,.4)
        finally:thread.join()

    def test_outbound_size_and_non_object_are_rejected(self):
        for value in [[],{'payload':'x'*1024}]:
            with self.subTest(value=type(value)),patch('hotturkey.ipc.MAX_FRAME',100):
                with self.assertRaises(ProtocolError):send(self.left,value)

    def test_workspace_file_is_not_a_trusted_root_executable(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as temp:
            path=Path(temp)/'tool';path.write_text('test');path.chmod(0o755)
            with self.assertRaises(PermissionError):trusted_path(path)
            link=Path(temp)/'linked';link.symlink_to('/usr/bin/true')
            with self.assertRaises(PermissionError):trusted_path(link)
        self.assertEqual(trusted_path('/usr/bin/true'),Path('/usr/bin/true'))

    def test_kernel_identity_ignores_claimed_uid(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-ipc-') as temp:
            listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            path=str(Path(temp)/'socket');listener.bind(path);listener.listen(1)
            client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            try:
                client.connect(path)
                connection,_=listener.accept()
                with connection:
                    send(client,{'uid':0,'pid':1})
                    identity=peer_identity(connection)
                    self.assertEqual(identity.uid,os.getuid())
                    self.assertEqual(identity.pid,os.getpid())
                    self.assertEqual(len(identity.audit_token),32)
                    self.assertEqual(receive(connection),{'uid':0,'pid':1})
            finally:client.close();listener.close()


if __name__=='__main__':unittest.main()
