"""Verify code identity of a real Unix-socket peer without system installation."""
import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.ipc import peer_identity


def main():
    checker=ROOT/'build/HotTurkeyPeerCheck'
    fixture=ROOT/'build/HotTurkeyPeerFixture'
    def describe(path):
        return json.loads(subprocess.check_output([str(checker),'--describe',str(path)]))
    approved=describe(fixture)['requirement']
    wrong=describe(checker)['requirement']
    proof={}
    with tempfile.TemporaryDirectory(prefix='ht-peer-',dir='/private/tmp') as temporary:
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        listener.bind(str(Path(temporary)/'socket'));listener.listen(2);listener.settimeout(5)
        process=subprocess.Popen([str(fixture),str(Path(temporary)/'socket')])
        connection=None
        try:
            connection,_=listener.accept()
            identity=peer_identity(connection)
            assert identity.uid==os.getuid() and identity.pid==process.pid
            token=base64.b64encode(identity.audit_token).decode()
            def verify(requirement):
                result=subprocess.run([str(checker),'--audit',token,'--requirement',requirement],capture_output=True,text=True,timeout=5)
                return result.returncode==0 and json.loads(result.stdout)['ok']
            assert verify(approved),'Real signed peer was not recognized'
            assert not verify(wrong),'Wrong executable identity was accepted'
            proof.update(kernel_uid_and_pid='PASS',approved_cdhash='PASS',wrong_cdhash_rejected='PASS')
            connection.sendall(b'x');process.wait(timeout=5)
            assert not verify(approved),'Expired audit token was accepted after process exit'
            proof['exited_peer_rejected']='PASS'
        finally:
            if connection is not None:connection.close()
            listener.close()
            if process.poll() is None:process.kill();process.wait()
    (ROOT/'build/peer-identity-proof.json').write_text(json.dumps(proof,indent=2))
    print(json.dumps(proof))


if __name__=='__main__':main()
