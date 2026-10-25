"""Actual macOS directory exchanges and abrupt installer-process termination.

Only self-created files and child processes are used. This is not a physical
power-loss test, root installation or installed-service cutover.
"""
import json
import os
import selectors
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.system_transaction import FileTransaction,installation_lock

CHILD=r'''
import os,sys
from pathlib import Path
from hotturkey.system_transaction import FileTransaction,installation_lock
import hotturkey.system_transaction as transaction_module
root=Path(sys.argv[1]);mode=sys.argv[2];staged=Path(sys.argv[3]);journal=root/'journal/transaction.json';target=root/'program'
def checkpoint():
    print('CHECKPOINT',flush=True);sys.stdin.readline()
with installation_lock(root/'journal',owner_uid=os.getuid(),anchor=root):
    if mode=='initial-link':
        link=transaction_module.os.link
        def paused_link(*args,**values):
            result=link(*args,**values);checkpoint();return result
        transaction_module.os.link=paused_link
    transaction=FileTransaction(journal,{'program':target},owner_uid=os.getuid(),anchor=root)
    if mode=='after-exchange':
        rename=Path.rename
        def paused_rename(path,destination):
            if path==staged:checkpoint()
            return rename(path,destination)
        Path.rename=paused_rename
    transaction.publish('program',staged)
    if mode in {'rollback-cleanup','commit-cleanup'}:
        remove=transaction.remove_owned
        def paused_remove(path):
            checkpoint();return remove(path)
        transaction.remove_owned=paused_remove
        if mode=='rollback-cleanup':transaction.rollback()
        else:transaction.commit()
'''


def scenario(root,mode):
    (root/'journal').mkdir(mode=0o700);target=root/'program';target.mkdir();(target/'entry').write_text('old')
    staged=root/('.hotturkey-stage-'+uuid.uuid4().hex);staged.mkdir();(staged/'entry').write_text('new')
    stop=threading.Event();misses=[];observations=[]
    def observe():
        while not stop.is_set():
            try:target.lstat()
            except FileNotFoundError:misses.append(True)
            observations.append(True);stop.wait(.001)
    observer=threading.Thread(target=observe);observer.start()
    process=subprocess.Popen([sys.executable,'-E','-s','-B','-c',CHILD,str(root),mode,str(staged)],cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout,selectors.EVENT_READ)
            assert selector.select(10),'Child did not reach interruption point'
            line=process.stdout.readline()
            if line!=b'CHECKPOINT\n':raise AssertionError('Unexpected installer checkpoint')
        if mode=='after-exchange':assert (target/'entry').read_text()=='new' and (staged/'entry').read_text()=='old'
        elif mode=='rollback-cleanup':assert (target/'entry').read_text()=='old'
        elif mode=='commit-cleanup':
            assert (target/'entry').read_text()=='new';(target/'entry').write_text('new-used')
        elif mode=='initial-link':assert (root/'journal/transaction.json').stat().st_nlink==2
        process.kill();process.wait(timeout=5)
        assert process.returncode==-9
        # SIGKILL must release the actual kernel installation lock as well.
        with installation_lock(root/'journal',owner_uid=os.getuid(),anchor=root):
            transaction=FileTransaction(root/'journal/transaction.json',{'program':target},owner_uid=os.getuid(),anchor=root,resume=True)
            result=transaction.recover()
        expected='new-used' if mode=='commit-cleanup' else 'old'
        assert (target/'entry').read_text()==expected
        assert result==('committed' if mode=='commit-cleanup' else 'rolled-back')
    finally:
        if process.poll() is None:process.kill();process.wait(timeout=5)
        process.stdin.close();process.stdout.close();process.stderr.close()
        stop.set();observer.join(timeout=2);assert not observer.is_alive()
    assert not misses and len(observations)>1
    return len(observations)


def main():
    proof={'root_installed':False,'system_files_written':False,'installed_rules_read_or_changed':False,'physical_power_loss_tested':False}
    with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-atomic-install-') as temporary:
        total=0
        for mode in ['after-exchange','rollback-cleanup','commit-cleanup','initial-link']:
            root=Path(temporary)/mode;root.mkdir(mode=0o700);total+=scenario(root,mode);proof[mode]='PASS'
        proof.update(actual_installer_SIGKILL_tested=True,startup_path_missing_observations=0,startup_path_observations=total)
    (ROOT/'build/system-transaction-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof))


if __name__=='__main__':main()
