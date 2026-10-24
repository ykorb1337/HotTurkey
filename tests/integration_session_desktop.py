"""Real signed no-window launch fixture; no installed UI or login items."""
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent


def main():
    harness=ROOT/'build/HotTurkeySessionDesktopFixture';stub=ROOT/'build/HotTurkeyLoginAppFixture'
    first={'id':'a'*64};second={'id':'b'*64};proof={}
    with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-login-ui-') as temporary:
        directory=Path(temporary);app=directory/'HotTurkey.app';contents=app/'Contents';binary=contents/'MacOS/HotTurkey'
        binary.parent.mkdir(parents=True);shutil.copy2(stub,binary)
        receipt=directory/'receipt.jsonl'
        info={'CFBundleIdentifier':'local.hotturkey.desktop','CFBundleExecutable':'HotTurkey','CFBundlePackageType':'APPL',
              'CFBundleVersion':'1','HotTurkeySystemMode':True,'FixtureReceipt':str(receipt)}
        (contents/'Info.plist').write_bytes(plistlib.dumps(info))
        subprocess.run(['/usr/bin/codesign','--force','--sign','-',str(app)],check=True,capture_output=True)
        def run(replies):
            result=subprocess.run([str(harness),str(app)],input=json.dumps(replies).encode(),capture_output=True,timeout=15)
            assert result.returncode==0,result.stderr.decode()
            return json.loads(result.stdout)
        replies=[{'accepted':True,'desktop':first},{'accepted':True,'desktop':first},
                 {'accepted':True},{'accepted':True,'desktop':first},
                 {'accepted':True,'desktop':{**second,'path':'/tmp/forged'}},
                 {'accepted':False,'desktop':second},{'accepted':True,'desktop':second}]
        results=run(replies)
        assert [v['launch_calls'] for v in results]==[1,1,1,1,1,1,2]
        assert results[0]['result']=={**first,'ok':True} and results[-1]['result']=={**second,'ok':True}
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            rows=receipt.read_text().splitlines() if receipt.exists() else []
            if len(rows)==2:break
            time.sleep(.05)
        assert len(rows)==2
        assert all(json.loads(row)[1:]==['--system','--login'] for row in rows)
        proof.update(actual_signed_fixture_spawn='PASS',fixed_system_login_arguments='PASS',duplicate_ticket_no_respawn='PASS',malformed_or_unaccepted_command_no_launch='PASS')
        # A group-writable executable, invalid signature or symlink is never run.
        binary.chmod(0o775)
        assert run([{'accepted':True,'desktop':first}])[0]['result']['ok'] is False
        binary.chmod(0o755)
        metadata=contents/'Info.plist';metadata.chmod(0o666)
        assert run([{'accepted':True,'desktop':first}])[0]['result']['ok'] is False
        metadata.chmod(0o644)
        (contents/'Info.plist').write_bytes(plistlib.dumps({**info,'FixtureReceipt':str(directory/'tampered')}))
        assert run([{'accepted':True,'desktop':first}])[0]['result']['ok'] is False
        (contents/'Info.plist').write_bytes(plistlib.dumps(info))
        real=binary.with_name('Real');binary.rename(real);binary.symlink_to(real)
        assert run([{'accepted':True,'desktop':first}])[0]['result']['ok'] is False
        assert len(receipt.read_text().splitlines())==2
        proof['writable_tampered_and_linked_app_rejected']='PASS'
    proof.update(root_installed=False,installed_ui_opened=False,login_item_installed=False,native_window_ready_verified=False)
    (ROOT/'build/session-desktop-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof))


if __name__=='__main__':main()
