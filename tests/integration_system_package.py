"""Real sealed app -> protected payload, without writing/loading system paths."""
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.system_package import (digest,inventory,native_requirement,prepare_payload,verify_payload)


def main():
    proof={'root_installed':False,'system_files_written':False,'services_loaded':False,'installed_rules_read_or_changed':False}
    with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-system-package-') as temporary:
        root=Path(temporary);payload=root/'payload'
        bindings={'Edge':{'requirement':'identifier "com.microsoft.edgemac"','origins':['chrome-extension://'+'a'*32+'/']}}
        value=prepare_payload(ROOT/'build/HotTurkey.app',payload,os.getuid(),bindings)
        assert verify_payload(payload)==value
        assert plistlib.loads((payload/'HotTurkey.app/Contents/Info.plist').read_bytes())['HotTurkeySystemMode'] is True
        proof.update(real_signed_payload_verified=True,inventory_entries=len(value['files']),system_app_mode_sealed=True)
        def refresh():
            value['files']=inventory(payload,ignore_manifest=True);(payload/'payload.json').write_text(json.dumps(value))
        helper=payload/'HotTurkeySessionAgent';original=helper.read_bytes();helper.write_bytes(b'corrupt');refresh()
        try:verify_payload(payload)
        except ValueError:pass
        else:raise AssertionError('Changed helper authorized by rewritten manifest')
        helper.write_bytes(original);refresh()
        assert verify_payload(payload)==value
        proof['rewritten_manifest_cannot_authorize_changed_helper']=True
        config=payload/'authority.json';original=config.read_bytes();changed=json.loads(original);changed['requirements']['session']='cdhash H"'+'0'*40+'"';config.write_text(json.dumps(changed));refresh()
        try:verify_payload(payload)
        except ValueError:pass
        else:raise AssertionError('Role pin does not match actual code')
        config.write_bytes(original);refresh();assert verify_payload(payload)==value
        proof['role_pins_match_actual_restricted_executables']=True
        checker=payload/'HotTurkeyPeerCheck';probe=root/'probe';shutil.copy2(ROOT/'build/HotTurkeyPeerFixture',probe)
        entitlements=root/'entitlements.plist'
        for flags,values in [('0',{}),('runtime',{'com.apple.security.get-task-allow':True}),('runtime',{})]:
            entitlements.write_bytes(plistlib.dumps(values))
            subprocess.run(['/usr/bin/codesign','--force','--options',flags,'--entitlements',str(entitlements),'--sign','-',str(probe)],check=True,capture_output=True)
            if flags=='runtime' and not values:assert native_requirement(checker,probe).startswith('cdhash H"')
            else:
                try:native_requirement(checker,probe)
                except ValueError:pass
                else:raise AssertionError('Debuggable or unhardened code accepted')
        proof['real_unhardened_and_debuggable_signatures_rejected']=True
        poison=root/'poison';poison.mkdir();(poison/'sitecustomize.py').write_text('raise RuntimeError("user code imported")')
        python=payload/'HotTurkey.app/Contents/Resources/python/bin/python3'
        result=subprocess.run([str(python),'-I','-B','-c','import json,sys; print(json.dumps({"isolated":sys.flags.isolated,"no_user_site":sys.flags.no_user_site,"path":sys.path}))'],
                              cwd=poison,env={'PATH':'/nonexistent','PYTHONPATH':str(poison),'PYTHONHOME':'/nonexistent'},check=True,capture_output=True,text=True)
        runtime=json.loads(result.stdout);assert runtime['isolated']==1 and runtime['no_user_site']==1 and str(poison) not in runtime['path'] and '' not in runtime['path']
        proof['isolated_runtime_ignores_user_environment_and_working_directory']=True
        assert verify_payload(payload)==value
        proof['signature_valid_after_runtime_check']=True
    (ROOT/'build/system-package-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof))


if __name__=='__main__':main()
