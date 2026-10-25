import copy
import json
import os
import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hotturkey import system_package as package


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.app=self.root/'HotTurkey.app'
        resources=self.app/'Contents/Resources';(resources/'python/bin').mkdir(parents=True)
        (resources/'python/bin/python3.13').write_text('python');(resources/'python/bin/python3.13').chmod(0o755)
        (resources/'python/bin/python3').symlink_to('python3.13');(resources/'python-path.txt').write_text('python/bin/python3')
        source=resources/'project';(source/'hotturkey').mkdir(parents=True);(source/'hotturkey/authority_server.py').write_text('fixture')
        (source/'build').mkdir()
        for name in package.HELPERS:(source/'build'/name).write_text(name);(source/'build'/name).chmod(0o755)
        (source/'build/HotTurkeyAgent').write_text('legacy helper')
        (self.app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'local.hotturkey.desktop','CFBundleShortVersionString':'0.3.0'}))
        self.destination=self.root/'payload';self.bindings={'Edge':{'requirement':'identifier "com.microsoft.edgemac"','origins':['chrome-extension://'+'a'*32+'/']}}
        self.patches=[patch.object(package,'verify_signature'),patch.object(package,'native_requirement',side_effect=self.requirement),patch.object(package.subprocess,'run')]
        for item in self.patches:item.start()
    def tearDown(self):
        for item in reversed(self.patches):item.stop()
        self.temp.cleanup()
    @staticmethod
    def requirement(checker,executable):return 'cdhash H"'+({'HotTurkeyPolicyClient':'a','HotTurkeySessionAgent':'b','HotTurkeyBrowserHost':'c'}[Path(executable).name]*40)+'"'
    def prepare(self):return package.prepare_payload(self.app,self.destination,501,self.bindings)
    def refresh_manifest(self):
        value=json.loads((self.destination/'payload.json').read_text());value['files']=package.inventory(self.destination,ignore_manifest=True)
        (self.destination/'payload.json').write_text(json.dumps(value))
    def test_payload_fixed_paths_separate_roles_and_no_activation(self):
        value=self.prepare();self.assertEqual(package.verify_payload(self.destination),value)
        config=json.loads((self.destination/'authority.json').read_text());self.assertEqual(config['controller_uid'],501)
        self.assertEqual(len(set(config['requirements'].values())),3)
        plan=plistlib.loads((self.destination/'authority.plist').read_bytes())
        self.assertIn('-I',plan['ProgramArguments']);self.assertIn('-B',plan['ProgramArguments'])
        self.assertEqual(plan['EnvironmentVariables']['HOME'],'/var/root')
        metadata=plistlib.loads((self.destination/'HotTurkey.app/Contents/Info.plist').read_bytes());self.assertTrue(metadata['HotTurkeySystemMode'])
        self.assertNotIn('HotTurkeySystemMode',plistlib.loads((self.app/'Contents/Info.plist').read_bytes()))
        for call in package.subprocess.run.call_args_list:self.assertNotIn('/bin/launchctl',call.args[0])
    def test_tampering_extra_file_mode_and_injected_startup_are_rejected(self):
        self.prepare();target=self.destination/'project/hotturkey/authority_server.py';target.write_text('tampered')
        with self.assertRaises(ValueError):package.verify_payload(self.destination)
        self.refresh_manifest()
        with self.assertRaises(ValueError):package.verify_payload(self.destination)
        target.write_text('fixture');target.chmod(0o666);self.refresh_manifest()
        with self.assertRaises(ValueError):package.verify_payload(self.destination)
        target.chmod(0o644);(self.destination/'authority-entry.py').write_text('injected');self.refresh_manifest()
        with self.assertRaises(ValueError):package.verify_payload(self.destination)
    def test_modified_helper_and_role_hash_cannot_be_authorized_by_manifest(self):
        self.prepare();(self.destination/'HotTurkeySessionAgent').write_text('changed');self.refresh_manifest()
        with self.assertRaises(ValueError):package.verify_payload(self.destination)
    def test_extra_project_code_and_custom_plist_are_rejected(self):
        self.prepare();(self.destination/'project/injected.py').write_text('injected');self.refresh_manifest()
        with self.assertRaises(ValueError):package.verify_payload(self.destination)
        (self.destination/'project/injected.py').unlink();plan=package.daemon_plan();plan['ProgramArguments']=['/tmp/python']
        (self.destination/'authority.plist').write_bytes(plistlib.dumps(plan));self.refresh_manifest()
        with self.assertRaises(ValueError):package.verify_payload(self.destination)
    def test_existing_destination_is_never_replaced(self):
        self.destination.mkdir();(self.destination/'keep').write_text('keep')
        with self.assertRaises(FileExistsError):self.prepare()
        self.assertEqual((self.destination/'keep').read_text(),'keep')
    def test_qa_or_external_runtime_rejected_before_destination_created(self):
        path=self.app/'Contents/Info.plist';info=plistlib.loads(path.read_bytes());info['HotTurkeyDataDirectory']='/tmp/qa';path.write_bytes(plistlib.dumps(info))
        with self.assertRaises(ValueError):self.prepare()
        del info['HotTurkeyDataDirectory'];path.write_bytes(plistlib.dumps(info));(self.app/'Contents/Resources/python-path.txt').write_text('/usr/bin/python3')
        with self.assertRaises(ValueError):self.prepare()
        self.assertFalse(self.destination.exists())
    def test_failed_signature_or_copy_removes_only_new_staging(self):
        with patch.object(package,'native_requirement',side_effect=ValueError('bad signature')):
            with self.assertRaises(ValueError):self.prepare()
        self.assertFalse(self.destination.exists());self.assertTrue(self.app.is_dir())
    def test_production_app_with_qa_helper_is_rejected(self):
        (self.app/'Contents/Resources/project/build/HotTurkeySystemAgentQA').write_text('QA')
        with self.assertRaises(ValueError):self.prepare()
        self.assertFalse(self.destination.exists())
    def test_internal_file_symlink_allowed_escaping_directory_special_links_denied(self):
        root=self.root/'links';root.mkdir();(root/'file').write_text('x');(root/'link').symlink_to('file')
        self.assertEqual(package.inventory(root)['link'],{'type':'link','target':'file'})
        (root/'link').unlink();(root/'link').symlink_to('../outside')
        with self.assertRaises(ValueError):package.inventory(root)
        (root/'link').unlink();(root/'folder').mkdir();(root/'link').symlink_to('folder')
        with self.assertRaises(ValueError):package.inventory(root)
        (root/'link').unlink();os.mkfifo(root/'fifo')
        with self.assertRaises(ValueError):package.inventory(root)
    def test_binding_scopes_and_controller_uid_are_strict(self):
        for uid in [True,0,499,'501']:
            with self.assertRaises(ValueError):package.prepare_payload(self.app,self.destination,uid,self.bindings)
        for origins in [['*'],['chrome-extension://'+'a'*32+'/']*2,[{}],['hotturkey@local.hotturkey']]:
            incoming=copy.deepcopy(self.bindings);incoming['Edge']['origins']=origins
            with self.assertRaises(ValueError):package.validate_bindings(incoming)
        package.validate_bindings({'Firefox':{'requirement':'fixture','origins':['hotturkey@local.hotturkey']}})
    def test_real_browser_requirement_is_inline_and_keeps_developer_identity(self):
        info={'CFBundleIdentifier':'com.microsoft.edgemac'};(self.app/'Contents/Info.plist').write_bytes(plistlib.dumps(info))
        requirement='identifier "com.microsoft.edgemac" and anchor apple generic and certificate leaf[subject.OU] = FIXTURE'
        package.subprocess.run.return_value=subprocess.CompletedProcess([],0,stdout='',stderr='designated => '+requirement+'\n')
        value=package.browser_binding('Edge',self.app,['chrome-extension://'+'a'*32+'/'])
        self.assertEqual(value['requirement'],requirement)
        self.assertEqual(package.subprocess.run.call_args.args[0][2:4],['-R','='+requirement])
        package.subprocess.run.return_value=subprocess.CompletedProcess([],0,stdout='',stderr='designated => cdhash H"'+'a'*40+'"\n')
        with self.assertRaises(ValueError):package.browser_binding('Edge',self.app,['chrome-extension://'+'a'*32+'/'])


class NativeRequirementTests(unittest.TestCase):
    def test_role_pins_require_a_restricted_runtime_without_debug_exceptions(self):
        value={'ok':True,'restricted_runtime':True,'requirement':'cdhash H"'+'a'*40+'"'}
        with patch.object(package.subprocess,'run') as run:
            run.return_value=subprocess.CompletedProcess([],0,stdout=json.dumps(value).encode())
            self.assertEqual(package.native_requirement('checker','client'),value['requirement'])
            for bad in [{**value,'restricted_runtime':False},{'ok':True,'requirement':value['requirement']},None,{**value,'requirement':'identifier forged'}]:
                run.return_value=subprocess.CompletedProcess([],0,stdout=json.dumps(bad).encode())
                with self.assertRaises(ValueError):package.native_requirement('checker','client')


if __name__=='__main__':unittest.main()
