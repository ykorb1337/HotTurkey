import hashlib
import io
import json
import os
import plistlib
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from hotturkey.runtime import application_python
from hotturkey.store import Store
from hotturkey.engine import Engine
from scripts.prepare_runtime import checked_members,verified_download,target_triple
from scripts import install as installer


class RuntimeTests(unittest.TestCase):
    def archive(self,entries):
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w') as archive:
            for name,kind,target in entries:
                member=tarfile.TarInfo(name);member.type=kind;member.mode=0o755;member.linkname=target
                archive.addfile(member)
        stream.seek(0)
        return tarfile.open(fileobj=stream)

    def test_relative_runtime_and_symlink_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);resources=root/'App.app/Contents/Resources';(resources/'python/bin').mkdir(parents=True)
            executable=resources/'python/bin/python3.13';executable.write_text('fixture')
            (resources/'python/bin/python3').symlink_to('python3.13')
            (resources/'python-path.txt').write_text('python/bin/python3')
            self.assertEqual(application_python(root/'App.app'),resources/'python/bin/python3')
            (resources/'python-path.txt').write_text('../../../../outside')
            with self.assertRaises(ValueError):application_python(root/'App.app')
            (resources/'python-path.txt').write_text('python/bin/missing')
            with self.assertRaises(ValueError):application_python(root/'App.app')

    def test_safe_runtime_archive_and_rejected_escape_variants(self):
        with self.archive([('python',tarfile.DIRTYPE,''),('python/bin/python3.13',tarfile.REGTYPE,''),('python/bin/python3',tarfile.SYMTYPE,'python3.13')]) as archive:
            self.assertEqual(len(checked_members(archive)),3)
        bad=[[('../outside',tarfile.REGTYPE,'')],[('/absolute',tarfile.REGTYPE,'')],[('python/bin/python3',tarfile.SYMTYPE,'../../../outside')],[('python/bin/python3',tarfile.LNKTYPE,'outside')],[('python/bin',tarfile.SYMTYPE,'.'),('python/bin/child',tarfile.REGTYPE,'')],[('python/device',tarfile.CHRTYPE,'')]]
        for entries in bad:
            with self.subTest(entries=entries),self.archive(entries) as archive:
                with self.assertRaises(ValueError):checked_members(archive)

    def test_bad_download_is_never_promoted_and_verified_cache_is_offline(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'runtime.tgz';expected=b'good'
            asset={'url':'https://github.com/astral-sh/python-build-standalone/releases/download/test/python.tar.gz','size':4,'sha256':hashlib.sha256(expected).hexdigest()}
            with patch('urllib.request.urlopen',return_value=io.BytesIO(b'evil')):
                with self.assertRaises(ValueError):verified_download(asset,path)
            self.assertFalse(path.exists());self.assertFalse(path.with_suffix('.tgz.partial').exists())
            path.write_bytes(expected)
            with patch('urllib.request.urlopen',side_effect=AssertionError('Network should not be used')):verified_download(asset,path)

    def test_cpu_target_mapping_is_explicit(self):
        self.assertEqual(target_triple('arm64'),'aarch64-apple-darwin');self.assertEqual(target_triple('x86_64'),'x86_64-apple-darwin')
        with self.assertRaises(ValueError):target_triple('unsupported')


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.project=self.root/'project';(self.project/'build').mkdir(parents=True)
        for folder in ['hotturkey','web','extension']:(self.project/folder).mkdir();(self.project/folder/'new.txt').write_text(folder)
        (self.project/'build/HotTurkeyAgent').write_text('fixture agent')
        self.source=self.app(self.root/'Source.app','new')
        self.target=self.root/'profile/data';self.app_target=self.root/'apps/HotTurkey.app';self.launch=self.root/'profile/launch/service.plist'
        self.browser=[self.root/'profile/Chrome/NativeMessagingHosts/local.hotturkey.bridge.json']

    def tearDown(self):self.temp.cleanup()

    def app(self,path,version):
        resources=path/'Contents/Resources';(resources/'python/bin').mkdir(parents=True)
        (resources/'python/bin/python3.13').write_text(version);(resources/'python/bin/python3.13').chmod(0o755)
        (resources/'python/bin/python3').symlink_to('python3.13');(resources/'python-path.txt').write_text('python/bin/python3')
        (path/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'local.hotturkey.desktop'}))
        return path

    def install(self,prepare_only=True,source=None):
        with patch.object(installer,'ROOT',self.project),patch.object(installer,'manual_server',return_value=None),patch.object(installer,'restart_old_hosts',return_value=0):
            return installer.install(source or self.source,self.target,self.app_target,self.launch,self.browser,{'b'*32},prepare_only)

    def test_prepare_uses_installed_runtime_and_preserves_registration_and_policy(self):
        self.browser[0].parent.mkdir(parents=True);self.browser[0].write_text(json.dumps({'allowed_origins':['chrome-extension://'+'a'*32+'/']}))
        store=Store(self.target);Engine(store).save_block({'name':'Existing','websites':['example.com']});store.charge(1,'existing',23)
        store.save();state=json.loads(json.dumps(store.state));store.db.close()
        python=self.install()
        self.assertEqual(python,self.app_target/'Contents/Resources/python/bin/python3')
        launch=plistlib.loads(self.launch.read_bytes());self.assertEqual(launch['ProgramArguments'][:4],[str(python),'-E','-s','-B'])
        self.assertIn(str(python),(self.target/'native-host').read_text());self.assertIn(' -E -s -B ',(self.target/'native-host').read_text())
        self.assertEqual(json.loads(self.browser[0].read_text())['allowed_origins'],['chrome-extension://'+'a'*32+'/','chrome-extension://'+'b'*32+'/'])
        self.assertTrue((self.app_target/'Contents/Resources/python/bin/python3').is_symlink())
        store=Store(self.target)
        try:self.assertEqual(store.state,state);self.assertEqual(store.used('existing',0),23)
        finally:store.db.close()

    def test_same_application_source_is_not_removed(self):
        self.app(self.app_target,'installed')
        self.install(source=self.app_target)
        self.assertEqual((self.app_target/'Contents/Resources/python/bin/python3.13').read_text(),'installed')

    def test_locked_update_leaves_code_untouched(self):
        store=Store(self.target);engine=Engine(store);block=engine.save_block({'name':'Locked'});engine.set_lock(block['id'],{'type':'password','password':'secret'});store.db.close()
        with self.assertRaises(ValueError):self.install()
        self.assertFalse(self.app_target.exists());self.assertFalse((self.target/'runtime').exists())

    def test_failed_start_restores_code_app_registration_and_launch_metadata(self):
        self.app(self.app_target,'old');(self.target/'runtime').mkdir(parents=True);(self.target/'runtime/old.txt').write_text('old runtime')
        self.launch.parent.mkdir(parents=True);self.launch.write_bytes(plistlib.dumps({'Label':'old'}))
        (self.target/'native-host').write_text('old host');(self.target/'installation.json').write_text('old receipt')
        self.browser[0].parent.mkdir(parents=True);self.browser[0].write_text('{}')
        old={p:p.read_bytes() for p in [self.launch,self.target/'native-host',self.target/'installation.json',self.browser[0]]}
        bootstraps=[]
        def command(args,**kwargs):
            if args[1]=='bootout' and not bootstraps:self.assertTrue((self.target/'runtime/old.txt').exists())
            if args[1]=='bootstrap':
                bootstraps.append(args)
                if len(bootstraps)==1:raise subprocess.CalledProcessError(1,args)
            return SimpleNamespace(returncode=0)
        with patch.object(installer.subprocess,'run',side_effect=command):
            with self.assertRaises(subprocess.CalledProcessError):self.install(False)
        self.assertEqual(len(bootstraps),2)
        self.assertEqual((self.target/'runtime/old.txt').read_text(),'old runtime')
        self.assertEqual((self.app_target/'Contents/Resources/python/bin/python3.13').read_text(),'old')
        for path,content in old.items():self.assertEqual(path.read_bytes(),content)

    def test_prepare_refuses_to_mutate_a_running_installation(self):
        self.launch.parent.mkdir(parents=True);self.launch.write_bytes(plistlib.dumps({'Label':'old'}))
        with patch.object(installer.subprocess,'run',return_value=SimpleNamespace(returncode=0)):
            with self.assertRaises(ValueError):self.install()
        self.assertFalse((self.target/'runtime').exists())

    def test_concurrent_install_refused_without_replacing_code(self):
        with installer.install_lock(self.target):
            with self.assertRaises(ValueError):self.install()
        self.assertFalse((self.target/'runtime').exists())
        self.install()
        self.assertEqual((self.target/'.install.lock').stat().st_mode&0o777,0o600)

    def test_host_migration_only_restarts_owned_module_in_replaced_directory(self):
        old=self.root/'old-runtime';old.mkdir();uid=os.getuid()
        processes=f'41 {uid} /python -m hotturkey.native_host\n42 {uid} /python -m hotturkey.native_host\n43 {uid+1} /python -m hotturkey.native_host\n44 {uid} /python -m hotturkey.native_host_other\n'
        def output(command,**kwargs):
            if command[0]=='/bin/ps':return processes
            return 'p'+command[3]+'\nn'+str(old if command[3]=='41' else self.root/'other')+'\n'
        with patch.object(installer.subprocess,'check_output',side_effect=output),patch.object(installer.os,'kill') as kill:
            self.assertEqual(installer.restart_old_hosts(old),1)
            kill.assert_called_once_with(41,installer.signal.SIGTERM)

if __name__=='__main__':unittest.main()
