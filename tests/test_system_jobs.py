import dataclasses
import os
import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from hotturkey import system_jobs as jobs
from hotturkey.system_package import DAEMON,LABEL
from hotturkey.session_launch import SESSION_PLIST


class Runner:
    def __init__(self):
        self.calls=[];self.loaded=set();self.domains={'system','gui/501','gui/502'};self.codes={};self.effect=None
    def __call__(self,args,**values):
        self.calls.append((args,values));command=tuple(args[1:])
        if self.effect:self.effect(command)
        if command in self.codes:return SimpleNamespace(returncode=self.codes[command])
        if command[0]=='print':
            target=command[1]
            if target=='system' or target.startswith('gui/') and target.count('/')==1:return SimpleNamespace(returncode=0 if target in self.domains else 112)
            domain=target.rsplit('/',1)[0]
            return SimpleNamespace(returncode=112 if domain not in self.domains else 0 if target in self.loaded else 113)
        if command[0]=='bootstrap':
            self.loaded.add(command[1]+'/'+plistlib.loads(Path(command[2]).read_bytes())['Label'])
        elif command[0]=='bootout':self.loaded.discard(command[1])
        else:raise AssertionError('Unexpected launchctl action')
        return SimpleNamespace(returncode=0)


class JobTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/private/tmp');self.root=Path(self.temp.name);self.runner=Runner();self.permissions=[]
        self.plan={'Label':'local.hotturkey.qa.fixture','ProgramArguments':['/usr/bin/true'],'RunAtLoad':True}
        self.path=self.root/'agent.plist';self.path.write_bytes(plistlib.dumps(self.plan));self.path.chmod(0o600)
        self.job=jobs._Job('gui/501',self.plan['Label'],self.path,self.plan)
        self.control=jobs._JobControl(lambda:self.permissions.append(True),lambda job:jobs.read_plan(job.plist,job.expected,owner_uid=os.getuid(),anchor=self.root),run=self.runner)
    def tearDown(self):self.temp.cleanup()

    def test_idempotent_load_and_unload_target_only_one_job(self):
        self.assertTrue(self.control.load(self.job));self.assertTrue(self.control.load(self.job))
        self.assertTrue(self.control.unload(self.job));self.assertFalse(self.control.unload(self.job))
        mutations=[args for args,_ in self.runner.calls if args[1]!='print']
        self.assertEqual(mutations,[['/bin/launchctl','bootstrap','gui/501',str(self.path)],['/bin/launchctl','bootout',self.job.target]])
        self.assertEqual(len(self.permissions),4)

    def test_unknown_queries_permission_failures_and_killed_queries_are_not_off(self):
        for code in [1,3,5,126,255,-9]:
            self.runner.codes[('print',self.job.target)]=code
            with self.subTest(code=code),self.assertRaises(RuntimeError):self.control.loaded(self.job)
        self.assertFalse(any(args[1]!='print' for args,_ in self.runner.calls))

    def test_absent_domain_is_distinct_from_a_failed_domain_query(self):
        self.runner.domains.remove('gui/501');self.assertFalse(self.control.loaded(self.job));self.assertFalse(self.control.load(self.job))
        self.runner.codes[('print','gui/501')]=5
        with self.assertRaises(RuntimeError):self.control.loaded(self.job)

    def test_inconsistent_missing_domain_and_existing_domain_is_rejected(self):
        self.runner.codes[('print',self.job.target)]=112
        with self.assertRaises(RuntimeError):self.control.loaded(self.job)
        self.runner.codes[('print','system')]=112
        with self.assertRaises(RuntimeError):self.control.domain_exists('system')

    def test_user_logout_during_bootstrap_is_a_bounded_no_session_result(self):
        self.runner.codes[('bootstrap','gui/501',str(self.path))]=112
        self.runner.effect=lambda command:self.runner.domains.discard('gui/501') if command[0]=='bootstrap' else None
        self.assertFalse(self.control.load(self.job))

    def test_bootstrap_failure_while_session_exists_is_not_ignored(self):
        self.runner.codes[('bootstrap','gui/501',str(self.path))]=5
        with self.assertRaises(RuntimeError):self.control.load(self.job)

    def test_bootout_failure_while_job_exists_is_not_ignored(self):
        self.runner.loaded.add(self.job.target);self.runner.codes[('bootout',self.job.target)]=5
        with self.assertRaises(RuntimeError):self.control.unload(self.job)

    def test_external_unload_race_is_idempotent_without_other_mutations(self):
        self.runner.loaded.add(self.job.target);self.runner.codes[('bootout',self.job.target)]=113
        self.runner.effect=lambda command:self.runner.loaded.discard(self.job.target) if command[0]=='bootout' else None
        self.assertTrue(self.control.unload(self.job))
        self.assertEqual([args[1] for args,_ in self.runner.calls if args[1]!='print'],['bootout'])

    def test_timeouts_propagate_without_reporting_success(self):
        def failure(*args,**values):raise subprocess.TimeoutExpired(args[0],values['timeout'])
        control=jobs._JobControl(lambda:None,lambda _:None,run=failure)
        with self.assertRaises(subprocess.TimeoutExpired):control.load(self.job)
        with self.assertRaises(subprocess.TimeoutExpired):control.unload(self.job)

    def test_combined_queries_have_one_total_deadline_and_never_bootstrap_late(self):
        now=[0];self.runner.effect=lambda command:now.__setitem__(0,now[0]+2)
        control=jobs._JobControl(lambda:None,lambda _:None,run=self.runner,timeout=3,clock=lambda:now[0])
        with self.assertRaises(TimeoutError):control.load(self.job)
        self.assertFalse(any(args[1]!='print' for args,_ in self.runner.calls));self.assertIsNone(control.deadline)
        self.assertEqual(self.runner.calls[-1][1]['timeout'],1)

    def test_commands_have_bounded_io_and_no_inherited_user_environment(self):
        with patch.dict(os.environ,{'DYLD_INSERT_LIBRARIES':'hostile','LAUNCHD_SOCKET':'hostile','PYTHONPATH':'hostile'}):self.control.load(self.job)
        for args,values in self.runner.calls:
            self.assertEqual(args[0],'/bin/launchctl');self.assertLessEqual(values['timeout'],10)
            self.assertEqual(values['cwd'],'/');self.assertTrue(values['close_fds'])
            self.assertEqual(set(values['env']),{'PATH','LC_ALL'})
            for name in ['stdin','stdout','stderr']:self.assertEqual(values[name],subprocess.DEVNULL)

    def test_permission_is_checked_before_validation_or_mutation(self):
        def deny():raise PermissionError('Denied')
        control=jobs._JobControl(deny,lambda _:self.fail('No file read expected'),run=self.runner)
        with self.assertRaises(PermissionError):control.load(self.job)
        with self.assertRaises(PermissionError):control.unload(self.job)
        self.assertEqual(self.runner.calls,[])

    def test_even_loaded_jobs_require_exact_plan_before_a_load(self):
        self.runner.loaded.add(self.job.target);foreign={**self.plan,'UserName':'root'};self.path.write_bytes(plistlib.dumps(foreign))
        with self.assertRaises(ValueError):self.control.load(self.job)
        self.assertEqual(self.runner.calls,[])

    def test_plan_links_writable_files_special_files_and_ambiguous_xml_rejected(self):
        self.path.chmod(0o666)
        with self.assertRaises(PermissionError):self.control.load(self.job)
        self.path.chmod(0o600);self.path.unlink();self.path.symlink_to(self.root/'other')
        with self.assertRaises(OSError):self.control.load(self.job)
        self.path.unlink();os.mkfifo(self.path,0o600)
        with self.assertRaises(PermissionError):self.control.load(self.job)
        self.path.unlink();raw=plistlib.dumps(self.plan).replace(b'<dict>',b'<dict>\n<key>Label</key><string>foreign.service</string>',1);self.path.write_bytes(raw);self.path.chmod(0o600)
        with self.assertRaises(ValueError):self.control.load(self.job)

    def test_selector_validation_never_accepts_a_domain_removal_target(self):
        for domain in ['gui/0','gui/499','gui/4294967296','gui/501/other','user/501','system/other','gui/501\n']:
            with self.subTest(domain=domain),self.assertRaises(ValueError):dataclasses.replace(self.job,domain=domain)
        for label in ['other.service','local.hotturkey.foo/../bar','local.hotturkey.foo\n']:
            with self.subTest(label=label),self.assertRaises(ValueError):dataclasses.replace(self.job,label=label)
        for timeout in [0,31,True,float('nan')]:
            with self.assertRaises(ValueError):jobs._JobControl(lambda:None,lambda _:None,timeout=timeout)

    def test_account_validation_rejects_privilege_accounts_and_untrusted_homes(self):
        def account(uid,home='/Users/real',name='real'):return SimpleNamespace(pw_uid=uid,pw_dir=home,pw_name=name)
        self.assertEqual(jobs.human_account(501,lambda uid:account(uid)).pw_uid,501)
        for uid in [0,499,True,4294967296]:
            with self.assertRaises(ValueError):jobs.human_account(uid,lambda uid:account(uid))
        for home,name in [('/var/root','root'),('/Users','user'),('/Users/a/../b','real'),('/Users/real','_daemon')]:
            with self.assertRaises(ValueError):jobs.human_account(501,lambda uid:account(uid,home,name))

    def test_production_factory_refuses_unprivileged_use_before_any_paths(self):
        with patch.object(jobs.os,'geteuid',return_value=501),patch.object(jobs,'protected_directory') as directory:
            with self.assertRaises(PermissionError):jobs.SystemJobs(501,'a'*32)
            directory.assert_not_called()

    def test_production_factory_uses_only_fixed_labels_and_paths(self):
        account=SimpleNamespace(pw_dir='/Users/example',pw_uid=501,pw_name='example')
        with patch.object(jobs,'root_only'),patch.object(jobs,'human_account',return_value=account),patch.object(jobs,'protected_directory'):
            control=jobs.SystemJobs(501,'a'*32)
            self.assertEqual(control.authority.plist,DAEMON);self.assertEqual(control.authority.target,'system/'+LABEL)
            self.assertEqual(control.session(502).plist,SESSION_PLIST);self.assertEqual(control.session(502).target,'gui/502/local.hotturkey.session')
            self.assertEqual(control.legacy.target,'gui/501/local.hotturkey.service')
            self.assertEqual(control.saved_legacy.plist,jobs.REGISTRY/'jobs'/('a'*32)/'legacy.plist')

    def test_capture_uses_gui_domains_and_only_fixed_loaded_plans(self):
        accounts={uid:SimpleNamespace(pw_dir='/Users/u'+str(uid),pw_uid=uid,pw_name='u'+str(uid)) for uid in [501,502,503]}
        accounts[503].pw_name='_daemon'
        with patch.object(jobs,'root_only'),patch.object(jobs,'protected_directory'),patch.object(jobs.pwd,'getpwuid',side_effect=lambda uid:accounts[uid]),\
             patch.object(jobs.pwd,'getpwall',return_value=[accounts[503],accounts[502],accounts[501],accounts[501]]),patch.object(jobs,'read_plan') as read:
            # human_account's default resolver was bound when the module loaded.
            real_account=jobs.human_account
            with patch.object(jobs,'human_account',side_effect=lambda uid:real_account(uid,lambda value:accounts[value])):
                controller=jobs.SystemJobs(501,'a'*32);controller.control=jobs._JobControl(lambda:None,lambda _:None,run=self.runner)
                self.runner.loaded.update({controller.authority.target,controller.legacy.target,controller.session(501).target})
                self.assertEqual(controller.capture(),{'legacy_loaded':True,'authority_loaded':True,'session_loaded':[501],'gui_uids':[501,502]})
                paths={call.args[0] for call in read.call_args_list}
                self.assertEqual(paths,{controller.authority.plist,controller.legacy.plist,SESSION_PLIST})
                self.runner.codes[('print','gui/502')]=5
                with self.assertRaises(RuntimeError):controller.capture()

    def test_gui_enumeration_rejects_oversized_catalog_instead_of_truncating_users(self):
        account=SimpleNamespace(pw_dir='/Users/example',pw_uid=501,pw_name='example')
        with patch.object(jobs,'root_only'),patch.object(jobs,'protected_directory'),patch.object(jobs,'human_account',return_value=account),\
             patch.object(jobs.pwd,'getpwall',return_value=[account]*4097):
            controller=jobs.SystemJobs(501,'a'*32);controller.control=jobs._JobControl(lambda:None,lambda _:None,run=self.runner)
            with self.assertRaises(ValueError):controller.gui_uids()
            self.assertEqual(self.runner.calls,[])


class SavedPlanTests(unittest.TestCase):
    def test_legacy_restore_uses_canonical_private_snapshot_not_changed_user_xml(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as temporary:
            root=Path(temporary);home=root/'home';home.mkdir(mode=0o700);registry=root/'registry';folder=registry/'jobs'/('a'*32);folder.mkdir(mode=0o700,parents=True)
            guard=jobs.protected_directory;read=jobs.read_plan;owned=jobs.owned_entry
            def directory(path,owner_uid=0,anchor=Path('/')):return guard(path,os.getuid(),root if anchor==Path('/') else anchor)
            def plan(path,expected,owner_uid=0,anchor=Path('/')):return read(path,expected,owner_uid=os.getuid(),anchor=root if anchor==Path('/') else anchor)
            with patch.object(jobs,'root_only'),patch.object(jobs,'human_account',return_value=SimpleNamespace(pw_dir=str(home))),patch.object(jobs,'REGISTRY',registry),\
                 patch.object(jobs,'protected_directory',side_effect=directory),patch.object(jobs,'read_plan',side_effect=plan),patch.object(jobs,'owned_entry',side_effect=lambda path:owned(path,os.getuid())):
                controller=jobs.SystemJobs(501,'a'*32);controller.legacy.plist.parent.mkdir(parents=True)
                controller.legacy.plist.write_bytes(plistlib.dumps(controller.legacy.expected));controller.legacy.plist.chmod(0o600)
                stale=folder/'legacy.plist.new';stale.write_text('partial');stale.chmod(0o600)
                controller.save_legacy();self.assertFalse(stale.exists());self.assertTrue(controller.saved_legacy.plist.read_bytes().startswith(b'bplist00'))
                controller.legacy.plist.write_bytes(plistlib.dumps({'Label':'foreign.service','UserName':'root'}))
                runner=Runner();controller.control=jobs._JobControl(jobs.root_only,lambda job:plan(job.plist,job.expected),run=runner)
                self.assertTrue(controller.load_legacy());self.assertEqual(runner.calls[-2][0][1:3],['bootstrap','gui/501'])
                runner.calls.clear();controller.saved_legacy.plist.unlink()
                with self.assertRaises(FileNotFoundError):controller.unload_legacy()
                self.assertEqual(runner.calls,[])


if __name__=='__main__':unittest.main()
