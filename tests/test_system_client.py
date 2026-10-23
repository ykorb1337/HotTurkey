import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch

from hotturkey import cli
from hotturkey.model import PolicyError
from hotturkey.system_client import SystemClient


class SystemClientTests(unittest.TestCase):
    def test_production_uses_only_fixed_protected_native_client(self):
        client=SystemClient()
        with patch('hotturkey.system_client.trusted_path',return_value='/protected/client') as trusted,patch('hotturkey.system_client.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=b'{"ok":true,"result":{"id":"x"}}')) as run:
            self.assertEqual(client.api('blocks/add-targets',{'id':'x','websites':['example.invalid']}),{'id':'x'})
            self.assertEqual(run.call_args.args[0],['/protected/client']);self.assertTrue(trusted.called)
            payload=json.loads(run.call_args.kwargs['input']);self.assertEqual(payload['op'],'add-targets');self.assertNotIn('uid',payload)
    def test_authentication_session_is_forwarded_and_check_is_read_only(self):
        client=SystemClient(command=['qa-client'])
        with patch.object(client,'request',side_effect=[{'session':'token'},{'blocked':False}]) as request:
            client.api('auth',{'password':'secret'});self.assertEqual(client.session,'token')
            client.api('check',{'url':'https://a','record':False});self.assertEqual(request.call_args.args,('check',{'url':'https://a'}))
        with self.assertRaises(PolicyError):client.api('native',{'kill':[1]})
    def test_transport_failures_and_policy_errors_are_separate(self):
        client=SystemClient(command=['qa-client'])
        for result in [SimpleNamespace(returncode=1,stdout=b''),SimpleNamespace(returncode=0,stdout=b'not json'),SimpleNamespace(returncode=0,stdout=b'{"ok":false,"error":"locked"}')]:
            with self.subTest(result=result),patch('hotturkey.system_client.subprocess.run',return_value=result),self.assertRaises(PolicyError):client.request('snapshot')
        with patch('hotturkey.system_client.subprocess.run',side_effect=subprocess.TimeoutExpired('qa',1)),self.assertRaises(PolicyError):client.request('snapshot')
        with patch('hotturkey.system_client.trusted_path',side_effect=FileNotFoundError()),self.assertRaises(PolicyError):SystemClient().request('snapshot')
    def test_cli_system_mode_does_not_open_a_legacy_connection_or_database(self):
        client=Mock();client.api.return_value={'authenticated':True,'can_manage':True,'blocks':[]}
        output=io.StringIO()
        with patch('sys.argv',['hotturkey','--system','status']),patch('hotturkey.system_client.SystemClient',return_value=client),patch('pathlib.Path.read_text',side_effect=AssertionError('Legacy connection was opened')),contextlib.redirect_stdout(output):cli.main()
        client.api.assert_called_once_with('state',None);self.assertEqual(json.loads(output.getvalue())['blocks'],[])
    def test_noncontroller_can_read_own_statistics_without_manager_password_prompt(self):
        client=Mock();client.api.side_effect=[{'authenticated':False,'can_manage':False,'blocks':[]},{'totals':{'seconds':5}}]
        with patch('sys.argv',['hotturkey','--system','stats']),patch('hotturkey.system_client.SystemClient',return_value=client),patch('getpass.getpass',side_effect=AssertionError('Unexpected controller password prompt')),contextlib.redirect_stdout(io.StringIO()):cli.main()
        self.assertEqual([call.args[0] for call in client.api.call_args_list],['state','statistics'])
    def test_cli_import_default_is_inert_even_with_an_older_backend(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'rules.json';path.write_text(json.dumps({'blocks':[{'name':'Device','device':'shutdown','autostart':{'type':'once','at':1}}]}))
            client=Mock();client.api.side_effect=[{'authenticated':True,'blocks':[]},{'count':1}]
            with patch('sys.argv',['hotturkey','--system','import',str(path)]),patch('hotturkey.system_client.SystemClient',return_value=client),contextlib.redirect_stdout(io.StringIO()):cli.main()
            payload=client.api.call_args.args[1];self.assertFalse(payload['allow_autostart']);self.assertEqual(payload['blocks'][0]['autostart'],{'type':'none'})
    def test_cli_device_autostart_needs_its_specific_confirmation_flag(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'rules.json';path.write_text(json.dumps({'blocks':[{'name':'Device','device':'shutdown','autostart':{'type':'once','at':1}}]}))
            client=Mock();client.api.return_value={'authenticated':True,'blocks':[]}
            with patch('sys.argv',['hotturkey','--system','import',str(path),'--keep-autostart']),patch('hotturkey.system_client.SystemClient',return_value=client),contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):cli.main()
            self.assertEqual(client.api.call_count,1)


if __name__=='__main__':unittest.main()
