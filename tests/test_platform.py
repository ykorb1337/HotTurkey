import json
import os
import plistlib
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from hotturkey.platform_macos import configure_ui_login
from hotturkey.platform_macos import native_samples, native_command, stop_native

class NativeTransportTests(unittest.TestCase):
    def setUp(self):
        self.processes=[]
        self.stop=threading.Event()

    def helper(self,code):
        process=subprocess.Popen([sys.executable,'-u','-c',code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,bufsize=0)
        self.processes.append(process)
        return process

    def tearDown(self):
        for process in self.processes:stop_native(process)

    def test_partial_utf8_sample_is_reassembled(self):
        process=self.helper("import json,os,time; wire=json.dumps({'apps':[],'front':{'application':'测试'}},ensure_ascii=False).encode()+b'\\n'; split=wire.index('测'.encode())+1; os.write(1,wire[:split]); time.sleep(.05); os.write(1,wire[split:]); time.sleep(5)")
        samples=native_samples(process,self.stop,lambda:None)
        self.assertEqual(next(samples)['front']['application'],'测试')
        samples.close()

    def test_trickling_partial_sample_still_times_out(self):
        process=self.helper("import os,time\nfor _ in range(200):\n os.write(1,b'{'); time.sleep(.01)")
        with patch('hotturkey.platform_macos.NATIVE_SAMPLE_TIMEOUT',.2):
            started=time.monotonic()
            with self.assertRaises(TimeoutError):next(native_samples(process,self.stop,lambda:None))
            self.assertLess(time.monotonic()-started,1)

    def test_eof_and_malformed_samples_fail_instead_of_hanging(self):
        for code in ['pass',"print('invalid')","print('{}')","print('{\"apps\":[42],\"front\":{}}')"]:
            with self.subTest(code=code):
                process=self.helper(code)
                with self.assertRaises(RuntimeError):next(native_samples(process,self.stop,lambda:None))

    def test_oversized_unterminated_frame_is_rejected(self):
        process=self.helper("import os,time; os.write(1,b'x'*200); time.sleep(5)")
        with patch('hotturkey.platform_macos.MAX_NATIVE_SAMPLE',100):
            with self.assertRaisesRegex(RuntimeError,'size limit'):next(native_samples(process,self.stop,lambda:None))

    def test_full_command_pipe_times_out(self):
        process=self.helper('import time; time.sleep(5)')
        with patch('hotturkey.platform_macos.NATIVE_COMMAND_TIMEOUT',.2):
            with self.assertRaises(TimeoutError):native_command(process,self.stop,{'payload':'x'*2_000_000})

    def test_stalled_sample_keeps_policy_clock_running(self):
        process=self.helper('import time; time.sleep(5)')
        ticks=[]
        def tick():
            ticks.append(time.monotonic())
            self.stop.set()
        with patch('hotturkey.platform_macos.NATIVE_SAMPLE_TIMEOUT',2):
            self.assertEqual(list(native_samples(process,self.stop,tick)),[])
        self.assertEqual(len(ticks),1)

    def test_shutdown_interrupts_a_stalled_read(self):
        process=self.helper('import time; time.sleep(5)')
        timer=threading.Timer(.05,self.stop.set);timer.start()
        try:
            started=time.monotonic()
            self.assertEqual(list(native_samples(process,self.stop,lambda:None)),[])
            self.assertLess(time.monotonic()-started,1)
        finally:timer.join()

    def test_suspended_helper_is_killed_and_reaped(self):
        process=self.helper("import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print('ready',flush=True); time.sleep(10)")
        self.assertEqual(process.stdout.readline(),b'ready\n')
        process.send_signal(signal.SIGSTOP)
        _,status=os.waitpid(process.pid,os.WUNTRACED)
        self.assertTrue(os.WIFSTOPPED(status))
        stop_native(process)
        self.assertEqual(process.poll(),-signal.SIGKILL)

class LoginTests(unittest.TestCase):
    def test_ui_login_is_separate_from_service_and_has_stable_path(self):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp);app=home/'Applications/HotTurkey.app';app.mkdir(parents=True)
            directory=home/'data';directory.mkdir();(directory/'installation.json').write_text(json.dumps({'app_path':str(app)}))
            with patch('hotturkey.platform_macos.Path.home',return_value=home),patch('hotturkey.platform_macos.subprocess.run') as run:
                configure_ui_login(True,directory)
                path=home/'Library/LaunchAgents/local.hotturkey.desktop.plist'
                value=plistlib.loads(path.read_bytes())
                self.assertEqual(value['ProgramArguments'],['/usr/bin/open','-a',str(app),'--args','--login'])
                run.assert_not_called()
                configure_ui_login(False,directory)
                self.assertFalse(path.exists())
                run.assert_called_once()

if __name__=='__main__':unittest.main()
