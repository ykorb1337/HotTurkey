"""Run a relocated app's backend/helper/Native Messaging with no host Python lookup."""
import json
import os
import shutil
import struct
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
MAGIC={b'\xcf\xfa\xed\xfe',b'\xfe\xed\xfa\xcf',b'\xca\xfe\xba\xbe',b'\xbe\xba\xfe\xca'}


def main():
    proof={}
    with tempfile.TemporaryDirectory(prefix='运行时搬移 验证-',dir=ROOT/'build') as temporary:
        directory=Path(temporary);app=directory/'HotTurkey Relocated.app'
        shutil.copytree(ROOT/'build/HotTurkey.app',app,symlinks=True)
        resources=app/'Contents/Resources';python=resources/'python/bin/python3';project=resources/'project'
        env={**os.environ,'PATH':'/nonexistent','PYTHONHOME':'/nonexistent-python','PYTHONPATH':'/nonexistent-modules','HOTTURKEY_DATA':str(directory/'data')}
        command=[str(python),'-E','-s','-B']
        modules='import sys,ssl,sqlite3,hashlib,zlib,ctypes,json; print(json.dumps({"prefix":sys.prefix,"executable":sys.executable,"version":sys.version.split()[0]}))'
        result=json.loads(subprocess.check_output(command+['-c',modules],env=env,text=True))
        assert Path(result['prefix']).resolve()==(resources/'python').resolve()
        Path(result['executable']).resolve().relative_to(app.resolve())
        native=[]
        for path in (resources/'python').rglob('*'):
            if path.is_symlink() or not path.is_file():continue
            with path.open('rb') as stream:magic=stream.read(4)
            if magic in MAGIC:native.append(path)
        output=subprocess.check_output(['/usr/bin/otool','-L']+[str(path) for path in native],text=True)
        current=None
        for line in output.splitlines():
            if line.endswith(':'):current=Path(line[:-1]);continue
            if not line.startswith('\t'):continue
            dependency=line.strip().split(' (')[0]
            # otool prints a dylib's own LC_ID_DYLIB before its dependencies.
            if current and current.suffix=='.dylib' and dependency==current.name:continue
            assert dependency.startswith(('/usr/lib/','/System/Library/','@loader_path/','@executable_path/','@rpath/')),dependency
        subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)],check=True)
        proof.update(relocated_app_runs=True,host_python_environment_ignored=True,python_version=result['version'],native_runtime_files_audited=len(native),no_external_development_dependencies=True,signature_valid_after_relocation=True)
        with (directory/'service-output.log').open('wb') as log:
            service=subprocess.Popen(command+['-m','hotturkey.server','--enforce'],cwd=project,env=env,stdout=log,stderr=subprocess.STDOUT)
            fixture=None
            try:
                connection=None
                def call(path,data=None):
                    request=urllib.request.Request('http://127.0.0.1:'+str(connection['port'])+'/api/'+path,data=None if data is None else json.dumps(data).encode(),headers={'Authorization':'Bearer '+connection['token'],'Content-Type':'application/json'})
                    with urllib.request.urlopen(request,timeout=3) as response:return json.load(response)
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    assert service.poll() is None,(directory/'service-output.log').read_text()
                    try:
                        connection=json.loads((directory/'data/connection.json').read_text())
                        if call('state')['enforcement']['desktop_connected']:break
                    except (OSError,ValueError):pass
                    time.sleep(.1)
                else:raise AssertionError('Relocated background did not become healthy')
                source=directory/'fixture.c'
                source.write_text('#include <unistd.h>\nint main(void) { sleep(90); return 0; }\n')
                executable=directory/'blocked.fixture'
                subprocess.run(['/usr/bin/clang',str(source),'-o',str(executable)],check=True)
                fixture=subprocess.Popen([str(executable)])
                block=call('blocks/save',{'block':{'name':'Portable runtime QA','enabled':True,'websites':['runtime-fixture.example']}})
                locked=call('blocks/lock',{'id':block['id'],'type':'text','custom_text':'runtime-qa'})
                assert fixture.poll() is None
                added=call('blocks/add-targets',{'id':block['id'],'applications':['binary:'+str(executable)]})
                assert added['locked'] and added['lock']==locked['lock']
                deadline=time.monotonic()+6
                while fixture.poll() is None and time.monotonic()<deadline:time.sleep(.1)
                assert fixture.poll() is not None and fixture.returncode<0
                payload=json.dumps({'op':'check','data':{'url':'https://runtime-fixture.example','record':False}}).encode()
                host=subprocess.run(command+['-m','hotturkey.native_host'],input=struct.pack('<I',len(payload))+payload,capture_output=True,env=env,cwd=project,check=True,timeout=8)
                size=struct.unpack('<I',host.stdout[:4])[0];decision=json.loads(host.stdout[4:4+size]);assert decision['blocked']
                proof.update(relocated_service_healthy=True,relocated_native_enforcement=True,relocated_native_messaging=True,locked_rule_preserved=True)
            finally:
                if fixture and fixture.poll() is None:fixture.kill()
                if fixture:fixture.wait()
                service.terminate()
                try:service.wait(timeout=8)
                except subprocess.TimeoutExpired:service.kill();service.wait();raise
        subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)],check=True)
        proof['signature_preserved_after_running']=True
    (ROOT/'build/portable-runtime-proof.json').write_text(json.dumps(proof,indent=2))
    print(json.dumps(proof))

if __name__=='__main__':main()
