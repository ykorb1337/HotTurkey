"""Only terminates a disposable executable created by this test, never a user's app."""
import json
import os
import subprocess
import tempfile
import time
import urllib.request
import argparse
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
parser=argparse.ArgumentParser();parser.add_argument('--data',type=Path,default=ROOT/'.runtime');args=parser.parse_args()
info=json.loads((args.data/'connection.json').read_text())
def call(path,data=None):
    request=urllib.request.Request(f'http://127.0.0.1:{info["port"]}/api/'+path,data=json.dumps(data).encode() if data is not None else None,headers={'Authorization':'Bearer '+info['token'],'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=10) as response:return json.load(response)

source=ROOT/'build/fixture.c'
source.write_text('#include <unistd.h>\nint main(void) { sleep(90); return 0; }\n')
fixture=ROOT/'build/HotTurkeyFixture'
subprocess.run(['/usr/bin/clang',str(source),'-o',str(fixture)],check=True)
process=subprocess.Popen([str(fixture)])
block=None
try:
    time.sleep(.5)
    assert process.poll() is None,'Fixture failed to start'
    block=call('blocks/save',{'block':{'name':'QA disposable native fixture','enabled':True,'applications':['binary:'+str(fixture)]}})
    for _ in range(16):
        if process.poll() is not None:break
        time.sleep(.5)
    assert process.poll() is not None,'Native blocker did not terminate disposable fixture'
    assert process.returncode<0,('Expected signal termination',process.returncode)
    state=call('state')
    assert state['enforcement']['desktop_connected'],'Native helper lost heartbeat'
    print(json.dumps({'native_executable_block':'PASS','signal':process.returncode,'helper_online':True}))
finally:
    if process.poll() is None:process.terminate()
    process.wait()
    if block:call('blocks/delete',{'id':block['id']})
