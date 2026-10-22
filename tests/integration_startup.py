"""Prepare/verify a delayed native startup fixture, with UI driven through CUA.

No UI automation, installed data, launch items or user processes are controlled
by this script. Open the returned disposable app, then use --verify.
"""
import argparse
import json
import plistlib
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.store import Store

RECORD=ROOT/'build/startup-fixture.json'


def prepare(reuse=None):
    build=(ROOT/'build').resolve()
    if reuse:
        value=json.loads(Path(reuse).read_text());app=Path(value['app']);data=Path(value['data'])
        app.resolve().relative_to(build);data.resolve().relative_to(build)
        check=subprocess.run(['/usr/sbin/lsof','-t',str(app/'Contents/MacOS/HotTurkey')],capture_output=True,text=True)
        if check.stdout.strip():raise RuntimeError('Close the disposable app before preparing it')
        info=plistlib.loads((app/'Contents/Info.plist').read_bytes())
        shutil.rmtree(app)
    else:
        folder=Path(tempfile.mkdtemp(prefix='startup-ui-',dir=build))
        app=folder/'HotTurkey Startup QA.app';data=folder/'data'
        info=plistlib.loads((build/'HotTurkey.app/Contents/Info.plist').read_bytes())
        info.update(CFBundleIdentifier='local.hotturkey.startupqa',CFBundleDisplayName='HotTurkey Startup QA')
        store=Store(data);store.state['settings']['statistics']=False;store.save();store.db.close()
    shutil.copytree(build/'HotTurkey.app',app,symlinks=True)
    info['HotTurkeyDataDirectory']=str(data)
    (app/'Contents/Info.plist').write_bytes(plistlib.dumps(info))
    marker=data/'startup-delay.json'
    marker.unlink(missing_ok=True)
    log=data/'desktop.log'
    offset=log.stat().st_size if log.exists() else 0
    server=app/'Contents/Resources/project/hotturkey/server.py'
    prefix=('import json as _qa_json, os as _qa_os, time as _qa_time\n'
            'from pathlib import Path as _QAPath\n'
            '_qa_file=_QAPath(_qa_os.environ["HOTTURKEY_DATA"])/"startup-delay.json"\n'
            '_qa_started=_qa_time.time()\n'
            '_qa_file.write_text(_qa_json.dumps({"started":_qa_started,"delay":14}))\n'
            '_qa_time.sleep(14)\n'
            '_qa_file.write_text(_qa_json.dumps({"started":_qa_started,"delay":14,"released":_qa_time.time()}))\n')
    server.write_text(prefix+server.read_text())
    subprocess.run(['/usr/bin/codesign','--force','--deep','--sign','-',str(app)],check=True,capture_output=True)
    subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)],check=True)
    RECORD.write_text(json.dumps({'app':str(app),'data':str(data),'offset':offset},indent=2));RECORD.chmod(0o600)
    print(str(app))


def verify():
    value=json.loads(RECORD.read_text());data=Path(value['data'])
    deadline=time.monotonic()+45
    while True:
        try:
            marker=json.loads((data/'startup-delay.json').read_text())
            log=(data/'desktop.log').read_bytes()[value['offset']:].decode()
            if 'released' in marker and any(line.endswith(' ready') for line in log.splitlines()):break
        except (OSError,ValueError):pass
        if time.monotonic()>=deadline:raise TimeoutError('Delayed fixture has not yet reached page readiness')
        time.sleep(.2)
    assert marker['released']-marker['started']>=14
    assert 'background pending; continuing retry' in log,log
    ready=[float(line.split()[0]) for line in log.splitlines() if line.endswith(' ready')]
    assert ready and ready[-1]>=marker['released'],log
    connection=json.loads((data/'connection.json').read_text())
    import urllib.request
    request=urllib.request.Request('http://127.0.0.1:'+str(connection['port'])+'/api/state',headers={'Authorization':'Bearer '+connection['token']})
    with urllib.request.urlopen(request,timeout=5) as response:state=json.load(response)
    assert state['enforcement']['desktop_connected']
    proof={'native_startup_delay_seconds':round(marker['released']-marker['started'],2),
           'continued_after_old_retry_limit':True,'automatic_connection_after_delay':True,
           'native_page_ready_after_delay':True,'disposable_backend_healthy':True}
    (ROOT/'build/startup-recovery-proof.json').write_text(json.dumps(proof,indent=2))
    print(json.dumps(proof))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--prepare',action='store_true');parser.add_argument('--reuse',type=Path);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    if args.prepare:prepare(args.reuse)
    elif args.verify:verify()
    else:parser.error('Choose --prepare or --verify')


if __name__=='__main__':main()
