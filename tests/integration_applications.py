"""Actual bundle and Steam-launcher blocking using only disposable processes."""
import json
import plistlib
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.app_targets import ApplicationTargets
from hotturkey.server import Service


def main():
    proof={}
    with tempfile.TemporaryDirectory(prefix='app-block-',dir=ROOT/'build') as temporary:
        root=Path(temporary)
        c=root/'fixture.c';c.write_text('#include <unistd.h>\n#include <signal.h>\nint main(void) { signal(SIGTERM, SIG_IGN); sleep(60); return 0; }\n')
        plain=root/'plain'
        subprocess.run(['/usr/bin/clang',str(c),'-o',str(plain)],check=True)
        swift=root/'fixture.swift'
        swift.write_text('import AppKit\nlet app=NSApplication.shared\napp.setActivationPolicy(.prohibited)\napp.run()\n')
        appkit=root/'appkit'
        subprocess.run(['/usr/bin/swiftc','-swift-version','5','-module-cache-path',str(ROOT/'build/swift-cache'),str(swift),'-o',str(appkit),'-framework','AppKit'],check=True)

        def bundle(path,identifier,binary):
            executable=path/'Contents/MacOS/Fixture';executable.parent.mkdir(parents=True)
            executable.write_bytes(binary.read_bytes());executable.chmod(0o755)
            (path/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':identifier,'CFBundleName':'HotTurkey Disposable Fixture','CFBundleExecutable':'Fixture','CFBundlePackageType':'APPL'}))
            return executable

        normal=root/'Normal.app';normal_bin=bundle(normal,'local.hotturkey.fixture.normal',appkit)
        background=root/'Background.app';background_bin=bundle(background,'local.hotturkey.fixture.background',plain)
        steam=root/'Steam';game=steam/'steamapps/common/Actual Game/Game.app'
        game_bin=bundle(game,'local.hotturkey.fixture.game',plain)
        client=steam/'Steam.AppBundle/Steam';client_bin=bundle(client,'com.valvesoftware.steam',plain)
        manifest=steam/'steamapps/appmanifest_9000001.acf'
        manifest.write_text('"AppState" { "appid" "9000001" "installdir" "Actual Game" }')
        shortcut=root/'Shortcut.app';script=shortcut/'Contents/MacOS/run.sh';script.parent.mkdir(parents=True)
        script.write_text('#!/bin/bash\nopen steam://run/9000001\n')
        (shortcut/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable':'run.sh'})+b'\0\0')
        service=Service(root/'data',enforce=True)
        service.engine.application_targets=ApplicationTargets(steam_root=steam,app_roots=[root])
        thread=threading.Thread(target=service.run,daemon=True);thread.start()
        decoy=subprocess.Popen([str(plain)])

        def call(path,data=None):
            request=urllib.request.Request(service.origin+'/api/'+path,data=json.dumps(data).encode() if data is not None else None,headers={'Authorization':'Bearer '+service.token,'Content-Type':'application/json'})
            with urllib.request.urlopen(request,timeout=5) as response:return json.load(response)

        try:
            for name,binary,selector in [('appkit_bundle',normal_bin,'bundle:local.hotturkey.fixture.normal'),('background_bundle',background_bin,'bundle:local.hotturkey.fixture.background'),('steam_client_bundle',client_bin,'bundle:com.valvesoftware.steam'),('steam_shortcut',game_bin,str(shortcut))]:
                process=subprocess.Popen([str(binary)])
                block=None
                try:
                    time.sleep(.5)
                    assert process.poll() is None,'Fixture did not start: '+name
                    block=call('blocks/save',{'block':{'name':'QA '+name,'enabled':True,'websites':['original.example']}})
                    locked=call('blocks/lock',{'id':block['id'],'type':'password','password':'integration-only'})
                    assert process.poll() is None,'Unlisted fixture was terminated: '+name
                    assert not call('check',{'url':'https://added.example','record':False})['blocked']
                    added=call('blocks/add-targets',{'id':block['id'],'applications':[selector],'websites':['added.example']})
                    assert added['locked'] and added['lock']==locked['lock'],'Lock changed during addition'
                    assert added['websites']==['original.example','added.example']
                    assert call('check',{'url':'https://added.example','record':False})['blocked']
                    until=time.monotonic()+8
                    while process.poll() is None and time.monotonic()<until:time.sleep(.1)
                    assert process.poll() is not None and process.returncode<0,'Application not blocked: '+name
                    assert decoy.poll() is None,'Unrelated fixture was terminated'
                    proof[name]={'blocked':True,'signal':process.returncode,'added_while_locked':True,'lock_preserved':True,'added_website_blocked':True}
                finally:
                    if process.poll() is None:process.kill()
                    process.wait()
                    if block:
                        call('blocks/unlock',{'id':block['id'],'answer':'integration-only'})
                        call('blocks/delete',{'id':block['id']})
            proof['unrelated_process_preserved']=True
            assert call('state')['enforcement']['desktop_connected']
        finally:
            decoy.kill();decoy.wait()
            service.http.shutdown();thread.join(timeout=7);service.store.db.close()
    (ROOT/'build/application-block-proof.json').write_text(json.dumps(proof,indent=2))
    print(json.dumps(proof))


if __name__=='__main__':main()
