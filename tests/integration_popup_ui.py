"""Isolated popup UI: real worker/native messaging, explicit browser API doubles.

Open the printed UI with CUA. This does not install or test a real extension.
The manager URL uses the same disposable backend to test persisted text sizing.
"""
import copy,json,os,secrets,struct,subprocess,sys,tempfile,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.server import Service
from hotturkey.engine import password_hash


def main():
    with tempfile.TemporaryDirectory(prefix='ht-popup-ui-',dir=ROOT/'build') as temporary:
        service=Service(Path(temporary)/'data');stop=threading.Event();control=secrets.token_urlsafe(32)
        thread=threading.Thread(target=service.run,daemon=True);thread.start()
        locked=service.engine.save_block({'name':'锁定目标','enabled':True,'websites':['existing.invalid'],'exceptions':['example.com/learn'],'break':{'type':'allowance','allowance_minutes':5}})
        service.engine.set_lock(locked['id'],{'type':'text','custom_text':'popup-fixture'})
        disabled=service.engine.save_block({'name':'未启用目标','enabled':False,'websites':[]})
        baseline=copy.deepcopy(service.store.state)
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def reply(self,data,kind='application/json'):
                blob=json.dumps(data).encode() if not isinstance(data,bytes) else data
                self.send_response(200);self.send_header('Content-Type',kind+'; charset=utf-8');self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(blob)));self.end_headers();self.wfile.write(blob)
            def do_GET(self):
                name=urlsplit(self.path).path.lstrip('/') or 'popup.html'
                if name=='fixture.js':self.reply(bridge.encode(),'application/javascript');return
                if name not in {'popup.html','popup.js','background.js','blocked.css','icon.svg'}:self.send_error(404);return
                blob=(ROOT/'extension'/name).read_bytes()
                kind='application/javascript' if name.endswith('.js') else 'text/css' if name.endswith('.css') else 'image/svg+xml' if name.endswith('.svg') else 'text/html'
                if name=='popup.html':
                    blob=blob.replace(b'<script src="popup.js" defer>',b'<script src="fixture.js"></script><script src="background.js" defer></script><script src="popup.js" defer>')
                    blob=blob.replace(b'<main>',b'<main><p style="font-size:11px">QA: browser APIs doubled; real local backend</p>')
                self.reply(blob,kind)
            def do_POST(self):
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<1024*1024:self.send_error(400);return
                data=json.loads(self.rfile.read(length))
                if self.path=='/control':
                    if self.headers.get('X-Fixture-Control')!=control:self.send_error(403);return
                    with service.store.lock:
                        if data['op']=='password':service.store.state['settings']['settings_password']=password_hash('popup-manager');service.store.save()
                        if data['op']=='snapshot':
                            state=copy.deepcopy(service.store.state)
                            preserved=all({k:v for k,v in a.items() if k!='websites'}=={k:v for k,v in b.items() if k!='websites'} for a,b in zip(state['blocks'],baseline['blocks']))
                            self.reply({'blocks':service.engine.snapshot()['blocks'],'text_scale':state['settings']['text_scale'],'all_non_website_rule_fields_preserved':preserved,'original_runtime_preserved':all(state['runtime'].get(k)==v for k,v in baseline['runtime'].items())});return
                        if data['op']=='stop':stop.set()
                    self.reply({'ok':True});return
                if self.path!='/bridge':self.send_error(404);return
                env={**os.environ,'HOTTURKEY_DATA':str(service.store.directory),'PYTHONDONTWRITEBYTECODE':'1'}
                payload=json.dumps(data).encode()
                result=subprocess.run([sys.executable,'-B','-m','hotturkey.native_host'],input=struct.pack('<I',len(payload))+payload,capture_output=True,cwd=ROOT,env=env,check=True,timeout=8)
                size=struct.unpack('<I',result.stdout[:4])[0];self.reply(json.loads(result.stdout[4:4+size]))
        bridge=r'''const hooks={},event=name=>({addListener(fn){hooks[name]=fn;}});
const tab={id:7,url:'https://example.com/learn/a?private=not-saved#token',active:true,windowId:1};
window.chrome={
 storage:{local:{get:async()=>({}),set:async()=>{}},session:{get:async()=>({tabContext:'a'.repeat(48)}),set:async()=>{}}},
 runtime:{getURL:s=>location.origin+'/'+s,onMessage:event('message'),onStartup:event('startup'),onInstalled:event('installed'),
 sendMessage:message=>new Promise((resolve,reject)=>{try{hooks.message(message,{url:location.origin+'/popup.html',frameId:0},resolve);}catch(e){reject(e);}}),
 connectNative(){let receiver;let chain=Promise.resolve();return {onMessage:{addListener(fn){receiver=fn;}},onDisconnect:{addListener(){}},disconnect(){},postMessage(message){chain=chain.then(()=>fetch('/bridge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(message)})).then(r=>r.json()).then(r=>receiver(r));}}}},
 action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},idle:{setDetectionInterval(){},onStateChanged:event('idle')},alarms:{create(){},onAlarm:event('alarm')},
 tabs:{query:async()=>[tab],get:async()=>tab,sendMessage:async()=>{},onUpdated:event('updated'),onCreated:event('created'),onActivated:event('activated'),onRemoved:event('removed')},
 windows:{get:async()=>({focused:true}),getLastFocused:async()=>({id:1,focused:true}),onFocusChanged:event('focus')},webNavigation:{onHistoryStateUpdated:event('history')},extension:{isAllowedIncognitoAccess:async()=>true,isAllowedFileSchemeAccess:async()=>true},
 declarativeNetRequest:{getSessionRules:async()=>[],updateSessionRules:async()=>{}}
};'''
        http=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        info=ROOT/'build/popup-ui-info.json';value={'url':'http://127.0.0.1:'+str(http.server_address[1])+'/popup.html','manager':service.origin+'/#token='+service.token,'control':control}
        info.write_text(json.dumps(value));info.chmod(0o600)
        threading.Thread(target=http.serve_forever,daemon=True).start()
        print(json.dumps({k:v for k,v in value.items() if k!='control'}),flush=True)
        try:stop.wait()
        finally:
            http.shutdown();http.server_close();service.http.shutdown();thread.join(timeout=8);service.store.db.close();info.unlink(missing_ok=True)


if __name__=='__main__':main()
