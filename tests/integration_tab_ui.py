"""Interactive isolated block-page fixture; real policy and Native Messaging.

Serves the shipped worker and block page in a regular browser with explicit
browser-API doubles. This is NOT proof of a real installed browser extension.
No installed rules, user processes, login items or browser files are changed.
"""
import json
import os
import secrets
import struct
import subprocess
import sys
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.server import Service


def main():
    with tempfile.TemporaryDirectory(prefix='ht-tab-ui-',dir='/private/tmp') as temporary:
        service=Service(Path(temporary)/'data')
        service_thread=threading.Thread(target=service.run,daemon=True);service_thread.start()
        context=secrets.token_hex(24);control=secrets.token_urlsafe(32);stop=threading.Event()
        blocks=[]
        for name in ['文本验证','独立规则']:
            blocks.append(service.engine.save_block({'name':name,'enabled':True,'websites':['127.0.0.1']}))
        service.engine.set_lock(blocks[0]['id'],{'type':'text','custom_text':'focus'})
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def reply(self,data,kind='application/json'):
                blob=json.dumps(data).encode() if not isinstance(data,bytes) else data
                self.send_response(200);self.send_header('Content-Type',kind+'; charset=utf-8');self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(blob)));self.end_headers();self.wfile.write(blob)
            def do_GET(self):
                parsed=urllib.parse.urlsplit(self.path)
                if parsed.path=='/allowed':
                    tab=int(urllib.parse.parse_qs(parsed.query).get('tab',['7'])[0])
                    target=base+'/allowed?tab='+str(tab)
                    with service.store.lock:decision=service.engine.evaluate(target,exemptions=service.tab_exceptions.ids({'context':context,'tab':tab}))
                    if decision['blocked']:
                        self.send_response(302);self.send_header('Location',base+'/blocked.html?tab='+str(tab)+'#url='+target);self.end_headers();return
                    html='<meta charset="utf-8"><meta http-equiv="refresh" content="2"><title>标签页 '+str(tab)+' 已放行</title><h1>当前标签页已临时放行</h1><p>标签页 '+str(tab)+'；其他标签页和规则继续独立判断。</p>'
                    self.reply(html.encode(),'text/html');return
                if parsed.path=='/fixture-bridge.js':self.reply(bridge.replace('CONTEXT_VALUE',json.dumps(context)).encode(),'application/javascript');return
                name=parsed.path.lstrip('/')
                if name not in {'blocked.html','blocked.js','background.js','blocked.css','icon.svg'}:self.send_error(404);return
                blob=(ROOT/'extension'/name).read_bytes()
                kind='application/javascript' if name.endswith('.js') else 'text/css' if name.endswith('.css') else 'image/svg+xml' if name.endswith('.svg') else 'text/html'
                if name=='blocked.html':blob=blob.replace(b'<script src="blocked.js" defer>',b'<script src="fixture-bridge.js"></script><script src="background.js" defer></script><script src="blocked.js" defer>')
                self.reply(blob,kind)
            def do_POST(self):
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<1024*1024:self.send_error(400);return
                data=json.loads(self.rfile.read(length))
                if self.path=='/control':
                    if self.headers.get('X-Fixture-Control')!=control:self.send_error(403);return
                    action=data['action']
                    if action=='password':
                        service.engine.unlock(blocks[0]['id'],{'answer':'focus'})
                        service.engine.set_lock(blocks[0]['id'],{'type':'password','password':'fixture-password'})
                    if action=='close':service.tab_exceptions.close({'context':context,'tab':7})
                    if action=='snapshot':
                        with service.store.lock:
                            grants=service.tab_exceptions.snapshot(context,[7,8])
                            self.reply({'locks':[{k:b[k] for k in ['name','locked','blocking']} for b in service.engine.snapshot()['blocks']],'grants':[{'id':g['id'],'tab':g['tab'],'remaining':round(g['remaining'],1)} for g in grants]});return
                    if action=='stop':stop.set()
                    self.reply({'ok':True});return
                if self.path!='/bridge':self.send_error(404);return
                env={**os.environ,'HOTTURKEY_DATA':str(service.store.directory),'PYTHONDONTWRITEBYTECODE':'1'}
                payload=json.dumps(data).encode()
                result=subprocess.run([sys.executable,'-B','-m','hotturkey.native_host'],input=struct.pack('<I',len(payload))+payload,capture_output=True,cwd=ROOT,env=env,timeout=8,check=True)
                size=struct.unpack('<I',result.stdout[:4])[0]
                self.reply(json.loads(result.stdout[4:4+size]))
        http=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        base='http://127.0.0.1:'+str(http.server_address[1])
        bridge=r'''// Browser APIs are doubled only in this isolated localhost fixture.
window.addEventListener('error',e=>{const box=document.createElement('pre');box.textContent='Fixture error: '+e.message;document.body.append(box);});
const fixtureTab=Number(new URL(location.href).searchParams.get('tab')||sessionStorage.fixtureTab||7);
sessionStorage.fixtureTab=fixtureTab;
const fixtureHooks={};let fixturePolicy={};
const fixtureEvent=name=>({addListener(fn){fixtureHooks[name]=fn;}});
const ownTab=()=>({id:fixtureTab,url:location.href,active:true,windowId:1});
window.chrome={
 storage:{local:{get:async()=>fixturePolicy,set:async v=>{fixturePolicy=v;}},session:{get:async()=>({tabContext:CONTEXT_VALUE}),set:async()=>{}}},
 runtime:{getURL:name=>location.origin+'/'+name,onMessage:fixtureEvent('message'),onStartup:fixtureEvent('startup'),onInstalled:fixtureEvent('installed'),
  sendMessage:message=>new Promise((resolve,reject)=>{try{if(!fixtureHooks.message)throw Error('Fixture worker not registered');fixtureHooks.message(message,{tab:ownTab(),url:location.href,frameId:0},resolve);}catch(e){const box=document.createElement('pre');box.textContent='Fixture send: '+e.message;document.body.append(box);reject(e);}}),
  connectNative(){let receiver;let chain=Promise.resolve();return {onMessage:{addListener(fn){receiver=fn;}},onDisconnect:{addListener(){}},disconnect(){},postMessage(message){chain=chain.then(()=>fetch('/bridge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(message)})).then(r=>r.json()).then(r=>receiver(r));}}}},
 action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},idle:{setDetectionInterval(){},onStateChanged:fixtureEvent('idle')},alarms:{create(){},onAlarm:fixtureEvent('alarm')},
 tabs:{query:async()=>[ownTab()],get:async id=>({...ownTab(),id}),sendMessage:async()=>{},onUpdated:fixtureEvent('updated'),onCreated:fixtureEvent('created'),onActivated:fixtureEvent('activated'),onRemoved:fixtureEvent('removed')},
 windows:{get:async()=>({focused:true}),getLastFocused:async()=>({id:1,focused:true}),onFocusChanged:fixtureEvent('focus')},webNavigation:{onHistoryStateUpdated:fixtureEvent('history')},extension:{isAllowedIncognitoAccess:async()=>true,isAllowedFileSchemeAccess:async()=>true},
 declarativeNetRequest:{getSessionRules:async()=>[],updateSessionRules:async()=>{}}
};'''
        info=ROOT/'build/tab-ui-info.json'
        info.write_text(json.dumps({'base':base,'control':control}));info.chmod(0o600)
        thread=threading.Thread(target=http.serve_forever,daemon=True);thread.start()
        print(json.dumps({'url':base+'/blocked.html?tab=7#url='+base+'/allowed?tab=7','second_tab':base+'/blocked.html?tab=8#url='+base+'/allowed?tab=8'}),flush=True)
        try:stop.wait()
        except KeyboardInterrupt:pass
        finally:
            http.shutdown();http.server_close();service.http.shutdown();service_thread.join(timeout=10)
            service.http.server_close();service.store.db.close();service.singleton.close();info.unlink(missing_ok=True)


if __name__=='__main__':main()
