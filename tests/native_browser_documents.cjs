'use strict';
// Real signed native parent/host, with the actual extension document decoder.
// No browser API or live browser is claimed by this transport test.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto'),cp=require('node:child_process');
const args=process.argv.slice(2),legacy=args[0]==='--legacy';
const [fixture,host,config,socket,uid,origin]=args;
const child=legacy?cp.spawn(args[1],['-E','-s','-B','-m','hotturkey.native_host'],{stdio:['pipe','pipe','pipe']}):cp.spawn(fixture,[host,config,socket,uid,origin],{stdio:['pipe','pipe','pipe']});
let buffer=Buffer.alloc(0),pending=null,maxFrame=0,replies=0;
child.stdout.on('data',data=>{buffer=Buffer.concat([buffer,data]);while(buffer.length>=4){const size=buffer.readUInt32LE();if(size>1024*1024){pending?.reject(Error('Oversized native frame'));return;}if(buffer.length<size+4)return;const body=buffer.subarray(4,size+4);buffer=buffer.subarray(size+4);maxFrame=Math.max(maxFrame,size);replies++;const item=pending;pending=null;if(item){clearTimeout(item.timer);try{item.resolve(JSON.parse(body));}catch(error){item.reject(error);}}}});
child.on('error',error=>pending?.reject(error));child.on('exit',()=>{if(pending){clearTimeout(pending.timer);pending.reject(Error('Native fixture exited'));pending=null;}});
function wire(op,data,capable=true){assert.equal(pending,null);return new Promise((resolve,reject)=>{const body=Buffer.from(JSON.stringify({op,data,...(capable?{document_protocol:1}:{})})),header=Buffer.alloc(4);header.writeUInt32LE(body.length);pending={resolve,reject,timer:setTimeout(()=>reject(Error('Native deadline')),12000)};child.stdin.write(Buffer.concat([header,body]));});}
const source=fs.readFileSync(require('node:path').join(__dirname,'../extension/background.js'),'utf8'),begin=source.indexOf('async function resolveNativeDocument('),end=source.indexOf('function glob(',begin);
const context={crypto:crypto.webcrypto,Uint8Array,TextDecoder,atob};vm.createContext(context);vm.runInContext(source.slice(begin,end),context);
(async()=>{
  const request={context:'e'.repeat(48),tabs:[1],usage:[]};let first;
  for(let i=0;i<25;i++){first=await wire('sync',request);if(!first.error)break;await new Promise(resolve=>setTimeout(resolve,100));}
  assert(first.__hotturkey_document__,'Large browser policy was not paged');
  const result=await context.resolveNativeDocument(first,data=>wire('document-read',data));
  const large=result.blocks.find(b=>b.name==='Large browser transport');assert.equal(large.websites.length,4000);assert(large.websites[0].includes('星'));
  const usage=Array.from({length:200},(_,tab)=>({tab,url:'https://upload.invalid/'+tab+'/'+'x'.repeat(7900),active:false}));
  const outgoing={context:'e'.repeat(48),tabs:usage.map(x=>x.tab),usage};assert(Buffer.byteLength(JSON.stringify(outgoing))>1024*1024);
  const second=await wire('sync',outgoing);assert(second.__hotturkey_document__);
  const restored=await context.resolveNativeDocument(second,data=>wire('document-read',data));assert.equal(restored.blocks.find(b=>b.id===large.id).websites.length,4000);
  const older=await wire('sync',request,false);assert(older.error&&older.policy,'Old decoder did not receive a clear upgrade response');
  console.log(JSON.stringify({large_browser_policy_JS_decoder:true,large_browser_input_uploaded:true,old_decoder_upgrade_response:true,all_native_frames_bounded:maxFrame<=1024*1024,replies}));
})().catch(error=>{console.error(error.message);process.exitCode=1;}).finally(()=>{if(pending)clearTimeout(pending.timer);child.stdin.end();setTimeout(()=>{if(child.exitCode===null)child.kill();},1000).unref();});
