'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto');
const source=fs.readFileSync(require('node:path').join(__dirname,'../extension/background.js'),'utf8');
const begin=source.indexOf('async function resolveNativeDocument('),end=source.indexOf('function glob(',begin);
const context={crypto:crypto.webcrypto,Uint8Array,TextDecoder,atob,console};vm.createContext(context);vm.runInContext(source.slice(begin,end),context);
const resolve=(first,fetch)=>context.resolveNativeDocument(first,fetch);
function pages(bytes){
  const hash=crypto.createHash('sha256').update(bytes).digest('hex'),meta={id:'a'.repeat(43),size:bytes.length,sha256:hash},result=[];
  for(let offset=0;offset<bytes.length;offset+=17){const end=Math.min(bytes.length,offset+17);result.push({__hotturkey_document__:{...meta},offset,data:bytes.subarray(offset,end).toString('base64'),next:end<bytes.length?end:null});}
  return result;
}
let count=0;
async function rejected(change){const list=pages(Buffer.from(JSON.stringify({blocks:['中文😀','x'.repeat(130)]})));change(list);let index=1;await assert.rejects(()=>resolve(list[0],async()=>list[index++]));count++;}
(async()=>{
  const input={blocks:['中文😀','x'.repeat(130)],settings:{block_inactive:true}};
  const list=pages(Buffer.from(JSON.stringify(input)));let index=1;
  const value=await resolve(list[0],async data=>{assert.equal(data.offset,list[index].offset);return list[index++];});
  assert.deepEqual(JSON.parse(JSON.stringify(value)),input);count++;
  const plain={error:'policy rejection',policy:true};assert.equal(await resolve(plain,()=>assert.fail()),plain);count++;
  await rejected(p=>{p[1].offset=0;});await rejected(p=>{p[1].__hotturkey_document__.id='b'.repeat(43);});
  await rejected(p=>{p[1].__hotturkey_document__.size++;});await rejected(p=>{p[0].next=0;});
  await rejected(p=>{p[0].next=null;});await rejected(p=>{p[0].data='';});
  await rejected(p=>{p[0].data='%%%';});await rejected(p=>{p[0].__hotturkey_document__.size=65*1024*1024;});
  await rejected(p=>{p[p.length-1].data=Buffer.from('corrupt').toString('base64');});
  await rejected(p=>{for(const page of p)page.__hotturkey_document__.sha256='0'.repeat(64);});
  const invalid=pages(Buffer.from([0xff,0xfe]));await assert.rejects(()=>resolve(invalid[0],()=>assert.fail()));count++;
  const error={error:'expired',policy:true},partial=pages(Buffer.from(JSON.stringify(input)));
  assert.equal(await resolve(partial[0],async()=>error),error);count++;
  const timers=[],transport={queue:[],port:{postMessage(){},disconnect(){}},connect(){},setTimeout(fn,delay){timers.push(delay);return timers.length;},clearTimeout(){}};
  vm.createContext(transport);vm.runInContext(source.slice(source.indexOf('function nativeFrame('),begin),transport);
  transport.nativeFrame('sync',{});const ordinary=timers.pop();transport.queue.length=0;
  transport.nativeFrame('sync',{payload:'x'.repeat(300000)});const large=timers.pop();
  transport.nativeFrame('check',{url:'https://a'});assert(large>ordinary);assert(timers.pop()>=large);count++;
  console.log(`${count} bounded document, Unicode, integrity and page-isolation checks passed`);
})().catch(error=>{console.error(error);process.exitCode=1;});
