// Execute the real worker with browser API doubles; no duplicated policy implementation.
const vm=require('node:vm'),fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {webcrypto}=require('node:crypto');
const hooks={},event=name=>({addListener(fn){hooks[name]=fn;}});
let now=100000,generated=[],persisted=[],requests=[],offline=false,serverGrants=[];
const revision='1'.repeat(64),secondRevision='2'.repeat(64);
const policy={tab_unblock_supported:true,blocks:[{id:'a',name:'A',blocking:true,locked:true,lock:{type:'text'},websites:['example.com'],exceptions:[],tab_revision:revision},{id:'b',name:'B',blocking:true,locked:false,websites:['example.com'],exceptions:[],tab_revision:secondRevision}],settings:{block_inactive:true,block_embeds:true,allow_files:true}};
const blockedURL='chrome-extension://test/blocked.html#url=https://example.com/a';
let tabs=new Map([[7,{id:7,url:blockedURL,active:true,windowId:1}],[8,{id:8,url:'https://example.com/a',active:false,windowId:1}]]);
let storedContext;
const api={
 storage:{local:{get:async()=>({}),set:async value=>persisted.push(JSON.parse(JSON.stringify(value)))},session:{get:async()=>({tabContext:storedContext}),set:async value=>{storedContext=value.tabContext;}}},
 runtime:{getURL:s=>'chrome-extension://test/'+s,connectNative(){throw Error('offline');},onMessage:event('message'),onStartup:event('startup'),onInstalled:event('installed')},
 action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},idle:{setDetectionInterval(){},onStateChanged:event('idle')},alarms:{create(){},onAlarm:event('alarm')},
 tabs:{query:async query=>[...tabs.values()].filter(t=>!query.active||t.active),get:async id=>{if(!tabs.has(id))throw Error('No tab');return tabs.get(id);},remove:async id=>tabs.delete(id),sendMessage:async()=>{},onActivated:event('activated'),onRemoved:event('removed'),onUpdated:event('updated'),onCreated:event('created')},
 windows:{get:async()=>({focused:true}),getLastFocused:async()=>({id:1,focused:true}),onFocusChanged:event('focus')},webNavigation:{onHistoryStateUpdated:event('history')},extension:{isAllowedIncognitoAccess:async()=>true,isAllowedFileSchemeAccess:async()=>true},
 declarativeNetRequest:{getSessionRules:async()=>generated,updateSessionRules:async value=>{generated=value.addRules;}}
};
const context={chrome:api,navigator:{userAgent:'Edg/130.0'},console,URL,Map,Set,Promise,crypto:webcrypto,Uint8Array,performance:{now:()=>now},setInterval(){},setTimeout(){},clearTimeout(){}};
vm.createContext(context);const run=code=>vm.runInContext(code,context);
run(fs.readFileSync(path.join(__dirname,'../extension/background.js'),'utf8'));
context.remote=async(op,data)=>{
 requests.push({op,...data});
 if(offline)return {error:'offline'};
 if(op==='sync')return {...policy,tab_grants:serverGrants.filter(g=>data.tabs.includes(g.tab))};
 if(op==='tab-unblock'){
  if(data.answer!=='focus')return {id:data.id,method:'text',challenge:'focus'};
  const grant={id:data.id,tab:data.tab,remaining:60,revision};serverGrants=[grant];return {...grant,granted:true};
 }
 if(op==='tab-close'){serverGrants=serverGrants.filter(g=>g.tab!==data.tab);return {ok:true};}
 if(op==='check')return run(`localCheck(${JSON.stringify(data.url)},[],true,false,${JSON.stringify(data.tab)})`);
 return {error:'unsupported'};
};
run('native=(op,data)=>remote(op,data)');
const sender={tab:tabs.get(7),url:blockedURL,frameId:0};
const emit=(op,data,senderValue=sender)=>new Promise(resolve=>hooks.message({op,data},senderValue,resolve));
let count=0;
(async()=>{
 await run('sync()');
 assert.match(storedContext,/^[a-f0-9]{48}$/);count++;
 const status=await emit('status',{});assert.equal(status.tab_unblock_available,1);assert.equal('context' in status,false);count++;
 for(const bad of [{tab:tabs.get(7),url:'https://example.com',frameId:0},{...sender,frameId:1},{url:blockedURL,frameId:0}]){
  assert.ok((await emit('tab-unblock',{id:'a',answer:'focus'},bad)).error);count++;
 }
 const challenge=await emit('tab-unblock',{id:'a',minutes:1});assert.equal(challenge.challenge,'focus');assert.equal(serverGrants.length,0);count++;
 const granted=await emit('tab-unblock',{id:'a',minutes:1,answer:'focus',tab:8,context:'attacker',url:'https://wrong.example'});
 assert.equal(granted.granted,true);const request=requests.findLast(r=>r.op==='tab-unblock');assert.equal(request.tab,7);assert.equal(request.context,storedContext);assert.equal(request.url,'https://example.com/a');count++;
 assert.equal(generated.length,2);assert.deepEqual(Array.from(generated[0].condition.excludedTabIds),[7]);assert.equal(generated[1].condition.excludedTabIds,undefined);assert.equal(generated.some(r=>r.action.type==='allow'),false);count++;
 assert.equal(run("localCheck('https://example.com/a',[],true,false,7).blocks.length"),1);assert.equal(run("localCheck('https://example.com/a',[],true,false,8).blocks.length"),2);count++;
 assert.equal(persisted.some(p=>p.policy.tab_grants||JSON.stringify(p).includes(storedContext)),false);count++;
 await emit('check',{url:'https://example.com/a',tab:8,context:'spoofed'},{...sender,url:'https://example.com/a'});
 const checked=requests.findLast(r=>r.op==='check');assert.equal(checked.tab,7);assert.equal(checked.context,storedContext);count++;
 now+=60000;await run('updateNetworkRules()');assert.equal(generated[0].condition.excludedTabIds,undefined);count++;
 serverGrants=[{id:'a',tab:7,remaining:60,revision}];await run('sync()');policy.blocks[0].tab_revision='3'.repeat(64);await run('updateNetworkRules()');assert.equal(generated[0].condition.excludedTabIds,undefined);count++;policy.blocks[0].tab_revision=revision;
 serverGrants=[{id:'a',tab:7,remaining:60,revision}];await run('sync()');tabs.delete(7);hooks.removed(7);await new Promise(setImmediate);await run('updateNetworkRules()');assert.equal(generated[0].condition.excludedTabIds,undefined);assert.equal(serverGrants.length,0);count++;
 tabs.set(7,sender.tab);hooks.created(sender.tab);serverGrants=[{id:'a',tab:7,remaining:60,revision}];await run('sync()');offline=true;await run('sync()');assert.equal(generated[0].condition.excludedTabIds,undefined);count++;offline=false;
 policy.settings.block_inactive=false;serverGrants=[{id:'a',tab:7,remaining:60,revision}];await run('sync()');assert.equal(generated.length,1);assert.equal(generated[0].condition.excludedTabIds,undefined);assert.deepEqual(Array.from(generated[0].condition.tabIds),[7]);count++;
 tabs.set(7,{...sender.tab,url:'https://different.example'});assert.ok((await emit('tab-unblock',{id:'a',answer:'focus'})).error);count++;
 console.log(`${count} tab-only authorization, isolation, expiry and network-rule checks passed`);
})().catch(error=>{console.error(error);process.exitCode=1;});
