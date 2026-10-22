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
 if(op==='sync')return {...policy,tab_grants:[]};
 if(op==='add-site-options')return {blocks:[{id:'a',name:'A',enabled:true,locked:true,mode:'continuous'}]};
 if(op==='add-site')return {ok:true,target:data.scope==='page'?'https://example.com/a':'example.com',added:true,block:{enabled:true,mode:'continuous'}};
 return {error:'unsupported'};
};
run('native=(op,data)=>remote(op,data)');
const popup={url:'chrome-extension://test/popup.html'};
const message=(op,data={},sender=popup)=>new Promise(resolve=>hooks.message({op,data},sender,resolve));
let count=0;
(async()=>{
 await new Promise(setImmediate);requests=[];
 assert.match((await message('add-site-options',{}, {url:'https://evil.example',tab:tabs.get(7),frameId:0})).error,/弹窗/);assert.equal(requests.length,0);count++;
 assert.match((await message('add-site-options',{}, {...popup,frameId:1})).error,/弹窗/);assert.equal(requests.length,0);count++;
 let value=await message('add-site-options');assert.equal(value.page.url,'https://example.com/a');assert.equal(value.page.domain,'example.com');assert.equal(value.blocks[0].id,'a');count++;
 let page=value.page;
 assert.equal((await message('add-site',{...page,id:'a',scope:'domain',websites:['evil.example'],applications:['evil'],exceptions:['*'],enabled:false,password:'manager'})).ok,true);
 const request=requests.find(r=>r.op==='add-site');assert.deepEqual(Object.keys(request).sort(),['op','id','url','scope','password'].sort());assert.equal(request.url,'https://example.com/a');count++;
 requests=[];assert.match((await message('add-site',{...page,tab:8,id:'a',scope:'domain'})).error,/改变/);assert.equal(requests.filter(r=>r.op==='add-site').length,0);count++;
 tabs.get(7).pendingUrl='https://different.example/';assert.match((await message('add-site',{...page,id:'a',scope:'domain'})).error,/改变/);delete tabs.get(7).pendingUrl;count++;
 assert.match((await message('add-site',{...page,id:'a',scope:'exceptions'})).error,/请选择/);count++;
 tabs.get(7).url='edge://settings';assert.match((await message('add-site-options')).error,/普通/);count++;
 tabs.get(7).url='https://user:secret@example.com/';assert.match((await message('add-site-options')).error,/普通/);count++;
 tabs.get(7).url='https://example.com/%E4%B8%AD%E6%96%87?token=private#secret';value=await message('add-site-options');assert.equal(value.page.page,'https://example.com/中文');assert.equal(value.page.domain,'example.com');count++;
 tabs.get(7).url='https://example.com./a';value=await message('add-site-options');assert.equal(value.page.domain,'example.com');assert.equal(run("localCheck('https://example.com./a',[],true,false,7).blocked"),true);count++;
 const oldTargets=policy.blocks[0].websites;policy.blocks[0].websites=['::1'];assert.equal(run("localCheck('http://[::1]/a',[],true,false,7).blocked"),true);policy.blocks[0].websites=oldTargets;count++;
 offline=true;assert.equal((await message('add-site',{...value.page,id:'a',scope:'domain'})).error,'offline');count++;
 assert.equal(persisted.some(v=>JSON.stringify(v).includes('manager')),false);count++;
 console.log(`${count} popup-only website addition, scope, navigation and privacy checks passed`);
})().catch(error=>{console.error(error);process.exitCode=1;});
