// Execute the real worker against browser API doubles, including navigation races.
const vm=require('node:vm'),fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const hooks={},event=name=>({addListener(fn){hooks[name]=fn;}});
let tabs=new Map(),removed=[],reports=[],requests=[],failRemoval=false,replyGate=null;
const policy={blocks:[{id:'a',blocking:true,websites:['edge://settings','about:preferences'],exceptions:['edge://settings/downloads']}],settings:{block_inactive:false,block_embeds:true,allow_files:true}};
const api={
  storage:{local:{get:async()=>({}),set:async()=>{}}},
  runtime:{getURL:s=>'chrome-extension://test/'+s,connectNative(){throw Error('offline');},onMessage:event('message'),onStartup:event('startup'),onInstalled:event('installed')},
  action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},idle:{setDetectionInterval(){},onStateChanged:event('idle')},alarms:{create(){},onAlarm:event('alarm')},
  tabs:{query:async()=>[...tabs.values()],get:async id=>{if(!tabs.has(id))throw Error('No tab');return tabs.get(id);},remove:async id=>{if(failRemoval)throw Error('Removal failed');removed.push(id);tabs.delete(id);},sendMessage:async()=>{},onActivated:event('activated'),onRemoved:event('removed'),onUpdated:event('updated'),onCreated:event('created')},
  windows:{get:async()=>({focused:true}),getLastFocused:async()=>({id:1,focused:true}),onFocusChanged:event('focus')},webNavigation:{onHistoryStateUpdated:event('history')},extension:{isAllowedIncognitoAccess:async()=>true,isAllowedFileSchemeAccess:async()=>true}
};
const context={chrome:api,navigator:{userAgent:'Edg/130.0'},console:{warn(){},debug(){}},URL,Map,Set,Promise,setInterval(){},setTimeout(){},clearTimeout(){}};
vm.createContext(context);const run=code=>vm.runInContext(code,context);
run(fs.readFileSync(path.join(__dirname,'../extension/background.js'),'utf8'));
context.remote=async(op,data)=>{
 requests.push({op,...data});
 if(op==='sync')return policy;
 if(op==='closed-tab'){reports.push(data);return {ok:true};}
 if(replyGate)await replyGate.promise;
 return run(`localCheck(${JSON.stringify(data.url)},[],${JSON.stringify(data.active)})`);
};
const put=(url,extra={})=>{const tab={id:7,url,active:true,windowId:1,...extra};tabs.set(tab.id,tab);return tab;};
const enforce=tab=>run(`enforceBrowserPage(${tab.id},${JSON.stringify(tab)})`);
const gate=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
let count=0;
(async()=>{
 await new Promise(setImmediate);run('native=(op,data)=>remote(op,data)');context.fixturePolicy=policy;run('cache=fixturePolicy');
 await enforce(put('edge://settings/privacy',{incognito:true}));assert.deepEqual(removed,[7]);assert.equal(reports[0].incognito,true);assert.equal(requests.find(x=>x.op==='check').record,false);count++;
 removed=[];reports=[];
 await enforce(put('edge://settings/downloads'));assert.deepEqual(removed,[]);assert.deepEqual(reports,[]);count++;
 await enforce(put('https://settings/privacy'));await enforce(put('chrome-extension://test/options'));assert.deepEqual(removed,[]);count++;
 await enforce(put('edge://settings/privacy',{active:false}));assert.deepEqual(removed,[]);count++;
 policy.settings.block_inactive=true;await enforce(tabs.get(7));assert.deepEqual(removed,[7]);count++;policy.settings.block_inactive=false;
 removed=[];reports=[];replyGate=gate();let tab=put('edge://settings/privacy');let task=enforce(tab);
 tabs.set(7,{...tab,url:'https://allowed.example'});replyGate.resolve();await task;assert.deepEqual(removed,[]);assert.deepEqual(reports,[]);count++;replyGate=null;
 replyGate=gate();tab=put('edge://settings/privacy');const before=requests.filter(x=>x.op==='check').length;
 const first=enforce(tab),second=enforce(tab);replyGate.resolve();await Promise.all([first,second]);replyGate=null;
 assert.deepEqual(removed,[7]);assert.equal(requests.filter(x=>x.op==='check').length,before+1);count++;
 removed=[];reports=[];failRemoval=true;tab=put('edge://settings/privacy');await enforce(tab);assert.deepEqual(reports,[]);failRemoval=false;await enforce(tab);assert.deepEqual(removed,[7]);count++;
 removed=[];tab=put('about:preferences#privacy');hooks.updated(tab.id,{url:tab.url},tab);await new Promise(setImmediate);assert.deepEqual(removed,[7]);count++;
 removed=[];tab=put('edge://settings/privacy');hooks.created(tab);await new Promise(setImmediate);assert.deepEqual(removed,[7]);count++;
 removed=[];put('edge://settings/privacy');await run('sync()');assert.deepEqual(removed,[7]);count++;
 removed=[];reports=[];run("native=async()=>({error:'offline'})");await enforce(put('edge://settings/privacy'));assert.deepEqual(removed,[7]);count++;
 console.log(`${count} internal browser page enforcement and race checks passed`);
})().catch(error=>{console.error(error);process.exitCode=1;});
