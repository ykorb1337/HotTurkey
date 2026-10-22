'use strict';
const api = typeof browser!=='undefined'?browser:chrome;
const BROWSER = /Edg\//.test(navigator.userAgent)?'Edge':/Firefox\//.test(navigator.userAgent)?'Firefox':/OPR\//.test(navigator.userAgent)?'Opera':/Vivaldi/.test(navigator.userAgent)?'Vivaldi':(navigator.brave?'Brave':'Chrome');
let cache={blocks:[],settings:{block_inactive:false,block_embeds:true,allow_files:true},now:0};
let connected=false, port=null, requestId=0, pending=new Map(), idle='active', channels=new Map();
// Native Messaging is ordered. A queue maps each response to the matching request.
let queue=[];
const monotonicNow=()=>typeof performance!=='undefined'?performance.now():Date.now();
let tabGrants=new Map(),contextTask=null,networkTask=Promise.resolve(),syncTask=null;
const closedTabs=new Set();
const cacheReady=api.storage.local.get('policy').then(value=>{if(value.policy){cache=value.policy;delete cache.tab_grants;}return updateNetworkRules();}).catch(()=>{});
async function browserContext(){
  if(!api.storage.session||typeof crypto==='undefined')throw Error('此浏览器需要支持会话存储才能临时放行');
  if(!contextTask)contextTask=(async()=>{const saved=await api.storage.session.get('tabContext');if(/^[a-zA-Z0-9_-]{32,128}$/.test(saved.tabContext||''))return saved.tabContext;const bytes=crypto.getRandomValues(new Uint8Array(24));const value=Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');await api.storage.session.set({tabContext:value});return value;})();
  return contextTask;
}
function pruneTabGrants(){const now=monotonicNow();for(const [key,g] of tabGrants){const block=cache.blocks.find(b=>b.id===g.id);if(g.until<=now||!block||block.tab_revision!==g.revision||closedTabs.has(g.tab))tabGrants.delete(key);}}
function tabIsGranted(tab,id){pruneTabGrants();return tabGrants.has(tab+':'+id);}
function acceptTabGrants(values,elapsed=0){tabGrants.clear();const now=monotonicNow();for(const g of (Array.isArray(values)?values:[]).slice(0,512)){if(!Number.isInteger(g.tab)||g.tab<0||typeof g.id!=='string'||typeof g.revision!=='string'||!Number.isFinite(g.remaining)||g.remaining<=0||g.remaining>86400)continue;tabGrants.set(g.tab+':'+g.id,{...g,until:now+g.remaining*1000-elapsed});}pruneTabGrants();scheduleGrantExpiry();}
function scheduleGrantExpiry(){pruneTabGrants();if(!tabGrants.size)return;const delay=Math.max(1,Math.min(...Array.from(tabGrants.values(),g=>g.until-monotonicNow())));api.alarms.create('tab-grant-expiry',{when:Date.now()+delay});}
function forgetTabGrants(tab){for(const [key,g] of tabGrants)if(tab===undefined||g.tab===tab)tabGrants.delete(key);return updateNetworkRules();}
function blockedTarget(url){try{if(String(url).split(/[?#]/)[0]!==api.runtime.getURL('blocked.html'))return null;const raw=new URL(url).hash.slice(1);const target=raw.startsWith('url=')?raw.slice(4):JSON.parse(decodeURIComponent(raw)).url;return /^https?:\/\//.test(target)?target:null;}catch{return null;}}
async function currentStatus(sender){await sync();await updateNetworkRules();const tab=sender?.tab||(await api.tabs.query({active:true,lastFocusedWindow:true}))[0];return {connected,...cache,tab_unblock_available:cache.tab_unblock_supported===true&&!!api.storage.session?1:0,tab_grants:Array.from(tabGrants.values()).filter(g=>g.tab===tab?.id).map(g=>({id:g.id,remaining:Math.max(0,(g.until-monotonicNow())/1000)}))};}
async function requestTabUnblock(data,sender){
  if(!sender?.tab||sender.frameId!==0||!blockedTarget(sender.url))return {error:'只能从当前标签页的拦截页申请临时放行'};
  const tab=await api.tabs.get(sender.tab.id);if(tab.url!==sender.url||tab.pendingUrl&&tab.pendingUrl!==sender.url)return {error:'标签页已改变，请重新检查'};
  const context=await browserContext();
  const result=await native('tab-unblock',{context,tab:tab.id,url:blockedTarget(tab.url),channels:channels.get(tab.id)||[],id:data.id,minutes:data.minutes,...(data.answer!==undefined?{answer:data.answer}:{})});
  if(result.granted){const current=await api.tabs.get(tab.id).catch(()=>null);if(!current||current.url!==sender.url){await forgetTabGrants(tab.id);await native('tab-close',{context,tab:tab.id});return {error:'标签页已改变，临时放行已取消'};}if(syncTask)await syncTask;await sync();if(await updateNetworkRules()===false){await forgetTabGrants(tab.id);await native('tab-close',{context,tab:tab.id});return {error:'无法更新浏览器拦截规则，临时放行已取消'};}}
  return result;
}
function requirePopup(sender){if(sender?.url!==api.runtime.getURL('popup.html')||(sender.frameId!==undefined&&sender.frameId!==0))throw Error('只能从 HotTurkey 扩展弹窗添加网站');}
async function popupPage(){
  const tab=(await api.tabs.query({active:true,lastFocusedWindow:true}))[0];
  const raw=tab?.pendingUrl||tab?.url||'',url=blockedTarget(raw)||raw;
  let parsed;try{parsed=new URL(url);}catch{throw Error('当前页面不能添加为网站规则');}
  if(!['http:','https:'].includes(parsed.protocol)||parsed.username||parsed.password)throw Error('请打开普通 HTTP 或 HTTPS 网页后再添加');
  return {tab:tab.id,url,actual:raw,domain:parsed.hostname.replace(/^\[|\]$/g,'').replace(/\.$/,''),page:parsed.protocol+'//'+parsed.hostname.replace(/^\[|\]$/g,'').replace(/\.$/,'')+decodeURIComponent(parsed.pathname||'/')};
}
async function quickAddOptions(data,sender){
  requirePopup(sender);const page=await popupPage();
  const result=await native('add-site-options',typeof data.password==='string'?{password:data.password}:{});
  return {...result,...(!result.error?{page}:{})};
}
async function quickAddSite(data,sender){
  requirePopup(sender);const page=await popupPage();
  if(page.tab!==data.tab||page.url!==data.url||page.actual!==data.actual)throw Error('当前标签页已改变，请重新打开扩展');
  if(!['domain','page'].includes(data.scope)||typeof data.id!=='string')throw Error('请选择目标规则和范围');
  const result=await native('add-site',{id:data.id,url:page.url,scope:data.scope,...(typeof data.password==='string'?{password:data.password}:{})});
  if(result.ok){await sync();await updateNetworkRules();}
  return result;
}
function connect(){if(port)return;try{port=api.runtime.connectNative('local.hotturkey.bridge');port.onMessage.addListener(result=>{if(result.error&&!result.policy)forgetTabGrants().catch(()=>{});const item=queue.shift();if(item){clearTimeout(item.timer);item.resolve(result);}connected=!result.error||result.policy===true;});port.onDisconnect.addListener(()=>{port=null;connected=false;forgetTabGrants().catch(()=>{});for(const item of queue){clearTimeout(item.timer);item.resolve({error:'后台未连接'});}queue=[];api.action.setBadgeText({text:'!'});api.action.setBadgeBackgroundColor({color:'#b95636'});});}catch{port=null;connected=false;}}
function native(op,data){connect();if(!port)return Promise.resolve({error:'后台未连接'});return new Promise(resolve=>{const item={resolve,timer:setTimeout(()=>{if(port)port.disconnect();},7000)};queue.push(item);try{port.postMessage({op,data});}catch{queue.pop();clearTimeout(item.timer);resolve({error:'后台未连接'});}});}
function glob(pattern,value){return new RegExp('^'+pattern.replace(/[.+?^${}()|[\]\\]/g,'\\$&').replace(/\*/g,'.*')+'$','i').test(value);}
function browserPage(url){try{const u=new URL(url);const scheme=u.protocol.slice(0,-1).toLowerCase();let page,path;if(scheme==='about'){const parts=u.pathname.split('/');page=parts.shift();path=parts.join('/');}else if(['chrome','edge','brave','vivaldi','opera'].includes(scheme)){page=u.hostname;path=u.pathname.replace(/^\/+/, '');}else return null;if(!page)return null;return [scheme,page.toLowerCase(),decodeURIComponent((path?'/'+path:'')+u.search+u.hash).toLowerCase()];}catch{return null;}}
function browserPageMatches(pattern,url){const actual=browserPage(url),wanted=browserPage(pattern);if(!actual||!wanted)return false;const [scheme,page,suffix]=actual,[wantedScheme,wantedPage,expected]=wanted;if(wantedScheme!==scheme&&!(wantedScheme==='chrome'&&['brave','vivaldi','opera'].includes(scheme)))return false;if(['newtab','newtab-page','extensions','addons','welcome','home'].includes(page)&&wantedPage!==page)return false;if(!glob(wantedPage,page))return false;return !expected||(expected.includes('*')?glob(expected,suffix):suffix.startsWith(expected));}
function matches(pattern,url){try{pattern=pattern.trim().toLowerCase();if(/^(?:chrome|edge|brave|vivaldi|opera|about):/i.test(url))return browserPageMatches(pattern,url);const u=new URL(url);const hostname=u.hostname.replace(/^\[|\]$/g,'').replace(/\.$/,'');if(pattern==='*.*')return ['http:','https:','ftp:'].includes(u.protocol);if(pattern==='*')return true;if(pattern.includes('://')){const p=pattern.split('://');if(!glob(p[0]+':',u.protocol))return false;pattern=p.slice(1).join('://');}const slash=pattern.indexOf('/'),host=slash<0?pattern:pattern.slice(0,slash),path=slash<0?'':pattern.slice(slash);const actual=decodeURIComponent(u.pathname+u.search+u.hash).toLowerCase();if(pattern.startsWith('*')&&!pattern.startsWith('*.')&&(slash<0||pattern.startsWith('*/')))return glob(pattern,hostname+actual)||glob(pattern,hostname);const ok=host.includes('*')?glob(host,hostname):hostname===host||hostname.endsWith('.'+host);return ok&&(!path||(path.includes('*')?glob(path,actual):actual.startsWith(path)));}catch{return false;}}
function localCheck(url,channelURLs=[],active=true,embedded=false,tabId=null){if(url.startsWith('file:')&&cache.settings.allow_files)return {blocked:false,blocks:[]};if((!active&&!cache.settings.block_inactive)||(embedded&&!cache.settings.block_embeds))return {blocked:false,blocks:[]};const urls=[url,...channelURLs];const blocks=cache.blocks.filter(b=>b.blocking&&!tabIsGranted(tabId,b.id)&&b.websites.some(p=>urls.some(u=>matches(p,u)))&&!b.exceptions.some(p=>urls.some(u=>matches(p,u))));return {blocked:blocks.length>0,blocks};}
async function check(data,sender){const tab=sender?.tab;const active=tab?tab.active&&(await api.windows.get(tab.windowId)).focused:true;const url=/^(https?:|file:)/.test(sender?.url||'')?sender.url:String(data.url||'');const channelURLs=Array.isArray(data.channels)?data.channels.filter(u=>/^https:\/\/(www\.)?youtube\.com\//.test(u)):[];if(tab&&channelURLs.length)channels.set(tab.id,channelURLs);let context;try{if(tab)context=await browserContext();}catch{}const payload={url,channels:channelURLs,active,embedded:sender?.frameId>0,incognito:tab?.incognito||false,record:data.record!==false,...(context?{context,tab:tab.id}:{})};let result=await native('check',payload);if(result.error){result=localCheck(url,channelURLs,active,payload.embedded,tab?.id);result.offline=true;}return result;}
function patternRegex(pattern){if(pattern==='*.*'||pattern==='*')return '^https?://';if(pattern.includes('://')&&!/^https?:\/\//.test(pattern))return null;pattern=pattern.replace(/^https?:\/\//,'');if(pattern.startsWith('*')&&!pattern.startsWith('*.'))return null;const slash=pattern.indexOf('/'),host=slash<0?pattern:pattern.slice(0,slash),path=slash<0?'':pattern.slice(slash);const quote=s=>s.replace(/[.+?^${}()|[\]\\]/g,'\\$&').replace(/\*/g,'.*');return '^https?://'+(host.includes('*')?'':'([^/]+\\.)?')+quote(host).replace(/\.\*/g,'[^/]*')+'(:[0-9]+)?'+(path?quote(path):'(/|$)');}
function updateNetworkRules(){networkTask=networkTask.catch(()=>{}).then(buildNetworkRules);return networkTask;}
async function buildNetworkRules(){pruneTabGrants();if(!api.declarativeNetRequest)return true;const rules=[];let id=1;for(const b of cache.blocks){if(!b.blocking)continue;const exceptions=b.exceptions.filter(p=>p!=='file://*');if(exceptions.some(p=>p.includes('/')||p.includes('*')||p.includes('?')))continue;const targets=cache.settings.block_embeds?['main_frame','sub_frame']:['main_frame'];for(const pattern of b.websites){const regex=patternRegex(pattern);if(!regex||regex.length>1900||id>900||!/^[\x00-\x7f]+$/.test(regex))continue;const condition={regexFilter:regex+'.*$',resourceTypes:targets};if(exceptions.length)condition.excludedRequestDomains=exceptions;const tabIds=cache.settings.block_inactive?null:(await api.tabs.query({active:true,lastFocusedWindow:true})).map(t=>t.id);const exempt=Array.from(tabGrants.values()).filter(g=>g.id===b.id).map(g=>g.tab);if(tabIds){condition.tabIds=tabIds.filter(tab=>!exempt.includes(tab));if(!condition.tabIds.length)continue;}else if(exempt.length)condition.excludedTabIds=exempt;rules.push({id:id++,priority:1,action:{type:'redirect',redirect:{regexSubstitution:api.runtime.getURL('blocked.html')+'#url=\\0'}},condition});}}
// Session rules support tabIds; each block uses only its own excluded domains.
try{const old=await api.declarativeNetRequest.getSessionRules();await api.declarativeNetRequest.updateSessionRules({removeRuleIds:old.map(r=>r.id),addRules:rules});return true;}catch(error){console.warn('Network rules unavailable',error.message);return false;}}
// Internal browser pages cannot run content scripts or DNR redirects.
// Close only a matching tab, then let the native host record and notify.
const closingTabs=new Set();
async function enforceBrowserPage(tabId,tab,url=tab?.pendingUrl||tab?.url){
  if(!Number.isInteger(tabId)||!browserPage(url)||closingTabs.has(tabId))return;
  closingTabs.add(tabId);
  try{
    const active=!!tab.active&&(await api.windows.get(tab.windowId)).focused;
    let result=await native('check',{url,active,incognito:!!tab.incognito,record:false});
    if(result.error)result=localCheck(url,[],active);
    if(!result.blocked)return;
    // A slow reply must never close a tab that has navigated to an allowed page.
    const current=await api.tabs.get(tabId);
    if((current.pendingUrl||current.url)!==url)return;
    if(!cache.settings.block_inactive&&(!current.active||!(await api.windows.get(current.windowId)).focused))return;
    await api.tabs.remove(tabId);
    await native('closed-tab',{url,incognito:!!current.incognito});
  }catch(error){console.debug('Browser page no longer available',error.message);}
  finally{closingTabs.delete(tabId);}
}
function sync(){if(syncTask)return syncTask;syncTask=syncPolicy().finally(()=>{syncTask=null;});return syncTask;}
async function syncPolicy(){await cacheReady;await updateNetworkRules();try{let incognito=false,files=false;try{incognito=await api.extension.isAllowedIncognitoAccess();files=await api.extension.isAllowedFileSchemeAccess();}catch{}const tabs=await api.tabs.query({});let frontWindow;try{frontWindow=await api.windows.getLastFocused();}catch{}const usage=[];for(const t of tabs){if(!/^https?:/.test(t.url||'')&&!/^file:/.test(t.url||''))continue;usage.push({tab:t.id,url:t.url,active:t.active&&frontWindow?.focused&&frontWindow.id===t.windowId,idle:idle==='active'?0:100000,playing:!!t.audible,incognito:t.incognito,channels:channels.get(t.id)||[]});}let context;try{context=await browserContext();}catch{}const started=monotonicNow();const result=await native('sync',{browser:BROWSER,incognito_allowed:incognito,files_allowed:files,usage,tabs:tabs.map(t=>t.id).slice(0,1000),...(context?{context}:{})});if(!result.error){const {tab_grants,...policy}=result;cache=policy;connected=true;acceptTabGrants(tab_grants,monotonicNow()-started);await api.storage.local.set({policy:cache});await updateNetworkRules();await api.action.setBadgeText({text:''});for(const t of tabs){if(browserPage(t.pendingUrl||t.url)){await enforceBrowserPage(t.id,t);continue;}if(t.active||cache.settings.block_inactive){api.tabs.sendMessage(t.id,{op:'recheck'}).catch(()=>{});}}}else{tabGrants.clear();await updateNetworkRules();}}finally{scheduleGrantExpiry();}}
api.runtime.onMessage.addListener((message,sender,reply)=>{const run=async()=>{if(message.op==='check')return check(message.data,sender);if(message.op==='status')return currentStatus(sender);if(message.op==='tab-unblock')return requestTabUnblock(message.data||{},sender);if(message.op==='add-site-options')return quickAddOptions(message.data||{},sender);if(message.op==='add-site')return quickAddSite(message.data||{},sender);if(message.op==='break'){if(!sender.url?.startsWith(api.runtime.getURL('')))return {error:'Not permitted'};const result=await native('break',message.data);if(result.id){const index=cache.blocks.findIndex(b=>b.id===result.id);if(index>=0)cache.blocks[index]=result;await updateNetworkRules();}return result;}return {error:'Unsupported message'};};run().then(reply).catch(e=>reply({error:e.message}));return true;});
api.idle.setDetectionInterval(180);api.idle.onStateChanged.addListener(s=>{idle=s;});
api.alarms.create('sync',{periodInMinutes:.5});api.alarms.onAlarm.addListener(()=>{updateNetworkRules().then(()=>sync()).catch(()=>{});});
api.tabs.onUpdated.addListener((id,change,tab)=>{if(change.url)enforceBrowserPage(id,tab,change.url);});
api.tabs.onCreated.addListener(tab=>{closedTabs.delete(tab.id);enforceBrowserPage(tab.id,tab);});
api.tabs.onActivated.addListener(()=>sync());api.tabs.onRemoved.addListener(id=>{channels.delete(id);closedTabs.add(id);if(closedTabs.size>4096)closedTabs.delete(closedTabs.values().next().value);forgetTabGrants(id).catch(()=>{});browserContext().then(context=>native('tab-close',{context,tab:id})).catch(()=>{});});api.windows.onFocusChanged.addListener(()=>sync());
api.webNavigation.onHistoryStateUpdated.addListener(details=>{if(details.frameId===0)api.tabs.sendMessage(details.tabId,{op:'recheck'}).catch(()=>{});});
api.runtime.onStartup.addListener(()=>sync());api.runtime.onInstalled.addListener(()=>sync());
setInterval(sync,5000);sync();
