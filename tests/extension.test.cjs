// Test the actual service-worker policy and generated network rules with browser APIs mocked.
const vm=require('node:vm');
const fs=require('node:fs');
const assert=require('node:assert/strict');
const path=require('node:path');
let generated=[];
const event={addListener(){}};
const api={storage:{local:{get:async()=>({}),set:async()=>{}}},runtime:{getURL:s=>'chrome-extension://test/'+s,connectNative(){throw Error('offline')},onMessage:event,onStartup:event,onInstalled:event},action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},idle:{setDetectionInterval(){},onStateChanged:event},alarms:{create(){},onAlarm:event},tabs:{query:async()=>[{id:9,active:true,windowId:1,url:'https://example.com'}],sendMessage:async()=>{},onActivated:event,onRemoved:event,onUpdated:event,onCreated:event},windows:{get:async()=>({focused:true}),getLastFocused:async()=>({id:1,focused:true}),onFocusChanged:event},webNavigation:{onHistoryStateUpdated:event},extension:{isAllowedIncognitoAccess:async()=>true,isAllowedFileSchemeAccess:async()=>true},declarativeNetRequest:{getSessionRules:async()=>[],updateSessionRules:async value=>{generated=value.addRules;}}};
const context={chrome:api,navigator:{userAgent:'Edg/130.0'},console,URL,Map,Set,Promise,setInterval(){},setTimeout(){},clearTimeout(){}};
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname,'../extension/background.js'),'utf8'),context);
const evaluate=code=>vm.runInContext(code,context);
let count=0;
function check(code,expected=true){assert.equal(evaluate(code),expected,code);count++;}
check("matches('example.com','https://sub.example.com/a')");
check("matches('example.com','https://example.com.evil.test')",false);
check("matches('example.com','https://evil-example.com')",false);
check("matches('reddit.com/r/work','https://reddit.com/r/work/top')");
check("matches('*.*','file:///tmp/a')",false);
check("matches('*unicorn*','https://google.com/search?q=unicorn')");
check("matches('google.com/*q=*hello world*','https://google.com/search?q=hello%20world')");
check("matches('file://*','file:///tmp/a.pdf')");
check("matches('http://example.com','https://example.com')",false);
check("matches('youtube.com/@learn','https://youtube.com/@learn/videos')");
check("matches('*.xxx','https://a.xxx/page')");
check("matches('*.xxx','https://example.com/file.xxx')",false);
check("matches('example.com/*?q=*','https://example.com/searchaq=x')",false);
for(const [pattern,url,expected] of JSON.parse(fs.readFileSync(path.join(__dirname,'browser_page_cases.json'),'utf8'))){
  check(`matches(${JSON.stringify(pattern)},${JSON.stringify(url)})`,expected);
}
evaluate("cache={blocks:[{id:'a',blocking:true,websites:['example.com'],exceptions:['example.com/learn']}],settings:{block_inactive:false,block_embeds:true,allow_files:true}};");
check("localCheck('https://example.com/learn').blocked",false);
check("localCheck('https://example.com/else').blocked");
check("localCheck('https://example.com/else',[],false).blocked",false);
evaluate("cache.blocks.push({id:'b',blocking:true,websites:['example.com'],exceptions:[]});");
check("localCheck('https://example.com/learn').blocked");
evaluate("cache.blocks=[{id:'a',blocking:true,websites:['youtube.com'],exceptions:['youtube.com/@learn']}];");
check("localCheck('https://youtube.com/watch?v=1',['https://youtube.com/@learn']).blocked",false);
check("localCheck('https://youtube.com/watch?v=1',['https://youtube.com/@game']).blocked");
for(const pattern of ['example.com','reddit.com/r/work','*.*','*.xxx']){
  const regex=evaluate(`patternRegex(${JSON.stringify(pattern)})`);
  assert.equal(typeof regex,'string');count++;
}
(async()=>{
  evaluate("cache.blocks=[{id:'a',blocking:true,websites:['example.com'],exceptions:['example.com/learn']}];");
  await evaluate('updateNetworkRules()');assert.equal(generated.length,0,'Complex exceptions must use native policy, not unsafe global DNR allows');count++;
  evaluate("cache.blocks=[{id:'a',blocking:true,websites:['*.*'],exceptions:['learn.example.com']},{id:'b',blocking:true,websites:['learn.example.com'],exceptions:[]}];");
  await evaluate('updateNetworkRules()');assert.equal(generated.length,2);assert.ok(generated[0].action.redirect.regexSubstitution.endsWith('#url=\\0'));assert.deepEqual(Array.from(generated[0].condition.excludedRequestDomains),['learn.example.com']);assert.equal(generated[1].condition.excludedRequestDomains,undefined);assert.deepEqual(Array.from(generated[0].condition.tabIds),[9]);count+=4;
  console.log(`${count} extension policy and network-rule checks passed`);
})().catch(error=>{console.error(error);process.exitCode=1;});
