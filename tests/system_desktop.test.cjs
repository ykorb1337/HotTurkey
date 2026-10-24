'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync('web/app.js','utf8');
const elements=new Map(),element=selector=>{
 if(!elements.has(selector))elements.set(selector,{innerHTML:'',textContent:'',classList:{toggle(){}}});
 return elements.get(selector);
};
const block={id:'x',name:'Shared rule',device:'none',websites:['fixture.invalid'],exceptions:[],applications:[],
 mode:'continuous',schedule:[],enabled:true,locked:true,active:true,blocking:true,lock:{type:'timer'},
 break:{type:'text'},break_status:{type:'text'}};
let calls=[],rendered=[];
const context={state:{can_manage:false,authenticated:false,blocks:[block],settings:{week_start:'monday'}},page:'blocks',
 $:element,$$:()=>[],esc:String,btn:(a,label,extra='',style='')=>`<button data-action="${a}" ${extra}>${label}</button>`,
 LOCK:{timer:'定时锁'},BREAK:{text:'输入文本休息'},DAY:[],calendarBlock:'',filter:'',hm:value=>String(value),
 refresh:async()=>{},toast:()=>{},confirm:()=>true,setup:()=>rendered.push('setup'),
 api:async(path,data)=>{calls.push({path,data});return {};},
 renderOverview:()=>rendered.push('overview'),renderBlocks:()=>rendered.push('blocks'),
 renderCalendar:()=>rendered.push('schedule'),renderStats:()=>rendered.push('statistics'),renderSettings:()=>rendered.push('settings')};
vm.createContext(context);
for(const name of ['canManage','allowedAction','resetPomodoroButton','blockCard'])vm.runInContext(source.match(new RegExp(`function ${name}\\([^\\n]+`))[0],context);
vm.runInContext(source.slice(source.indexOf('function renderPage('),source.indexOf('function renderOverview(')),context);
vm.runInContext(source.slice(source.indexOf('async function action('),source.indexOf("document.addEventListener('click'")),context);
let count=0;
(async()=>{
 for(const a of ['new','edit','delete','toggle','add-targets','apply-lock','unlock','settings-password','import','clear-stats','install-backend']){
  await assert.rejects(()=>context.action(a,{dataset:{id:'x'}}),/管理账户/);
 }
 assert.equal(calls.length,0);count++;
 const readonly=context.blockCard(block);
 assert(!readonly.includes('data-action="edit"'));assert(!readonly.includes('role="switch"'));
 assert(!readonly.includes('data-action="delete"'));assert(!readonly.includes('data-action="lock"'));
 assert(readonly.includes('data-action="break"'));count++;
 await context.action('break',{dataset:{id:'x'}});assert.equal(calls[0].path,'blocks/break');count++;
 for(const page of ['overview','blocks','schedule','statistics']){
  context.page=page;context.renderPage();assert.equal(rendered.at(-1),page);
  assert(!element('#header-actions').innerHTML.includes('data-action="new"'));
 }
 context.page='settings';context.renderPage();assert(element('#content').innerHTML.includes('由管理账户设置'));count++;
 context.state.can_manage=true;context.page='blocks';context.renderPage();assert(element('#content').innerHTML.includes('设置已受密码保护'));count++;
 context.state.authenticated=true;context.renderPage();assert.equal(rendered.at(-1),'blocks');
 const managed=context.blockCard(block);assert(managed.includes('data-action="edit"'));assert(managed.includes('role="switch"'));count++;
 context.state.can_manage=false;
 vm.runInContext(source.match(/function renderBlocks\([^\n]+/)[0],context);context.renderBlocks();
 assert(!element('#content').innerHTML.includes('data-action="import"'));assert(!element('#content').innerHTML.includes('data-action="new"'));count++;
 vm.runInContext(source.match(/function renderCalendar\([^\n]+/)[0],context);context.renderCalendar();assert(!element('#content').innerHTML.includes('data-action="calendar-add"'));count++;
 context.openModal=(title,body)=>{context.modalBody=body;};context.state.mode='system';
 vm.runInContext(source.slice(source.indexOf('async function setup('),source.indexOf('function download(')),context);
 await context.setup();assert(context.modalBody.includes('共享规则'));assert(!context.modalBody.includes('install-backend'));count++;
 vm.runInContext(source.match(/function settingToggle\([^\n]+/)[0],context);
 assert(context.settingToggle('open_at_login','Login','Description').includes('disabled'));
 assert(!context.settingToggle('statistics','Statistics','Description').includes('disabled'));
 context.state.system_session={desktop_login:{supported:true,status:'pending'}};
 assert(!context.settingToggle('open_at_login','Login','Description').includes('disabled'));
 assert(context.settingToggle('start_in_tray','Tray','Description').includes('下次登录'));
 context.window={};context.api=async()=>{throw Error('Protected offline');};context.refresh=async()=>{throw Error('Protected offline');};
 vm.runInContext(source.match(/async function boot\([^\n]+/)[0],context);await context.boot();
 assert(element('#content').innerHTML.includes('Protected offline'));assert(element('#content').innerHTML.includes('retry-connection'));count++;
 console.log(`${count} protected desktop role, navigation, break and offline UI checks passed`);
})().catch(error=>{console.error(error);process.exitCode=1;});
