'use strict';
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync('web/app.js','utf8');
let fields={},calls=[],closed=0,confirmation=true,opened='';
const context={state:{authenticated:true,settings:{device_recovery_hash:false},blocks:[]},
 $:selector=>fields[selector],$$:()=>[{value:'0'},{value:'1'}],
 api:async(path,data)=>{calls.push({path,data});if(path==='device/configure-recovery')context.state.settings.device_recovery_hash=true;return {until:1000};},
 refresh:async()=>{},closeModal:()=>{closed++;},toast:()=>{},confirm:()=>confirmation,
 newBlock:()=>({break:{type:'none'},websites:[]}),minute:value=>Number(value.split(':')[0])*60+Number(value.split(':')[1]),
 openModal:(title,body)=>{opened=body;},field:(title,body)=>title+body,btn:()=>'',dateTime:String,
 hm:String,DAY:['Mon','Tue','Wed','Thu','Fri','Sat','Sun'],editorImport:null};
vm.createContext(context);
for(const name of ['canManage','allowedAction'])vm.runInContext(source.match(new RegExp(`function ${name}\\([^\\n]+`))[0],context);
vm.runInContext(source.slice(source.indexOf('function deviceWizard('),source.indexOf('function theme(')),context);
vm.runInContext(source.slice(source.indexOf('async function action('),source.indexOf("document.addEventListener('click'")),context);
function reset(){
 calls=[];context.state.settings.device_recovery_hash=false;context.state.can_manage=true;confirmation=true;
 fields={'#device-word-confirmed':{checked:true},'#device-start':{value:'23:00'},'#device-end':{value:'07:00'},
 '#device-name':{value:'Rest'},'#device-enabled':{checked:false},'#device-word':{value:'fixture-escape'},'#device-word-repeat':{value:'fixture-escape'}};
}
const act=a=>context.action(a,{dataset:{}});let count=0;
(async()=>{
 reset();context.deviceWizard();assert(opened.includes('紧急安全词'));assert(opened.includes('30 秒'));assert(!opened.includes('id="device-enabled" type="checkbox" checked'));count++;
 fields['#device-word-confirmed'].checked=false;await assert.rejects(()=>act('save-device'));assert.equal(calls.length,0);count++;
 reset();fields['#device-word-repeat'].value='different';await assert.rejects(()=>act('save-device'));assert.equal(calls.length,0);count++;
 reset();fields['#device-word'].value=fields['#device-word-repeat'].value='short';await assert.rejects(()=>act('save-device'));assert.equal(calls.length,0);count++;
 reset();fields['#device-enabled'].checked=true;confirmation=false;await act('save-device');assert.equal(calls.length,0);count++;
 reset();await act('save-device');assert.equal(calls[0].path,'device/configure-recovery');assert.equal(calls[1].path,'blocks/save');
 const block=calls[1].data.block;assert.equal(block.enabled,false);assert.equal(block.device,'sleep');assert.equal(block.schedule[0].end,420);assert.equal(block.schedule[0].start,1380);assert(!('word' in block));count++;
 reset();context.state.settings.device_recovery_hash=true;await act('save-device');assert.equal(calls.length,1);assert.equal(calls[0].path,'blocks/save');count++;
 reset();context.state.can_manage=false;await assert.rejects(()=>act('new-device'));assert.equal(calls.length,0);count++;
 fields['#device-emergency-word']={value:'fixture-escape'};await act('device-emergency-submit');assert.equal(calls[0].path,'device/recover');assert.equal(calls[0].data.stop_plan,false);count++;
 calls=[];context.state.can_manage=true;fields['#device-stop-plan']={checked:true};confirmation=false;await act('device-emergency-submit');assert.equal(calls.length,0);
 confirmation=true;await act('device-emergency-submit');assert.equal(calls[0].data.stop_plan,true);
 context.state.can_manage=true;fields['#recovery-new']={value:'new-safety'};fields['#recovery-repeat']={value:'mismatch'};await assert.rejects(()=>act('device-recovery-save'));count++;
 console.log(`${count} device safety, inactive defaults, confirmation, secret isolation and emergency access checks passed`);
})().catch(error=>{console.error(error);process.exitCode=1;});
