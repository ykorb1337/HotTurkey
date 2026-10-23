'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(require('node:path').join(__dirname,'../web/app.js'),'utf8');
const action=source.slice(source.indexOf('async function action('),source.indexOf("document.addEventListener('click'"));
let opened=null,calls=[],keep=false,confirmation=false,closed=0;
const fixture={blocks:[{name:'<unsafe>',websites:['example.invalid'],device:'shutdown',autostart:{type:'once',at:10}}]};
const context={state:{blocks:[]},importDraft:null,editorImport:null,readFile:async()=>JSON.stringify(fixture),
  openModal:(title,body,buttons)=>{opened={title,body,buttons};},closeModal:()=>{closed++;context.importDraft=null;},
  esc:value=>String(value).replaceAll('<','&lt;').replaceAll('>','&gt;'),btn:()=>'',
  $:()=>({checked:keep}),confirm:()=>confirmation,api:async(path,data)=>{calls.push({path,data});return {count:1};},toast:()=>{},refresh:async()=>{}};
vm.createContext(context);vm.runInContext(action,context);
const invoke=name=>context.action(name,{dataset:{}});
let count=0;
(async()=>{
  await invoke('import');assert.equal(calls.length,0);assert(opened.body.includes('&lt;unsafe&gt;'));assert(opened.body.includes('type="checkbox"'));assert(!opened.body.includes(' checked'));count++;
  await invoke('close');assert.equal(calls.length,0);assert.equal(closed,1);count++;
  await invoke('import');await invoke('confirm-import');assert.equal(calls[0].data.allow_autostart,false);assert.equal(calls[0].data.blocks[0].autostart.type,'none');assert.equal(fixture.blocks[0].autostart.type,'once');count++;
  calls=[];keep=true;await invoke('import');const before=closed;await invoke('confirm-import');assert.equal(calls.length,0);assert.equal(closed,before);assert(context.importDraft);count++;
  confirmation=true;await invoke('confirm-import');assert.equal(calls[0].data.allow_autostart,true);assert.equal(calls[0].data.confirm_device,true);assert.equal(calls[0].data.blocks[0].autostart.type,'once');count++;
  context.readFile=async()=>JSON.stringify({blocks:new Array(201).fill({name:'too many'})});await assert.rejects(()=>invoke('import'));count++;
  console.log(`${count} import preview, escaped names, cancellation and explicit device confirmation checks passed`);
})().catch(error=>{console.error(error);process.exitCode=1;});
