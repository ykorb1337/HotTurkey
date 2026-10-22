'use strict';
// Page sizing includes controls and dialogs so text is never clipped in a fixed box.
window.HotTurkeyTextSize=(()=>{
 let scale=100,saved=100,pending=null,saving=false,save=null,notify=()=>{};
 function valid(value){return Number.isInteger(value)&&value>=50&&value<=200;}
 function apply(value){
  scale=value;const root=document.documentElement,width=window.innerWidth/(value/100),height=window.innerHeight/(value/100);
  document.body.style.zoom=String(value/100);document.body.style.width=width+'px';root.style.setProperty('--ui-width',width+'px');root.style.setProperty('--ui-height',height+'px');
  root.classList.toggle('ui-medium',width<=1050);root.classList.toggle('ui-compact',width<=760);
  const control=document.querySelector('#text-scale');if(control)control.value=String(value);
 }
 async function persist(){
  if(saving)return;saving=true;
  try{while(pending!==null){const target=pending;pending=null;try{await save(target);saved=target;}catch(error){if(pending===null)apply(saved);notify(error.message);}}}
  finally{saving=false;}
 }
 function change(value){if(!save||!valid(value)||value===scale)return;apply(value);pending=value;persist();}
 function step(direction){change(Math.max(50,Math.min(200,scale+direction*10)));}
 window.addEventListener('resize',()=>apply(scale));
 document.addEventListener('keydown',event=>{
  if(!(event.metaKey||event.ctrlKey)||event.altKey)return;
  if(['+','=','-','_','*','0'].includes(event.key)){
   event.preventDefault();if(['*','0'].includes(event.key))change(100);else step(['+','='].includes(event.key)?1:-1);
  }
 });
 let wheel=0,wheelAt=0;
 document.addEventListener('wheel',event=>{
  if(!(event.metaKey||event.ctrlKey)||event.altKey||!event.deltaY)return;
  event.preventDefault();const now=performance.now();if(now-wheelAt>250)wheel=0;wheelAt=now;
  wheel+=event.deltaY*(event.deltaMode===1?16:event.deltaMode===2?100:1);
  if(Math.abs(wheel)>=40){step(wheel<0?1:-1);wheel=0;}
 },{passive:false});
 document.addEventListener('auxclick',event=>{if(event.button===1&&(event.metaKey||event.ctrlKey)){event.preventDefault();change(100);}});
 document.addEventListener('change',event=>{if(event.target.id==='text-scale')change(Number(event.target.value));});
 return {configure(options){save=options.save;notify=options.notify||notify;},sync(value){if(!saving&&pending===null&&valid(value)){saved=value;apply(value);}},get value(){return scale;}};
})();
