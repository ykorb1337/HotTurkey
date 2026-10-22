(()=>{
'use strict';
const api=typeof browser!=='undefined'?browser:chrome;
let info={blocks:[],url:''};
try{const raw=location.hash.slice(1);info=raw.startsWith('url=')?{url:raw.slice(4),blocks:[]}:JSON.parse(decodeURIComponent(raw));}catch{}
const error=document.querySelector('#error');
function message(text){error.textContent=text;}
async function send(op,data){return api.runtime.sendMessage({op,data});}
async function requestBreak(id,answer){
  const result=await send('break',{id,...(answer!==undefined?{answer}:{})});
  if(result.error){message(result.error);return;}
  const target=document.querySelector(`[data-block="${id}"]`);
  if(result.challenge){
    target.replaceChildren();
    const challenge=document.createElement('div');challenge.className='challenge';challenge.textContent=result.challenge;
    const input=document.createElement('textarea');input.placeholder='手动输入以上文本';input.addEventListener('paste',e=>e.preventDefault());
    const button=document.createElement('button');button.textContent='验证并休息';button.onclick=()=>requestBreak(id,input.value);
    target.append(challenge,input,button);
  }else if(result.ready_at){message('等待至 '+new Date(result.ready_at*1000).toLocaleTimeString()+'，然后再次申请休息。');}
  else{message('休息已开始。');await retry();}
}
function tabAction(block){
  const row=document.createElement('div');row.className='break-item';
  const label=document.createElement('strong');label.textContent=block.name;row.append(label);
  const method=block.locked?block.lock?.type:'none';
  if(!['none','text','password'].includes(method)){
    const note=document.createElement('p');note.textContent='此规则的锁定条件不允许临时放行。';row.append(note);return row;
  }
  const choice=document.createElement('label');choice.textContent='放行时长（分钟）';
  const minutes=document.createElement('input');minutes.type='number';minutes.min='1';minutes.max='1440';minutes.value='5';minutes.setAttribute('aria-label',block.name+'放行分钟');choice.append(minutes);row.append(choice);
  const controls=document.createElement('div');row.append(controls);
  let answer;
  const button=document.createElement('button');
  button.textContent=method==='text'?'输入文本后放行':method==='password'?'输入密码后放行':'临时放行此标签页';
  button.onclick=async()=>{
    button.disabled=true;message('');
    try{
      const result=await send('tab-unblock',{id:block.id,minutes:Number(minutes.value),...(answer?{answer:answer.value}:{})});
      if(result.error){message(result.error);return;}
      if(result.granted){message('当前标签页已临时放行，其他标签页保持拦截。');await retry();return;}
      if(!answer){
        if(result.challenge){const challenge=document.createElement('div');challenge.className='challenge';challenge.textContent=result.challenge;controls.append(challenge);}
        answer=document.createElement(result.method==='password'?'input':'textarea');
        answer.maxLength=5000;answer.setAttribute('aria-label',result.method==='password'?'规则密码':'验证文本');
        if(result.method==='password'){answer.type='password';answer.autocomplete='off';answer.placeholder='输入此规则的锁定密码';}
        else{answer.placeholder='手动输入以上文本';answer.addEventListener('paste',e=>e.preventDefault());answer.addEventListener('drop',e=>e.preventDefault());}
        controls.append(answer);button.textContent='验证并放行此标签页';answer.focus();
      }
    }catch{message('无法连接扩展，请重新检查。');}
    finally{button.disabled=false;}
  };
  row.append(button);return row;
}
async function load(){
  const decision=await send('check',{url:info.url,record:false});
  if(decision.error){message(decision.error);return;}
  info.blocks=decision.blocks||[];
  document.querySelector('#details').textContent=info.blocks.length?'由 '+info.blocks.map(b=>b.name).join('、')+' 守护':'此网页目前没有命中拦截规则。';
  const result=await send('status');
  const ids=info.blocks.map(b=>b.id);
  const breaks=document.querySelector('#breaks');breaks.replaceChildren();
  const tabs=document.querySelector('#tab-actions');tabs.replaceChildren();
  for(const block of result.blocks||[]){
    if(!ids.includes(block.id))continue;
    if(result.tab_unblock_available===1)tabs.append(tabAction(block));
    if(!['text','delay'].includes(block.break?.type))continue;
    const row=document.createElement('div');row.className='break-item';row.dataset.block=block.id;
    const label=document.createElement('span');label.textContent=block.name+' · ';
    const button=document.createElement('button');button.textContent=block.break.type==='text'?'输入文本以休息（整条规则）':'开始等待以休息（整条规则）';button.onclick=()=>requestBreak(block.id);
    row.append(label,button);breaks.append(row);
  }
  const webPage=ids.length&&/^https?:\/\//.test(info.url);
  document.querySelector('#tab-section').hidden=!webPage||result.tab_unblock_available!==1;
  document.querySelector('#tab-unavailable').hidden=!webPage||result.tab_unblock_available===1;
}
async function retry(){
  if(!/^https?:|^file:/.test(info.url)){message('请在地址栏重新打开原网址以检查拦截状态。');return;}
  const result=await send('check',{url:info.url,record:false});
  if(!result.blocked&&!result.error)location.replace(info.url);
  else{message(result.error||'仍有规则在拦截此标签页。');await load();}
}
document.querySelector('#retry').onclick=()=>retry().catch(()=>message('无法连接扩展，请重新检查。'));
load().catch(()=>message('无法连接扩展，请重新检查。'));

})();
