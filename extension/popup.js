(()=>{
'use strict';
const api=typeof browser!=='undefined'?browser:chrome;
api.runtime.sendMessage({op:'status'}).then(state=>{const status=document.querySelector('#connection');status.textContent=state.connected?'● 已连接本地后台':'○ 后台离线 · 使用最近缓存规则';status.className=state.connected?'online':'offline';for(const b of state.blocks||[]){if(!b.enabled)continue;const row=document.createElement('div');row.className='status-item';const title=document.createElement('b');title.textContent=b.name;const description=document.createElement('p');const remaining=Math.ceil((b.break_status?.remaining||0)/60);const grant=(state.tab_grants||[]).find(g=>g.id===b.id);description.textContent=grant?'当前标签页临时放行 · 剩余 '+Math.ceil(grant.remaining/60)+' 分钟 · 其他标签页继续拦截':(b.blocking?'正在拦截':'未拦截')+(remaining?' · 剩余 '+remaining+' 分钟':'')+(b.locked?' · 已锁定':'');row.append(title,description);document.querySelector('#blocks').append(row);}});

const $=selector=>document.querySelector(selector);
let selectedPage=null,busy=false;
function previewSite(){$('#add-result').textContent='';$('#add-error').textContent='';if(selectedPage)$('#add-preview').textContent=$('#add-scope').value==='domain'?selectedPage.domain:selectedPage.page;}
async function loadRules(){
 if(busy)return;busy=true;$('#load-rules').disabled=true;$('#add-error').textContent='';
 try{
  const password=$('#add-password').value;
  const value=await api.runtime.sendMessage({op:'add-site-options',data:password?{password}:{}});
  if(value.error)throw Error(value.error==='Unsupported message'?'请先更新扩展与后台':value.error);
  selectedPage=value.page;
  $('#add-form').hidden=false;$('#add-password-row').hidden=!value.authentication_required&&!password;
  $('#add-choices').hidden=!!value.authentication_required;
  if(value.authentication_required){$('#add-hint').textContent='输入设置密码后选择目标规则。';return;}
  const select=$('#add-rule');select.replaceChildren();
  for(const b of value.blocks||[]){const option=document.createElement('option');option.value=b.id;option.textContent=b.name+(b.locked?' · 已锁定':'')+(!b.enabled?' · 未启用':b.mode==='scheduled'?' · 按日程':'');select.append(option);}
  $('#add-submit').disabled=!select.options.length;
  $('#add-hint').textContent=select.options.length?'只追加网站，保留原锁、日程和例外。未启用的规则需在桌面中开启。':'还没有普通网站规则，请先在桌面应用中创建。';
  previewSite();
 }catch(error){$('#add-error').textContent=error.message;$('#add-hint').textContent='暂时无法读取网站或规则。';$('#add-password').value='';}
 finally{busy=false;$('#load-rules').disabled=false;}
}
$('#add-scope').addEventListener('change',previewSite);
$('#add-rule').addEventListener('change',()=>{$('#add-result').textContent='';$('#add-error').textContent='';});
$('#load-rules').addEventListener('click',loadRules);
$('#add-form').addEventListener('submit',async event=>{
 event.preventDefault();if(busy||!selectedPage)return;
 if($('#add-choices').hidden)return loadRules();
 busy=true;$('#add-submit').disabled=true;$('#add-error').textContent='';$('#add-result').textContent='';
 try{
  const password=$('#add-password').value;
  const value=await api.runtime.sendMessage({op:'add-site',data:{...selectedPage,id:$('#add-rule').value,scope:$('#add-scope').value,...(password?{password}:{})}});
  if(value.error)throw Error(value.error);
  if(value.authentication_required){$('#add-password-row').hidden=false;throw Error('请输入当前设置密码后重试');}
  if(!value.ok)throw Error('添加未完成，请重新打开扩展检查');
  $('#add-result').textContent=(value.added?'已添加：':'已存在：')+value.target+(value.matches_current_page?'':'。当前页面命中既有例外，例外保持不变。')+(!value.block.enabled?'。规则尚未启用。':value.block.mode==='scheduled'?'。按原日程生效。':'');
 }catch(error){$('#add-error').textContent=error.message;}
 finally{busy=false;$('#add-submit').disabled=false;$('#add-password').value='';}
});
loadRules();

})();
