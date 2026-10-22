'use strict';
(()=>{
const api=typeof browser!=='undefined'?browser:chrome;
if(['127.0.0.1','localhost'].includes(location.hostname))return;
let checking=false,last='',overlay=null,hidden=false,initial=true,channelWait=0;
const root=document.documentElement;
const originalVisibility=root?.style.visibility||'';
if(root){root.style.visibility='hidden';hidden=true;}
function reveal(){if(hidden&&document.documentElement){document.documentElement.style.visibility=originalVisibility;hidden=false;}}
function channels(){if(!/(^|\.)youtube\.com$/.test(location.hostname))return [];return [...document.querySelectorAll('ytd-watch-metadata #owner a[href], #upload-info a[href], link[itemprop="url"][href*="/channel/"], ytd-reel-player-header-renderer a[href]')].map(a=>a.href).filter(u=>/youtube\.com\/(?:@|channel\/|c\/|user\/)/.test(u));}
async function run(){if(checking)return;checking=true;try{const list=channels();const result=await api.runtime.sendMessage({op:'check',data:{url:location.href,channels:list}});if(result.blocked){
  // YouTube channel exceptions need channel metadata before a final decision.
  const needsChannel=result.pending_channel;
  if(needsChannel&&channelWait++<10){setTimeout(run,500);return;}
  if(window.top===window){const url=api.runtime.getURL('blocked.html')+'#'+encodeURIComponent(JSON.stringify({url:location.href,blocks:result.blocks.map(b=>({id:b.id,name:b.name})),offline:result.offline}));location.replace(url);}else{document.documentElement.textContent='此嵌入内容已被 HotTurkey 拦截。';reveal();}
}else{reveal();initial=false;}}catch{reveal();}finally{checking=false;}}
api.runtime.onMessage.addListener(message=>{if(message.op==='recheck')run();});
document.addEventListener('yt-navigate-finish',()=>{channelWait=0;run();});
document.addEventListener('visibilitychange',run);
new MutationObserver(()=>{const current=location.href+'|'+channels().join(',');if(current!==last){last=current;run();}}).observe(document,{childList:true,subtree:true});
run();setInterval(run,5000);
})();
