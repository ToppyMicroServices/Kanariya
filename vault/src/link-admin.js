export const html = `<section class="viewer-card owner-tools"><details id="links-panel"><summary>閲覧用URL</summary><p id="links-status" role="status" aria-live="polite"></p><div id="links-controls" hidden><dl class="document-info"><div><dt>開示先</dt><dd id="links-recipient"></dd></div></dl><form id="links-form"><label for="links-expiry">URLの閲覧期限</label><p id="links-time" class="form-help">日本時間で指定してください。</p><div class="expiry-controls"><input id="links-expiry" type="datetime-local" step="60" required disabled aria-describedby="links-time links-limit"><button id="links-create" type="submit" class="primary" disabled>閲覧用URLを発行</button></div><p id="links-limit" class="form-help"></p></form><div id="links-issued" class="links-issued" hidden><label for="links-url">発行したURL</label><textarea id="links-url" rows="3" readonly spellcheck="false" autocomplete="off"></textarea><p class="form-help">URLは再表示できません。ページを閉じる前にコピーしてください。</p><button id="links-copy" type="button" disabled>URLをコピー</button></div><ul id="links-list" class="owner-list"></ul></div><button id="links-refresh" type="button" class="quiet">再読み込み</button><details class="management-notes"><summary>ご案内</summary><p>URLを持つ方が、パスワードなしで閲覧できます。開示先をご確認のうえ共有してください。</p><p>停止や期限切れは、その後の文書取得を停止します。保存済みのPDFは回収できません。</p></details></details></section>`;

export const css = `
.links-issued{margin-top:20px;padding:16px;border:1px solid var(--border);border-radius:6px}.links-issued textarea{width:100%;overflow-wrap:anywhere;font-size:13px}.links-row{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:12px}.links-row p{margin:0;font-size:14px}.links-row small{display:block;margin-top:4px;color:var(--muted);font-size:12px;overflow-wrap:anywhere}
`;

export const js = `"use strict";
const names=["links-panel","links-status","links-controls","links-recipient","links-form","links-expiry","links-create","links-limit","links-issued","links-url","links-copy","links-list","links-refresh"];
const el=Object.fromEntries(names.map(name=>[name,document.getElementById(name)]));
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,TOKEN=/^[a-f0-9]{64}$/,JAPAN_OFFSET=32400000,MAX_LINKS=20;
let documentId=null,data=null,issued=null,busy=false,uncertain=false,epoch=0,visible=true,expiryTimer=null;
const controllers=new Set();
function active(g){return visible&&g===epoch;}
function timestamp(value){return Number.isSafeInteger(value)&&value>0&&value<=8640000000000000-JAPAN_OFFSET;}
function exact(value,fields){return value&&typeof value==="object"&&!Array.isArray(value)&&Object.keys(value).length===fields.length&&fields.every(field=>Object.hasOwn(value,field));}
function revision(value){return Number.isSafeInteger(value)&&value>=0;}
function dateLabel(value){return new Intl.DateTimeFormat("ja-JP",{timeZone:"Asia/Tokyo",year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",hourCycle:"h23"}).format(value);}
function dateInput(value){return new Date(value+JAPAN_OFFSET).toISOString().slice(0,16);}
function inputDate(value){if(!/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}$/.test(value))return NaN;const parsed=Date.parse(value+":00+09:00");return Number.isSafeInteger(parsed)&&dateInput(parsed)===value?parsed:NaN;}
function checkedLink(value){if(!exact(value,["id","createdAt","expiresAt","revoked"])||!UUID.test(value.id)||!timestamp(value.createdAt)||!timestamp(value.expiresAt)||value.createdAt>=value.expiresAt||typeof value.revoked!=="boolean")throw new Error();return value;}
function checked(value){
 if(!exact(value,["revision","links","recipientName","documentExpiresAt","revoked","enabled"])||!revision(value.revision)||!Array.isArray(value.links)||value.links.length>MAX_LINKS||!(value.recipientName===null||typeof value.recipientName==="string"&&value.recipientName.length<=200&&!/[\\x00-\\x1f\\x7f-\\x9f]/.test(value.recipientName))||!timestamp(value.documentExpiresAt)||typeof value.revoked!=="boolean"||typeof value.enabled!=="boolean")throw new Error();
 const ids=new Set();for(const link of value.links){checkedLink(link);if(ids.has(link.id))throw new Error();ids.add(link.id);}return value;
}
function live(link){return Boolean(data?.enabled&&!data.revoked&&data.documentExpiresAt>Date.now()&&link&&!link.revoked&&link.expiresAt>Date.now());}
function canCreate(){const expiresAt=inputDate(el["links-expiry"].value);return Boolean(data?.enabled&&!data.revoked&&timestamp(expiresAt)&&expiresAt>Date.now()&&expiresAt<=data.documentExpiresAt&&data.links.filter(link=>live(link)).length<MAX_LINKS);}
function clearIssued(){issued=null;el["links-url"].value="";el["links-issued"].hidden=true;el["links-copy"].disabled=true;}
function render(){
 clearTimeout(expiryTimer);el["links-controls"].hidden=!data?.enabled;el["links-recipient"].textContent=data?.recipientName||"未設定";el["links-create"].disabled=busy||uncertain||!canCreate();el["links-expiry"].disabled=busy||uncertain||!data?.enabled||data.revoked||data.documentExpiresAt<=Date.now();el["links-refresh"].disabled=busy;
 if(data){el["links-expiry"].min=dateInput(Math.ceil((Date.now()+1)/60000)*60000);el["links-expiry"].max=dateInput(data.documentExpiresAt);el["links-limit"].textContent="文書の閲覧期限："+dateLabel(data.documentExpiresAt)+"（日本時間）";}else{el["links-expiry"].value="";el["links-limit"].textContent="";}
 if(issued&&!live(data?.links.find(link=>link.id===issued.id)))clearIssued();
 el["links-issued"].hidden=!issued;el["links-url"].value=issued?.url||"";el["links-copy"].disabled=busy||uncertain||!issued;
 const rows=[];for(const link of data?.links||[]){const row=document.createElement("li"),details=document.createElement("div"),label=document.createElement("p"),identifier=document.createElement("small");row.className="links-row";label.textContent=dateLabel(link.createdAt)+" 発行 ／ "+(link.revoked?"停止済み":data.revoked?"共有終了":!live(link)?"期限切れ":"有効")+" ／ 期限："+dateLabel(Math.min(link.expiresAt,data.documentExpiresAt));identifier.textContent="URL ID: "+link.id;details.append(label,identifier);row.append(details);if(live(link)){const stop=document.createElement("button");stop.type="button";stop.textContent="停止";stop.disabled=busy||uncertain;stop.addEventListener("click",()=>void change("revoke",link.id));row.append(stop);}rows.push(row);}el["links-list"].replaceChildren(...rows);
 if(data){const future=[data.documentExpiresAt,...data.links.filter(link=>!link.revoked).map(link=>link.expiresAt)].filter(value=>value>Date.now());if(future.length)expiryTimer=setTimeout(render,Math.min(2147483647,Math.max(1,Math.min(...future)-Date.now())));}
}
async function api(path,body){
 const c=new AbortController();controllers.add(c);const timer=setTimeout(()=>c.abort(),15000);
 try{const response=await fetch(path,{method:body===undefined?"GET":"POST",credentials:"same-origin",cache:"no-store",redirect:"error",signal:c.signal,...(body===undefined?{}:{headers:{"content-type":"application/json"},body:JSON.stringify(body)})});if(c.signal.aborted)throw new Error();if(!response.ok){const error=new Error();error.status=response.status;throw error;}if(!response.headers.get("content-type")?.startsWith("application/json")||Number(response.headers.get("content-length"))>65536)throw new Error();
 const reader=response.body.getReader(),parts=[];let size=0;try{while(true){const {done,value}=await reader.read();if(c.signal.aborted)throw new Error();if(done)break;size+=value.length;if(size>65536)throw new Error();parts.push(value);}}finally{void reader.cancel().catch(()=>{});reader.releaseLock();}const bytes=new Uint8Array(size);let offset=0;for(const part of parts){bytes.set(part,offset);offset+=part.length;}return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));
 }finally{clearTimeout(timer);controllers.delete(c);}
}
function readMessage(){return !data.enabled?"この文書では、閲覧用URLを発行できません。":data.revoked?"文書の共有は終了しています。":data.documentExpiresAt<=Date.now()?"文書の閲覧期限を過ぎています。":data.links.length?"":"閲覧用URLは未発行です。";}
async function read(){
 if(busy||!documentId)return;busy=true;clearIssued();render();const g=epoch;el["links-status"].textContent="閲覧用URLを確認しています…";
 try{const value=checked(await api("/v1/documents/"+documentId+"/links"));if(!active(g))return;data=value;uncertain=false;el["links-expiry"].value=dateInput(data.documentExpiresAt);el["links-status"].textContent=readMessage();}
 catch(error){if(active(g)){data=null;uncertain=true;el["links-status"].textContent=error.status===401||error.status===403?"管理者としてログインし直してください。":"閲覧用URLを確認できません。再読み込みしてください。";}}
 finally{if(active(g)){busy=false;render();}}
}
async function change(action,linkId){
 render();if(busy||uncertain||!data||action==="create"&&!canCreate()||action==="revoke"&&!live(data.links.find(link=>link.id===linkId)))return;
 const previous=data,expiresAt=inputDate(el["links-expiry"].value),body=action==="create"?{action,expiresAt,expectedRevision:data.revision}:{action,linkId,expectedRevision:data.revision},g=epoch;busy=true;clearIssued();render();el["links-status"].textContent=action==="create"?"閲覧用URLを発行しています…":"閲覧用URLを停止しています…";
 try{const value=await api("/v1/documents/"+documentId+"/links",body);if(!active(g))return;
 if(action==="create"){
  if(!exact(value,["revision","link","url"])||!revision(value.revision)||value.revision<=previous.revision||typeof value.url!=="string")throw new Error();const link=checkedLink(value.link),base=location.origin+"/p/"+documentId+"#link=";if(link.revoked||link.expiresAt!==expiresAt||link.createdAt>Date.now()+60000||previous.links.some(existing=>existing.id===link.id)||!value.url.startsWith(base)||!TOKEN.test(value.url.slice(base.length)))throw new Error();
  const next=checked(await api("/v1/documents/"+documentId+"/links"));if(!active(g))return;const confirmed=next.links.find(item=>item.id===link.id);if(next.revision<value.revision||!confirmed||confirmed.createdAt!==link.createdAt||confirmed.expiresAt!==link.expiresAt||confirmed.revoked)throw new Error();data=next;if(!live(confirmed))throw new Error();issued={id:link.id,url:value.url};el["links-expiry"].value=dateInput(data.documentExpiresAt);el["links-status"].textContent="閲覧用URLを発行しました。コピーして開示先にお渡しください。";
 }else{data=checked(value);if(data.revision<=previous.revision||!data.links.find(link=>link.id===linkId&&link.revoked))throw new Error();el["links-status"].textContent="閲覧用URLを停止しました。";}
 }catch(error){if(active(g)){clearIssued();uncertain=true;el["links-status"].textContent=error.status===401||error.status===403?"管理者としてログインし直してください。":error.status===409?"設定が変更されています。再読み込みして確認してください。":error.status===400?"開示先と閲覧期限を確認し、再読み込みしてください。":action==="create"?"発行結果を確認できません。再読み込みで確認し、必要なら停止して発行し直してください。":"停止結果を確認できません。再読み込みして確認してください。";}}
 finally{if(active(g)){busy=false;render();}}
}
el["links-form"].addEventListener("submit",event=>{event.preventDefault();void change("create");});el["links-expiry"].addEventListener("input",render);el["links-refresh"].addEventListener("click",()=>void read());
el["links-copy"].addEventListener("click",async()=>{render();if(el["links-copy"].disabled)return;const current=issued,g=epoch;try{await navigator.clipboard.writeText(current.url);if(active(g)&&issued===current)el["links-status"].textContent="閲覧用URLをコピーしました。";}catch{if(active(g)&&issued===current)el["links-status"].textContent="発行したURLを選択してコピーしてください。";}});
el["links-panel"].addEventListener("toggle",()=>{if(el["links-panel"].open&&!data)void read();});
async function boot(){const g=epoch;try{const value=await api("/v1/management");if(!active(g))return;if(!UUID.test(value?.documentId||""))throw new Error();documentId=value.documentId;if(el["links-panel"].open)void read();}catch{if(active(g))el["links-status"].textContent="文書の情報を読み込めません。管理ページを開き直してください。";}render();}
addEventListener("pagehide",()=>{visible=false;epoch++;busy=false;clearTimeout(expiryTimer);for(const c of controllers)c.abort();controllers.clear();clearIssued();documentId=null;data=null;uncertain=true;el["links-status"].textContent="";render();});addEventListener("pageshow",event=>{if(event.persisted){visible=true;void boot();}});
render();void boot();
`;
