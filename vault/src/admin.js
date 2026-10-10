import { css as viewerCss } from './viewer.js';
import * as extensions from './admin-extensions.js';
import * as canary from './canary-admin.js';

export const html = `<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="theme-color" content="#02213b"><title>文書の管理 | ToppyMicroServices</title><link rel="stylesheet" href="/v1/admin/assets/admin.css"></head>
<body><header class="site-header"><div class="header-inner"><a class="brand" href="https://www.toppymicros.com/" target="_blank" rel="noopener noreferrer" aria-label="ToppyMicroServicesのサイト（新しいタブ）"><img src="/brand.png" width="32" height="32" alt=""><span>ToppyMicroServices</span></a><span class="service-name">Kanariya</span></div></header>
<main><div class="intro"><p class="eyebrow">KANARIYA · DOCUMENT SHARING</p><h1>文書の管理</h1></div>
<p id="status" role="status" aria-live="polite" aria-atomic="true">文書の情報を読み込んでいます…</p><p id="error" role="alert" hidden></p><div class="recovery-actions"><button id="reload" type="button" class="quiet" hidden>再読み込み</button><a id="owner-page" href="/v1/admin" hidden>管理ページを開き直す</a></div>
<section id="management" class="viewer-card management-card" aria-label="共有文書の設定" hidden><div class="document-heading"><h2>管理対象のPDF</h2><span id="sharing-state" class="state-label"></span></div>
<dl class="document-info"><div id="recipient-row" hidden><dt>開示先</dt><dd id="recipient"></dd></div><div><dt>閲覧期限</dt><dd id="deadline"></dd></div></dl>
<div class="actions"><button id="copy-link" type="button" disabled>共有リンクをコピー</button><a id="preview" class="button-link" target="_blank" rel="noopener noreferrer" aria-label="閲覧ページを開く（新しいタブ）" aria-disabled="true">閲覧ページを開く</a></div>
<form id="expiry-form" class="expiry-form"><label for="expires-at">閲覧期限を変更</label><p id="expiry-help" class="form-help">日本時間で指定してください。</p><div class="expiry-controls"><input id="expires-at" type="datetime-local" step="60" required disabled aria-describedby="expiry-help expiry-limit"><button id="save-expiry" type="submit" class="primary" disabled>期限を保存</button></div><p id="expiry-limit" class="form-help"></p></form>
<div class="sharing-end"><button id="stop-sharing" type="button" class="quiet" disabled>共有を終了</button><div id="stop-confirmation" class="confirmation" hidden><p>共有を終了すると、この文書を新たに開いたり保存したりできなくなります。元に戻すことはできません。</p><div class="actions"><button id="confirm-stop" type="button" class="danger">共有を終了する</button><button id="cancel-stop" type="button">キャンセル</button></div></div></div>
<details class="management-notes"><summary>ご案内</summary><p>現在はダミーPDFを共有しています。新しいPDFは、非公開の登録候補として保存できます。</p><p>閲覧期限や共有の終了は、すでに表示・保存された内容を回収するものではありません。</p></details></section>${extensions.html}${canary.html}<noscript><p class="noscript">文書の管理にはJavaScriptが必要です。</p></noscript></main>
<footer class="site-footer"><span>ToppyMicroServices OÜ</span><span>Document sharing · Kanariya</span></footer><script src="/v1/admin/assets/admin.js" type="module"></script><script src="/v1/admin/assets/management.js" type="module"></script><script src="/v1/admin/assets/canary.js" type="module"></script></body></html>`;

export const css = viewerCss + extensions.css + `
.management-card{margin-top:24px}.document-heading{display:flex;align-items:center;justify-content:space-between;gap:16px}.document-heading h2{margin:0;font-size:19px}.state-label{color:var(--accent);font-size:13px;white-space:nowrap}.document-info{margin:20px 0}.document-info>div{display:grid;grid-template-columns:90px minmax(0,1fr);gap:12px;margin-top:8px}.document-info dt{color:var(--muted);font-size:14px}.document-info dd{margin:0;overflow-wrap:anywhere;font-size:14px;font-variant-numeric:tabular-nums}
.button-link{display:inline-flex;align-items:center;justify-content:center;min-height:46px;padding:10px 18px;border:1px solid var(--border);border-radius:6px;color:var(--fg);text-decoration:none;font-size:14px;font-weight:700}.button-link:hover{border-color:var(--accent);background:rgba(98,210,255,.08)}.button-link[aria-disabled=true]{opacity:.5;pointer-events:none;cursor:default}
.expiry-form{margin-top:28px;padding-top:24px;border-top:1px solid var(--border)}.expiry-controls{display:flex;align-items:stretch;gap:12px;max-width:620px}.expiry-controls input{flex:1}.expiry-controls button{flex:none}#expiry-limit{margin-top:8px;font-size:12px;overflow-wrap:anywhere}.sharing-end{margin-top:24px}.confirmation{max-width:700px;margin-top:16px;padding:16px;border:1px solid var(--border);border-radius:6px}.confirmation p{margin:0 0 14px;font-size:14px}.danger{border-color:#ffbac1;color:#ffbac1}.management-notes{margin-top:24px;padding-top:16px;border-top:1px solid var(--border);font-size:13px;color:var(--muted)}.management-notes summary{cursor:pointer;width:fit-content}.management-notes p{max-width:700px;margin:8px 0 0}#error{padding:12px 16px;border-left:2px solid #ffbac1;background:rgba(2,33,59,.45);font-size:14px}.recovery-actions{display:flex;flex-wrap:wrap;align-items:center;gap:12px}.recovery-actions a{font-size:13px}
@media(max-width:540px){.document-heading{align-items:flex-start}.document-heading h2{font-size:17px}.document-info>div{grid-template-columns:70px minmax(0,1fr);gap:8px}.expiry-controls{flex-direction:column}.expiry-controls button{width:100%}.button-link{padding-inline:14px}.management-notes{font-size:12px}}
`;

export const managementJs = extensions.js;
export const canaryJs = canary.js;

export const js = `"use strict";
const ids=["status","error","reload","owner-page","management","sharing-state","recipient-row","recipient","deadline","copy-link","preview","expiry-form","expires-at","save-expiry","expiry-limit","stop-sharing","stop-confirmation","confirm-stop","cancel-stop"];
const el=Object.fromEntries(ids.map(id=>[id,document.getElementById(id)]));
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const JAPAN_OFFSET=9*60*60*1000,MAX_TIMER=2147483647;
let metadata=null,documentId=null,pending=null,generation=0,expiryTimer=null,uncertain=false,needsLogin=false;
function dateLabel(value){return new Intl.DateTimeFormat("ja-JP",{timeZone:"Asia/Tokyo",year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",hourCycle:"h23"}).format(value)+"（日本時間）";}
function localDate(value){return new Date(value+JAPAN_OFFSET).toISOString().slice(0,16);}
function inputDate(value){
 if(!/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}$/.test(value))return NaN;
 const parsed=Date.parse(value+":00+09:00");return Number.isSafeInteger(parsed)&&localDate(parsed)===value?parsed:NaN;
}
function timestamp(value){return Number.isSafeInteger(value)&&value>0&&value<=8640000000000000;}
function validate(value){
 if(!value||value.id!==documentId||value.mime!=="application/pdf"||!Number.isSafeInteger(value.size)||value.size<=0||value.size>1048576||!["password","access"].includes(value.authMode)||!timestamp(value.expiresAt)||!timestamp(value.sealedExpiresAt)||value.expiresAt>value.sealedExpiresAt||typeof value.revoked!=="boolean"||!(value.recipientName===null||typeof value.recipientName==="string"&&value.recipientName.length<=200))throw new Error();
 return value;
}
function active(token){return pending===token&&generation===token.generation&&!token.controller.signal.aborted;}
function setError(message){el.error.textContent=message;el.error.hidden=!message;}
function controls(){
 const blocked=Boolean(pending||uncertain||!metadata),shared=metadata&&!metadata.revoked&&metadata.expiresAt>Date.now();
 const latest=metadata&&metadata.sealedExpiresAt>Date.now();
 const chosen=inputDate(el["expires-at"].value),valid=metadata&&Number.isSafeInteger(chosen)&&chosen>Date.now()&&chosen<=metadata.sealedExpiresAt;
 el["copy-link"].disabled=blocked||!shared;el.preview.setAttribute("aria-disabled",blocked||!shared?"true":"false");
 if(!blocked&&shared)el.preview.href=location.origin+(metadata.authMode==="password"?"/p/"+documentId:"/#"+documentId);else el.preview.removeAttribute("href");
 el["expires-at"].disabled=blocked||metadata?.revoked||!latest;el["save-expiry"].disabled=blocked||metadata?.revoked||!valid;el["stop-sharing"].disabled=blocked||metadata?.revoked;
 el["confirm-stop"].disabled=blocked||metadata?.revoked;el["cancel-stop"].disabled=Boolean(pending);el.reload.disabled=Boolean(pending);
}
function render(){
 clearTimeout(expiryTimer);if(!metadata){el.management.hidden=true;controls();return;}
 el.management.hidden=false;el["sharing-state"].textContent=metadata.revoked?"共有終了":metadata.expiresAt<=Date.now()?"閲覧期限切れ":"共有中";
 el["recipient-row"].hidden=!metadata.recipientName;el.recipient.textContent=metadata.recipientName||"";el.deadline.textContent=dateLabel(metadata.expiresAt);
 el["expires-at"].value=localDate(metadata.expiresAt);el["expires-at"].min=localDate(Math.ceil((Date.now()+1)/60000)*60000);el["expires-at"].max=localDate(metadata.sealedExpiresAt);
 el["expiry-limit"].textContent="設定できる最終日時："+dateLabel(metadata.sealedExpiresAt);
 el["stop-confirmation"].hidden=true;controls();
 if(!metadata.revoked&&metadata.expiresAt>Date.now())expiryTimer=setTimeout(()=>{expiryTimer=null;render();},Math.min(MAX_TIMER,metadata.expiresAt-Date.now()));
}
function begin(message){
 if(pending)return null;setError("");el.status.textContent=message;el.reload.hidden=true;el["owner-page"].hidden=true;needsLogin=false;el.reload.textContent="再読み込み";
 const token={controller:new AbortController(),generation,timeout:null};pending=token;token.timeout=setTimeout(()=>token.controller.abort(),20000);controls();return token;
}
function finish(token){clearTimeout(token.timeout);if(pending===token){pending=null;controls();}}
function failure(status){const error=new Error();error.status=status;return error;}
async function request(token,path,method="GET",body){
 const response=await fetch(path,{method,credentials:"same-origin",cache:"no-store",redirect:"error",signal:token.controller.signal,...(body===undefined?{}:{headers:{"content-type":"application/json"},body:JSON.stringify(body)})});
 if(!active(token))throw new Error();if(!response.ok)throw failure(response.status);
 if(!response.headers.get("content-type")?.startsWith("application/json"))throw new Error();const text=await response.text();if(!active(token)||text.length>8192)throw new Error();return JSON.parse(text);
}
async function readMetadata(token){return validate(await request(token,"/v1/documents/"+documentId+"/metadata"));}
function readError(error){
 metadata=null;render();el.status.textContent="";el.reload.hidden=false;needsLogin=error.status===401||error.status===403;
 el.reload.textContent=needsLogin?"ログインし直す":"再読み込み";el["owner-page"].hidden=needsLogin;
 setError(needsLogin?"管理者としてログインし直してください。":"文書の情報を読み込めません。再読み込みしてください。ログインが必要な場合は、管理ページを開き直してください。");
}
async function load(){
 const token=begin("文書の情報を読み込んでいます…");if(!token)return;
 try{const value=await request(token,"/v1/management");if(!UUID.test(value?.documentId||""))throw new Error();documentId=value.documentId;
 const next=await readMetadata(token);if(!active(token))return;metadata=next;uncertain=false;render();el.status.textContent="";
 }catch(error){if(pending===token&&generation===token.generation)readError(error);}finally{finish(token);}
}
async function change(kind,body){
 const token=begin(kind==="expiry"?"閲覧期限を保存しています…":"共有を終了しています…");if(!token)return;let accepted=false;
 try{await request(token,"/v1/documents/"+documentId+"/"+kind,"POST",body);accepted=true;
 const next=await readMetadata(token);if(!active(token))return;metadata=next;render();el.status.textContent=kind==="expiry"?"閲覧期限を保存しました。":"共有を終了しました。";
 }catch(error){if(pending!==token||generation!==token.generation)return;
 el.status.textContent="";
 if(error.status===401||error.status===403){readError(error);return;}
 if(error.status===409&&!accepted){
  try{const next=await readMetadata(token);if(!active(token))return;metadata=next;render();setError("文書の設定が変更されています。表示を更新しました。確認してから再度操作してください。");}
  catch(readFailure){readError(readFailure);}return;
 }
 if(error.status===400&&!accepted){setError("期限を確認してください。現在より先、設定できる最終日時までを指定してください。");return;}
 uncertain=true;el.reload.hidden=false;setError(accepted?"変更は受け付けられました。再読み込みして最新の状態を確認してください。":"処理結果を確認できません。再読み込みして確認してください。");
 }finally{finish(token);}
}
el.reload.addEventListener("click",()=>{if(pending)return;if(needsLogin)location.reload();else void load();});el["expires-at"].addEventListener("input",controls);
el["expiry-form"].addEventListener("submit",event=>{
 event.preventDefault();if(pending||uncertain||!metadata||metadata.revoked)return;const expiresAt=inputDate(el["expires-at"].value);
 if(!Number.isSafeInteger(expiresAt)||expiresAt<=Date.now()||expiresAt>metadata.sealedExpiresAt){setError("期限を確認してください。現在より先、設定できる最終日時までを指定してください。");return;}
 void change("expiry",{expiresAt,expectedExpiresAt:metadata.expiresAt});
});
el["copy-link"].addEventListener("click",async()=>{
 if(pending||uncertain||!metadata||metadata.revoked||metadata.expiresAt<=Date.now())return;
 const expected=metadata,version=generation;try{await navigator.clipboard.writeText(el.preview.href);if(metadata===expected&&version===generation){setError("");el.status.textContent="共有リンクをコピーしました。";}}
 catch{if(metadata===expected&&version===generation)setError("リンクをコピーできませんでした。閲覧ページを開き、アドレスをコピーしてください。");}
});
el["stop-sharing"].addEventListener("click",()=>{if(pending||uncertain||!metadata||metadata.revoked)return;el["stop-confirmation"].hidden=false;el["confirm-stop"].focus();});
el["cancel-stop"].addEventListener("click",()=>{if(pending)return;el["stop-confirmation"].hidden=true;el["stop-sharing"].focus();});
el["confirm-stop"].addEventListener("click",()=>{if(pending||uncertain||!metadata||metadata.revoked||el["stop-confirmation"].hidden)return;void change("revoke",{});});
addEventListener("pagehide",()=>{generation++;pending?.controller.abort();if(pending)clearTimeout(pending.timeout);pending=null;clearTimeout(expiryTimer);metadata=null;documentId=null;el.recipient.textContent="";el.deadline.textContent="";el["expires-at"].value="";el.status.textContent="";setError("");render();});
addEventListener("pageshow",event=>{if(event.persisted)void load();});
void load();
`;
