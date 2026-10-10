function page(password) {
  const assets = password ? "/p/assets" : "";
  const login = password
    ? '<form id="unlock-form" method="post" autocomplete="off"><label for="password">閲覧用パスワード</label><p id="password-help" class="form-help">文書提供者から通知されたパスワードを入力してください。</p><div class="unlock-row"><input id="password" type="password" autocomplete="off" aria-describedby="password-help" required><button id="unlock" type="submit" class="primary">認証する</button></div></form>'
    : '<p class="access-note">認証済みアカウントの閲覧権限を確認します。</p>';
  return `<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="theme-color" content="#02213b"><title>保護文書の閲覧 | ToppyMicroServices</title><link rel="stylesheet" href="${assets}/viewer.css"></head>
<body>
<header class="site-header"><div class="header-inner"><a class="brand" href="https://www.toppymicros.com/" target="_blank" rel="noopener noreferrer" aria-label="ToppyMicroServicesのサイト（新しいタブ）"><img src="${assets}/brand.png" width="32" height="32" alt=""><span>ToppyMicroServices</span></a><span class="service-name">Kanariya</span></div></header>
<main id="main"><div class="intro"><p class="eyebrow">KANARIYA · DOCUMENT SHARING</p><h1>保護文書の閲覧</h1><p class="intro-copy">本ページは、文書提供者が指定した開示先向けの閲覧ページです。${password ? "共通パスワード方式では、実際の閲覧者本人を確認するものではありません。" : ""}</p></div>
<section class="viewer-card" aria-label="文書へのアクセス">${login}<div class="actions"><button id="open" type="button"${password ? " disabled" : ""} class="primary">文書を開く</button><button id="download" type="button" hidden>PDFを保存</button><button id="close" type="button" hidden>閲覧を終了</button>${password ? '<button id="logout" type="button" class="quiet" hidden>ログアウト</button>' : ""}</div><p id="deadline" class="deadline" aria-live="polite" aria-atomic="true">文書の閲覧期限：${password ? "認証後に表示します。" : "文書を開く際に表示します。"}</p>${password ? '<p id="session-deadline" class="session-deadline" hidden></p>' : ""}<p id="status" role="status" aria-live="polite" aria-atomic="true"></p><div class="viewing-notice"><h2>閲覧に関するご案内</h2><p>文書を開く操作（画面表示・PDF保存）は復号イベントとして記録され、文書提供者への通知対象となります。現行の通知では表示と保存を区別しません。</p><details><summary>閲覧期限・保存資料の取扱い</summary><p>失効または閲覧期限を過ぎると、本ページから文書を開くことやPDFを保存することはできません。失効および閲覧期限は、その後の文書取得を停止するもので、すでに受信・保存された内容を回収するものではありません。開示先名が設定された文書は、宛名入りのPDFとして保存できます。</p>${password ? '<p>認証は最長5分間有効です。認証の有効期限を過ぎると表示を閉じますが、文書の閲覧期限内であれば再度認証して開くことができます。</p>' : '<p>表示中の失効は定期確認しません。表示は文書の閲覧期限、閲覧の終了、またはページからの離脱時に閉じます。</p>'}<p>保存済みのPDFやスクリーンショットには閲覧期限は適用されず、回収もできません。保存した資料の再閲覧は記録・通知の対象外です。</p></details></div></section>
<div id="document" aria-label="保護文書のページ" hidden></div><noscript><p class="noscript">文書の表示にはJavaScriptが必要です。</p></noscript></main>
<footer class="site-footer"><span>ToppyMicroServices OÜ</span><span>Document sharing · Kanariya</span></footer><script src="${assets}/viewer.js" type="module"></script></body></html>`;
}
export const html = page(false);
export const passwordHtml = page(true);
// Shared palette and proportions from the ToppyMicroServices website.
// All assets stay on this origin; no external fonts or analytics are loaded.
export const css = `
:root{color-scheme:dark;--bg:#02213b;--surface:#072d4a;--fg:#f5fbff;--muted:#b4cad9;--accent:#62d2ff;--border:rgba(185,226,255,.2)}
*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.7 "Plus Jakarta Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--accent)}button,input,summary{font:inherit}
a:focus-visible,button:focus-visible,input:focus-visible,summary:focus-visible{outline:3px solid var(--accent);outline-offset:4px}
.site-header{border-bottom:1px solid var(--border)}.header-inner{min-height:72px;display:flex;align-items:center;justify-content:space-between;gap:20px}
.header-inner,main,.site-footer{width:min(calc(100% - 40px),1040px);margin-inline:auto}
.brand{display:inline-flex;align-items:center;gap:10px;color:var(--fg);font-size:16px;font-weight:800;text-decoration:none;letter-spacing:-.025em}.brand img{display:block;border-radius:6px}.service-name{color:var(--muted);font-size:13px}
main{padding-block:40px 48px}.intro{margin-bottom:28px}.eyebrow{margin:0 0 8px;color:var(--accent);font-size:11px;font-weight:700;letter-spacing:.12em}
h1{margin:0;font-size:clamp(28px,4vw,38px);line-height:1.3;letter-spacing:-.035em}.intro-copy{margin:12px 0 0;color:var(--muted);font-size:15px}
.viewer-card{padding:24px;border:1px solid var(--border);border-radius:6px;background:var(--surface)}
label{display:block;font-size:15px;font-weight:700}.form-help{margin:4px 0 14px;color:var(--muted);font-size:14px}.unlock-row{display:flex;align-items:stretch;gap:12px;max-width:660px}
input{min-width:0;flex:1;width:100%;min-height:48px;padding:10px 14px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--fg);letter-spacing:.04em}
button{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:46px;padding:10px 18px;border:1px solid var(--border);border-radius:6px;background:transparent;color:var(--fg);font-size:14px;font-weight:700;cursor:pointer;transition:background-color .15s,border-color .15s}
button:hover:not(:disabled){border-color:var(--accent);background:rgba(98,210,255,.08)}button.primary{background:var(--accent);border-color:var(--accent);color:var(--bg)}button.primary:hover:not(:disabled){background:#9ae2ff;border-color:#9ae2ff}
button:disabled{opacity:.5;cursor:default}.quiet{color:var(--muted)}.actions{display:flex;flex-wrap:wrap;gap:10px}.viewer-card:has(#unlock-form:not([hidden])) .actions{display:none}
.access-note{margin:0 0 20px;color:var(--muted);font-size:14px}.deadline{margin:20px 0 0;font-size:14px;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}.session-deadline{margin:4px 0 0;color:var(--muted);font-size:13px;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
#status{margin:20px 0 0;padding:12px 16px;border-left:2px solid var(--accent);background:rgba(2,33,59,.45);font-size:14px;line-height:1.7;overflow-wrap:anywhere}#status:empty{display:none}
.viewing-notice{margin-top:20px;padding-top:16px;border-top:1px solid var(--border);color:var(--muted);font-size:13px;line-height:1.8}.viewing-notice h2{margin:0 0 8px;color:var(--fg);font-size:14px;font-weight:700}.viewing-notice p{margin:0}.viewing-notice details{margin-top:8px}.viewing-notice summary{width:fit-content;cursor:pointer}.viewing-notice details p{max-width:700px;margin-top:8px}
#document{margin-top:24px;padding:20px;border:1px solid var(--border);border-radius:6px;background:#011729}.document-page{margin-bottom:24px}.document-page:last-child{margin-bottom:0}#document canvas{display:block;width:100%;height:auto;margin:0 auto;background:#fff}.page-text{margin-top:12px;padding:12px 16px;border:1px solid var(--border);border-radius:6px;font-size:14px}.page-text summary{cursor:pointer}.text-help{color:var(--muted);font-size:12px}.text-content{white-space:pre-wrap;overflow-wrap:anywhere;unicode-bidi:plaintext}
.site-footer{display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px 24px;padding-block:20px 28px;border-top:1px solid var(--border);color:var(--muted);font-size:12px}.noscript{padding:16px;border:1px solid var(--border)}
@media(max-width:540px){.header-inner{min-height:64px;gap:12px}.brand{font-size:14px;gap:8px}.brand img{width:28px;height:28px}.service-name{font-size:12px}main{padding-block:28px 32px}.intro{margin-bottom:22px}.viewer-card{padding:20px}.unlock-row{flex-direction:column}.unlock-row button{width:100%}.actions{gap:8px}.actions button{padding-inline:14px}.intro-copy{font-size:14px}.viewing-notice{font-size:12px}#document{padding:0;border:0;background:transparent}#document canvas{margin-bottom:16px}.site-footer{font-size:11px}}
@media(max-width:420px){.header-inner,main,.site-footer{width:calc(100% - 28px)}.viewer-card{padding:18px}.brand{font-size:13px}.service-name{font-size:11px}}
@media(prefers-reduced-motion:reduce){button{transition:none}}
@media print{body{display:none}}
`;

function script(password) {
  const assets = password ? "/p/assets" : "";
  return `import { getDocument, GlobalWorkerOptions } from "${assets}/pdfjs/pdf.min.mjs";
"use strict";
GlobalWorkerOptions.workerSrc="${assets}/pdfjs/pdf.worker.min.mjs";
const passwordMode=${password},fontPath="${assets}/pdfjs/standard_fonts/";
const openButton=document.getElementById("open"),closeButton=document.getElementById("close"),downloadButton=document.getElementById("download"),status=document.getElementById("status"),pages=document.getElementById("document");
const deadline=document.getElementById("deadline"),sessionDeadline=document.getElementById("session-deadline");
const form=document.getElementById("unlock-form"),passwordInput=document.getElementById("password"),unlockButton=document.getElementById("unlock"),logoutButton=document.getElementById("logout");
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_BYTES=1048576,MAX_PAGES=20,MAX_PAGE_PIXELS=4000000,MAX_TOTAL_PIXELS=12000000,MAX_TIMER=2147483647;
const MAX_TEXT_CHARS=200000,MAX_TEXT_ITEMS=20000;
let active=null,pending=null,auth=null,authTimer=null,generation=0;
const downloadURLs=new Set();
function revokeDownload(url){URL.revokeObjectURL(url);downloadURLs.delete(url);}
function downloadName(response){
 try{const encoded=response.headers.get("x-vault-download-filename");if(!encoded||encoded.length>1024)return null;
 const name=decodeURIComponent(encoded);if(name.length>200||!name.startsWith("CV_")||!name.endsWith(".pdf")||/[\\\\/:*?"<>|\\x00-\\x1f\\x7f-\\x9f\\u061c\\u200e\\u200f\\u2028\\u2029\\u202a-\\u202e\\u2066-\\u2069]/.test(name))return null;return name;
 }catch{return null;}
}
function route(){return location.pathname+location.search+location.hash;}
function documentId(){const id=passwordMode?(location.pathname.match(/^\\/p\\/([^/]+)$/)?.[1]||""):location.hash.slice(1);return UUID.test(id)?id:null;}
function dateLabel(value){
 try{return new Intl.DateTimeFormat("ja-JP",{timeZone:"Asia/Tokyo",year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit",hourCycle:"h23"}).format(value)+"（日本時間）";}
 catch{return "日時を表示できません。";}
}
function focusControl(){if(!document.hidden)(passwordMode&&!auth?passwordInput:openButton)?.focus({preventScroll:true});}
function controls(){
 const documentExpiry=passwordMode?auth?.expiresAt:active?.documentExpiresAt;
 deadline.textContent="文書の閲覧期限："+(documentExpiry?dateLabel(documentExpiry):passwordMode?"認証後に表示します。":"文書を開く際に表示します。");
 if(sessionDeadline){sessionDeadline.hidden=!auth;sessionDeadline.textContent=auth?"現在の認証の有効期限："+dateLabel(auth.sessionExpiresAt)+"。期限後は再度認証してください。":"";}
 openButton.disabled=Boolean(pending||(active&&active.busy)||(passwordMode&&!auth));closeButton.hidden=!active;
 downloadButton.hidden=!active?.downloadFilename;downloadButton.disabled=Boolean(pending||active?.busy);
 if(passwordMode){form.hidden=Boolean(auth);unlockButton.disabled=Boolean(pending);passwordInput.disabled=Boolean(pending);logoutButton.hidden=!auth&&pending?.kind!=="logout";logoutButton.disabled=Boolean(pending);}
}
function release(session){
 if(!session)return;session.controller.abort();clearTimeout(session.timer);clearTimeout(session.expiryTimer);clearTimeout(session.pollTimer);clearTimeout(session.statusTimer);
 try{session.render?.cancel();}catch{}
 try{const cleanup=session.loading?.destroy();if(cleanup)void cleanup.catch(()=>{});}catch{}
 try{session.data?.fill(0);}catch{}session.data=null;
 try{const cancelled=session.textReader?.cancel();if(cancelled)void cancelled.catch(()=>{});}catch{}
 for(const node of session.textNodes||[])node.textContent="";session.textNodes?.clear();
 for(const canvas of session.canvases){canvas.width=0;canvas.height=0;}session.canvases.clear();
}
function reset(lock=false){
 generation++;release(active);active=null;
 if(pending){pending.controller.abort();clearTimeout(pending.timer);pending=null;}
 pages.replaceChildren();pages.hidden=true;
 for(const url of downloadURLs)revokeDownload(url);
 if(lock){clearTimeout(authTimer);authTimer=null;auth=null;}
 if(passwordInput)passwordInput.value="";
 controls();focusControl();
}
function expire(){reset(true);status.textContent="閲覧期限またはセッションの有効期限が切れたため、表示を閉じました。";}
function changed(){reset(true);status.textContent="文書リンクが変わりました。開く文書をご確認ください。";}
function current(token,isPending=false){
 if((isPending?pending:active)!==token||generation!==token.generation||token.controller.signal.aborted)return false;
 if(route()!==token.route){changed();return false;}
 if(document.hidden){reset(true);status.textContent="ページが非表示になったため、表示を閉じました。";return false;}
 if(token.expiresAt&&token.expiresAt<=Date.now()){expire();return false;}
 return true;
}
function timestamp(value){const number=typeof value==="number"?value:typeof value==="string"&&/^\\d+$/.test(value)?Number(value):NaN;if(!Number.isSafeInteger(number)||number<=Date.now())throw new Error();return number;}
function times(value){return {expiresAt:timestamp(value.expiresAt),sessionExpiresAt:timestamp(value.sessionExpiresAt)};}
function armAuth(){
 clearTimeout(authTimer);const expected=auth;if(!expected)return;
 authTimer=setTimeout(()=>{if(auth!==expected)return;if(route()!==expected.route){changed();return;}if(Math.min(expected.expiresAt,expected.sessionExpiresAt)<=Date.now())expire();else armAuth();},Math.min(MAX_TIMER,Math.max(0,Math.min(expected.expiresAt,expected.sessionExpiresAt)-Date.now())));
}
function applyTimes(value){
 const next=times(value);
 auth.expiresAt=Math.min(auth.expiresAt,next.expiresAt);auth.sessionExpiresAt=Math.min(auth.sessionExpiresAt,next.sessionExpiresAt);armAuth();controls();
 return Math.min(auth.expiresAt,auth.sessionExpiresAt);
}
function armExpiry(session){
 clearTimeout(session.expiryTimer);
 session.expiryTimer=setTimeout(()=>{if(!current(session))return;armExpiry(session);},Math.min(MAX_TIMER,Math.max(0,session.expiresAt-Date.now())));
}
function requestOptions(token,method,body){return {method,credentials:"same-origin",cache:"no-store",redirect:"error",signal:token.controller.signal,...(body===undefined?{}:{headers:{"content-type":"application/json"},body})};}
async function pageText(page,session){
 const reader=page.streamTextContent({includeMarkedContent:false}).getReader();session.textReader=reader;
 const parts=[];let items=0;
 try{
  while(true){
   const chunk=await reader.read();if(!current(session))return null;if(chunk.done)break;
   if(!Array.isArray(chunk.value?.items))throw new Error();
   for(const item of chunk.value.items){
    if(++items>MAX_TEXT_ITEMS||typeof item.str!=="string")throw new Error();
    const part=item.str+(item.hasEOL?"\\n":"");session.textChars+=part.length;
    if(session.textChars>MAX_TEXT_CHARS)throw new Error();parts.push(part);
   }
  }
  return parts.join("").trim();
 }finally{
  if(session.textReader===reader)session.textReader=null;
  try{await reader.cancel();}catch{}reader.releaseLock();parts.length=0;
 }
}
function textAlternative(text,number,session){
 const details=document.createElement("details"),summary=document.createElement("summary"),help=document.createElement("p"),content=document.createElement("div");
 details.className="page-text";summary.textContent=number+"ページ目の読み上げ用テキスト";
 help.className="text-help";help.textContent="PDFから抽出したテキストです。表や段組みの読み順が異なる場合があります。";
 content.className="text-content";content.setAttribute("dir","auto");content.textContent=text||"このページからテキストを取得できません。文書提供者にテキスト版をお問い合わせください。";
 session.textNodes.add(content);details.append(summary,help,content);return details;
}
async function jsonResponse(response){if(!response.ok||!response.headers.get("content-type")?.startsWith("application/json"))throw new Error();return response.json();}
function pollLater(session){session.pollTimer=setTimeout(()=>checkStatus(session),15000);}
async function checkStatus(session){
 if(!current(session))return;
 session.statusTimer=setTimeout(()=>{if(current(session)){reset(true);status.textContent="閲覧権限を確認できなかったため、表示を閉じました。再度認証を行ってください。";}},10000);
 try{
  const response=await fetch("/p/"+session.id+"/status",requestOptions(session,"GET"));if(!current(session))return;
  const value=await jsonResponse(response);if(!current(session))return;
  session.expiresAt=Math.min(session.expiresAt,applyTimes(value));armExpiry(session);pollLater(session);
 }catch{if(current(session)){reset(true);status.textContent="閲覧権限を確認できなかったため、表示を閉じました。再度認証を行ってください。";}}
 finally{clearTimeout(session.statusTimer);}
}
closeButton.addEventListener("click",()=>{reset();status.textContent="表示を閉じました。";});
downloadButton.addEventListener("click",async()=>{
 const session=active;if(pending||!session||session.busy||!session.downloadFilename||!current(session))return;
 const request={kind:"download",id:session.id,route:route(),controller:new AbortController(),generation,expiresAt:session.expiresAt,timer:null};
 pending=request;controls();status.textContent="権限を確認してPDFを準備しています…";
 request.timer=setTimeout(()=>{if(current(request,true)){reset(true);status.textContent="PDFの保存が時間内に開始できませんでした。";}},30000);
 let bytes=null,url=null,link=null;
 try{
  const path=passwordMode?"/p/"+request.id+"/open":"/v1/documents/"+request.id+"/open";
  const response=await fetch(path,requestOptions(request,"POST",JSON.stringify({requestId:crypto.randomUUID()})));
  if(!current(request,true)||!current(session))return;
  if(!response.ok||!response.headers.get("content-type")?.startsWith("application/pdf")||downloadName(response)!==session.downloadFilename)throw new Error();
  const expiresAt=timestamp(response.headers.get("x-vault-expires-at"));
  request.expiresAt=Math.min(request.expiresAt,passwordMode?applyTimes({expiresAt,sessionExpiresAt:response.headers.get("x-vault-session-expires-at")}):expiresAt);
  session.expiresAt=Math.min(session.expiresAt,request.expiresAt);session.documentExpiresAt=Math.min(session.documentExpiresAt,expiresAt);armExpiry(session);controls();
  const declared=response.headers.get("content-length");if(declared&&(!/^\\d+$/.test(declared)||Number(declared)>MAX_BYTES))throw new Error();
  bytes=new Uint8Array(await response.arrayBuffer());
  if(!current(request,true)||!current(session))return;if(!bytes.length||bytes.length>MAX_BYTES)throw new Error();
  url=URL.createObjectURL(new Blob([bytes],{type:"application/pdf"}));downloadURLs.add(url);
  link=document.createElement("a");link.href=url;link.download=session.downloadFilename;link.hidden=true;document.body.append(link);link.click();link.remove();link=null;
  const savedURL=url;setTimeout(()=>revokeDownload(savedURL),1000);url=null;
  pending=null;controls();status.textContent="宛名入りPDFの保存を開始しました。文書提供者への通知を受け付けました。";
 }catch{if(current(request,true)){reset(true);status.textContent="PDFを保存できませんでした。もう一度文書を開いてください。";}}
 finally{bytes?.fill(0);link?.remove();if(url)revokeDownload(url);clearTimeout(request.timer);}
});
addEventListener("pagehide",()=>reset(true));
addEventListener("pageshow",event=>{if(event.persisted)reset(true);});
addEventListener("hashchange",changed);addEventListener("popstate",changed);
// Same-document history changes do not emit popstate until Back/Forward.
if(typeof history!=="undefined")for(const method of ["pushState","replaceState"]){
 const original=history[method];if(typeof original!=="function")continue;
 history[method]=function(...args){const previous=route(),result=original.apply(this,args);if(route()!==previous)changed();return result;};
}
document.addEventListener("visibilitychange",()=>{if(document.hidden){reset(true);status.textContent="ページが非表示になったため、表示を閉じました。";}});
if(passwordMode){
 form.addEventListener("submit",async event=>{
  event.preventDefault();if(pending||auth||document.hidden){passwordInput.value="";return;}
  const id=documentId();if(!id){passwordInput.value="";status.textContent="文書リンクを確認してください。";return;}
  let body=JSON.stringify({password:passwordInput.value});passwordInput.value="";
  reset(true);const request={kind:"unlock",id,route:route(),controller:new AbortController(),generation,timer:null};pending=request;controls();status.textContent="閲覧用パスワードを確認しています…";
  request.timer=setTimeout(()=>{if(current(request,true)){reset(true);status.textContent="認証できませんでした。閲覧期限、パスワードおよびサービスの状態をご確認ください。";}},30000);
  try{
   const fetching=fetch("/p/"+id+"/session",requestOptions(request,"POST",body));body=null;
   const response=await fetching;if(!current(request,true))return;
   const value=times(await jsonResponse(response));if(!current(request,true))return;
   auth={id,route:request.route,...value};pending=null;armAuth();controls();focusControl();status.textContent="認証が完了しました。「文書を開く」を選択してください。";
  }catch{if(current(request,true)){reset(true);status.textContent="認証できませんでした。閲覧期限、パスワードおよびサービスの状態をご確認ください。";}}
  finally{body=null;clearTimeout(request.timer);}
 });
 logoutButton.addEventListener("click",async()=>{
  if(pending)return;const id=auth?.id||documentId();reset(true);if(!id)return;
  const request={kind:"logout",id,route:route(),controller:new AbortController(),generation,timer:null};pending=request;controls();status.textContent="ログアウトしています…";
  request.timer=setTimeout(()=>{if(current(request,true)){reset(true);status.textContent="表示は閉じましたが、ログアウトを確認できませんでした。";}},30000);
  try{
   const response=await fetch("/p/"+id+"/session",requestOptions(request,"DELETE","{}"));if(!current(request,true))return;if(!response.ok)throw new Error();
   pending=null;controls();focusControl();status.textContent="ログアウトしました。";
  }catch{if(current(request,true)){reset(true);status.textContent="表示は閉じましたが、ログアウトを確認できませんでした。";}}
  finally{clearTimeout(request.timer);}
 });
}
controls();
openButton.addEventListener("click",async()=>{
 const id=documentId();if(!id){reset(passwordMode);status.textContent="文書リンクを確認してください。";return;}
 if(document.hidden||pending)return;
 if(passwordMode&&(!auth||auth.id!==id||auth.route!==route())){reset(true);status.textContent="閲覧用パスワードによる認証を行ってください。";return;}
 if(passwordMode&&Math.min(auth.expiresAt,auth.sessionExpiresAt)<=Date.now()){expire();return;}
 reset();const session={id,route:route(),controller:new AbortController(),generation,canvases:new Set(),textNodes:new Set(),textReader:null,textChars:0,loading:null,render:null,data:null,timer:null,expiryTimer:null,pollTimer:null,statusTimer:null,expiresAt:passwordMode?Math.min(auth.expiresAt,auth.sessionExpiresAt):null,busy:true};active=session;
 controls();status.textContent="権限を確認しています…";
 let registered=false;
 session.timer=setTimeout(()=>{if(current(session)){reset(passwordMode);status.textContent=registered?"閲覧の記録と通知の受付は完了しましたが、表示が時間内に完了しませんでした。":"処理が時間内に完了しませんでした。サービスの状態をご確認ください。";}},30000);
 try{
  const url=passwordMode?"/p/"+id+"/open":"/v1/documents/"+id+"/open";
  const response=await fetch(url,requestOptions(session,"POST",JSON.stringify({requestId:crypto.randomUUID()})));
  if(!current(session))return;
  if(!response.ok||!response.headers.get("content-type")?.startsWith("application/pdf"))throw new Error();
  registered=true;status.textContent="閲覧を記録し、文書提供者への通知を受け付けました。文書を表示しています…";
  const expiresAt=timestamp(response.headers.get("x-vault-expires-at"));
  session.expiresAt=passwordMode?applyTimes({expiresAt,sessionExpiresAt:response.headers.get("x-vault-session-expires-at")}):expiresAt;session.documentExpiresAt=expiresAt;armExpiry(session);controls();
  const declared=response.headers.get("content-length");if(declared&&(!/^\\d+$/.test(declared)||Number(declared)>MAX_BYTES))throw new Error();
  const data=new Uint8Array(await response.arrayBuffer());
  if(!current(session)){data.fill(0);return;}if(!data.length||data.length>MAX_BYTES){data.fill(0);throw new Error();}session.data=data;
  session.loading=getDocument({data,standardFontDataUrl:fontPath,disableFontFace:true,useSystemFonts:false,useWasm:false,enableXfa:false,stopAtErrors:true,verbosity:0,maxImageSize:MAX_PAGE_PIXELS,canvasMaxAreaInBytes:MAX_PAGE_PIXELS*4});
  const pdf=await session.loading.promise;if(!current(session))return;
  if(!Number.isSafeInteger(pdf.numPages)||pdf.numPages<1||pdf.numPages>MAX_PAGES)throw new Error();
  let pixels=0;
  for(let number=1;number<=pdf.numPages;number++){
   const page=await pdf.getPage(number);if(!current(session))return;
   const base=page.getViewport({scale:1});if(!Number.isFinite(base.width)||!Number.isFinite(base.height)||base.width<=0||base.height<=0)throw new Error();
   const budget=Math.min(MAX_PAGE_PIXELS,Math.floor((MAX_TOTAL_PIXELS-pixels)/(pdf.numPages-number+1)));
   const desiredWidth=Math.min(1000,pages.clientWidth||1000)*Math.min(2,devicePixelRatio||1);
   const scale=Math.min(desiredWidth/base.width,Math.sqrt(budget/(base.width*base.height)));
   const viewport=page.getViewport({scale}),canvas=document.createElement("canvas");session.canvases.add(canvas);
   canvas.width=Math.floor(viewport.width);canvas.height=Math.floor(viewport.height);
   if(canvas.width<1||canvas.height<1||canvas.width*canvas.height>budget)throw new Error();
   pixels+=canvas.width*canvas.height;canvas.setAttribute("aria-hidden","true");
   session.render=page.render({canvas,canvasContext:canvas.getContext("2d"),viewport});
   await session.render.promise;session.render=null;
   if(!current(session)){canvas.width=0;canvas.height=0;return;}
   const text=await pageText(page,session);if(!current(session))return;
   const section=document.createElement("section");section.className="document-page";section.setAttribute("aria-label",number+" / "+pdf.numPages+" ページ");
   section.append(canvas,textAlternative(text,number,session));pages.append(section);pages.hidden=false;page.cleanup();
   if(passwordMode&&number===1)pollLater(session);
  }
  session.downloadFilename=downloadName(response);
  status.textContent="文書を表示しました（"+pdf.numPages+"ページ）。閲覧を記録し、文書提供者への通知を受け付けました。";
 }catch{if(current(session)){reset(passwordMode);status.textContent=registered?"閲覧の記録と通知の受付は完了しましたが、文書を表示できませんでした。":"文書を開けませんでした。閲覧権限、閲覧期限およびサービスの状態をご確認ください。";}}
 finally{clearTimeout(session.timer);if(current(session)){session.busy=false;controls();}else release(session);}
});`;
}
export const js = script(false);
export const passwordJs = script(true);
