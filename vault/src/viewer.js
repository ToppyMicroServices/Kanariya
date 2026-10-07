function page(password) {
  const assets = password ? "/p/assets" : "";
  const login = password
    ? '<p>共有用パスワードでロックを解除してから、文書を開いてください。</p><form id="unlock-form" method="post" autocomplete="off"><label for="password">共有用パスワード</label><input id="password" type="password" autocomplete="off" required><button id="unlock" type="submit">ロックを解除</button></form>'
    : '<p>Cloudflare Accessでログインしたアカウントの閲覧権限を確認します。</p>';
  return `<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>保護文書</title><link rel="stylesheet" href="${assets}/viewer.css"><main><h1>保護文書</h1>${login}<p>「文書を開く」で復号を記録し、所有者への通知を待機列に登録します。保存したPDFやスクリーンショットは取り消せません。保存したコピーの再閲覧は検知できません。</p><button id="open" type="button"${password ? " disabled" : ""}>文書を開く</button><button id="close" type="button" hidden>閉じる</button>${password ? '<button id="logout" type="button" hidden>ログアウト</button>' : ""}<p id="status" role="status"></p><div id="document" aria-label="保護文書のページ" hidden></div><noscript>文書の表示にはJavaScriptが必要です。</noscript></main><script src="${assets}/viewer.js" type="module"></script></html>`;
}
export const html = page(false);
export const passwordHtml = page(true);
export const css = `body{font:16px system-ui,sans-serif;background:#f5f7fa;color:#182536;margin:0}main{max-width:1000px;margin:40px auto;padding:24px}button,input{padding:12px 20px;margin:6px 12px 6px 0;border:1px solid #234566;border-radius:6px;background:#fff;color:#163957}button{cursor:pointer}button:disabled{opacity:.5}label{display:block}input{max-width:100%;box-sizing:border-box}#document canvas{display:block;width:100%;height:auto;margin:16px 0;border:1px solid #ccd4df;background:white}#status{min-height:1.5em}@media print{main{display:none}}`;

function script(password) {
  const assets = password ? "/p/assets" : "";
  return `import { getDocument, GlobalWorkerOptions } from "${assets}/pdfjs/pdf.min.mjs";
"use strict";
GlobalWorkerOptions.workerSrc="${assets}/pdfjs/pdf.worker.min.mjs";
const passwordMode=${password},fontPath="${assets}/pdfjs/standard_fonts/";
const openButton=document.getElementById("open"),closeButton=document.getElementById("close"),status=document.getElementById("status"),pages=document.getElementById("document");
const form=document.getElementById("unlock-form"),passwordInput=document.getElementById("password"),unlockButton=document.getElementById("unlock"),logoutButton=document.getElementById("logout");
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_BYTES=1048576,MAX_PAGES=20,MAX_PAGE_PIXELS=4000000,MAX_TOTAL_PIXELS=12000000,MAX_TIMER=2147483647;
let active=null,pending=null,auth=null,authTimer=null,generation=0;
function route(){return location.pathname+location.search+location.hash;}
function documentId(){const id=passwordMode?(location.pathname.match(/^\\/p\\/([^/]+)$/)?.[1]||""):location.hash.slice(1);return UUID.test(id)?id:null;}
function controls(){
 openButton.disabled=Boolean(pending||(active&&active.busy)||(passwordMode&&!auth));closeButton.hidden=!active;
 if(passwordMode){form.hidden=Boolean(auth);unlockButton.disabled=Boolean(pending);passwordInput.disabled=Boolean(pending);logoutButton.hidden=!auth&&pending?.kind!=="logout";logoutButton.disabled=Boolean(pending);}
}
function release(session){
 if(!session)return;session.controller.abort();clearTimeout(session.timer);clearTimeout(session.expiryTimer);clearTimeout(session.pollTimer);clearTimeout(session.statusTimer);
 try{session.render?.cancel();}catch{}
 try{const cleanup=session.loading?.destroy();if(cleanup)void cleanup.catch(()=>{});}catch{}
 try{session.data?.fill(0);}catch{}session.data=null;
 for(const canvas of session.canvases){canvas.width=0;canvas.height=0;}session.canvases.clear();
}
function reset(lock=false){
 generation++;release(active);active=null;
 if(pending){pending.controller.abort();clearTimeout(pending.timer);pending=null;}
 pages.replaceChildren();pages.hidden=true;
 if(lock){clearTimeout(authTimer);authTimer=null;auth=null;}
 if(passwordInput)passwordInput.value="";
 controls();
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
 auth.expiresAt=Math.min(auth.expiresAt,next.expiresAt);auth.sessionExpiresAt=Math.min(auth.sessionExpiresAt,next.sessionExpiresAt);armAuth();
 return Math.min(auth.expiresAt,auth.sessionExpiresAt);
}
function armExpiry(session){
 clearTimeout(session.expiryTimer);
 session.expiryTimer=setTimeout(()=>{if(!current(session))return;armExpiry(session);},Math.min(MAX_TIMER,Math.max(0,session.expiresAt-Date.now())));
}
function requestOptions(token,method,body){return {method,credentials:"same-origin",cache:"no-store",redirect:"error",signal:token.controller.signal,...(body===undefined?{}:{headers:{"content-type":"application/json"},body})};}
async function jsonResponse(response){if(!response.ok||!response.headers.get("content-type")?.startsWith("application/json"))throw new Error();return response.json();}
function pollLater(session){session.pollTimer=setTimeout(()=>checkStatus(session),15000);}
async function checkStatus(session){
 if(!current(session))return;
 session.statusTimer=setTimeout(()=>{if(current(session)){reset(true);status.textContent="閲覧権限を確認できなかったため、表示を閉じました。もう一度ロックを解除してください。";}},10000);
 try{
  const response=await fetch("/p/"+session.id+"/status",requestOptions(session,"GET"));if(!current(session))return;
  const value=await jsonResponse(response);if(!current(session))return;
  session.expiresAt=Math.min(session.expiresAt,applyTimes(value));armExpiry(session);pollLater(session);
 }catch{if(current(session)){reset(true);status.textContent="閲覧権限を確認できなかったため、表示を閉じました。もう一度ロックを解除してください。";}}
 finally{clearTimeout(session.statusTimer);}
}
closeButton.addEventListener("click",()=>{reset();status.textContent="表示を閉じました。";});
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
  reset(true);const request={kind:"unlock",id,route:route(),controller:new AbortController(),generation,timer:null};pending=request;controls();status.textContent="共有用パスワードを確認しています…";
  request.timer=setTimeout(()=>{if(current(request,true)){reset(true);status.textContent="ロックを解除できませんでした。期限、パスワード、サービスの状態をご確認ください。";}},30000);
  try{
   const fetching=fetch("/p/"+id+"/session",requestOptions(request,"POST",body));body=null;
   const response=await fetching;if(!current(request,true))return;
   const value=times(await jsonResponse(response));if(!current(request,true))return;
   auth={id,route:request.route,...value};pending=null;armAuth();controls();status.textContent="ロックを解除しました。「文書を開く」で表示します。";
  }catch{if(current(request,true)){reset(true);status.textContent="ロックを解除できませんでした。期限、パスワード、サービスの状態をご確認ください。";}}
  finally{body=null;clearTimeout(request.timer);}
 });
 logoutButton.addEventListener("click",async()=>{
  if(pending)return;const id=auth?.id||documentId();reset(true);if(!id)return;
  const request={kind:"logout",id,route:route(),controller:new AbortController(),generation,timer:null};pending=request;controls();status.textContent="ログアウトしています…";
  request.timer=setTimeout(()=>{if(current(request,true)){reset(true);status.textContent="表示は閉じましたが、ログアウトを確認できませんでした。";}},30000);
  try{
   const response=await fetch("/p/"+id+"/session",requestOptions(request,"DELETE","{}"));if(!current(request,true))return;if(!response.ok)throw new Error();
   pending=null;controls();status.textContent="ログアウトしました。";
  }catch{if(current(request,true)){reset(true);status.textContent="表示は閉じましたが、ログアウトを確認できませんでした。";}}
  finally{clearTimeout(request.timer);}
 });
}
controls();
openButton.addEventListener("click",async()=>{
 const id=documentId();if(!id){reset(passwordMode);status.textContent="文書リンクを確認してください。";return;}
 if(document.hidden||pending)return;
 if(passwordMode&&(!auth||auth.id!==id||auth.route!==route())){reset(true);status.textContent="共有用パスワードでロックを解除してください。";return;}
 if(passwordMode&&Math.min(auth.expiresAt,auth.sessionExpiresAt)<=Date.now()){expire();return;}
 reset();const session={id,route:route(),controller:new AbortController(),generation,canvases:new Set(),loading:null,render:null,data:null,timer:null,expiryTimer:null,pollTimer:null,statusTimer:null,expiresAt:passwordMode?Math.min(auth.expiresAt,auth.sessionExpiresAt):null,busy:true};active=session;
 controls();status.textContent="権限を確認しています…";
 let registered=false;
 session.timer=setTimeout(()=>{if(current(session)){reset(passwordMode);status.textContent=registered?"復号操作と通知登録は完了しましたが、表示が時間内に完了しませんでした。":"処理が時間内に完了しませんでした。サービスの状態をご確認ください。";}},30000);
 try{
  const url=passwordMode?"/p/"+id+"/open":"/v1/documents/"+id+"/open";
  const response=await fetch(url,requestOptions(session,"POST",JSON.stringify({requestId:crypto.randomUUID()})));
  if(!current(session))return;
  if(!response.ok||!response.headers.get("content-type")?.startsWith("application/pdf"))throw new Error();
  registered=true;status.textContent="復号操作を記録し、通知を待機列に登録しました。文書を表示しています…";
  const expiresAt=timestamp(response.headers.get("x-vault-expires-at"));
  session.expiresAt=passwordMode?applyTimes({expiresAt,sessionExpiresAt:response.headers.get("x-vault-session-expires-at")}):expiresAt;armExpiry(session);
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
   pixels+=canvas.width*canvas.height;canvas.setAttribute("role","img");canvas.setAttribute("aria-label",number+" / "+pdf.numPages+" ページ");
   session.render=page.render({canvas,canvasContext:canvas.getContext("2d"),viewport});
   await session.render.promise;session.render=null;
   if(!current(session)){canvas.width=0;canvas.height=0;return;}
   pages.append(canvas);pages.hidden=false;page.cleanup();
   if(passwordMode&&number===1)pollLater(session);
  }
  status.textContent="文書を表示しました（"+pdf.numPages+"ページ）。復号操作を記録し、通知を待機列に登録しました。";
 }catch{if(current(session)){reset(passwordMode);status.textContent=registered?"復号操作と通知登録は完了しましたが、文書を表示できませんでした。":"文書を開けませんでした。権限、期限、サービスの状態をご確認ください。";}}
 finally{clearTimeout(session.timer);if(current(session)){session.busy=false;controls();}else release(session);}
});`;
}
export const js = script(false);
export const passwordJs = script(true);
