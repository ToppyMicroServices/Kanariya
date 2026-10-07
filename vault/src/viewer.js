export const html = `<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>保護文書</title><link rel="stylesheet" href="/viewer.css"><main><h1>保護文書</h1><p>「文書を開く」で復号を記録し、所有者への通知を待機列に登録します。保存したPDFの再閲覧は検知できません。</p><button id="open" type="button">文書を開く</button><button id="close" type="button" hidden>閉じる</button><p id="status" role="status"></p><div id="document" aria-label="保護文書のページ" hidden></div><noscript>文書の表示にはJavaScriptが必要です。</noscript></main><script src="/viewer.js" type="module"></script></html>`;
export const css = `body{font:16px system-ui,sans-serif;background:#f5f7fa;color:#182536;margin:0}main{max-width:1000px;margin:40px auto;padding:24px}button{padding:12px 20px;margin-right:12px;border:1px solid #234566;border-radius:6px;background:#fff;color:#163957;cursor:pointer}button:disabled{opacity:.5}#document canvas{display:block;width:100%;height:auto;margin:16px 0;border:1px solid #ccd4df;background:white}#status{min-height:1.5em}`;
export const js = `import { getDocument, GlobalWorkerOptions } from "/pdfjs/pdf.min.mjs";
"use strict";
GlobalWorkerOptions.workerSrc="/pdfjs/pdf.worker.min.mjs";
const openButton=document.getElementById("open"),closeButton=document.getElementById("close"),status=document.getElementById("status"),pages=document.getElementById("document");
const MAX_BYTES=1048576,MAX_PAGES=20,MAX_PAGE_PIXELS=4000000,MAX_TOTAL_PIXELS=12000000;
let active=null,generation=0;
function release(session){
 if(!session)return;session.controller.abort();clearTimeout(session.timer);
 try{session.render?.cancel();}catch{}
 try{const cleanup=session.loading?.destroy();if(cleanup)void cleanup.catch(()=>{});}catch{}
 for(const canvas of session.canvases){canvas.width=0;canvas.height=0;}session.canvases.clear();
}
function closeDocument(){generation++;release(active);active=null;pages.replaceChildren();pages.hidden=true;closeButton.hidden=true;openButton.disabled=false;}
closeButton.addEventListener("click",()=>{closeDocument();status.textContent="表示を閉じました。";});
addEventListener("pagehide",closeDocument);
addEventListener("hashchange",()=>{closeDocument();status.textContent="文書リンクが変わりました。開く文書をご確認ください。";});
openButton.addEventListener("click",async()=>{
 const id=location.hash.slice(1);
 if(!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)){status.textContent="文書リンクを確認してください。";return;}
 closeDocument();const session={controller:new AbortController(),generation,canvases:new Set(),loading:null,render:null,timer:null};active=session;
 const current=()=>active===session&&generation===session.generation&&!session.controller.signal.aborted&&location.hash.slice(1)===id;
 openButton.disabled=true;closeButton.hidden=false;status.textContent="権限を確認しています…";
 let registered=false;
 session.timer=setTimeout(()=>{if(current()){closeDocument();status.textContent=registered?"復号操作と通知登録は完了しましたが、表示が時間内に完了しませんでした。":"処理が時間内に完了しませんでした。サービスの状態をご確認ください。";}},30000);
 try{
  const response=await fetch("/v1/documents/"+id+"/open",{method:"POST",credentials:"same-origin",cache:"no-store",redirect:"error",signal:session.controller.signal,headers:{"content-type":"application/json"},body:JSON.stringify({requestId:crypto.randomUUID()})});
  if(!current())return;
  if(!response.ok||!response.headers.get("content-type")?.startsWith("application/pdf"))throw new Error();
  registered=true;status.textContent="復号操作を記録し、通知を待機列に登録しました。文書を表示しています…";
  const declared=response.headers.get("content-length");if(declared&&(!/^\\d+$/.test(declared)||Number(declared)>MAX_BYTES))throw new Error();
  const data=new Uint8Array(await response.arrayBuffer());
  if(!current()){data.fill(0);return;}if(!data.length||data.length>MAX_BYTES){data.fill(0);throw new Error();}
  session.loading=getDocument({data,standardFontDataUrl:"/pdfjs/standard_fonts/",disableFontFace:true,useSystemFonts:false,useWasm:false,enableXfa:false,stopAtErrors:true,verbosity:0,maxImageSize:MAX_PAGE_PIXELS,canvasMaxAreaInBytes:MAX_PAGE_PIXELS*4});
  const pdf=await session.loading.promise;if(!current())return;
  if(!Number.isSafeInteger(pdf.numPages)||pdf.numPages<1||pdf.numPages>MAX_PAGES)throw new Error();
  let pixels=0;
  for(let number=1;number<=pdf.numPages;number++){
   const page=await pdf.getPage(number);if(!current())return;
   const base=page.getViewport({scale:1});if(!Number.isFinite(base.width)||!Number.isFinite(base.height)||base.width<=0||base.height<=0)throw new Error();
   const budget=Math.min(MAX_PAGE_PIXELS,Math.floor((MAX_TOTAL_PIXELS-pixels)/(pdf.numPages-number+1)));
   const desiredWidth=Math.min(1000,pages.clientWidth||1000)*Math.min(2,devicePixelRatio||1);
   const scale=Math.min(desiredWidth/base.width,Math.sqrt(budget/(base.width*base.height)));
   const viewport=page.getViewport({scale}),canvas=document.createElement("canvas");
   canvas.width=Math.floor(viewport.width);canvas.height=Math.floor(viewport.height);
   if(canvas.width<1||canvas.height<1||canvas.width*canvas.height>budget)throw new Error();
   pixels+=canvas.width*canvas.height;session.canvases.add(canvas);canvas.setAttribute("role","img");canvas.setAttribute("aria-label",number+" / "+pdf.numPages+" ページ");
   session.render=page.render({canvas,canvasContext:canvas.getContext("2d"),viewport});
   await session.render.promise;session.render=null;
   if(!current()){canvas.width=0;canvas.height=0;return;}
   pages.append(canvas);pages.hidden=false;page.cleanup();
  }
  status.textContent="文書を表示しました（"+pdf.numPages+"ページ）。復号操作を記録し、通知を待機列に登録しました。";
 }catch{if(current()){closeDocument();status.textContent=registered?"復号操作と通知登録は完了しましたが、文書を表示できませんでした。":"文書を開けませんでした。権限、期限、サービスの状態をご確認ください。";}}
 finally{clearTimeout(session.timer);if(current())openButton.disabled=false;else release(session);}
});`;
