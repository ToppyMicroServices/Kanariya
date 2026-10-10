export const js = String.raw`import { getDocument, GlobalWorkerOptions } from "/p/assets/pdfjs/pdf.min.mjs";
GlobalWorkerOptions.workerSrc="/p/assets/pdfjs/pdf.worker.min.mjs";
const MAX_BYTES=1048576,MAX_PNG_BYTES=524288,MAX_PAGES=20,MAX_PAGE_PIXELS=4000000,MAX_TOTAL_PIXELS=12000000;
const MAX_TEXT_CHARS=200000,MAX_TEXT_ITEMS=20000,TIMEOUT=20000,SHA256=/^[0-9a-f]{64}$/;
const unsafeName=/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\\/:*?"<>|]/u;
const previews=new WeakMap();
function failed(){return new Error("pdf_preparation_failed");}
function aborted(){return new DOMException("Operation aborted","AbortError");}
function wipe(bytes){try{bytes?.fill(0);}catch{}}
function check(signal){if(signal?.aborted)throw aborted();}
function bounded(promise,signal){
 return new Promise((resolve,reject)=>{
  const stop=()=>{signal.removeEventListener("abort",stop);reject(aborted());};
  signal.addEventListener("abort",stop,{once:true});
  if(signal.aborted)stop();
  Promise.resolve(promise).then(value=>{signal.removeEventListener("abort",stop);resolve(value);},error=>{signal.removeEventListener("abort",stop);reject(error);});
 });
}
function recipient(value){
 if(typeof value!=="string"||!value.isWellFormed()||unsafeName.test(value))throw failed();
 const name=value.normalize("NFC").trim();if(!name||new TextEncoder().encode(name).length>180)throw failed();return name;
}
async function digest(bytes){return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes)),b=>b.toString(16).padStart(2,"0")).join("");}
function rasterLines(context,label,size){
 context.font=size+"px sans-serif";const lines=[];let line="";
 for(const character of label){
  if(context.measureText(line+character).width>1936){if(!line)return null;lines.push(line);line=character;if(lines.length>1)return null;}
  else line+=character;
 }
 if(line)lines.push(line);return lines.length&&lines.length<=2&&lines.every(value=>context.measureText(value).width<=1936)?lines:null;
}
async function raster(name,signal){
 const canvas=document.createElement("canvas");canvas.width=2048;canvas.height=256;
 try{
  let context=canvas.getContext("2d");if(!context)throw failed();
  let lines=null,size=64;for(const candidate of [64,56,48]){lines=rasterLines(context,"開示先: "+name,candidate);if(lines){size=candidate;break;}}
  if(!lines)throw failed();
  const width=Math.ceil(Math.max(...lines.map(line=>context.measureText(line).width))+96),height=lines.length*size+(lines.length-1)*24+64;
  if(!Number.isSafeInteger(width)||width>2048||height>512)throw failed();canvas.width=Math.max(256,width);canvas.height=height;
  context=canvas.getContext("2d");if(!context)throw failed();
  context.clearRect(0,0,canvas.width,canvas.height);context.font=size+"px sans-serif";
  context.fillStyle="rgb(115,115,115)";context.globalAlpha=1;context.textAlign="center";context.textBaseline="middle";
  for(let index=0;index<lines.length;index++)context.fillText(lines[index],canvas.width/2,canvas.height/2+(index-(lines.length-1)/2)*(size+24));
  const blob=await bounded(new Promise(resolve=>canvas.toBlob(resolve,"image/png")),signal);check(signal);
  if(!blob||!Number.isSafeInteger(blob.size)||blob.size<8||blob.size>MAX_PNG_BYTES)throw failed();
  const bytes=await bounded(blob.arrayBuffer().then(buffer=>{const result=new Uint8Array(buffer);if(signal.aborted){wipe(result);throw aborted();}return result;}),signal);
  if(bytes.length!==blob.size){wipe(bytes);throw failed();}return bytes;
 }finally{canvas.width=0;canvas.height=0;}
}
export async function prepareRegistration(file,recipientName,watermarkEnabled,signal){
 check(signal);if(!file||!Number.isSafeInteger(file.size)||file.size<5||file.size>MAX_BYTES||typeof file.arrayBuffer!=="function"||typeof watermarkEnabled!=="boolean")throw failed();
 const name=recipient(recipientName),controller=new AbortController();let worker=null,bytes=null,png=null,result=null,done=false,closed=false;
 const stop=()=>controller.abort();signal?.addEventListener("abort",stop,{once:true});
 const timer=setTimeout(stop,TIMEOUT);
 try{
  bytes=await bounded(Promise.resolve(file.arrayBuffer()).then(buffer=>{const value=new Uint8Array(buffer);if(controller.signal.aborted){wipe(value);throw aborted();}return value;}),controller.signal);
  if(bytes.length!==file.size||String.fromCharCode(...bytes.subarray(0,5))!=="%PDF-")throw failed();
  const sourceSha256=await bounded(digest(bytes),controller.signal);check(controller.signal);
  if(watermarkEnabled)png=await raster(name,controller.signal);check(controller.signal);
  worker=new Worker("/v1/admin/assets/pdf-preparation-worker.js",{type:"module"});
  const reply=new Promise((resolve,reject)=>{
   worker.onmessage=event=>{
    const value=event.data;
    if(closed||controller.signal.aborted){wipe(value?.bytes);reject(failed());return;}
    if(!value||Object.keys(value).length!==4||!(value.bytes instanceof Uint8Array)||value.bytes.length<5||value.bytes.length>MAX_BYTES||
      typeof value.sourceSha256!=="string"||!SHA256.test(value.sourceSha256)||value.sourceSha256!==sourceSha256||
      typeof value.finalSha256!=="string"||!SHA256.test(value.finalSha256)||!Number.isSafeInteger(value.pages)||value.pages<1||value.pages>MAX_PAGES){wipe(value?.bytes);reject(failed());return;}
    resolve(value);
   };
   worker.onerror=event=>{event.preventDefault?.();reject(failed());};worker.onmessageerror=()=>reject(failed());
   try{worker.postMessage({bytes,recipientName:name,watermarkEnabled,watermarkPng:png},png?[bytes.buffer,png.buffer]:[bytes.buffer]);}catch{reject(failed());}
  });
  result=await bounded(reply,controller.signal);check(controller.signal);
  if(String.fromCharCode(...result.bytes.subarray(0,5))!=="%PDF-"||await bounded(digest(result.bytes),controller.signal)!==result.finalSha256)throw failed();
  done=true;return result;
 }catch{if(signal?.aborted)throw aborted();throw failed();}
 finally{
  closed=true;clearTimeout(timer);signal?.removeEventListener("abort",stop);if(worker){worker.onmessage=null;worker.onerror=null;worker.onmessageerror=null;worker.terminate();}
  wipe(bytes);wipe(png);if(!done)wipe(result?.bytes);
 }
}
function destroyLoading(session){try{const promise=session.loading?.destroy();if(promise)void promise.catch(()=>{});}catch{}session.loading=null;wipe(session.data);session.data=null;}
function release(session){
 session.controller.abort();clearTimeout(session.timer);session.signal?.removeEventListener("abort",session.stop);
 try{session.render?.cancel();}catch{}session.render=null;
 try{const promise=session.reader?.cancel();if(promise)void promise.catch(()=>{});}catch{}
 destroyLoading(session);for(const canvas of session.canvases){canvas.width=0;canvas.height=0;}session.canvases.clear();
 for(const node of session.textNodes)node.textContent="";session.textNodes.clear();
}
export function clearRegistrationPreview(container){
 const session=previews.get(container);if(session){previews.delete(container);release(session);}container.replaceChildren();container.hidden=true;
}
function current(container,session){if(previews.get(container)!==session||session.controller.signal.aborted)throw aborted();}
async function text(page,session){
 const reader=page.streamTextContent({includeMarkedContent:false}).getReader();session.reader=reader;const parts=[];let items=0;
 try{
  while(true){const chunk=await bounded(reader.read(),session.controller.signal);if(chunk.done)break;
   if(!Array.isArray(chunk.value?.items))throw failed();for(const item of chunk.value.items){
    if(++items>MAX_TEXT_ITEMS||typeof item.str!=="string")throw failed();const value=item.str+(item.hasEOL?"\n":"");
    session.textChars+=value.length;if(session.textChars>MAX_TEXT_CHARS)throw failed();parts.push(value);
   }
  }return parts.join("").trim();
 }finally{if(session.reader===reader)session.reader=null;try{const promise=reader.cancel();if(promise)void promise.catch(()=>{});}catch{}try{reader.releaseLock();}catch{}parts.length=0;}
}
export async function showRegistrationPreview(container,result,signal){
 clearRegistrationPreview(container);check(signal);
 if(!result||!(result.bytes instanceof Uint8Array)||result.bytes.length<5||result.bytes.length>MAX_BYTES||!Number.isSafeInteger(result.pages)||result.pages<1||result.pages>MAX_PAGES)throw failed();
 const session={controller:new AbortController(),signal,stop:null,timer:null,timedOut:false,loading:null,render:null,reader:null,data:result.bytes.slice(),canvases:new Set(),textNodes:new Set(),textChars:0};
 session.stop=()=>{if(previews.get(container)===session)clearRegistrationPreview(container);};
 previews.set(container,session);signal?.addEventListener("abort",session.stop,{once:true});session.timer=setTimeout(()=>{session.timedOut=true;session.stop();},TIMEOUT);
 try{
  session.loading=getDocument({data:session.data,standardFontDataUrl:"/p/assets/pdfjs/standard_fonts/",disableFontFace:true,useSystemFonts:false,useWasm:false,isEvalSupported:false,
   enableXfa:false,disableAutoFetch:true,disableStream:true,stopAtErrors:true,verbosity:0,maxImageSize:MAX_PAGE_PIXELS,canvasMaxAreaInBytes:MAX_PAGE_PIXELS*4});
  const pdf=await bounded(session.loading.promise,session.controller.signal);current(container,session);
  if(!Number.isSafeInteger(pdf.numPages)||pdf.numPages!==result.pages)throw failed();let pixels=0;
  for(let number=1;number<=pdf.numPages;number++){
   const page=await bounded(pdf.getPage(number),session.controller.signal);current(container,session);
   try{
    const base=page.getViewport({scale:1});if(!Number.isFinite(base.width)||!Number.isFinite(base.height)||base.width<=0||base.height<=0)throw failed();
    const budget=Math.min(MAX_PAGE_PIXELS,Math.floor((MAX_TOTAL_PIXELS-pixels)/(pdf.numPages-number+1)));
    const desiredWidth=Math.min(1000,container.clientWidth||1000)*Math.min(2,Math.max(1,Number(globalThis.devicePixelRatio)||1));
    const scale=Math.min(desiredWidth/base.width,Math.sqrt(budget/(base.width*base.height))),viewport=page.getViewport({scale});
    const canvas=document.createElement("canvas");session.canvases.add(canvas);canvas.width=Math.floor(viewport.width);canvas.height=Math.floor(viewport.height);
    if(!Number.isSafeInteger(canvas.width)||!Number.isSafeInteger(canvas.height)||canvas.width<1||canvas.height<1||canvas.width*canvas.height>budget)throw failed();pixels+=canvas.width*canvas.height;
    canvas.style.maxWidth="100%";canvas.style.height="auto";canvas.setAttribute("aria-hidden","true");
    const context=canvas.getContext("2d");if(!context)throw failed();session.render=page.render({canvas,canvasContext:context,viewport});
    await bounded(session.render.promise,session.controller.signal);session.render=null;current(container,session);
    const content=await text(page,session);current(container,session);
    const section=document.createElement("section");section.className="document-page";section.setAttribute("aria-label",number+" / "+pdf.numPages+" ページ");
    const details=document.createElement("details"),summary=document.createElement("summary"),body=document.createElement("pre");
    details.className="page-text";summary.textContent="本文をテキストで読む（"+number+"ページ目）";
    body.setAttribute("dir","auto");body.textContent=content||"本文のテキストを取得できません。";session.textNodes.add(body);details.append(summary,body);
    section.append(canvas,details);container.append(section);container.hidden=false;
   }finally{try{page.cleanup();}catch{}}
  }
  current(container,session);clearTimeout(session.timer);session.timer=null;destroyLoading(session);
 }catch{
  const cancelled=!session.timedOut&&(signal?.aborted||session.controller.signal.aborted);if(previews.get(container)===session)clearRegistrationPreview(container);else release(session);
  if(cancelled)throw aborted();throw failed();
 }
}
`;

export const workerJs = String.raw`import { preparePdf } from "./pdf-preparation.mjs";
let used=false;
const wipe=bytes=>{try{bytes?.fill(0);}catch{}};
self.onmessage=async event=>{
 if(used)return;used=true;const input=event.data;let result;
 try{
  result=await preparePdf(input);
  self.postMessage({bytes:result.bytes,sourceSha256:result.sourceSha256,finalSha256:result.finalSha256,pages:result.pages},[result.bytes.buffer]);
 }catch{self.postMessage({error:"pdf_preparation_failed"});}
 finally{wipe(input?.bytes);wipe(input?.watermarkPng);wipe(result?.bytes);}
};
`;
