export const html = `<section class="viewer-card owner-tools" aria-label="文書の登録と共有先"><details id="registration-panel"><summary>PDFの登録・差し替え</summary><p class="form-help">登録したPDFは非公開です。共有中のPDFは変更されません。</p><form id="registration-form"><label for="registration-file">PDF</label><input id="registration-file" type="file" accept="application/pdf,.pdf" required><label for="registration-expiry">閲覧期限</label><input id="registration-expiry" type="datetime-local" step="60" required aria-describedby="registration-time"><p id="registration-time" class="form-help">日本時間で指定してください。PDFは1 MBまでです。</p><label class="check-label"><input id="registration-replace" type="checkbox">共有中のPDFの差し替え候補にする</label><button id="register-pdf" type="submit" class="primary" disabled>非公開で登録</button></form><p id="registration-status" role="status" aria-live="polite"></p><button id="registration-reload" type="button" class="quiet">登録済みのPDFを確認</button><ul id="registration-list" class="owner-list"></ul></details><details id="contacts-panel"><summary>開示先メール</summary><form id="contacts-form"><label for="contact-emails">メールアドレス（1行に1件）</label><textarea id="contact-emails" rows="4" autocomplete="off" spellcheck="false" maxlength="12750" disabled></textarea><p class="form-help">共通パスワードでの閲覧者本人を確認するものではありません。</p><button id="save-contacts" type="submit" disabled>保存</button></form><p id="contacts-status" role="status" aria-live="polite"></p><button id="contacts-reload" type="button" class="quiet">再読み込み</button></details><details id="logs-panel"><summary>閲覧ログ</summary><p class="form-help">直近30日分。共通パスワードの閲覧者は本人未確認として表示します。</p><p id="logs-status" role="status" aria-live="polite"></p><div class="log-scroll"><table class="log-table"><thead><tr><th scope="col">日時（日本時間）</th><th scope="col">閲覧者</th><th scope="col">結果</th><th scope="col">通知</th></tr></thead><tbody id="log-rows"></tbody></table></div><div class="actions"><button id="logs-reload" type="button" class="quiet">最新の記録</button><button id="logs-next" type="button" hidden>次の記録</button></div></details></section>`;

export const css = `
.owner-tools{margin-top:24px}.owner-tools>details+details{margin-top:20px;padding-top:20px;border-top:1px solid var(--border)}.owner-tools summary{font-weight:700;cursor:pointer}.owner-tools form{display:grid;gap:10px;max-width:620px;margin:20px 0}.owner-tools input,.owner-tools textarea{width:100%;box-sizing:border-box}.owner-tools input[type=file]{padding:12px;font-size:14px}.owner-tools input[type=checkbox]{width:18px;height:18px;margin:0;flex:none}.check-label{display:flex;align-items:center;gap:10px;font-size:14px}.owner-tools textarea{font:inherit;padding:12px;color:var(--fg);background:var(--bg);border:1px solid var(--border);border-radius:6px;resize:vertical}.owner-tools p[role=status]{font-size:14px;overflow-wrap:anywhere}.owner-list{padding-left:20px;font-size:14px}.owner-list li{margin-top:10px;overflow-wrap:anywhere}.log-scroll{overflow-x:auto;margin:16px 0}.log-table{width:100%;border-collapse:collapse;font-size:13px}.log-table th,.log-table td{padding:12px 8px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top;overflow-wrap:anywhere}.log-table th{font-weight:600}.log-event{display:block;color:var(--muted);font-size:11px;margin-top:4px}.log-table td:first-child{white-space:nowrap}
@media(max-width:540px){.log-table{min-width:620px}}
`;

export const js = `"use strict";
const ids=["registration-panel","registration-form","registration-file","registration-expiry","registration-replace","register-pdf","registration-status","registration-reload","registration-list","contacts-panel","contacts-form","contact-emails","save-contacts","contacts-status","contacts-reload","logs-panel","logs-status","log-rows","logs-reload","logs-next"];
const el=Object.fromEntries(ids.map(id=>[id,document.getElementById(id)]));
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const JAPAN=9*3600000,MAX_PDF=1048576;
let docId=null,contacts=null,registry=null,cursor=null,epoch=0,visible=true;
let registrationBusy=false,contactsBusy=false,logsBusy=false,unknownId=null;
const controllers=new Set();
function dateLabel(value){return new Intl.DateTimeFormat("ja-JP",{timeZone:"Asia/Tokyo",year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",hourCycle:"h23"}).format(value);}
function dateInput(value){return new Date(value+JAPAN).toISOString().slice(0,16);}
function parseDate(value){if(!/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}$/.test(value))return NaN;const n=Date.parse(value+":00+09:00");return Number.isSafeInteger(n)&&dateInput(n)===value?n:NaN;}
function active(g){return visible&&g===epoch;}
function updateControls(){
 el["register-pdf"].disabled=registrationBusy||unknownId!==null||!registry||!docId||registry.documents.length+registry.pending>=20;
 el["registration-file"].disabled=registrationBusy||unknownId!==null;el["registration-expiry"].disabled=registrationBusy||unknownId!==null;el["registration-replace"].disabled=registrationBusy||unknownId!==null;
 el["registration-reload"].disabled=registrationBusy;
 el["contact-emails"].disabled=contactsBusy||!contacts;el["save-contacts"].disabled=contactsBusy||!contacts;el["contacts-reload"].disabled=contactsBusy;
 el["logs-next"].disabled=logsBusy;el["logs-next"].hidden=!cursor;el["logs-reload"].disabled=logsBusy;
}
async function api(path,method="GET",body){
 const controller=new AbortController();controllers.add(controller);const timeout=setTimeout(()=>controller.abort(),25000);
 try{
  const r=await fetch(path,{method,credentials:"same-origin",cache:"no-store",redirect:"error",signal:controller.signal,...(body===undefined?{}:{headers:{"content-type":"application/json"},body:JSON.stringify(body)})});
  if(!r.ok){const e=new Error();e.status=r.status;throw e;}
  if(!r.headers.get("content-type")?.startsWith("application/json")||Number(r.headers.get("content-length"))>65536)throw new Error();
  const reader=r.body.getReader();let total=0;const parts=[];
  try{while(true){const {done,value}=await reader.read();if(done)break;total+=value.length;if(total>65536)throw new Error();parts.push(value);}}finally{void reader.cancel().catch(()=>{});reader.releaseLock();}
  const bytes=new Uint8Array(total);let at=0;for(const p of parts){bytes.set(p,at);at+=p.length;}return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));
 }finally{clearTimeout(timeout);controllers.delete(controller);}
}
function readFailure(section,error){el[section+"-status"].textContent=error.status===401||error.status===403?"管理者としてログインし直してください。":"読み込めませんでした。再読み込みしてください。";}
function checkedContacts(value){if(!value||!Number.isSafeInteger(value.revision)||value.revision<0||!Array.isArray(value.emails)||value.emails.length>50||value.emails.some(x=>typeof x!=="string"||x.length>254))throw new Error();return value;}
async function readContacts(){
 if(contactsBusy||!docId)return;contactsBusy=true;updateControls();const g=epoch;
 try{const value=checkedContacts(await api("/v1/documents/"+docId+"/recipients"));if(!active(g))return;contacts=value;el["contact-emails"].value=value.emails.join("\\n");el["contacts-status"].textContent="";}
 catch(error){if(active(g)){contacts=null;el["contact-emails"].value="";readFailure("contacts",error);}}
 finally{contactsBusy=false;updateControls();}
}
function checkedRegistry(value){
 if(!value||!Number.isSafeInteger(value.revision)||value.revision<0||!Number.isSafeInteger(value.pending)||value.pending<0||!Array.isArray(value.documents)||value.documents.length+value.pending>20)throw new Error();
 for(const d of value.documents)if(!UUID.test(d.id)||d.status!=="private"||typeof d.fileName!=="string"||d.fileName.length>120||!Number.isSafeInteger(d.size)||d.size<5||d.size>MAX_PDF||!Number.isSafeInteger(d.createdAt)||!Number.isSafeInteger(d.expiresAt)||!(d.replaceOf===null||d.replaceOf===docId))throw new Error();
 return value;
}
function renderRegistry(){
 const list=el["registration-list"];list.replaceChildren();
 for(const d of registry.documents){const item=document.createElement("li");item.textContent=d.fileName+" — 非公開"+(d.replaceOf?"・差し替え候補":"")+" ／ 閲覧期限 "+dateLabel(d.expiresAt);list.append(item);}
}
async function readRegistry(){
 if(registrationBusy||!docId)return;registrationBusy=true;updateControls();const g=epoch;
 try{const value=checkedRegistry(await api("/v1/registrations"));if(!active(g))return;registry=value;renderRegistry();
  if(unknownId){const found=value.documents.some(d=>d.id===unknownId);el["registration-status"].textContent=found?"登録済みであることを確認しました。PDFは非公開です。":"登録は確認できませんでした。処理中の可能性があります。管理ページを開き直して再確認してください。";if(found){unknownId=null;el["registration-file"].value="";}}
  else el["registration-status"].textContent=value.documents.length+value.pending>=20?"登録上限の20件に達しています。":value.pending?"完了を確認できていない登録が "+value.pending+" 件あります。登録候補は非公開です。":value.documents.length?"":"登録済みのPDFはありません。";
 }catch(error){if(active(g)){registry=null;el["registration-list"].replaceChildren();readFailure("registration",error);}}
 finally{registrationBusy=false;updateControls();}
}
const outcome={decrypted:"復号済み",failed:"失敗",requested:"結果未確認"};
function renderLogs(page){
 if(!page||page.retentionDays!==30||!Array.isArray(page.events)||page.events.length>50||!(page.nextCursor===null||typeof page.nextCursor==="string"&&page.nextCursor.length<=2048))throw new Error();
 const rows=[];
 for(const event of page.events){
  if(!UUID.test(event.id)||!Number.isSafeInteger(event.at)||typeof event.subject!=="string"||!event.subject||event.subject.length>256||!Object.hasOwn(outcome,event.outcome)||!Array.isArray(event.notifications)||event.notifications.length>100||event.notifications.some(n=>!n||!["accepted","pending","failed"].includes(n.state)))throw new Error();
  const row=document.createElement("tr");for(const text of [dateLabel(event.at),event.subject==="shared-password"?"本人未確認（共通パスワード）":"Access認証済み",outcome[event.outcome],event.notifications.map(n=>n.state==="accepted"?"送信受付済み":n.state==="failed"?"失敗":"送信待ち").join("・")||"通知なし"]){const cell=document.createElement("td");cell.textContent=text;row.append(cell);}
  const eventId=document.createElement("small");eventId.className="log-event";eventId.textContent="イベントID: "+event.id;row.children[2].append(eventId);rows.push(row);
  if(event.subject!=="shared-password"){const identity=document.createElement("small");identity.className="log-event";identity.textContent="認証ID: "+event.subject;row.children[1].append(identity);}
 }
 el["log-rows"].replaceChildren(...rows);cursor=page.nextCursor;el["logs-status"].textContent=rows.length?"":cursor?"次の記録をご確認ください。":"記録はありません。";
}
async function readLogs(next=false){
 if(logsBusy||!docId||next&&!cursor)return;logsBusy=true;updateControls();const g=epoch;
 try{const page=await api("/v1/documents/"+docId+"/logs",next?"POST":"GET",next?{cursor}:undefined);if(active(g))renderLogs(page);}
 catch(error){if(active(g)){cursor=null;el["log-rows"].replaceChildren();readFailure("logs",error);}}
 finally{logsBusy=false;updateControls();}
}
el["contacts-form"].addEventListener("submit",async event=>{
 event.preventDefault();if(contactsBusy||!contacts||!docId)return;const emails=el["contact-emails"].value.split(/\\r?\\n/).map(x=>x.trim()).filter(Boolean);
 if(emails.length>50){el["contacts-status"].textContent="メールアドレスは50件までです。";return;}
 contactsBusy=true;updateControls();const g=epoch;
 try{const result=checkedContacts(await api("/v1/documents/"+docId+"/recipients","POST",{emails,expectedRevision:contacts.revision}));if(!active(g))return;contacts=result;el["contact-emails"].value=result.emails.join("\\n");el["contacts-status"].textContent="開示先メールを保存しました。";}
 catch(error){if(active(g)){contacts=null;el["contacts-status"].textContent=error.status===400?"メールアドレスを確認してください。":error.status===409?"設定が変更されています。再読み込みして確認してください。":"保存結果を確認できません。再読み込みして確認してください。";}}
 finally{contactsBusy=false;updateControls();}
});
el["registration-form"].addEventListener("submit",async event=>{
 event.preventDefault();if(registrationBusy||unknownId||!registry||!docId||registry.documents.length+registry.pending>=20)return;
 const file=el["registration-file"].files[0],expiresAt=parseDate(el["registration-expiry"].value);
 if(!file||file.size<5||file.size>MAX_PDF||!file.name.toLowerCase().endsWith(".pdf")||file.name.length>120||/[\\x00-\\x1f\\x7f]/.test(file.name)||!Number.isSafeInteger(expiresAt)||expiresAt<=Date.now()){el["registration-status"].textContent="PDFと閲覧期限を確認してください。";return;}
 registrationBusy=true;updateControls();const g=epoch;let bytes=null,id=null,submitted=false,pdfBase64="";
 try{
  bytes=new Uint8Array(await file.arrayBuffer());if(!active(g))return;if(bytes.length!==file.size||new TextDecoder().decode(bytes.subarray(0,5))!=="%PDF-"){el["registration-status"].textContent="PDFファイルを選択してください。";return;}
  for(let at=0;at<bytes.length;at+=8192)pdfBase64+=String.fromCharCode(...bytes.subarray(at,at+8192));pdfBase64=btoa(pdfBase64);
  id=crypto.randomUUID();submitted=true;unknownId=id;el["registration-status"].textContent="PDFを登録しています…";
  await api("/v1/registrations","POST",{id,pdfBase64,fileName:file.name,expiresAt,replaceOf:el["registration-replace"].checked?docId:null,expectedRevision:registry.revision});
  if(!active(g))return;registry=null;el["registration-file"].value="";unknownId=id;
 }catch(error){if(active(g)){
  if(submitted&&![400,401,403,409,429].includes(error.status)){unknownId=id;el["registration-status"].textContent="登録結果を確認できません。登録済みのPDFを確認してください。";}
  else{unknownId=null;registry=null;el["registration-status"].textContent=error.status===400?"PDFと閲覧期限を確認してください。":error.status===409?"登録情報が変更されています。再読み込みして確認してください。":"登録できませんでした。再読み込みして確認してください。";}
 }}finally{bytes?.fill(0);pdfBase64="";registrationBusy=false;updateControls();}
 if(active(g)&&unknownId===id)void readRegistry();
});
el["contacts-panel"].addEventListener("toggle",()=>{if(el["contacts-panel"].open&&!contacts)void readContacts();});
el["logs-panel"].addEventListener("toggle",()=>{if(el["logs-panel"].open)void readLogs();});
el["registration-panel"].addEventListener("toggle",()=>{if(el["registration-panel"].open&&!registry)void readRegistry();});
el["contacts-reload"].addEventListener("click",()=>void readContacts());el["registration-reload"].addEventListener("click",()=>void readRegistry());el["logs-reload"].addEventListener("click",()=>void readLogs());el["logs-next"].addEventListener("click",()=>void readLogs(true));
async function bootstrap(){const g=epoch;try{const value=await api("/v1/management");if(!active(g))return;if(!UUID.test(value?.documentId||""))throw new Error();docId=value.documentId;el["registration-expiry"].min=dateInput(Math.ceil((Date.now()+1)/60000)*60000);if(el["registration-panel"].open)void readRegistry();if(el["contacts-panel"].open)void readContacts();if(el["logs-panel"].open)void readLogs();}catch(error){if(active(g))for(const section of ["registration","contacts","logs"])readFailure(section,error);}updateControls();}
addEventListener("pagehide",()=>{visible=false;epoch++;for(const c of controllers)c.abort();controllers.clear();contacts=null;registry=null;docId=null;cursor=null;el["contact-emails"].value="";el["registration-file"].value="";el["registration-list"].replaceChildren();el["log-rows"].replaceChildren();updateControls();});
addEventListener("pageshow",event=>{if(event.persisted){visible=true;void bootstrap();}});
updateControls();void bootstrap();
`;
