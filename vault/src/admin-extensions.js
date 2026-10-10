export const html = `<section class="viewer-card owner-tools" aria-label="文書の登録と共有先"><details id="registration-panel"><summary>PDFの登録・差し替え</summary><p class="form-help">登録したPDFは非公開です。共有中のPDFは変更されません。</p><form id="registration-form"><label for="registration-file">PDF</label><input id="registration-file" type="file" accept="application/pdf,.pdf" required><label for="recipient-type">開示先</label><select id="recipient-type"><option value="organization">会社・組織</option><option value="person">個人</option></select><div id="organization-field"><label for="recipient-organization">会社・組織名</label><input id="recipient-organization" type="text" maxlength="180" autocomplete="off" required></div><label id="person-label" for="recipient-person">担当者名（任意）</label><input id="recipient-person" type="text" maxlength="180" autocomplete="off"><label class="check-label"><input id="registration-watermark" type="checkbox" checked>各ページに開示先の透かしを入れる</label><label for="registration-expiry">閲覧期限</label><input id="registration-expiry" type="datetime-local" step="60" required aria-describedby="registration-time"><p id="registration-time" class="form-help">日本時間で指定してください。PDFは1 MBまでです。</p><label class="check-label"><input id="registration-replace" type="checkbox">共有中のPDFの差し替え候補にする</label><button id="prepare-pdf" type="submit" class="primary" disabled>PDFを確認</button></form><section id="registration-review" hidden aria-label="登録するPDFの確認"><p id="registration-summary"></p><div id="registration-preview" class="registration-preview"></div><button id="register-pdf" type="button" class="primary" disabled>非公開で登録</button></section><p id="registration-status" role="status" aria-live="polite"></p><button id="registration-reload" type="button" class="quiet">登録済みのPDFを確認</button><ul id="registration-list" class="owner-list"></ul><section id="replacement-review" hidden aria-label="差し替え内容の確認"><h3>差し替え内容の確認</h3><p id="replacement-summary"></p><p class="form-help">共有中のPDFは変更されません。</p><div class="actions"><button id="replacement-prepare" type="button" disabled>差し替え候補を準備</button><button id="replacement-reload" type="button" class="quiet" hidden>準備状況を確認</button><button id="replacement-save" type="button" hidden>確認情報を保存</button></div><p id="replacement-status" role="status" aria-live="polite"></p></section></details><details id="contacts-panel"><summary>開示先メール</summary><form id="contacts-form"><label for="contact-emails">メールアドレス（1行に1件）</label><textarea id="contact-emails" rows="4" autocomplete="off" spellcheck="false" maxlength="12750" disabled></textarea><p class="form-help">共通パスワードでの閲覧者本人を確認するものではありません。</p><button id="save-contacts" type="submit" disabled>保存</button></form><p id="contacts-status" role="status" aria-live="polite"></p><button id="contacts-reload" type="button" class="quiet">再読み込み</button></details><details id="logs-panel"><summary>閲覧ログ</summary><p class="form-help">直近30日分。共通パスワードの閲覧者は本人未確認として表示します。</p><p id="logs-status" role="status" aria-live="polite"></p><div class="log-scroll"><table class="log-table"><thead><tr><th scope="col">日時（日本時間）</th><th scope="col">閲覧者</th><th scope="col">結果</th><th scope="col">通知</th></tr></thead><tbody id="log-rows"></tbody></table></div><div class="actions"><button id="logs-reload" type="button" class="quiet">最新の記録</button><button id="logs-next" type="button" hidden>次の記録</button></div></details></section>`;

export const css = `
.owner-tools{margin-top:24px}.owner-tools>details+details{margin-top:20px;padding-top:20px;border-top:1px solid var(--border)}.owner-tools summary{font-weight:700;cursor:pointer}.owner-tools form{display:grid;gap:10px;max-width:620px;margin:20px 0}.owner-tools input,.owner-tools textarea,.owner-tools select{width:100%;box-sizing:border-box}.owner-tools input[type=file]{padding:12px;font-size:14px}.owner-tools input[type=checkbox]{width:18px;height:18px;margin:0;flex:none}.owner-tools select{font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:12px}.registration-preview{margin:16px 0;max-width:760px}.registration-preview canvas{display:block;max-width:100%;height:auto;margin:12px 0;border:1px solid var(--border)}#registration-summary,#replacement-summary{font-size:14px;overflow-wrap:anywhere}.owner-list button{display:block;margin-top:8px}#replacement-review{margin-top:20px;padding-top:16px;border-top:1px solid var(--border)}#replacement-review h3{font-size:16px;margin:0}.check-label{display:flex;align-items:center;gap:10px;font-size:14px}.owner-tools textarea{font:inherit;padding:12px;color:var(--fg);background:var(--bg);border:1px solid var(--border);border-radius:6px;resize:vertical}.owner-tools p[role=status]{font-size:14px;overflow-wrap:anywhere}.owner-list{padding-left:20px;font-size:14px}.owner-list li{margin-top:10px;overflow-wrap:anywhere}.log-scroll{overflow-x:auto;margin:16px 0}.log-table{width:100%;border-collapse:collapse;font-size:13px}.log-table th,.log-table td{padding:12px 8px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top;overflow-wrap:anywhere}.log-table th{font-weight:600}.log-event{display:block;color:var(--muted);font-size:11px;margin-top:4px}.log-table td:first-child{white-space:nowrap}
@media(max-width:540px){.log-table{min-width:620px}}
`;

export const js = `import { prepareRegistration, showRegistrationPreview, clearRegistrationPreview } from "/v1/admin/assets/registration-preview.js";
import { normalizeRecipientName } from "/v1/admin/assets/recipient.js";
"use strict";
const ids=["registration-panel","registration-form","registration-file","registration-expiry","registration-replace","recipient-type","recipient-organization","recipient-person","person-label","organization-field","registration-watermark","prepare-pdf","registration-review","registration-summary","registration-preview","register-pdf","registration-status","registration-reload","registration-list","replacement-review","replacement-summary","replacement-prepare","replacement-reload","replacement-save","replacement-status","contacts-panel","contacts-form","contact-emails","save-contacts","contacts-status","contacts-reload","logs-panel","logs-status","log-rows","logs-reload","logs-next"];
const el=Object.fromEntries(ids.map(id=>[id,document.getElementById(id)]));
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const JAPAN=9*3600000,MAX_PDF=1048576;
let docId=null,contacts=null,registry=null,cursor=null,epoch=0,visible=true;
let registrationBusy=false,contactsBusy=false,logsBusy=false,unknownId=null;
const controllers=new Set(),replacementButtons=new Set(),unknownReplacements=new Set(),downloads=new Set();
let replacement=null,replacementManifest=null,replacementBusy=false,replacementReady=false,replacementOperation=0;
let prepared=null,preparationController=null,preparationVersion=0,registrationOperation=0;
const settingsIds=["registration-file","registration-expiry","registration-replace","recipient-type","recipient-organization","recipient-person","registration-watermark"];
function clearPrepared(){preparationVersion++;preparationController?.abort();preparationController=null;prepared?.bytes.fill(0);prepared=null;clearRegistrationPreview(el["registration-preview"]);el["registration-review"].hidden=true;el["registration-summary"].textContent="";}
function selectedRecipient(){const type=el["recipient-type"].value;if(!["organization","person"].includes(type))throw new Error();const organizationName=type==="organization"?normalizeRecipientName(el["recipient-organization"].value):null;const personName=type==="person"||el["recipient-person"].value.trim()?normalizeRecipientName(el["recipient-person"].value):null;return {recipient:{type,organizationName,personName},name:normalizeRecipientName([organizationName,personName].filter(Boolean).join(" "))};}
function settings(){const file=el["registration-file"].files[0],expiresAt=parseDate(el["registration-expiry"].value);if(!file||file.size<5||file.size>MAX_PDF||!file.name.toLowerCase().endsWith(".pdf")||file.name.length>120||/[\\x00-\\x1f\\x7f]/.test(file.name)||!Number.isSafeInteger(expiresAt)||expiresAt<=Date.now())throw new Error();return {file,expiresAt,replaceOf:el["registration-replace"].checked?docId:null,watermarkEnabled:el["registration-watermark"].checked,...selectedRecipient()};}
function sameSettings(a,b){return a.file===b.file&&a.expiresAt===b.expiresAt&&a.replaceOf===b.replaceOf&&a.watermarkEnabled===b.watermarkEnabled&&a.name===b.name&&JSON.stringify(a.recipient)===JSON.stringify(b.recipient);}
function dateLabel(value){return new Intl.DateTimeFormat("ja-JP",{timeZone:"Asia/Tokyo",year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",hourCycle:"h23"}).format(value);}
function dateInput(value){return new Date(value+JAPAN).toISOString().slice(0,16);}
function parseDate(value){if(!/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}$/.test(value))return NaN;const n=Date.parse(value+":00+09:00");return Number.isSafeInteger(n)&&dateInput(n)===value?n:NaN;}
function active(g){return visible&&g===epoch;}
function updateControls(){
 const blocked=registrationBusy||replacementBusy||unknownId!==null||!registry||!docId||registry.documents.length+registry.pending>=20;
 el["prepare-pdf"].disabled=blocked;el["register-pdf"].disabled=blocked||!prepared;
 for(const id of settingsIds)el[id].disabled=registrationBusy||replacementBusy||unknownId!==null;
 el["organization-field"].hidden=el["recipient-type"].value==="person";el["recipient-organization"].required=!el["organization-field"].hidden;el["recipient-person"].required=el["organization-field"].hidden;el["person-label"].textContent=el["organization-field"].hidden?"氏名":"担当者名（任意）";
 el["registration-reload"].disabled=registrationBusy||replacementBusy;
 for(const button of replacementButtons)button.disabled=registrationBusy||replacementBusy;
 el["replacement-prepare"].disabled=registrationBusy||replacementBusy||!replacement||!replacementReady||replacementManifest!==null||unknownReplacements.has(replacement.id);el["replacement-prepare"].hidden=replacementManifest!==null;
 el["replacement-reload"].disabled=registrationBusy||replacementBusy;el["replacement-reload"].hidden=!replacement;
 el["replacement-save"].disabled=replacementBusy||!replacementManifest;el["replacement-save"].hidden=!replacementManifest;
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
 finally{if(active(g)){contactsBusy=false;updateControls();}}
}
function checkedRegistry(value){
 if(!value||!Number.isSafeInteger(value.revision)||value.revision<0||!Number.isSafeInteger(value.pending)||value.pending<0||!Array.isArray(value.documents)||value.documents.length+value.pending>20)throw new Error();
 for(const d of value.documents){
  if(!UUID.test(d.id)||d.status!=="private"||typeof d.fileName!=="string"||d.fileName.length>120||!Number.isSafeInteger(d.size)||d.size<5||d.size>MAX_PDF||!Number.isSafeInteger(d.createdAt)||!Number.isSafeInteger(d.expiresAt)||!(d.replaceOf===null||UUID.test(d.replaceOf)&&d.replaceOf!==d.id))throw new Error();
  const fields=["recipient","watermarkEnabled","sourceSha256","preparedSha256","preparationVersion"];
  if(fields.some(key=>Object.hasOwn(d,key))){
   if(!fields.every(key=>Object.hasOwn(d,key))||d.preparationVersion!==1||typeof d.watermarkEnabled!=="boolean"||! /^[0-9a-f]{64}$/.test(d.sourceSha256)||! /^[0-9a-f]{64}$/.test(d.preparedSha256)||!d.recipient||!["organization","person"].includes(d.recipient.type))throw new Error();
   const r=d.recipient;if(r.type==="organization"&&r.organizationName===null||r.type==="person"&&(r.organizationName!==null||r.personName===null))throw new Error();
   for(const key of ["organizationName","personName"])if(r[key]!==null&&normalizeRecipientName(r[key])!==r[key])throw new Error();
   normalizeRecipientName([r.organizationName,r.personName].filter(Boolean).join(" "));
  }
 }

 return value;
}
function renderRegistry(){
 const list=el["registration-list"];list.replaceChildren();replacementButtons.clear();
 for(const d of registry.documents){const item=document.createElement("li");item.textContent=d.fileName+" — "+(d.id===docId?"共有中":"非公開")+(d.replaceOf&&d.id!==docId?"・差し替え候補":"")+" ／ "+(d.recipient?[d.recipient.organizationName,d.recipient.personName].filter(Boolean).join(" ")+"・透かし"+(d.watermarkEnabled?"あり":"なし")+" ／ ":"")+"閲覧期限 "+dateLabel(d.expiresAt);if(d.replaceOf===docId&&d.id!==docId){const button=document.createElement("button");button.type="button";button.className="quiet";button.textContent="差し替え内容を確認";button.addEventListener("click",()=>void readReplacement(d));replacementButtons.add(button);item.append(button);}list.append(item);}
}
async function readRegistry(){
 if(registrationBusy||replacementBusy||!docId)return;clearReplacement();registrationBusy=true;updateControls();const g=epoch,operation=++registrationOperation;
 try{const value=checkedRegistry(await api("/v1/registrations"));if(!active(g))return;registry=value;renderRegistry();
  if(unknownId){const found=value.documents.some(d=>d.id===unknownId);el["registration-status"].textContent=found?"登録済みであることを確認しました。PDFは非公開です。":"登録は確認できませんでした。処理中の可能性があります。管理ページを開き直して再確認してください。";if(found){unknownId=null;el["registration-file"].value="";}}
  else el["registration-status"].textContent=value.documents.length+value.pending>=20?"登録上限の20件に達しています。":value.pending?"完了を確認できていない登録が "+value.pending+" 件あります。登録候補は非公開です。":value.documents.length?"":"登録済みのPDFはありません。";
 }catch(error){if(active(g)){registry=null;el["registration-list"].replaceChildren();readFailure("registration",error);}}
 finally{if(active(g)&&operation===registrationOperation){registrationBusy=false;updateControls();}}
}
function clearReplacement(){replacementOperation++;replacement=null;replacementManifest=null;replacementReady=false;el["replacement-review"].hidden=true;el["replacement-summary"].textContent="";el["replacement-status"].textContent="";}
function replacementSummary(d){return "開示先："+(d.recipient?[d.recipient.organizationName,d.recipient.personName].filter(Boolean).join(" "):"未登録")+" ／ 透かし："+(typeof d.watermarkEnabled==="boolean"?(d.watermarkEnabled?"あり":"なし"):"未確認")+" ／ 閲覧期限："+dateLabel(d.expiresAt);}
function checkedReplacement(value,d){
 if(!value||Object.keys(value).length!==1||!Object.hasOwn(value,"replacement"))throw new Error();
 if(value.replacement===null)return null;
 const m=value.replacement,keys=["version","status","id","currentDocumentId","currentRecordSha256","recordSha256","preparedSha256","sourceSha256","recipient","recipientName","watermarkEnabled","expiresAt","authMode","registryRevision","createdAt"];
 if(!m||Object.keys(m).length!==keys.length||!keys.every(key=>Object.hasOwn(m,key))||m.version!==1||m.status!=="prepared_not_active"||m.id!==d.id||m.currentDocumentId!==docId||!UUID.test(m.id)||!UUID.test(m.currentDocumentId)||m.id===m.currentDocumentId||!["password","access"].includes(m.authMode)||!Number.isSafeInteger(m.registryRevision)||m.registryRevision<0||!Number.isSafeInteger(m.createdAt)||m.createdAt<=0||!Number.isSafeInteger(m.expiresAt)||m.expiresAt!==d.expiresAt||typeof m.watermarkEnabled!=="boolean")throw new Error();
 for(const key of ["currentRecordSha256","recordSha256","preparedSha256","sourceSha256"])if(typeof m[key]!=="string"||! /^[0-9a-f]{64}$/.test(m[key]))throw new Error();
 const r=m.recipient;if(!r||Object.keys(r).length!==3||!["organization","person"].includes(r.type)||r.type==="organization"&&r.organizationName===null||r.type==="person"&&(r.organizationName!==null||r.personName===null))throw new Error();
 for(const key of ["organizationName","personName"])if(r[key]!==null&&normalizeRecipientName(r[key])!==r[key])throw new Error();
 if(normalizeRecipientName([r.organizationName,r.personName].filter(Boolean).join(" "))!==m.recipientName||!d.recipient||["type","organizationName","personName"].some(key=>r[key]!==d.recipient[key])||m.watermarkEnabled!==d.watermarkEnabled||m.sourceSha256!==d.sourceSha256||m.preparedSha256!==d.preparedSha256)throw new Error();
 return m;
}
function displayReplacement(m){replacementManifest=m;replacementReady=true;el["replacement-review"].hidden=false;el["replacement-summary"].textContent=replacementSummary(replacement);el["replacement-status"].textContent=m?"公開前の確認待ち":"内容を確認して、差し替え候補を準備してください。";if(m)unknownReplacements.delete(replacement.id);}
async function readReplacement(d=replacement){
 if(registrationBusy||replacementBusy||!docId||!registry?.documents.includes(d)||d.replaceOf!==docId||d.id===docId)return;
 replacement=d;replacementManifest=null;replacementReady=false;replacementBusy=true;el["replacement-review"].hidden=false;el["replacement-summary"].textContent=replacementSummary(d);el["replacement-status"].textContent="準備状況を確認しています…";updateControls();const g=epoch,operation=++replacementOperation;
 try{const m=checkedReplacement(await api("/v1/registrations/"+d.id+"/replacement"),d);if(!active(g)||operation!==replacementOperation)return;displayReplacement(m);if(!m&&unknownReplacements.has(d.id))el["replacement-status"].textContent="準備結果を確認できません。準備状況を確認してください。";}
 catch(error){if(active(g)&&operation===replacementOperation){replacementManifest=null;replacementReady=false;el["replacement-status"].textContent=error.status===401||error.status===403?"閲覧期限と管理者ログインを確認してください。":error.status===409?"共有中のPDFか登録内容が変更されています。登録済みのPDFを確認してください。":"準備状況を確認できません。再確認してください。";}}
 finally{if(active(g)&&operation===replacementOperation){replacementBusy=false;updateControls();}}
}
el["replacement-prepare"].addEventListener("click",async()=>{
 if(registrationBusy||replacementBusy||!replacement||!replacementReady||replacementManifest||unknownReplacements.has(replacement.id)||!docId||!registry?.documents.includes(replacement)||replacement.replaceOf!==docId||replacement.id===docId)return;
 const d=replacement,g=epoch,operation=++replacementOperation;replacementBusy=true;unknownReplacements.add(d.id);el["replacement-status"].textContent="差し替え候補を準備しています…";updateControls();
 try{const m=checkedReplacement(await api("/v1/registrations/"+d.id+"/replacement","POST",{expectedRevision:registry.revision,currentDocumentId:docId}),d);if(!active(g)||operation!==replacementOperation)return;if(!m)throw new Error();displayReplacement(m);}
 catch(error){if(active(g)&&operation===replacementOperation){replacementManifest=null;replacementReady=false;if([400,401,403,409,429].includes(error.status))unknownReplacements.delete(d.id);el["replacement-status"].textContent=error.status===409?"共有中のPDFか登録内容が変更されています。登録済みのPDFを確認してください。":error.status===401||error.status===403?"閲覧期限と管理者ログインを確認してください。":"準備結果を確認できません。準備状況を確認してください。";}}
 finally{if(active(g)&&operation===replacementOperation){replacementBusy=false;updateControls();}}
});
el["replacement-reload"].addEventListener("click",()=>void readReplacement());
el["replacement-save"].addEventListener("click",()=>{
 if(replacementBusy||!replacementManifest||!visible)return;
 const fields=["version","status","id","currentDocumentId","currentRecordSha256","recordSha256","preparedSha256","sourceSha256","watermarkEnabled","expiresAt","authMode","registryRevision","createdAt"],review=Object.fromEntries(fields.map(key=>[key,replacementManifest[key]]));
 const url=URL.createObjectURL(new Blob([JSON.stringify(review,null,2)+"\\n"],{type:"application/json"}));downloads.add(url);const link=document.createElement("a");link.href=url;link.download="kanariya-replacement-"+replacementManifest.id+".json";document.body.append(link);link.click();link.remove();setTimeout(()=>{URL.revokeObjectURL(url);downloads.delete(url);},1000);
});
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
 finally{if(active(g)){logsBusy=false;updateControls();}}
}
el["contacts-form"].addEventListener("submit",async event=>{
 event.preventDefault();if(contactsBusy||!contacts||!docId)return;const emails=el["contact-emails"].value.split(/\\r?\\n/).map(x=>x.trim()).filter(Boolean);
 if(emails.length>50){el["contacts-status"].textContent="メールアドレスは50件までです。";return;}
 contactsBusy=true;updateControls();const g=epoch;
 try{const result=checkedContacts(await api("/v1/documents/"+docId+"/recipients","POST",{emails,expectedRevision:contacts.revision}));if(!active(g))return;contacts=result;el["contact-emails"].value=result.emails.join("\\n");el["contacts-status"].textContent="開示先メールを保存しました。";}
 catch(error){if(active(g)){contacts=null;el["contacts-status"].textContent=error.status===400?"メールアドレスを確認してください。":error.status===409?"設定が変更されています。再読み込みして確認してください。":"保存結果を確認できません。再読み込みして確認してください。";}}
 finally{if(active(g)){contactsBusy=false;updateControls();}}
});
el["registration-form"].addEventListener("submit",async event=>{
 event.preventDefault();if(registrationBusy||replacementBusy||unknownId||!registry||!docId||registry.documents.length+registry.pending>=20)return;
 clearPrepared();let input;try{input=settings();}catch{el["registration-status"].textContent="PDF・開示先・閲覧期限を確認してください。";return;}
 registrationBusy=true;updateControls();const g=epoch,operation=++registrationOperation,v=preparationVersion,controller=new AbortController();preparationController=controller;let result=null;
 el["registration-status"].textContent="確認用のPDFを準備しています…";
 try{result=await prepareRegistration(input.file,input.name,input.watermarkEnabled,controller.signal);if(!active(g)||v!==preparationVersion||controller.signal.aborted)return;
  if(!sameSettings(input,settings()))throw new Error();
  await showRegistrationPreview(el["registration-preview"],result,controller.signal);if(!active(g)||v!==preparationVersion||controller.signal.aborted)return;
  prepared={...input,...result};result=null;el["registration-summary"].textContent="開示先："+input.name+" ／ 透かし："+(input.watermarkEnabled?"あり":"なし")+" ／ 閲覧期限："+dateLabel(input.expiresAt)+" ／ 非公開";el["registration-review"].hidden=false;
  el["registration-status"].textContent="開示先と全ページを確認して、登録してください。";
 }catch{if(active(g)&&v===preparationVersion){clearPrepared();el["registration-status"].textContent="PDFを準備できませんでした。開示先とPDFを確認してください。";}}
 finally{result?.bytes.fill(0);if(active(g)&&operation===registrationOperation){registrationBusy=false;updateControls();}}
});
for(const id of settingsIds)el[id].addEventListener(id==="registration-file"||id==="recipient-type"||id==="registration-watermark"||id==="registration-replace"?"change":"input",()=>{clearPrepared();updateControls();});
el["register-pdf"].addEventListener("click",async()=>{
 if(registrationBusy||replacementBusy||unknownId||!prepared||!registry||!docId||registry.documents.length+registry.pending>=20)return;
 let input;try{input=settings();if(!sameSettings(input,prepared))throw new Error();}catch{clearPrepared();updateControls();el["registration-status"].textContent="PDF・開示先・閲覧期限を再確認してください。";return;}
 registrationBusy=true;updateControls();const g=epoch,operation=++registrationOperation;let id=null,submitted=false,pdfBase64="";
 try{
  for(let at=0;at<prepared.bytes.length;at+=8192)pdfBase64+=String.fromCharCode(...prepared.bytes.subarray(at,at+8192));pdfBase64=btoa(pdfBase64);
  id=crypto.randomUUID();submitted=true;unknownId=id;el["registration-status"].textContent="PDFを登録しています…";
  await api("/v1/registrations","POST",{id,pdfBase64,fileName:input.file.name,expiresAt:input.expiresAt,replaceOf:input.replaceOf,expectedRevision:registry.revision,recipient:input.recipient,watermarkEnabled:input.watermarkEnabled,sourceSha256:prepared.sourceSha256,preparedSha256:prepared.finalSha256,preparationVersion:1});
  if(!active(g))return;registry=null;el["registration-file"].value="";unknownId=id;clearPrepared();
 }catch(error){if(active(g)){
  if(submitted&&![400,401,403,409,429].includes(error.status)){unknownId=id;clearPrepared();el["registration-status"].textContent="登録結果を確認できません。登録済みのPDFを確認してください。";}
  else{unknownId=null;registry=null;clearPrepared();el["registration-status"].textContent=error.status===400?"PDF・開示先・閲覧期限を確認してください。":error.status===409?"登録情報が変更されています。再読み込みして確認してください。":"登録できませんでした。再読み込みして確認してください。";}
 }}finally{pdfBase64="";if(active(g)&&operation===registrationOperation){registrationBusy=false;updateControls();}}
 if(active(g)&&unknownId===id)void readRegistry();
});
el["contacts-panel"].addEventListener("toggle",()=>{if(el["contacts-panel"].open&&!contacts)void readContacts();});
el["logs-panel"].addEventListener("toggle",()=>{if(el["logs-panel"].open)void readLogs();});
el["registration-panel"].addEventListener("toggle",()=>{if(el["registration-panel"].open&&!registry)void readRegistry();});
el["contacts-reload"].addEventListener("click",()=>void readContacts());el["registration-reload"].addEventListener("click",()=>void readRegistry());el["logs-reload"].addEventListener("click",()=>void readLogs());el["logs-next"].addEventListener("click",()=>void readLogs(true));
async function bootstrap(){const g=epoch;try{const value=await api("/v1/management");if(!active(g))return;if(!UUID.test(value?.documentId||""))throw new Error();docId=value.documentId;el["registration-expiry"].min=dateInput(Math.ceil((Date.now()+1)/60000)*60000);if(el["registration-panel"].open)void readRegistry();if(el["contacts-panel"].open)void readContacts();if(el["logs-panel"].open)void readLogs();}catch(error){if(active(g))for(const section of ["registration","contacts","logs"])readFailure(section,error);}updateControls();}
addEventListener("pagehide",()=>{visible=false;epoch++;clearPrepared();clearReplacement();for(const url of downloads)URL.revokeObjectURL(url);downloads.clear();replacementBusy=false;replacementOperation++;registrationOperation++;registrationBusy=false;contactsBusy=false;logsBusy=false;for(const c of controllers)c.abort();controllers.clear();contacts=null;registry=null;docId=null;cursor=null;el["contact-emails"].value="";el["registration-file"].value="";el["recipient-organization"].value="";el["recipient-person"].value="";el["registration-list"].replaceChildren();el["log-rows"].replaceChildren();updateControls();});
addEventListener("pageshow",event=>{if(event.persisted){visible=true;void bootstrap();}});
updateControls();void bootstrap();
`;
