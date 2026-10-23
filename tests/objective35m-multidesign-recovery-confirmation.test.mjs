import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createLocalMultiDesignReview} from '../src/preview-multidesign-review.mjs';
import {createReviewChecklist,createLocalMultiReviewRecovery} from '../src/preview-multidesign-resume.mjs';
import {createLocalRecoveryConfirmation} from '../src/preview-multidesign-confirmation.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const now=1700000000000;
const entry=(i,revision=1)=>({reference:'TJ-'+i.toString(16).toUpperCase().padStart(24,'0'),revision,
 ownerToken:i.toString(16).padStart(64,'0'),productManifestId:'crew-shirt',productLabel:'Crew shirt',
 productGid:'gid://shopify/Product/123',variantGid:'gid://shopify/ProductVariant/456'});
const blockers=['CURRENT_CATALOG','ACTIVE_PURCHASABLE_VARIANT','AUTHORITATIVE_PRICE',
 'CUSTOMER_AUTHENTICATION','PRIVATE_ARTWORK_STORAGE','MANUFACTURING_APPROVAL','CHECKOUT_ORDER_RECONCILIATION'];
const checks=['LOCAL_DESIGN_OWNER','LOCAL_PRODUCT_VARIANT',...blockers].map((id,i)=>({id,
 status:i===0?'LOCAL_ONLY':i===1?'SNAPSHOT_ONLY':'BLOCKED',reason:'Local prototype only'}));
const readiness=x=>({schema:'TJ-CUSTOMER-CART-READINESS-1',scope:'OFFLINE_PREVIEW_ONLY',
 reference:x.reference,revision:x.expectedRevision,productGid:x.productGid,variantGid:x.variantGid,
 compositionSha256:'a'.repeat(64),previewValid:true,localOwnerChecked:true,
 shopifyCustomerAuthenticated:false,catalogCurrent:false,priceApproved:false,productionReady:false,
 checkoutEnabled:false,cartLine:null,cartMutation:null,checkoutUrl:null,shopifyOrderId:null,
 blockers:[...blockers],checks:checks.map(c=>({...c}))});
function setup(readReadiness=async x=>readiness(x),clock=()=>now+1){
 const review=createLocalMultiDesignReview({readReadiness});review.add(entry(1));review.add(entry(2));
 const checklist=createReviewChecklist(review.checklistEntries(),{now});review.clear();
 const recovery=createLocalMultiReviewRecovery({readReadiness,clock});
 recovery.importChecklist(checklist);
 const consent=createLocalRecoveryConfirmation({recovery});consent.reset();
 const accept=(e,selected)=>{review.add(e);review.select(e.reference,selected);};
 return {review,recovery,consent,accept};
}
const reject=(f,code)=>assert.rejects(f,{code});
test('35M imported checklist never automatically restores review',()=>{
 const {consent,review}=setup();assert.equal(review.list().length,0);
 assert.deepEqual([consent.status().total,consent.status().pending,consent.status().completed],[2,2,0]);
 assert.equal(consent.status().staged,null);
});
test('35M consent is mandatory before even one readiness read',async()=>{
 let calls=0;const {consent,accept}=setup(async x=>{calls++;return readiness(x);});
 await reject(consent.confirm(accept),'REVIEW_CONFIRM_EXPLICIT_CONSENT_REQUIRED');assert.equal(calls,0);
});
test('35M stage does not authorize, call server or alter review',()=>{
 let calls=0;const {consent,review}=setup(async x=>{calls++;return readiness(x);});
 const staged=consent.stage(entry(1));assert.equal(staged.staged.reference,entry(1).reference);
 assert.equal(calls,0);assert.equal(review.list().length,0);assert.equal(staged.checkoutEnabled,false);
});
test('35M confirmation rechecks twice and consumes exactly one pending receipt',async()=>{
 let calls=0;const {consent,accept,review}=setup(async x=>{calls++;return readiness(x);});
 consent.stage(entry(1));const result=await consent.confirm(accept);
 assert.equal(calls,2);assert.deepEqual([result.total,result.completed,result.pending],[2,1,1]);
 assert.equal(result.busy,false);assert.equal(result.checkoutEnabled,false);
 assert.equal(review.list().length,1);assert.equal(review.list()[0].reference,entry(1).reference);
});
test('35M multi-receipt progress only counts confirmed receipts',async()=>{
 const {consent,accept}=setup();consent.stage(entry(1));await consent.confirm(accept);
 consent.stage(entry(2));await consent.confirm(accept);
 assert.deepEqual([consent.status().completed,consent.status().pending],[2,0]);
});
test('35M second confirmation without re-staging fails closed',async()=>{
 const {consent,accept}=setup();consent.stage(entry(1));await consent.confirm(accept);
 await reject(consent.confirm(accept),'REVIEW_CONFIRM_EXPLICIT_CONSENT_REQUIRED');
});
test('35M duplicate replay of consumed reference is rejected at staging',async()=>{
 const {consent,accept}=setup();consent.stage(entry(1));await consent.confirm(accept);
 assert.throws(()=>consent.stage(entry(1)),{code:'REVIEW_CONFIRM_NOT_PENDING'});
});
test('35M cancellation keeps checklist pending but forgets staged owner grant',async()=>{
 const {consent,accept}=setup();consent.stage(entry(1));consent.cancel();
 assert.equal(consent.status().staged,null);assert.equal(consent.status().pending,2);
 await reject(consent.confirm(accept),'REVIEW_CONFIRM_EXPLICIT_CONSENT_REQUIRED');
});
test('35M reset clears staged grants and resets visible progress',async()=>{
 const {consent,recovery,accept}=setup();consent.stage(entry(1));await consent.confirm(accept);
 consent.stage(entry(2));recovery.clear();consent.reset();
 assert.deepEqual([consent.status().total,consent.status().completed,consent.status().pending],[0,0,0]);
 assert.equal(consent.status().staged,null);
});
test('35M rejects stale revision before any network read',()=>{
 const {consent}=setup();assert.throws(()=>consent.stage(entry(1,2)),{code:'REVIEW_CONFIRM_BINDING_CHANGED'});
});
test('35M rejects product and variant substitution before consent',()=>{
 const {consent}=setup();for(const field of ['productManifestId','productLabel','productGid','variantGid']){
  assert.throws(()=>consent.stage({...entry(1),[field]:field==='productLabel'?'Fake':field==='productManifestId'?'hat':'gid://shopify/Product/999'}));
 }
});
test('35M malformed and forged owner grant refused',()=>{
 const {consent}=setup();assert.throws(()=>consent.stage({...entry(1),ownerToken:'bad'}),{code:'REVIEW_CONFIRM_PRIVATE_ENTRY_INVALID'});
});
test('35M syntactically valid wrong owner cannot pass readiness',async()=>{
 const {consent,review,accept}=setup(async x=>{if(x.ownerToken!==entry(1).ownerToken)throw Error('OWNER_REFUSED');return readiness(x);});
 consent.stage({...entry(1),ownerToken:'f'.repeat(64)});
 await reject(consent.confirm(accept),'REVIEW_RECOVERY_READINESS_REFUSED');
 assert.equal(review.list().length,0);assert.equal(consent.status().pending,2);
});
test('35M stale digest on second pass refuses and retains pending',async()=>{
 let calls=0;const {consent,review,accept}=setup(async x=>({...readiness(x),compositionSha256:(++calls>1?'b':'a').repeat(64)}));
 consent.stage(entry(1));await reject(consent.confirm(accept),'REVIEW_RECOVERY_DESIGN_CHANGED');
 assert.equal(review.list().length,0);assert.equal(consent.status().pending,2);
});
test('35M cancellation during asynchronous readiness prevents review mutation',async()=>{
 let release;const gate=new Promise(r=>release=r);let entered;
 const started=new Promise(r=>entered=r);
 const {consent,review,accept}=setup(async x=>{entered();await gate;return readiness(x);});
 consent.stage(entry(1));const operation=consent.confirm(accept);await started;consent.cancel();release();
 await reject(operation,'REVIEW_CONFIRM_CANCELLED');assert.equal(review.list().length,0);
 assert.equal(consent.status().pending,2);
});
test('35M clearing checklist during readiness prevents stale acceptance',async()=>{
 let release;const gate=new Promise(r=>release=r);let entered;
 const started=new Promise(r=>entered=r);
 const {consent,recovery,review,accept}=setup(async x=>{entered();await gate;return readiness(x);});
 consent.stage(entry(1));const operation=consent.confirm(accept);await started;
 recovery.clear();consent.reset();release();
 await assert.rejects(operation);assert.equal(review.list().length,0);
});
test('35M concurrent confirmation rejected while first is pending',async()=>{
 let release;const gate=new Promise(r=>release=r);let entered;
 const started=new Promise(r=>entered=r);
 const {consent,accept}=setup(async x=>{entered();await gate;return readiness(x);});
 consent.stage(entry(1));const operation=consent.confirm(accept);await started;
 await reject(consent.confirm(accept),'REVIEW_CONFIRM_BUSY');release();await operation;
});
test('35M cannot stage another receipt during in-flight confirmation',async()=>{
 let release;const gate=new Promise(r=>release=r);let entered;
 const started=new Promise(r=>entered=r);
 const {consent,accept}=setup(async x=>{entered();await gate;return readiness(x);});
 consent.stage(entry(1));const operation=consent.confirm(accept);await started;
 assert.throws(()=>consent.stage(entry(2)),{code:'REVIEW_CONFIRM_BUSY'});release();await operation;
});
test('35M consumer callback refusal cannot consume pending receipt',async()=>{
 const {consent,recovery}=setup();consent.stage(entry(1));
 await assert.rejects(()=>consent.confirm(()=>{throw Error('EDITOR_CHANGED');}));
 assert.equal(recovery.list().length,2);assert.equal(consent.status().completed,0);
});
test('35M public status and confirmation result never leak owner capability',async()=>{
 const {consent,accept}=setup();const publicStatus=consent.stage(entry(1));
 assert.doesNotMatch(JSON.stringify(publicStatus),/ownerToken|0000000000000000000000000000000000000000000000000000000000000001/);
 const result=await consent.confirm(accept);
 assert.doesNotMatch(JSON.stringify(result),/ownerToken|0000000000000000000000000000000000000000000000000000000000000001/);
});
test('35M no persistence, network or commerce implementation in consent module',async()=>{
 const code=await readFile(resolve(root,'src/preview-multidesign-confirmation.mjs'),'utf8');
 assert.doesNotMatch(code,/fetch\(|https?:\/\/|localStorage|sessionStorage|\/cart\/add|checkout\.json|writeFile/);
});
test('35M actual editor exposes consent, cancel, progress and keyboard focus',async()=>{
 const html=await readFile(resolve(root,'demo/index.html'),'utf8');
 const js=await readFile(resolve(root,'demo/studio.mjs'),'utf8');
 const css=await readFile(resolve(root,'demo/studio.css'),'utf8');
 for(const id of ['multi-confirm','multi-cancel','multi-progress']){
  assert.match(html,new RegExp(`id="${id}"`));assert.match(js,new RegExp(`\\$\\('${id}'\\)`));
 }
 assert.match(html,/id="multi-confirm"[^>]*disabled/);
 assert.match(html,/id="multi-progress"[^>]*aria-live="polite"/);
 assert.match(js,/recoveryConfirmation\.stage/);
 assert.match(js,/recoveryConfirmation\.confirm/);
 const moduleCode=await readFile(resolve(root,'src/preview-multidesign-confirmation.mjs'),'utf8');
 assert.match(moduleCode,/recovery\.resume/); // existing recovery boundary remains the authority
 assert.match(js,/\$\('multi-status'\)\.focus/);
 assert.match(css,/#multi-confirm:disabled/);
 assert.match(html,/disabled class="disabled-checkout"/);
});

import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createLocalServer} from '../src/local-server.mjs';
import {createStagingRegistry} from '../src/shopify-bridge.mjs';
test('35M synthetic loopback owner grant: consent succeeds, forged grant and stale revision refused',async t=>{
 const products=JSON.parse(await readFile(resolve(root,'fixtures/shopify-draft-manufacturing-2026-10-14.json'),'utf8')).products;
 const item=createStagingRegistry(products).entries.find(e=>e.manifest&&e.manifest.surfaces.length);
 const dir=await mkdtemp(join(tmpdir(),'tj-35m-'));
 const server=await createLocalServer({dataDir:dir,shopifySnapshot:products});
 const addr=await server.listen(0),url=`http://127.0.0.1:${addr.port}`;
 t.after(async()=>{await new Promise(r=>server.server.close(r));await rm(dir,{recursive:true,force:true});});
 const post=async(path,body,token)=>{
  const res=await fetch(url+path,{method:'POST',headers:{'Content-Type':'application/json',
   ...(token?{Authorization:`Bearer ${token}`}:{})},body:JSON.stringify(body)});
  return {status:res.status,data:await res.json()};
 };
 const draft={productManifestId:item.manifest.id,layers:[{id:'synthetic-35m',type:'text',
  surfaceId:item.manifest.surfaces[0].id,x:.2,y:.2,width:.4,height:.2,rotationDeg:0,value:'Offline test'}]};
 const created=await post('/api/designs',draft);assert.equal(created.status,201);
 const saved={reference:created.data.reference,revision:created.data.revision,ownerToken:created.data.ownerToken,
  productManifestId:item.manifest.id,productLabel:item.manifest.label,productGid:item.product.id,
  variantGid:item.product.variants[0].id};
 let calls=0;
 const readReadiness=async x=>{calls++;const {ownerToken,...body}=x;
  const r=await post('/api/shopify/cart-readiness',body,ownerToken);
  if(r.status!==200)throw Error('LOCAL_AUTH_REFUSED');return r.data;
 };
 const review=createLocalMultiDesignReview({readReadiness});review.add(saved);
 const checklist=createReviewChecklist(review.checklistEntries(),{now});review.clear();
 const recovery=createLocalMultiReviewRecovery({readReadiness,clock:()=>now+1});recovery.importChecklist(checklist);
 const consent=createLocalRecoveryConfirmation({recovery});consent.reset();
 const accept=(e,s)=>{review.add(e);review.select(e.reference,s);};
 assert.equal(calls,0);consent.stage({...saved,ownerToken:'f'.repeat(64)});
 await reject(consent.confirm(accept),'REVIEW_RECOVERY_READINESS_REFUSED');
 assert.equal(review.list().length,0);
 consent.stage(saved);const result=await consent.confirm(accept);
 assert.equal(result.pending,0);assert.equal(review.list().length,1);
 const changed=await post(`/api/designs/${saved.reference}/revisions`,{
  ...draft,expectedRevision:1,layers:[{...draft.layers[0],value:'New revision'}]},saved.ownerToken);
 assert.equal(changed.status,201);
 review.clear();recovery.importChecklist(checklist);consent.reset();consent.stage(saved);
 await reject(consent.confirm(accept),'REVIEW_RECOVERY_READINESS_REFUSED');
 assert.equal(review.list().length,0);
});
test('35M stale file-open and checklist-import callbacks are guarded before mutation',async()=>{
 const js=await readFile(resolve(root,'demo/studio.mjs'),'utf8');
 assert.match(js,/const opening=\+\+privateReceiptOpenEpoch/);
 assert.match(js,/ensureOpening\(\)/);
 assert.match(js,/const importing=\+\+privateReceiptOpenEpoch/);
 assert.match(js,/importing!==privateReceiptOpenEpoch/);
 assert.match(js,/provisionalUrls\.push\(url\)/);
 assert.match(js,/for\(const url of provisionalUrls\)URL\.revokeObjectURL\(url\)/);
 assert.match(js,/if\(recoveryConfirmation\.status\(\)\.staged\)\$\('multi-confirm'\)\.focus/);
 assert.doesNotMatch(js,/Could not reopen draft: \$\{err\.message\}/);
});
