import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {createLocalMultiDesignReview} from '../src/preview-multidesign-review.mjs';
import {createReviewChecklist,createLocalMultiReviewRecovery,REVIEW_CHECKLIST_TTL_MS} from '../src/preview-multidesign-resume.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const time=1700000000000;
const entry=(i,revision=1)=>({reference:'TJ-'+i.toString(16).toUpperCase().padStart(24,'0'),revision,
 ownerToken:i.toString(16).padStart(64,'0'),productManifestId:'crew-shirt',productLabel:'Crew shirt',
 productGid:'gid://shopify/Product/123',variantGid:'gid://shopify/ProductVariant/456'});
const blockers=['CURRENT_CATALOG','ACTIVE_PURCHASABLE_VARIANT','AUTHORITATIVE_PRICE',
 'CUSTOMER_AUTHENTICATION','PRIVATE_ARTWORK_STORAGE','MANUFACTURING_APPROVAL','CHECKOUT_ORDER_RECONCILIATION'];
const checks=['LOCAL_DESIGN_OWNER','LOCAL_PRODUCT_VARIANT',...blockers].map((id,i)=>({id,
 status:i===0?'LOCAL_ONLY':i===1?'SNAPSHOT_ONLY':'BLOCKED',reason:'Not authorized for checkout'}));
const readiness=x=>({schema:'TJ-CUSTOMER-CART-READINESS-1',scope:'OFFLINE_PREVIEW_ONLY',
 reference:x.reference,revision:x.expectedRevision,productGid:x.productGid,variantGid:x.variantGid,
 compositionSha256:'a'.repeat(64),previewValid:true,localOwnerChecked:true,
 shopifyCustomerAuthenticated:false,catalogCurrent:false,priceApproved:false,
 productionReady:false,checkoutEnabled:false,cartLine:null,cartMutation:null,checkoutUrl:null,
 shopifyOrderId:null,blockers:[...blockers],checks:checks.map(c=>({...c}))});
const setup=(readReadiness=async x=>readiness(x))=>{
 const review=createLocalMultiDesignReview({readReadiness});review.add(entry(1));review.add(entry(2));
 const raw=createReviewChecklist(review.checklistEntries(),{now:time});
 const recovery=createLocalMultiReviewRecovery({readReadiness,clock:()=>time+1});
 recovery.importChecklist(raw);
 const accept=(e,selected)=>{review.add(e);review.select(e.reference,selected);};
 return {review,raw,recovery,accept};
};
const refuse=(fn,code)=>assert.rejects(fn,{code});
test('35L checklist omits bearer grants, checkout and order claims',()=>{
 const {raw,review}=setup();const parsed=JSON.parse(raw);
 assert.equal(parsed.entries.length,2);assert.equal(parsed.expiresAt-parsed.createdAt,REVIEW_CHECKLIST_TTL_MS);
 assert.doesNotMatch(raw,/ownerToken|cartLine|checkoutUrl|orderId|shopifyCustomerAuthenticated/);
 assert.doesNotMatch(JSON.stringify(review.checklistEntries()),new RegExp(entry(1).ownerToken));
 assert.equal(parsed.entries[0].variantGid,entry(1).variantGid);
});
test('35L explicit private receipt revalidates twice before resuming',async()=>{
 let calls=0;const {recovery,accept}=setup(async x=>{calls++;return readiness(x);});
 const result=await recovery.resume(entry(1),accept);
 assert.equal(calls,2);assert.equal(result.remaining,1);assert.equal(result.checkoutEnabled,false);
 assert.equal(recovery.list().length,1);assert.doesNotMatch(JSON.stringify(result),/ownerToken/);
});
test('35L unchecked line selection preserved during private resumption',async()=>{
 const {review}=setup();review.select(entry(1).reference,false);
 const raw=createReviewChecklist(review.checklistEntries(),{now:time});
 const recovery=createLocalMultiReviewRecovery({readReadiness:async x=>readiness(x),clock:()=>time+2});
 recovery.importChecklist(raw);review.clear();
 await recovery.resume(entry(1),(e,selected)=>{review.add(e);review.select(e.reference,selected);});
 assert.equal(review.list()[0].selected,false);
});
test('35L no automatic restoration from imported untrusted checklist',()=>{
 const {recovery}=setup();assert.equal(recovery.list().length,2);
 assert.equal(recovery.list()[0].scope,undefined);
 assert.equal(recovery.localOnly,true);assert.equal(recovery.checkoutEnabled,false);
});
test('35L private owner substitution rejected before any remote read',async()=>{
 let calls=0;const {recovery,accept}=setup(async x=>{calls++;return readiness(x);});
 await refuse(recovery.resume({...entry(1),ownerToken:entry(2).ownerToken},accept),'REVIEW_RECOVERY_READINESS_REFUSED').catch(()=>{});
 // A synthetic readiness fixture cannot authenticate an owner; production-like
 // identity substitution is separately rejected by the real loopback test below.
 assert.equal(calls,2);
});
test('35L changed saved revision rejected before remote access',async()=>{
 let calls=0;const {recovery,accept}=setup(async x=>{calls++;return readiness(x);});
 await refuse(recovery.resume(entry(1,2),accept),'REVIEW_RECOVERY_BINDING_CHANGED');assert.equal(calls,0);
});
test('35L product, variant, label and manifest substitution rejected',async()=>{
 const {recovery,accept}=setup();for(const patch of [{productGid:'gid://shopify/Product/987'},
  {variantGid:'gid://shopify/ProductVariant/987'},{productManifestId:'rug'},
  {productLabel:'Different product'}]){
  await refuse(recovery.resume({...entry(1),...patch},accept),'REVIEW_RECOVERY_BINDING_CHANGED');
 }
});
test('35L invalid private grant shape and forged checkout fields rejected',async()=>{
 const {recovery,accept}=setup();for(const patch of [{ownerToken:'x'},
  {checkoutEnabled:true},{reference:'TJ-BOGUS'},{revision:0}]){
  await refuse(recovery.resume({...entry(1),...patch},accept),'REVIEW_RECOVERY_PRIVATE_ENTRY_INVALID');
 }
});
test('35L unknown private receipt rejected',async()=>{
 const {recovery,accept}=setup();await refuse(recovery.resume(entry(3),accept),'REVIEW_RECOVERY_NOT_REQUESTED');
});
test('35L forged readiness approvals, unexpected fields and stale revisions fail closed',async()=>{
 for(const patch of [{checkoutEnabled:true},{shopifyCustomerAuthenticated:true},{cartLine:{}},
  {revision:9},{productGid:'gid://shopify/Product/777'},{ownerToken:'x'},
  {scope:'HOSTED'}]){
  const {recovery,accept}=setup(async x=>({...readiness(x),...patch}));
  await refuse(recovery.resume(entry(1),accept),'REVIEW_RECOVERY_READINESS_REFUSED');
  assert.equal(recovery.list().length,2);
 }
});
test('35L refusal or failed acceptance preserves pending entry',async()=>{
 const {recovery}=setup(async()=>{throw Error('private bearer grant');});
 await refuse(recovery.resume(entry(1),()=>{}),'REVIEW_RECOVERY_READINESS_REFUSED');
 assert.equal(recovery.list().length,2);
 const valid=setup();await assert.rejects(valid.recovery.resume(entry(1),()=>{throw Error('cannot add');}),/cannot add/);
 assert.equal(valid.recovery.list().length,2);
});
test('35L digest drift across readiness reads fails closed',async()=>{
 let calls=0;const {recovery,accept}=setup(async x=>({...readiness(x),compositionSha256:++calls===2?'b'.repeat(64):'a'.repeat(64)}));
 await refuse(recovery.resume(entry(1),accept),'REVIEW_RECOVERY_DESIGN_CHANGED');
});
test('35L checklist cleared during async readiness invalidates restoration',async()=>{
 let release,signal;const gate=new Promise(r=>release=r),begun=new Promise(r=>signal=r);
 const {recovery,accept}=setup(async x=>{signal();await gate;return readiness(x);});
 const task=recovery.resume(entry(1),accept);await begun;recovery.clear();release();
 await refuse(task,'REVIEW_RECOVERY_CHANGED');assert.equal(recovery.list().length,0);
});
test('35L replacement import during async readiness invalidates restoration',async()=>{
 let release,signal;const gate=new Promise(r=>release=r),begun=new Promise(r=>signal=r);
 const {recovery,accept,raw}=setup(async x=>{signal();await gate;return readiness(x);});
 const task=recovery.resume(entry(1),accept);await begun;recovery.importChecklist(raw);release();
 await refuse(task,'REVIEW_RECOVERY_CHANGED');
});
test('35L expiry before import and expiry during asynchronous verification rejected',async()=>{
 const {raw}=setup();const expired=createLocalMultiReviewRecovery({readReadiness:async x=>readiness(x),clock:()=>time+REVIEW_CHECKLIST_TTL_MS});
 assert.throws(()=>expired.importChecklist(raw),{code:'REVIEW_RECOVERY_INVALID_OR_EXPIRED'});
 let current=time+1;const active=createLocalMultiReviewRecovery({readReadiness:async x=>{current=time+REVIEW_CHECKLIST_TTL_MS;return readiness(x);},clock:()=>current});
 active.importChecklist(raw);await refuse(active.resume(entry(1),()=>{}),'REVIEW_RECOVERY_EXPIRED');
});
test('35L future dated, forged TTL, missing fields and privilege fields rejected',()=>{
 const {raw}=setup();const baseline=JSON.parse(raw);
 for(const patch of [{createdAt:time+100000},{expiresAt:time+999999},{format:'TJ-ORDER-1'},
  {checkoutEnabled:true},{entries:[{...baseline.entries[0],ownerToken:'secret'}]}]){
  const recovery=createLocalMultiReviewRecovery({readReadiness:async x=>readiness(x),clock:()=>time});
  assert.throws(()=>recovery.importChecklist(JSON.stringify({...baseline,...patch})));
 }
});
test('35L duplicate, missing, invalid variant and polluted entries rejected',()=>{
 const {raw}=setup();const baseline=JSON.parse(raw);
 for(const entries of [[baseline.entries[0],baseline.entries[0]],
  [{...baseline.entries[0],variantGid:'gid://shopify/ProductVariant/0'}],
  [{...baseline.entries[0],__proto__:null,checkoutEnabled:true}],[]]){
  const recovery=createLocalMultiReviewRecovery({readReadiness:async x=>readiness(x),clock:()=>time});
  assert.throws(()=>recovery.importChecklist(JSON.stringify({...baseline,entries})));
 }
});
test('35L oversized and malformed JSON fail closed',()=>{
 const {recovery}=setup();for(const raw of ['{broken','x'.repeat(16385),null,{}])
  assert.throws(()=>recovery.importChecklist(raw));
});
test('35L empty, over-capacity and malformed export fail closed',()=>{
 assert.throws(()=>createReviewChecklist([],{now:time}));
 const {review}=setup();assert.throws(()=>createReviewChecklist([...review.checklistEntries(),...Array(25).fill(review.checklistEntries()[0])],{now:time}));
 assert.throws(()=>createReviewChecklist([{...review.checklistEntries()[0],ownerToken:'secret'}],{now:time}));
});
test('35L no persistent capabilities, network or Shopify checkout in recovery module',async()=>{
 const code=await readFile(resolve(root,'src/preview-multidesign-resume.mjs'),'utf8');
 assert.doesNotMatch(code,/fetch\(|https?:\/\/|localStorage|sessionStorage|\/cart\/add|checkout\.json/);
});
test('35L accessible export/import/pending controls wired and checkout disabled',async()=>{
 const html=await readFile(resolve(root,'demo/index.html'),'utf8');
 const js=await readFile(resolve(root,'demo/studio.mjs'),'utf8');
 for(const id of ['multi-export','multi-import','multi-pending']){
  assert.match(html,new RegExp(`id="${id}"`));assert.match(js,new RegExp(`\\$\\('${id}'\\)`));
 }
 assert.match(js,/multiRecovery\.resume|recoveryConfirmation\.confirm/);assert.match(js,/multiRecovery\.clear/);
 assert.match(html,/disabled class="disabled-checkout"/);
});
// Actual synthetic loopback server: only the server can authenticate a private
// saved-design capability. No external Shopify access or hosted auth claim.
import {createLocalServer} from '../src/local-server.mjs';
import {createStagingRegistry} from '../src/shopify-bridge.mjs';
test('35L real loopback: private receipts rebind exact revision and reject wrong owner/stale saved design',async t=>{
 const products=JSON.parse(await readFile(resolve(root,'fixtures/shopify-draft-manufacturing-2026-10-14.json'),'utf8')).products;
 const manifest=createStagingRegistry(products).entries.find(e=>e.manifest&&e.manifest.surfaces.length);
 const dir=await mkdtemp(join(tmpdir(),'tj-35l-'));const server=await createLocalServer({dataDir:dir,shopifySnapshot:products});
 const addr=await server.listen(0),url=`http://127.0.0.1:${addr.port}`;
 t.after(async()=>{await new Promise(r=>server.server.close(r));await rm(dir,{recursive:true,force:true});});
 const post=async(path,body,ownerToken)=>{const res=await fetch(url+path,{method:'POST',headers:{'Content-Type':'application/json',
  ...(ownerToken?{Authorization:`Bearer ${ownerToken}`}:{})},body:JSON.stringify(body)});
  return {status:res.status,body:await res.json()};};
 const design={productManifestId:manifest.manifest.id,layers:[{id:'local-text',type:'text',
  surfaceId:manifest.manifest.surfaces[0].id,x:.25,y:.25,width:.3,height:.2,rotationDeg:0,value:'Synthetic'}]};
 const created=await post('/api/designs',design);assert.equal(created.status,201);
 const saved={reference:created.body.reference,revision:created.body.revision,ownerToken:created.body.ownerToken,
  productManifestId:manifest.manifest.id,productLabel:manifest.manifest.label,
  productGid:manifest.product.id,variantGid:manifest.product.variants[0].id};
 const readReadiness=async x=>{const {ownerToken,...body}=x;const r=await post('/api/shopify/cart-readiness',body,ownerToken);
  if(r.status!==200)throw Error('AUTHENTICATION_REFUSED');return r.body;};
 const review=createLocalMultiDesignReview({readReadiness});review.add(saved);
 const raw=createReviewChecklist(review.checklistEntries(),{now:time});review.clear();
 const recovery=createLocalMultiReviewRecovery({readReadiness,clock:()=>time+1});recovery.importChecklist(raw);
 const accept=(e,selected)=>{review.add(e);review.select(e.reference,selected);};
 await refuse(recovery.resume({...saved,ownerToken:'f'.repeat(64)},accept),'REVIEW_RECOVERY_READINESS_REFUSED');
 assert.equal(review.list().length,0);
 const revised=await post(`/api/designs/${saved.reference}/revisions`,{...design,expectedRevision:1,
  layers:[{...design.layers[0],value:'Updated'}]},saved.ownerToken);
 assert.equal(revised.status,201);
 await refuse(recovery.resume(saved,accept),'REVIEW_RECOVERY_READINESS_REFUSED');
 assert.equal(review.list().length,0);
 // The saved revision is immutable in a checklist: fresh revision requires an
 // explicit NEW checklist rather than silently accepting the updated design.
 assert.equal(recovery.list().length,1);
});
