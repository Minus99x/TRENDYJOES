import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {createLocalMultiReviewRecovery,createReviewChecklist} from '../src/preview-multidesign-resume.mjs';
import {createLocalRecoveryConfirmation} from '../src/preview-multidesign-confirmation.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const now=1700000000000;
const entry=i=>({reference:`TJ-${i.toString(16).toUpperCase().padStart(24,'0')}`,revision:1,
 ownerToken:i.toString(16).padStart(64,'0'),productManifestId:'crew-shirt',productLabel:'Crew shirt',
 productGid:'gid://shopify/Product/123',variantGid:'gid://shopify/ProductVariant/456'});
const blockers=['CURRENT_CATALOG','ACTIVE_PURCHASABLE_VARIANT','AUTHORITATIVE_PRICE','CUSTOMER_AUTHENTICATION',
 'PRIVATE_ARTWORK_STORAGE','MANUFACTURING_APPROVAL','CHECKOUT_ORDER_RECONCILIATION'];
const readiness=x=>({schema:'TJ-CUSTOMER-CART-READINESS-1',scope:'OFFLINE_PREVIEW_ONLY',
 reference:x.reference,revision:x.expectedRevision,productGid:x.productGid,variantGid:x.variantGid,
 compositionSha256:'a'.repeat(64),previewValid:true,localOwnerChecked:true,
 shopifyCustomerAuthenticated:false,catalogCurrent:false,priceApproved:false,productionReady:false,
 checkoutEnabled:false,cartLine:null,cartMutation:null,checkoutUrl:null,shopifyOrderId:null,
 blockers:[...blockers],checks:['LOCAL_DESIGN_OWNER','LOCAL_PRODUCT_VARIANT',...blockers].map((id,i)=>({id,
 status:i===0?'LOCAL_ONLY':i===1?'SNAPSHOT_ONLY':'BLOCKED',reason:'Local prototype only'}))});
function fixture(readReadiness=async x=>readiness(x)){
 const items=[entry(1),entry(2)].map(({ownerToken,...e})=>({...e,selected:true}));
 const recovery=createLocalMultiReviewRecovery({readReadiness,clock:()=>now+1});
 recovery.importChecklist(createReviewChecklist(items,{now}));
 const consent=createLocalRecoveryConfirmation({recovery});consent.reset();
 const accepted=[];const accept=(e)=>accepted.push(e.reference);
 return {recovery,consent,accepted,accept};
}
const deferred=()=>{let release;const promise=new Promise(r=>release=r);return {promise,release};};
const reject=(fn,code)=>assert.rejects(fn,{code});

test('35N cancel during first readiness explicitly marks in-flight cancellation without consuming receipt',async()=>{
 const gate=deferred(),entered=deferred();let calls=0;
 const {consent,recovery,accepted,accept}=fixture(async x=>{calls++;entered.release();await gate.promise;return readiness(x);});
 consent.stage(entry(1));const op=consent.confirm(accept);await entered.promise;
 assert.equal(consent.status().busy,true);assert.equal(consent.status().cancelled,false);
 const cancelled=consent.cancel();assert.equal(cancelled.busy,true);assert.equal(cancelled.cancelled,true);
 assert.equal(cancelled.staged,null);assert.equal(cancelled.checkoutEnabled,false);
 gate.release();await reject(op,'REVIEW_CONFIRM_CANCELLED');
 assert.equal(calls,1);assert.equal(accepted.length,0);assert.equal(recovery.list().length,2);
 assert.equal(consent.status().busy,false);assert.equal(consent.status().cancelled,false);
});
test('35N cancel during second readiness denies callback after both checks',async()=>{
 const gate=deferred(),entered=deferred();let calls=0;
 const {consent,recovery,accepted,accept}=fixture(async x=>{
  calls++;if(calls===2){entered.release();await gate.promise;}return readiness(x);
 });
 consent.stage(entry(1));const op=consent.confirm(accept);await entered.promise;
 consent.cancel();gate.release();await reject(op,'REVIEW_CONFIRM_CANCELLED');
 assert.equal(calls,2);assert.deepEqual(accepted,[]);assert.equal(recovery.list().length,2);
});
test('35N reset while readiness is pending cancels and resets progress',async()=>{
 const gate=deferred(),entered=deferred();const {consent,accepted,accept}=fixture(async x=>{
  entered.release();await gate.promise;return readiness(x);
 });
 consent.stage(entry(1));const op=consent.confirm(accept);await entered.promise;
 const state=consent.reset();assert.equal(state.cancelled,true);
 assert.deepEqual([state.total,state.pending,state.completed],[2,2,0]);
 gate.release();await reject(op,'REVIEW_CONFIRM_CANCELLED');assert.deepEqual(accepted,[]);
});
test('35N new staged grant cannot enter while cancelled readiness is unresolved',async()=>{
 const gate=deferred(),entered=deferred();const {consent,accept}=fixture(async x=>{
  entered.release();await gate.promise;return readiness(x);
 });
 consent.stage(entry(1));const op=consent.confirm(accept);await entered.promise;
 consent.cancel();assert.throws(()=>consent.stage(entry(2)),{code:'REVIEW_CONFIRM_BUSY'});
 gate.release();await assert.rejects(op);
 assert.equal(consent.stage(entry(2)).staged.reference,entry(2).reference);
});
test('35N cancellation remains idempotent during pending asynchronous readiness',async()=>{
 const gate=deferred(),entered=deferred();const {consent,accept}=fixture(async x=>{
  entered.release();await gate.promise;return readiness(x);
 });
 consent.stage(entry(1));const op=consent.confirm(accept);await entered.promise;
 consent.cancel();const second=consent.cancel();assert.equal(second.cancelled,true);
 gate.release();await assert.rejects(op);assert.equal(consent.status().cancelled,false);
});
test('35N ordinary staged cancellation does not report an in-flight cancellation',()=>{
 const {consent}=fixture();consent.stage(entry(1));const result=consent.cancel();
 assert.equal(result.busy,false);assert.equal(result.cancelled,false);assert.equal(result.staged,null);
});
test('35N completed confirmation remains possible after cancelled request settles',async()=>{
 const gate=deferred(),entered=deferred();let calls=0;
 const {consent,accepted,accept}=fixture(async x=>{
  if(++calls===1){entered.release();await gate.promise;}return readiness(x);
 });
 consent.stage(entry(1));const op=consent.confirm(accept);await entered.promise;
 consent.cancel();gate.release();await assert.rejects(op);
 consent.stage(entry(1));const result=await consent.confirm(accept);
 assert.equal(result.completed,1);assert.equal(result.pending,1);assert.deepEqual(accepted,[entry(1).reference]);
});
test('35N private capability remains absent from cancelled public status',async()=>{
 const gate=deferred(),entered=deferred();const {consent,accept}=fixture(async x=>{
  entered.release();await gate.promise;return readiness(x);
 });
 consent.stage(entry(1));const op=consent.confirm(accept);await entered.promise;
 const state=consent.cancel();assert.doesNotMatch(JSON.stringify(state),/ownerToken|0000000000000000000000000000000000000000000000000000000000000001/);
 gate.release();await assert.rejects(op);
});
test('35N editor exposes cancellation during busy state and preserves keyboard focus',async()=>{
 const js=await readFile(resolve(root,'demo/studio.mjs'),'utf8');
 assert.match(js,/\('multi-cancel'\)\.disabled=\(!progress\.staged&&!progress\.busy\)\|\|progress\.cancelled/);
 assert.match(js,/const operation=recoveryConfirmation\.confirm/);
 assert.match(js,/if\(!\$\('multi-cancel'\)\.disabled\)\$\('multi-cancel'\)\.focus/);
 assert.match(js,/privateReceiptOpenEpoch\+\+;\s*recoveryConfirmation\.cancel\(\)/);
 assert.match(js,/Cancellation requested\. Waiting for the private readiness check/);
});
test('35N stale confirmation success or refusal cannot overwrite later cancellation',async()=>{
 const js=await readFile(resolve(root,'demo/studio.mjs'),'utf8');
 assert.match(js,/const confirming=privateReceiptOpenEpoch/);
 assert.match(js,/if\(confirming!==privateReceiptOpenEpoch\)return/);
 assert.match(js,/if\(confirming===privateReceiptOpenEpoch\)\$\('multi-status'\)\.textContent='Confirmation refused/);
 assert.match(js,/if\(confirming===privateReceiptOpenEpoch\)\$\('multi-status'\)\.focus/);
});
test('35N stale private receipt or checklist import failure cannot overwrite newer result',async()=>{
 const js=await readFile(resolve(root,'demo/studio.mjs'),'utf8');
 assert.match(js,/if\(importing===privateReceiptOpenEpoch\)\$\('multi-status'\)\.textContent='Checklist refused/);
 assert.match(js,/if\(importing===privateReceiptOpenEpoch\)renderMultiReview\(\)/);
 assert.match(js,/if\(opening===privateReceiptOpenEpoch\)\$\('status'\)\.textContent='Could not reopen private draft/);
});
test('35N cancellation module cannot persist grants or invoke commerce APIs',async()=>{
 const code=await readFile(resolve(root,'src/preview-multidesign-confirmation.mjs'),'utf8');
 assert.doesNotMatch(code,/fetch\(|https?:\/\/|localStorage|sessionStorage|\/cart\/add|checkout\.json|writeFile/);
});
