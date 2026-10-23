import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createLocalMultiReviewTransition} from '../src/preview-multidesign-ui-transition.mjs';
import {createLocalMultiDesignReview} from '../src/preview-multidesign-review.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
const entry=i=>({reference:'TJ-'+i.toString(16).toUpperCase().padStart(24,'0'),revision:1,
 ownerToken:i.toString(16).padStart(64,'0'),productManifestId:'crew-shirt',productLabel:'Crew shirt',
 productGid:'gid://shopify/Product/123',variantGid:'gid://shopify/ProductVariant/456'});
const blockers=['CURRENT_CATALOG','ACTIVE_PURCHASABLE_VARIANT','AUTHORITATIVE_PRICE','CUSTOMER_AUTHENTICATION','PRIVATE_ARTWORK_STORAGE','MANUFACTURING_APPROVAL','CHECKOUT_ORDER_RECONCILIATION'];
const readiness=x=>({schema:'TJ-CUSTOMER-CART-READINESS-1',scope:'OFFLINE_PREVIEW_ONLY',reference:x.reference,revision:x.expectedRevision,
 productGid:x.productGid,variantGid:x.variantGid,compositionSha256:'a'.repeat(64),previewValid:true,localOwnerChecked:true,
 shopifyCustomerAuthenticated:false,catalogCurrent:false,priceApproved:false,productionReady:false,checkoutEnabled:false,
 cartLine:null,cartMutation:null,checkoutUrl:null,shopifyOrderId:null,blockers:[...blockers],
 checks:['LOCAL_DESIGN_OWNER','LOCAL_PRODUCT_VARIANT',...blockers].map((id,i)=>({id,status:i===0?'LOCAL_ONLY':i===1?'SNAPSHOT_ONLY':'BLOCKED',reason:'Local only'}))});
const fixture=(readReadiness=async x=>readiness(x))=>{
 const review=createLocalMultiDesignReview({readReadiness});review.add(entry(1));review.add(entry(2));
 return {review,transition:createLocalMultiReviewTransition({review})};
};
test('35P single-flight review refuses duplicate UI invocation',async()=>{
 const gate=deferred(),entered=deferred();const {transition}=fixture(async x=>{entered.resolve();await gate.promise;return readiness(x);});
 const op=transition.start();await entered.promise;
 assert.equal(transition.status().busy,true);assert.throws(()=>transition.start(),{code:'MULTI_PREVIEW_UI_BUSY'});
 gate.resolve();const result=await op.promise;assert.equal(result.lineCount,2);assert.equal(transition.status().busy,false);
});
test('35P selection change during readiness rejects stale result without presentation rights',async()=>{
 const gate=deferred(),entered=deferred();const {review,transition}=fixture(async x=>{entered.resolve();await gate.promise;return readiness(x);});
 const op=transition.start();await entered.promise;review.select(entry(1).reference,false);transition.invalidate();
 assert.equal(transition.current(op.ticket),false);gate.resolve();
 await assert.rejects(op.promise,{code:'MULTI_PREVIEW_UI_STALE'});assert.equal(transition.status().busy,false);
});
test('35P clear during readiness cannot show stale failure',async()=>{
 const gate=deferred(),entered=deferred();const {review,transition}=fixture(async x=>{entered.resolve();await gate.promise;throw Error('READINESS_DOWN');});
 const op=transition.start();await entered.promise;transition.invalidate();review.clear();gate.resolve();
 await assert.rejects(op.promise,{code:'MULTI_PREVIEW_UI_STALE'});assert.equal(review.list().length,0);
});
test('35P superseding review can finish before older pending readiness',async()=>{
 const gate=deferred(),entered=deferred();let calls=0;
 const {transition}=fixture(async x=>{if(++calls===1){entered.resolve();await gate.promise;}return readiness(x);});
 const old=transition.start();await entered.promise;transition.invalidate();
 const newer=transition.start();const newerResult=await newer.promise;
 assert.equal(newerResult.lineCount,2);assert.equal(transition.current(newer.ticket),true);
 gate.resolve();await assert.rejects(old.promise,{code:'MULTI_PREVIEW_UI_STALE'});
 assert.equal(transition.current(newer.ticket),true);assert.equal(transition.status().busy,false);
});
test('35P latest failed review releases busy gate for a valid retry',async()=>{
 let calls=0;const {transition}=fixture(async x=>{if(++calls===1)throw Error('OFFLINE_READINESS_FAILURE');return readiness(x);});
 const first=transition.start();await assert.rejects(first.promise,{code:'MULTI_PREVIEW_READINESS_REFUSED'});
 assert.equal(transition.status().busy,false);const retry=transition.start();assert.equal((await retry.promise).lineCount,2);
});
test('35P invalidated UI gate allows a new run while older request remains unresolved',async()=>{
 const gate=deferred(),entered=deferred();let calls=0;
 const {transition}=fixture(async x=>{if(++calls===1){entered.resolve();await gate.promise;}return readiness(x);});
 const first=transition.start();await entered.promise;transition.invalidate();
 assert.equal(transition.status().busy,false);const second=transition.start();assert.equal(transition.status().busy,true);
 gate.resolve();await assert.rejects(first.promise,{code:'MULTI_PREVIEW_UI_STALE'});
 assert.equal((await second.promise).lineCount,2);
});
test('35P transition never exposes local bearer grants or commerce capability',()=>{
 const {transition}=fixture();const state=transition.status();assert.equal(state.checkoutEnabled,false);
 assert.equal(transition.checkoutEnabled,false);assert.equal(transition.localOnly,true);
 assert.doesNotMatch(JSON.stringify(state),/ownerToken|0000000000000000000000000000000000000000000000000000000000000001/);
});
test('35P rejects missing review implementation before any transition',()=>{
 assert.throws(()=>createLocalMultiReviewTransition(),{code:'MULTI_PREVIEW_UI_CONFIGURATION'});
 assert.throws(()=>createLocalMultiReviewTransition({review:{review:1}}),{code:'MULTI_PREVIEW_UI_CONFIGURATION'});
});
test('35P old ticket cannot regain currency after repeated invalidation',()=>{
 const {transition}=fixture();const op=transition.start();transition.invalidate();transition.invalidate();
 assert.equal(transition.current(op.ticket),false);op.promise.catch(()=>{});
});
test('35P browser integration invalidates selection, removal, addition, clearing and recovered insertion',async()=>{
 const js=await readFile(resolve(root,'demo/studio.mjs'),'utf8');
 assert.match(js,/multiReview\.select\(item\.reference,checkbox\.checked\);multiReviewTransition\.invalidate\(\)/);
 assert.match(js,/multiReview\.remove\(item\.reference\);multiReviewTransition\.invalidate\(\)/);
 assert.match(js,/multiReview\.add\([\s\S]*?multiReviewTransition\.invalidate\(\)/);
 assert.match(js,/multiReviewTransition\.invalidate\(\);multiReview\.clear\(\)/);
 assert.match(js,/multiReview\.restore\(entry,selected\);\s*multiReviewTransition\.invalidate\(\)/);
});
test('35P browser completion and refusal are both guarded against stale UI writes',async()=>{
 const js=await readFile(resolve(root,'demo/studio.mjs'),'utf8');
 assert.match(js,/const result=await operation\.promise;\s*if\(!multiReviewTransition\.current\(operation\.ticket\)\)return/);
 assert.match(js,/catch\{\s*if\(!multiReviewTransition\.current\(operation\.ticket\)\)return/);
 assert.match(js,/finally\{\s*if\(multiReviewTransition\.current\(operation\.ticket\)\)/);
 assert.match(js,/multiReviewTransition\.status\(\)\.busy\|\|list\.filter/);
});
test('35P gate implementation has no persistent storage, network or commerce writes',async()=>{
 const js=await readFile(resolve(root,'src/preview-multidesign-ui-transition.mjs'),'utf8');
 assert.doesNotMatch(js,/fetch\(|https?:\/\/|localStorage|sessionStorage|\/cart\/add|checkout\.json|writeFile|ownerToken/);
});
