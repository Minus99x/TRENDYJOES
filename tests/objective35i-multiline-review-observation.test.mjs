import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {randomBytes,createHmac} from 'node:crypto';
import {LocalDesignStore} from '../src/local-store.mjs';
import {createStagingRegistry} from '../src/shopify-bridge.mjs';
import {reviewCustomerCartReadiness} from '../src/customer-cart-readiness.mjs';
import {createOfflineDurableLedger} from '../src/offline-durable-ledger.mjs';
import {createOfflineVersionedMetadataAuthority} from '../src/versioned-cart-metadata.mjs';
import {createOfflineReviewReceiptBoundary} from '../src/offline-review-receipt-boundary.mjs';
import {createOfflineMultiLineage,authenticateSyntheticMultiLineEvent} from '../src/offline-multiline-order.mjs';
import {createOfflineMultiReviewObservation} from '../src/offline-multiline-review-observation.mjs';
const shop='gucgmp-bc.myshopify.com',subject='gid://shopify/Customer/45678';
const sessionId='offline-multireview-session-012345';
const checkoutId='offline-checkout:'+'W'.repeat(24),orderGid='gid://shopify/Order/654321';
const now=Date.now();
const denied=(p,code)=>assert.rejects(p,e=>e?.code===code);
async function setup(t,{count=2}={}){
 const dir=await mkdtemp(join(tmpdir(),'tj-35i-'));t.after(()=>rm(dir,{recursive:true,force:true}));
 const fixture=JSON.parse(await readFile(new URL('../fixtures/shopify-draft-manufacturing-2026-10-14.json',import.meta.url),'utf8')).products;
 const registry=createStagingRegistry(fixture);
 const store=new LocalDesignStore(join(dir,'designs'),{manifests:Object.fromEntries(registry.entries.filter(e=>e.manifest).map(e=>[e.manifest.id,e.manifest]))});await store.init();
 const entries=registry.entries.filter(e=>e.manifest).slice(0,count);
 const ledger=createOfflineDurableLedger({directory:join(dir,'ledger')});
 const requests=[],drafts=[],bindings=[];
 for(let i=0;i<count;i++){
  const entry=entries[i];
  const draft={productManifestId:entry.manifest.id,layers:[{id:'custom-label',type:'text',surfaceId:entry.manifest.surfaces[0].id,
   x:.2,y:.2,width:.4,height:.2,rotationDeg:0,value:'CUSTOM '+i}]};
  const saved=await store.putDesign(draft);
  const request={lineId:101+i,store,registry,reference:saved.reference,ownerToken:saved.ownerToken,
   expectedRevision:1,productGid:entry.product.id,variantGid:entry.product.variants[0].id};
  const ready=await reviewCustomerCartReadiness(request);
  const binding=Object.fromEntries(['reference','revision','productGid','variantGid','compositionSha256'].map(k=>[k,ready[k]]));
  await ledger.putDesignCAS({design:{shop,ownerSubject:subject,...binding,status:'CURRENT'}});
  requests.push(request);drafts.push(draft);bindings.push(binding);
 }
 let principal={schema:'TJ-TRUSTED-PRINCIPAL-1',shop,subject,kind:'customer',sessionId,
  expiresAt:now+600_000,checkoutEnabled:false,productionReady:false};
 const authority=createOfflineVersionedMetadataAuthority({keys:[{id:'key-v2',secret:randomBytes(32),status:'ACTIVE',
  notBefore:now-60_000,verifyUntil:now+1_200_000}],activeKeyId:'key-v2',clock:()=>now,
  resolvePrincipal:async()=>principal,lookupDesign:ledger.lookupDesign,consumeNonce:ledger.consumeNonce});
 const boundary=createOfflineReviewReceiptBoundary({issueReceipt:authority.issue});
 const lineage=createOfflineMultiLineage({prepareCartReceipt:authority.prepareForAtomicLineage,
  resolveCheckout:async()=>({schema:'TJ-TRUSTED-OFFLINE-CHECKOUT-1',shop,ownerSubject:subject,sessionId,
   checkoutId,status:'BOUND_OFFLINE',expiresAt:now+600_000,checkoutEnabled:false,paymentVerified:false}),
  lookupEvent:ledger.lookupMultiLineageEvent,
  commitObserved:args=>ledger.commitMultiLineageWithReceipts({...args,assertPreparedReceipt:authority.assertPreparedForAtomicLineage}),
  commitCancellation:ledger.commitMultiLineageCancellation,clock:()=>now});
 const coordinator=createOfflineMultiReviewObservation({reviewBoundary:boundary,lineage});
 const eventSecret=randomBytes(32);
 function signed({lines=bindings.map((b,i)=>({lineId:101+i,...b})),ownerSubject=subject,
  eventId='123e4567-e89b-42d3-a456-426614174035',order=orderGid,action='ORDER_OBSERVED'}={}){
  const body={schema:'TJ-SYNTHETIC-MULTILINE-EVENT-1',shop,action,checkoutId,
   orderGid:order,ownerSubject,sessionId,lines,occurredAt:now};
  const rawBody=Buffer.from(JSON.stringify(body));
  const headers={'x-tj-event-id':eventId,'x-tj-shop':shop,
   'x-tj-signature':createHmac('sha256',eventSecret).update(Buffer.concat([
    Buffer.from(`TJ-OFFLINE-MULTILINE-EVENT-1\0${shop}\0${eventId}\0`),rawBody])).digest('base64url')};
  return authenticateSyntheticMultiLineEvent({rawBody,headers,secret:eventSecret,expectedShop:shop});
 }
 const observe=(changes={})=>coordinator.observe({requests,verifiedEvent:signed(),authContext:'synthetic-customer',...changes});
 const snapshot=async()=>JSON.parse(await readFile(join(dir,'ledger','ledger.json'),'utf8'));
 return {dir,store,registry,ledger,requests,drafts,bindings,authority,boundary,lineage,coordinator,
  signed,observe,snapshot,principal:p=>principal=p};
}
test('35I two actual saved product drafts produce one atomic synthetic observation',async t=>{
 const e=await setup(t),out=await e.observe();
 assert.equal(out.outcome,'acquired');assert.equal(out.lineCount,2);
 const s=await e.snapshot();assert.equal(s.nonces.length,2);assert.equal(s.multiOrders.length,1);
 assert.equal(s.multiOrders[0].state,'OBSERVED');assert.equal(s.multiEvents.length,1);
 assert.equal(s.multiOrders[0].lines[0].productGid,e.requests[0].productGid);
 assert.equal(s.multiOrders[0].lines[1].productGid,e.requests[1].productGid);
 assert.notEqual(e.requests[0].productGid,e.requests[1].productGid);
 for(const k of ['checkoutEnabled','paymentVerified','productionApproved','fulfillmentAuthorized'])assert.equal(out[k],false);
 for(const r of e.requests)assert.equal(JSON.stringify(s).includes(r.ownerToken),false);
 assert.equal(JSON.stringify(s).includes(sessionId),false);
});
test('35I three distinct real draft templates reconcile in one atomic commit',async t=>{
 const e=await setup(t,{count:3}),out=await e.observe();
 assert.equal(out.lineCount,3);assert.equal((await e.snapshot()).nonces.length,3);
});
test('35I identical signed event replay is idempotent with no new nonce',async t=>{
 const e=await setup(t);assert.equal((await e.observe()).outcome,'acquired');
 assert.equal((await e.observe()).outcome,'duplicate');
 const s=await e.snapshot();assert.equal(s.nonces.length,2);assert.equal(s.multiEvents.length,1);
});
test('35I forged event object rejected before any receipt issuance',async t=>{
 const e=await setup(t);let calls=0;
 const coordinator=createOfflineMultiReviewObservation({reviewBoundary:{prepare:async()=>{calls++;throw Error('should not issue');}},lineage:e.lineage});
 await denied(coordinator.observe({requests:e.requests,verifiedEvent:{...e.signed()},authContext:'synthetic-customer'}),'MULTI_REVIEW_EVENT_UNTRUSTED');
 assert.equal(calls,0);assert.equal((await e.snapshot()).nonces.length,0);
});
test('35I cancellation event cannot use customer review receipt flow',async t=>{
 const e=await setup(t);await denied(e.observe({verifiedEvent:e.signed({action:'CANCELLATION_OBSERVED'})}),'MULTI_REVIEW_EVENT_UNTRUSTED');
});
test('35I reversed, duplicate and missing lines rejected before receipt issuance',async t=>{
 const e=await setup(t);
 for(const requests of [[...e.requests].reverse(),[e.requests[0],e.requests[0]],[e.requests[0]]])
  await denied(e.observe({requests}),requests.length===2&&requests[0]!==requests[1]?'MULTI_REVIEW_REQUESTS_MISMATCH':'MULTI_REVIEW_REQUESTS_INVALID');
 assert.equal((await e.snapshot()).nonces.length,0);
});
test('35I rejects extra checkout permission and foreign request fields',async t=>{
 const e=await setup(t);
 for(const extra of [{checkoutEnabled:true},{shopifyCustomerAuthenticated:true},{ownerSubject:subject}])
  await denied(e.observe({requests:[{...e.requests[0],...extra},e.requests[1]]}),'MULTI_REVIEW_REQUESTS_MISMATCH');
});
test('35I wrong local owner capability on second line rejects whole batch',async t=>{
 const e=await setup(t);
 await denied(e.observe({requests:[e.requests[0],{...e.requests[1],ownerToken:'f'.repeat(64)}]}),'MULTI_REVIEW_RECEIPT_REJECTED');
 const s=await e.snapshot();assert.equal(s.nonces.length,0);assert.equal(s.multiOrders.length,0);
});
test('35I stale local second revision rejects whole batch before nonce use',async t=>{
 const e=await setup(t);await e.store.reviseDesign(e.requests[1].reference,e.requests[1].ownerToken,{...e.drafts[1],expectedRevision:1});
 await denied(e.observe(),'MULTI_REVIEW_RECEIPT_REJECTED');
 const s=await e.snapshot();assert.equal(s.nonces.length,0);assert.equal(s.multiOrders.length,0);
});
test('35I cross-owner authenticated principal rejects all receipts',async t=>{
 const e=await setup(t);e.principal({schema:'TJ-TRUSTED-PRINCIPAL-1',shop,subject:'gid://shopify/Customer/999',kind:'customer',sessionId,
  expiresAt:now+600_000,checkoutEnabled:false,productionReady:false});
 await denied(e.observe(),'MULTI_REVIEW_RECEIPT_REJECTED');assert.equal((await e.snapshot()).nonces.length,0);
});
test('35I signed variant substitution rejected before issuing receipts',async t=>{
 const e=await setup(t);const lines=e.bindings.map((b,i)=>({lineId:101+i,...b}));
 lines[1].variantGid='gid://shopify/ProductVariant/999999';
 await denied(e.observe({verifiedEvent:e.signed({lines})}),'MULTI_REVIEW_REQUESTS_MISMATCH');
 assert.equal((await e.snapshot()).nonces.length,0);
});
test('35I signed product substitution rejected before issuing receipts',async t=>{
 const e=await setup(t);const lines=e.bindings.map((b,i)=>({lineId:101+i,...b}));
 lines[0].productGid=e.requests[1].productGid;
 await denied(e.observe({verifiedEvent:e.signed({lines})}),'MULTI_REVIEW_REQUESTS_MISMATCH');
});
test('35I changing first draft while second receipt issues fails final whole-batch reread',async t=>{
 const e=await setup(t);let issued=0;
 const boundary=createOfflineReviewReceiptBoundary({issueReceipt:async args=>{
  const receipt=await e.authority.issue(args);
  if(++issued===2)await e.store.reviseDesign(e.requests[0].reference,e.requests[0].ownerToken,{...e.drafts[0],expectedRevision:1});
  return receipt;
 }});
 const coordinator=createOfflineMultiReviewObservation({reviewBoundary:boundary,lineage:e.lineage});
 // The adversarial coordinator must reject without an order commit.
 await denied(coordinator.observe({requests:e.requests,verifiedEvent:e.signed(),authContext:'synthetic-customer'}),'MULTI_REVIEW_CHANGED');
 const s=await e.snapshot();assert.equal(s.nonces.length,0);assert.equal(s.multiOrders.length,0);
});
test('35I trusted ledger stale second design blocks every nonce and order',async t=>{
 const e=await setup(t);await e.ledger.putDesignCAS({design:{shop,ownerSubject:subject,...e.bindings[1],revision:2,status:'CURRENT'},expectedRevision:1});
 await denied(e.observe(),'MULTI_REVIEW_RECEIPT_REJECTED');
 const s=await e.snapshot();assert.equal(s.nonces.length,0);assert.equal(s.multiOrders.length,0);
});
test('35I tampered issued receipt properties fail closed with zero claims',async t=>{
 const e=await setup(t);
 const boundary={prepare:async input=>{const out=await e.boundary.prepare(input);return {...out,properties:{...out.properties,'_TJ Cart Receipt':'TJ2.invalid.'+'A'.repeat(43)}};}};
 const coordinator=createOfflineMultiReviewObservation({reviewBoundary:boundary,lineage:e.lineage});
 await denied(coordinator.observe({requests:e.requests,verifiedEvent:e.signed(),authContext:'synthetic-customer'}),'MULTI_REVIEW_OBSERVATION_REJECTED');
 assert.equal((await e.snapshot()).nonces.length,0);
});
test('35I cross-owner signed observation fails checkout identity and leaves ledger unchanged',async t=>{
 const e=await setup(t);await denied(e.observe({verifiedEvent:e.signed({ownerSubject:'gid://shopify/Customer/999'})}),'MULTI_REVIEW_OBSERVATION_REJECTED');
 assert.equal((await e.snapshot()).nonces.length,0);
});
test('35I untrusted reread cannot claim hosted authentication or commerce readiness',async t=>{
 const e=await setup(t);
 for(const patch of [{checkoutEnabled:true},{shopifyCustomerAuthenticated:true},{priceApproved:true},{blockers:[]}]){
  const coordinator=createOfflineMultiReviewObservation({reviewBoundary:e.boundary,lineage:e.lineage,
   readReadiness:async input=>({...await reviewCustomerCartReadiness(input),...patch})});
  await denied(coordinator.observe({requests:e.requests,verifiedEvent:e.signed(),authContext:'synthetic-customer'}),'MULTI_REVIEW_CHANGED');
 }
 assert.equal((await e.snapshot()).nonces.length,0);
});
test('35I rejected second observation with reused designs cannot mint another order',async t=>{
 const e=await setup(t);await e.observe();
 await denied(e.observe({verifiedEvent:e.signed({eventId:'123e4567-e89b-42d3-a456-426614174036',order:'gid://shopify/Order/999'})}),'MULTI_REVIEW_OBSERVATION_REJECTED');
 const s=await e.snapshot();assert.equal(s.nonces.length,2);assert.equal(s.multiOrders.length,1);
});
test('35I configuration and untrusted lineage response fail closed',async t=>{
 const e=await setup(t);assert.throws(()=>createOfflineMultiReviewObservation(),{code:'MULTI_REVIEW_CONFIGURATION'});
 const coordinator=createOfflineMultiReviewObservation({reviewBoundary:e.boundary,lineage:{transition:async()=>({checkoutEnabled:true})}});
 await denied(coordinator.observe({requests:e.requests,verifiedEvent:e.signed(),authContext:'synthetic-customer'}),'MULTI_REVIEW_OBSERVATION_UNTRUSTED');
 const valid={schema:'TJ-OFFLINE-MULTILINE-TRANSITION-1',shop,orderGid,lineCount:2,action:'ORDER_OBSERVED',outcome:'acquired',
  syntheticOnly:true,checkoutEnabled:false,paymentVerified:false,productionApproved:false,fulfillmentAuthorized:false};
 const extra=createOfflineMultiReviewObservation({reviewBoundary:e.boundary,lineage:{transition:async()=>({...valid,checkoutUrl:'/checkout'})}});
 await denied(extra.observe({requests:e.requests,verifiedEvent:e.signed(),authContext:'synthetic-customer'}),'MULTI_REVIEW_OBSERVATION_UNTRUSTED');
});
