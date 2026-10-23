import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {randomBytes,createHmac} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {LocalDesignStore} from '../src/local-store.mjs';
import {createStagingRegistry} from '../src/shopify-bridge.mjs';
import {reviewCustomerCartReadiness} from '../src/customer-cart-readiness.mjs';
import {createOfflineDurableLedger} from '../src/offline-durable-ledger.mjs';
import {createOfflineVersionedMetadataAuthority} from '../src/versioned-cart-metadata.mjs';
import {createOfflineReviewReceiptBoundary} from '../src/offline-review-receipt-boundary.mjs';
import {authenticateSyntheticLineageEvent,createOfflineOrderLineage} from '../src/offline-order-lineage.mjs';
const shop='gucgmp-bc.myshopify.com',subject='gid://shopify/Customer/45678',sessionId='offline-review-session-012345';
const now=Date.now();
const draftLayer={id:'front-wording',type:'text',surfaceId:'front',x:.3,y:.3,width:.4,height:.2,rotationDeg:0,value:'CUSTOM'};
const fail=async(p,code)=>assert.rejects(p,e=>e?.code===code);
async function setup(t){
 const dir=await mkdtemp(join(tmpdir(),'tj-35h-'));t.after(()=>rm(dir,{recursive:true,force:true}));
 const fixture=JSON.parse(await readFile(new URL('../fixtures/shopify-draft-manufacturing-2026-10-14.json',import.meta.url),'utf8')).products;
 const registry=createStagingRegistry(fixture);
 const store=new LocalDesignStore(join(dir,'designs'),{manifests:Object.fromEntries(registry.entries.filter(e=>e.manifest).map(e=>[e.manifest.id,e.manifest]))});await store.init();
 const entry=registry.entries.find(x=>x.manifest?.category==='apparel');assert.ok(entry);
 const inputDraft={productManifestId:entry.manifest.id,layers:[draftLayer],previewSelection:{colorId:'oxblood',sizeId:'m'}};
 const saved=await store.putDesign(inputDraft);
 const request={store,registry,reference:saved.reference,ownerToken:saved.ownerToken,expectedRevision:1,
  productGid:entry.product.id,variantGid:entry.product.variants[0].id,authContext:'synthetic-customer'};
 const readiness=await reviewCustomerCartReadiness(request);
 const binding=Object.fromEntries(['reference','revision','productGid','variantGid','compositionSha256'].map(k=>[k,readiness[k]]));
 const ledger=createOfflineDurableLedger({directory:join(dir,'ledger')});
 await ledger.putDesignCAS({design:{shop,ownerSubject:subject,...binding,status:'CURRENT'}});
 let principal={schema:'TJ-TRUSTED-PRINCIPAL-1',shop,subject,kind:'customer',sessionId,
  expiresAt:now+600_000,checkoutEnabled:false,productionReady:false};
 const authority=createOfflineVersionedMetadataAuthority({keys:[{id:'key-v2',secret:randomBytes(32),status:'ACTIVE',
  notBefore:now-60_000,verifyUntil:now+1_200_000}],activeKeyId:'key-v2',clock:()=>now,
  resolvePrincipal:async()=>principal,lookupDesign:ledger.lookupDesign,consumeNonce:ledger.consumeNonce});
 const boundary=createOfflineReviewReceiptBoundary({issueReceipt:authority.issue});
 return {dir,store,registry,entry,request,inputDraft,readiness,binding,ledger,authority,boundary,
  principal:p=>principal=p};
}
test('35H actual local draft -> readiness -> independently signed synthetic receipt',async t=>{
 const e=await setup(t),out=await e.boundary.prepare(e.request);
 assert.equal(out.schema,'TJ-OFFLINE-REVIEW-RECEIPT-1');
 assert.equal(out.compositionSha256,e.binding.compositionSha256);
 assert.match(out.properties['_TJ Cart Receipt'],/^TJ2\./);
 assert.equal(Object.isFrozen(out),true);assert.equal(Object.isFrozen(out.properties),true);
 for(const k of ['checkoutEnabled','productionApproved','paymentVerified','fulfillmentAuthorized','shopifyCustomerAuthenticated','priceApproved'])assert.equal(out[k],false);
 assert.equal(out.cartLine,null);assert.equal(out.checkoutUrl,null);assert.equal(out.shopifyOrderId,null);
 assert.doesNotMatch(JSON.stringify(out),new RegExp(e.request.ownerToken));
 assert.doesNotMatch(JSON.stringify(out),/synthetic-customer|offline-review-session/);
 const proof=await e.authority.prepareForAtomicLineage({properties:out.properties,authContext:e.request.authContext,
  expectedBinding:e.binding,expectedIdentity:{shop,subject,sessionId}});
 assert.equal(proof.schema,'TJ-OFFLINE-PREPARED-CART-2');assert.equal(proof.revision,1);
 assert.equal(proof.checkoutEnabled,false);
});
test('35H stale saved revision fails before receipt issuance',async t=>{
 const e=await setup(t);await e.store.reviseDesign(e.request.reference,e.request.ownerToken,{...e.inputDraft,expectedRevision:1});
 await fail(e.boundary.prepare(e.request),'REVIEW_READINESS_REJECTED');
});
test('35H swapped product fails before issuance',async t=>{
 const e=await setup(t),other=e.registry.entries.find(x=>x.manifest&&x.product.id!==e.request.productGid);
 await fail(e.boundary.prepare({...e.request,productGid:other.product.id,variantGid:other.product.variants[0].id}),'REVIEW_READINESS_REJECTED');
});
test('35H variant substitution fails before issuance',async t=>{
 const e=await setup(t);await fail(e.boundary.prepare({...e.request,variantGid:'gid://shopify/ProductVariant/999999999'}),'REVIEW_READINESS_REJECTED');
});
test('35H wrong local owner capability fails before issuer',async t=>{
 const e=await setup(t);await fail(e.boundary.prepare({...e.request,ownerToken:'f'.repeat(64)}),'REVIEW_READINESS_REJECTED');
});
test('35H independently authenticated principal mismatch rejects issuance',async t=>{
 const e=await setup(t);e.principal({schema:'TJ-TRUSTED-PRINCIPAL-1',shop,subject:'gid://shopify/Customer/999',kind:'customer',sessionId,
  expiresAt:now+600_000,checkoutEnabled:false,productionReady:false});
 await fail(e.boundary.prepare(e.request),'REVIEW_RECEIPT_REJECTED');
});
test('35H trusted design ledger stale revision rejects issuance',async t=>{
 const e=await setup(t);await e.ledger.putDesignCAS({design:{shop,ownerSubject:subject,...e.binding,revision:2,status:'CURRENT'},expectedRevision:1});
 await fail(e.boundary.prepare(e.request),'REVIEW_RECEIPT_REJECTED');
});
test('35H trusted ledger variant substitution rejects issuance',async t=>{
 const e=await setup(t);await e.ledger.putDesignCAS({design:{shop,ownerSubject:subject,...e.binding,revision:2,variantGid:'gid://shopify/ProductVariant/999',status:'CURRENT'},expectedRevision:1});
 await fail(e.boundary.prepare(e.request),'REVIEW_RECEIPT_REJECTED');
});
test('35H concurrent local revision after signed issuance fails closed',async t=>{
 const e=await setup(t);
 const boundary=createOfflineReviewReceiptBoundary({issueReceipt:async args=>{
  const receipt=await e.authority.issue(args);
  await e.store.reviseDesign(e.request.reference,e.request.ownerToken,{...e.inputDraft,expectedRevision:1});
  return receipt;
 }});
 await fail(boundary.prepare(e.request),'REVIEW_CHANGED_DURING_ISSUE');
});
test('35H altered second-read composition digest fails closed',async t=>{
 const e=await setup(t);let calls=0;
 const boundary=createOfflineReviewReceiptBoundary({readReadiness:async input=>{
  const r=await reviewCustomerCartReadiness(input);return ++calls===2?{...r,compositionSha256:'f'.repeat(64)}:r;
 },issueReceipt:e.authority.issue});
 await fail(boundary.prepare(e.request),'REVIEW_CHANGED_DURING_ISSUE');
});
test('35H issued receipt invalidated by revision before downstream observation',async t=>{
 const e=await setup(t),out=await e.boundary.prepare(e.request);
 await e.ledger.putDesignCAS({design:{shop,ownerSubject:subject,...e.binding,revision:2,status:'CURRENT'},expectedRevision:1});
 await fail(e.authority.prepareForAtomicLineage({properties:out.properties,authContext:e.request.authContext,
  expectedBinding:e.binding,expectedIdentity:{shop,subject,sessionId}}),'METADATA_DESIGN_STALE');
});
test('35H invalid configuration and extra client authorization switches rejected',async t=>{
 const e=await setup(t);
 assert.throws(()=>createOfflineReviewReceiptBoundary(),{code:'REVIEW_BOUNDARY_CONFIGURATION'});
 await fail(e.boundary.prepare({...e.request,checkoutEnabled:true}),'REVIEW_INPUT_INVALID');
 await fail(e.boundary.prepare({...e.request,priceApproved:true}),'REVIEW_INPUT_INVALID');
});
test('35H untrusted readiness flags cannot be upgraded by injected adapter',async t=>{
 const e=await setup(t);
 for(const patch of [{checkoutEnabled:true},{priceApproved:true},{shopifyCustomerAuthenticated:true},
  {cartLine:{id:'fake'}},{checkoutUrl:'/checkout'},{blockers:[]},{scope:'HOSTED'}]){
  const boundary=createOfflineReviewReceiptBoundary({readReadiness:async input=>({...await reviewCustomerCartReadiness(input),...patch}),issueReceipt:e.authority.issue});
  await fail(boundary.prepare(e.request),'REVIEW_READINESS_UNTRUSTED');
 }
});
test('35H forged issuer metadata, extra properties and checkout flag rejected',async t=>{
 const e=await setup(t);
 const good=await e.authority.issue({authContext:e.request.authContext,binding:e.binding});
 for(const patch of [{checkoutEnabled:true},{productionApproved:true},{properties:{...good.properties,'_TJ Owner Token':'secret'}},
  {properties:{...good.properties,'_TJ Cart Receipt':'fake'}},{expiresAt:NaN}]){
  const boundary=createOfflineReviewReceiptBoundary({issueReceipt:async()=>({...good,...patch})});
  await fail(boundary.prepare(e.request),'REVIEW_RECEIPT_UNTRUSTED');
 }
});
test('35H issuer never receives local owner capability or untrusted input switches',async t=>{
 const e=await setup(t);let received;
 const boundary=createOfflineReviewReceiptBoundary({issueReceipt:async args=>{received=args;return e.authority.issue(args);}});
 await boundary.prepare(e.request);
 assert.deepEqual(Object.keys(received).sort(),['authContext','binding']);
 assert.equal(Object.isFrozen(received.binding),true);
 assert.equal(JSON.stringify(received).includes(e.request.ownerToken),false);
});
test('35H prototype has no Shopify cart or checkout operations',async t=>{
 const e=await setup(t),out=await e.boundary.prepare(e.request);
 assert.deepEqual(Object.keys(out.properties).sort(),['_TJ Cart Receipt','_TJ Protocol']);
 assert.equal(out.scope,'SYNTHETIC_OFFLINE_ONLY');assert.equal(e.boundary.localOnly,true);
});

function signedObservation(binding,secret,changes={}){
 const eventId='123e4567-e89b-42d3-a456-426614174123';
 const body={schema:'TJ-SYNTHETIC-LINEAGE-EVENT-1',shop,action:'ORDER_OBSERVED',
  checkoutId:'offline-checkout:'+'Q'.repeat(24),orderGid:'gid://shopify/Order/98765',
  ownerSubject:subject,sessionId,lineId:101,...binding,occurredAt:now,...changes};
 const rawBody=Buffer.from(JSON.stringify(body));
 const headers={'x-tj-event-id':eventId,'x-tj-shop':shop,
  'x-tj-signature':createHmac('sha256',secret).update(Buffer.concat([
   Buffer.from(`TJ-OFFLINE-LINEAGE-EVENT-1\0${shop}\0${eventId}\0`),rawBody])).digest('base64url')};
 return authenticateSyntheticLineageEvent({rawBody,headers,secret,expectedShop:shop});
}
function lineageFor(e){
 return createOfflineOrderLineage({verifyCartReceipt:e.authority.verify,
  resolveCheckout:async()=>({schema:'TJ-TRUSTED-OFFLINE-CHECKOUT-1',shop,ownerSubject:subject,sessionId,
   checkoutId:'offline-checkout:'+'Q'.repeat(24),status:'BOUND_OFFLINE',expiresAt:now+600_000,
   checkoutEnabled:false,paymentVerified:false}),commitTransition:e.ledger.commitLineageTransition,
  lookupLineageEvent:e.ledger.lookupLineageEvent,clock:()=>now});
}
test('35H real saved draft review -> signed receipt -> synthetic observed lineage -> idempotent retry',async t=>{
 const e=await setup(t),receipt=await e.boundary.prepare(e.request),secret=randomBytes(32);
 const event=signedObservation(e.binding,secret),lineage=lineageFor(e);
 const args={properties:receipt.properties,authContext:e.request.authContext,expectedBinding:e.binding,verifiedEvent:event};
 const observed=await lineage.transition(args);
 assert.equal(observed.outcome,'acquired');assert.equal(observed.checkoutEnabled,false);
 assert.equal(observed.paymentVerified,false);assert.equal(observed.productionApproved,false);
 assert.equal((await e.ledger.getLineage({shop,orderGid:'gid://shopify/Order/98765'})).state,'OBSERVED');
 assert.equal((await lineage.transition(args)).outcome,'duplicate');
});
test('35H review-to-synthetic-observation rejects variant substitution without order or nonce',async t=>{
 const e=await setup(t),receipt=await e.boundary.prepare(e.request),secret=randomBytes(32);
 const event=signedObservation(e.binding,secret,{variantGid:'gid://shopify/ProductVariant/999'});
 await fail(lineageFor(e).transition({properties:receipt.properties,authContext:e.request.authContext,
  expectedBinding:e.binding,verifiedEvent:event}),'LINEAGE_EXPECTED_BINDING');
 assert.equal(await e.ledger.getLineage({shop,orderGid:'gid://shopify/Order/98765'}),null);
});
