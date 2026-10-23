import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {randomBytes,createHmac} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {LocalDesignStore} from '../src/local-store.mjs';
import {createStagingRegistry} from '../src/shopify-bridge.mjs';
import {createOfflineDurableLedger} from '../src/offline-durable-ledger.mjs';
import {createOfflineVersionedMetadataAuthority} from '../src/versioned-cart-metadata.mjs';
import {createOfflineReviewReceiptBoundary} from '../src/offline-review-receipt-boundary.mjs';
import {createOfflineMultiReviewObservation} from '../src/offline-multiline-review-observation.mjs';
import {reviewCustomerCartReadiness} from '../src/customer-cart-readiness.mjs';
import {createOfflineMultiLineage,authenticateSyntheticMultiLineEvent} from '../src/offline-multiline-order.mjs';
const shop='gucgmp-bc.myshopify.com',subject='gid://shopify/Customer/45678';
const sessionId='offline-recovery-session-012345';
const checkoutId='offline-checkout:'+'R'.repeat(24),orderGid='gid://shopify/Order/654321';
const worker=fileURLToPath(new URL('./support/objective35j-recovery-worker.mjs',import.meta.url));
const deny=(p,code)=>assert.rejects(p,e=>e?.code===code);
async function fixture(t,{faultStage}={}){
 const directory=await mkdtemp(join(tmpdir(),'tj-35j-'));
 t.after(()=>rm(directory,{recursive:true,force:true}));
 const now=Date.now(),ledgerDir=join(directory,'ledger');
 const ledger=createOfflineDurableLedger({directory:ledgerDir});
 const faultyLedger=createOfflineDurableLedger({directory:ledgerDir,
  injectFault:faultStage?async stage=>{if(stage===faultStage)throw Error('SIMULATED_CRASH');}:undefined});
 const fixtureProducts=JSON.parse(await readFile(new URL('../fixtures/shopify-draft-manufacturing-2026-10-14.json',import.meta.url),'utf8')).products;
 const registry=createStagingRegistry(fixtureProducts);
 const store=new LocalDesignStore(join(directory,'designs'),{manifests:Object.fromEntries(registry.entries.filter(e=>e.manifest).map(e=>[e.manifest.id,e.manifest]))});
 await store.init();
 const requests=[],bindings=[];
 for(let i=0;i<2;i++){
  const entry=registry.entries.filter(e=>e.manifest)[i];
  const saved=await store.putDesign({productManifestId:entry.manifest.id,
   layers:[{id:'custom-label',type:'text',surfaceId:entry.manifest.surfaces[0].id,
    x:.2,y:.2,width:.4,height:.2,rotationDeg:0,value:'RECOVERY '+i}]});
  const r={lineId:201+i,store,registry,reference:saved.reference,ownerToken:saved.ownerToken,
   expectedRevision:1,productGid:entry.product.id,variantGid:entry.product.variants[0].id};
  const readiness=await reviewCustomerCartReadiness(r);
  const binding=Object.fromEntries(['reference','revision','productGid','variantGid','compositionSha256'].map(k=>[k,readiness[k]]));
  await ledger.putDesignCAS({design:{shop,ownerSubject:subject,...binding,status:'CURRENT'}});
  requests.push(r);bindings.push(binding);
 }
 const checkout={schema:'TJ-TRUSTED-OFFLINE-CHECKOUT-1',shop,ownerSubject:subject,sessionId,
  checkoutId,status:'BOUND_OFFLINE',expiresAt:now+600_000,checkoutEnabled:false,paymentVerified:false};
 const principal={schema:'TJ-TRUSTED-PRINCIPAL-1',shop,subject,kind:'customer',sessionId,
  expiresAt:now+600_000,checkoutEnabled:false,productionReady:false};
 const authority=createOfflineVersionedMetadataAuthority({keys:[{id:'key-v2',secret:randomBytes(32),status:'ACTIVE',
  notBefore:now-60_000,verifyUntil:now+1_200_000}],activeKeyId:'key-v2',clock:()=>now,
  resolvePrincipal:async()=>principal,lookupDesign:ledger.lookupDesign,consumeNonce:ledger.consumeNonce});
 const boundary=createOfflineReviewReceiptBoundary({issueReceipt:authority.issue});
 const lineage=createOfflineMultiLineage({prepareCartReceipt:authority.prepareForAtomicLineage,
  resolveCheckout:async()=>checkout,lookupEvent:ledger.lookupMultiLineageEvent,
  commitObserved:args=>faultyLedger.commitMultiLineageWithReceipts({...args,assertPreparedReceipt:authority.assertPreparedForAtomicLineage}),
  commitCancellation:ledger.commitMultiLineageCancellation,
  inspectCommitted:ledger.inspectCommittedMultiLineage,clock:()=>now});
 const coordinator=createOfflineMultiReviewObservation({reviewBoundary:boundary,lineage});
 const secret=randomBytes(32);
 function signed({eventId='123e4567-e89b-42d3-a456-426614174035',ownerSubject=subject,
  session=sessionId,order=orderGid,lines=bindings.map((b,i)=>({lineId:201+i,...b})),action='ORDER_OBSERVED'}={}){
  const body={schema:'TJ-SYNTHETIC-MULTILINE-EVENT-1',shop,action,checkoutId,
   orderGid:order,ownerSubject,sessionId:session,lines,occurredAt:now};
  const rawBody=Buffer.from(JSON.stringify(body));
  const headers={'x-tj-event-id':eventId,'x-tj-shop':shop,
   'x-tj-signature':createHmac('sha256',secret).update(Buffer.concat([
    Buffer.from(`TJ-OFFLINE-MULTILINE-EVENT-1\0${shop}\0${eventId}\0`),rawBody])).digest('base64url')};
  return {verifiedEvent:authenticateSyntheticMultiLineEvent({rawBody,headers,secret,expectedShop:shop}),
   rawBody:rawBody.toString('base64'),headers};
 }
 const event=signed();
 const observe=()=>coordinator.observe({requests,verifiedEvent:event.verifiedEvent,authContext:'synthetic-customer'});
 const snapshot=async()=>JSON.parse(await readFile(join(ledgerDir,'ledger.json'),'utf8'));
 function child(ev=event,{clock=now,checkoutOverride=checkout}={}){
  const input={directory:ledgerDir,shop,now:clock,checkout:checkoutOverride,
   secret:secret.toString('base64'),rawBody:ev.rawBody,headers:ev.headers};
  const result=spawnSync(process.execPath,[worker],{input:JSON.stringify(input),encoding:'utf8',timeout:15_000});
  assert.equal(result.status,0,result.stderr);return JSON.parse(result.stdout);
 }
 return {directory,ledgerDir,ledger,faultyLedger,requests,bindings,lineage,coordinator,
  event,observe,signed,child,snapshot,checkout,now};
}
test('35J post-rename lost acknowledgement recovers in a separate process without reissuing receipts',async t=>{
 const e=await fixture(t,{faultStage:'after-rename'});
 await deny(e.observe(),'MULTI_REVIEW_OBSERVATION_REJECTED');
 const before=await e.snapshot();assert.equal(before.multiEvents.length,1);assert.equal(before.nonces.length,2);
 const recovered=e.child();assert.equal(recovered.ok,true);assert.equal(recovered.result.outcome,'duplicate');
 assert.deepEqual(await e.snapshot(),before);
 for(const k of ['checkoutEnabled','paymentVerified','productionApproved','fulfillmentAuthorized'])assert.equal(recovered.result[k],false);
});
test('35J pre-rename interruption refuses recovery and leaves no observation/nonce',async t=>{
 const e=await fixture(t,{faultStage:'before-rename'});
 await deny(e.observe(),'MULTI_REVIEW_OBSERVATION_REJECTED');
 assert.equal(e.child().code,'MULTI_RECOVERY_NOT_COMMITTED');
 const s=await e.snapshot();assert.equal(s.multiEvents.length,0);assert.equal(s.nonces.length,0);
});
test('35J successful committed observation survives independent process recovery',async t=>{
 const e=await fixture(t);assert.equal((await e.observe()).outcome,'acquired');
 const before=await e.snapshot();assert.equal(e.child().result.outcome,'duplicate');
 assert.deepEqual(await e.snapshot(),before);
});
test('35J recovery before any observation never creates a synthetic order',async t=>{
 const e=await fixture(t);assert.equal(e.child().code,'MULTI_RECOVERY_NOT_COMMITTED');
 assert.equal((await e.snapshot()).multiOrders.length,0);
});
test('35J cloned event object cannot recover a committed order',async t=>{
 const e=await fixture(t);await e.observe();
 await deny(e.lineage.recoverCommitted({verifiedEvent:{...e.event.verifiedEvent}}),'MULTI_RECOVERY_EVENT_UNTRUSTED');
});
test('35J independently signed changed order under same event ID conflicts',async t=>{
 const e=await fixture(t);await e.observe();
 assert.equal(e.child(e.signed({order:'gid://shopify/Order/999'})).code,'MULTI_RECOVERY_CONFLICT');
});
test('35J independently signed reordered lines under same event ID conflicts',async t=>{
 const e=await fixture(t);await e.observe();
 assert.equal(e.child(e.signed({lines:[...e.event.verifiedEvent.body.lines].reverse()})).code,'MULTI_RECOVERY_CONFLICT');
});
test('35J independently signed changed owner and session fail trusted checkout binding',async t=>{
 const e=await fixture(t);await e.observe();
 assert.equal(e.child(e.signed({ownerSubject:'gid://shopify/Customer/999'})).code,'MULTI_RECOVERY_CHECKOUT_UNTRUSTED');
 assert.equal(e.child(e.signed({session:'offline-other-session-987654'})).code,'MULTI_RECOVERY_CHECKOUT_UNTRUSTED');
});
test('35J different signed event ID cannot steal existing order',async t=>{
 const e=await fixture(t);await e.observe();
 assert.equal(e.child(e.signed({eventId:'123e4567-e89b-42d3-a456-426614174036'})).code,'MULTI_RECOVERY_CONFLICT');
});
test('35J expired signed event fails closed even when durable event exists',async t=>{
 const e=await fixture(t);await e.observe();
 assert.equal(e.child(e.event,{clock:e.now+300_001}).code,'MULTI_RECOVERY_EVENT_TIME_INVALID');
});
test('35J invalid checkout status or switched checkout principal fails closed',async t=>{
 const e=await fixture(t);await e.observe();
 for(const patch of [{status:'UNBOUND'},{ownerSubject:'gid://shopify/Customer/999'},
  {checkoutEnabled:true},{paymentVerified:true}]){
  assert.equal(e.child(e.event,{checkoutOverride:{...e.checkout,...patch}}).code,'MULTI_RECOVERY_CHECKOUT_UNTRUSTED');
 }
});
test('35J corrupt durable ledger cannot be treated as a successful recovery',async t=>{
 const e=await fixture(t);await e.observe();
 await writeFile(join(e.ledgerDir,'ledger.json'),'{"tampered":true}');
 assert.equal(e.child().code,'MULTI_RECOVERY_LEDGER_UNAVAILABLE');
});
test('35J cancellation and compacted history retain original committed observation recovery',async t=>{
 const e=await fixture(t);await e.observe();
 const cancel=e.signed({eventId:'123e4567-e89b-42d3-a456-426614174036',action:'CANCELLATION_OBSERVED'});
 assert.equal((await e.lineage.transition({verifiedEvent:cancel.verifiedEvent})).outcome,'acquired');
 assert.equal(await e.ledger.compactMultiLineageHistory({shop,orderGid}),'acquired');
 assert.equal(e.child().result.outcome,'duplicate');
});
test('35J absent recovery adapter never assumes a committed order',async t=>{
 const e=await fixture(t);const unavailable=async()=>{throw Error('unused');};
 const lineage=createOfflineMultiLineage({prepareCartReceipt:unavailable,resolveCheckout:unavailable,
  commitObserved:unavailable,commitCancellation:unavailable,lookupEvent:unavailable});
 await deny(lineage.recoverCommitted({verifiedEvent:e.event.verifiedEvent}),'MULTI_RECOVERY_UNAVAILABLE');
});
