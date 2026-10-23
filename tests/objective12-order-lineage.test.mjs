import test from 'node:test';
import assert from 'node:assert/strict';
import {createHmac,randomBytes} from 'node:crypto';
import {mkdtemp,rm,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {createOfflineDurableLedger} from '../src/offline-durable-ledger.mjs';
import {createOfflineVersionedMetadataAuthority} from '../src/versioned-cart-metadata.mjs';
import {authenticateSyntheticLineageEvent,createOfflineOrderLineage} from '../src/offline-order-lineage.mjs';

const shop='gucgmp-bc.myshopify.com',owner='gid://shopify/Customer/45678';
const checkoutId='offline-checkout:'+'C'.repeat(20),sessionId='offline-session-0123456789';
const orderGid='gid://shopify/Order/99999';
const binding={reference:'TJ-'+'A'.repeat(24),revision:1,productGid:'gid://shopify/Product/12345',
 variantGid:'gid://shopify/ProductVariant/67890',compositionSha256:'a'.repeat(64)};
const now=Date.now(),eventId='123e4567-e89b-42d3-a456-426614174000';
const secret=randomBytes(32),webhookSecret=randomBytes(32);
const design=(overrides={})=>({shop,ownerSubject:owner,...binding,status:'CURRENT',...overrides});
const principal=(overrides={})=>({schema:'TJ-TRUSTED-PRINCIPAL-1',shop,subject:owner,kind:'customer',sessionId,
 expiresAt:now+10*60_000,checkoutEnabled:false,productionReady:false,...overrides});
const checkout=(overrides={})=>({schema:'TJ-TRUSTED-OFFLINE-CHECKOUT-1',shop,ownerSubject:owner,
 sessionId,checkoutId,status:'BOUND_OFFLINE',expiresAt:now+10*60_000,checkoutEnabled:false,paymentVerified:false,...overrides});
const body=(overrides={})=>({schema:'TJ-SYNTHETIC-LINEAGE-EVENT-1',shop,action:'ORDER_OBSERVED',
 checkoutId,orderGid,ownerSubject:owner,sessionId,lineId:101,...binding,occurredAt:now,...overrides});
const rejects=(p,code)=>assert.rejects(p,e=>e?.code===code);
async function setup(t,opts={}){
 const directory=await mkdtemp(join(tmpdir(),'tj-lineage12-'));
 t.after(async()=>rm(directory,{recursive:true,force:true}));
 const ledger=createOfflineDurableLedger({directory,lockTimeoutMs:5000});
 await ledger.putDesignCAS({design:design()});
 let who=principal(),check=checkout(),time=now;
 const authority=createOfflineVersionedMetadataAuthority({keys:[{id:'key-v2',secret,
  status:'ACTIVE',notBefore:now-60_000,verifyUntil:now+20*60_000}],activeKeyId:'key-v2',
  clock:()=>time,resolvePrincipal:async()=>who,lookupDesign:ledger.lookupDesign,consumeNonce:ledger.consumeNonce});
 const lineage=createOfflineOrderLineage({verifyCartReceipt:authority.verify,
  resolveCheckout:async()=>check,commitTransition:ledger.commitLineageTransition,
  lookupLineageEvent:ledger.lookupLineageEvent,clock:()=>time});
 const issue=()=>authority.issue({authContext:'offline-only',binding});
 const event=(changes={},id=eventId)=>signed(body(changes),id);
 const observe=async(receipt,verifiedEvent=event(),expectedBinding=binding)=>lineage.transition({
  properties:receipt.properties,authContext:'offline-only',expectedBinding,verifiedEvent});
 return {directory,ledger,authority,lineage,issue,event,observe,clock:n=>time=n,
  principal:p=>who=p,checkout:c=>check=c};
}
function signed(payload,id=eventId){
 const rawBody=Buffer.from(JSON.stringify(payload));
 const headers={'x-tj-event-id':id,'x-tj-shop':payload.shop,
  'x-tj-signature':createHmac('sha256',webhookSecret).update(Buffer.concat([
   Buffer.from(`TJ-OFFLINE-LINEAGE-EVENT-1\0${shop}\0${id.toLowerCase()}\0`),rawBody])).digest('base64url')};
 return authenticateSyntheticLineageEvent({rawBody,headers,secret:webhookSecret,expectedShop:shop});
}
async function accepted(e){const r=await e.issue();const ev=e.event();return e.observe(r,ev);}

test('v2 signed receipt + independently resolved checkout + HMAC event yields OBSERVED only',async t=>{
 const e=await setup(t),r=await accepted(e);
 assert.equal(r.outcome,'acquired');assert.equal(r.paymentVerified,false);assert.equal(r.checkoutEnabled,false);
 assert.equal(r.productionApproved,false);assert.equal(r.fulfillmentAuthorized,false);
 const state=await e.ledger.getLineage({shop,orderGid});
 assert.equal(state.state,'OBSERVED');assert.equal(state.ownerSubject,owner);
 assert.equal(JSON.stringify(state).includes(sessionId),false);
});
test('same authenticated event retries idempotently after consumed cart nonce and fresh ledger instance',async t=>{
 const e=await setup(t),receipt=await e.issue(),ev=e.event();await e.observe(receipt,ev);
 assert.equal((await e.observe(receipt,ev)).outcome,'duplicate');
 const fresh=createOfflineDurableLedger({directory:e.directory});
 assert.equal((await fresh.lookupLineageEvent({shop,eventId})).action,'ORDER_OBSERVED');
});
test('synthetic event is unforgeable by copying plain object',async t=>{
 const e=await setup(t),r=await e.issue(),ev=e.event();
 await rejects(e.observe(r,{...ev}),'LINEAGE_EVENT_UNTRUSTED');
 assert.equal((await e.observe(r,ev)).outcome,'acquired');
});
test('event HMAC tamper and wrong shop reject before receipt consumption',async t=>{
 const e=await setup(t),r=await e.issue();
 const rawBody=Buffer.from(JSON.stringify(body({revision:2}))),original=signed(body());
 assert.throws(()=>authenticateSyntheticLineageEvent({rawBody,headers:{'x-tj-event-id':eventId,
  'x-tj-shop':shop,'x-tj-signature':createHmac('sha256',webhookSecret).update(Buffer.concat([
   Buffer.from(`TJ-OFFLINE-LINEAGE-EVENT-1\0${shop}\0${eventId.toLowerCase()}\0`),Buffer.from(JSON.stringify(body()))])).digest('base64url')},
  secret:webhookSecret,expectedShop:shop}),{code:'LINEAGE_EVENT_HMAC_INVALID'});
 assert.throws(()=>signed(body({shop:'other.myshopify.com'})),{code:'LINEAGE_EVENT_ENVELOPE_INVALID'});
 assert.equal((await e.observe(r,original)).outcome,'acquired');
});
test('duplicate JSON keys, noncanonical JSON and oversized event bodies reject',()=>{
 const source=JSON.stringify(body());
 for(const text of [source.replace('"revision":1','"revision":1,"revision":2'),
  source.replace('"revision":1','"revision": 1'),source+' '.repeat(5000)]){
  const rawBody=Buffer.from(text),headers={'x-tj-event-id':eventId,'x-tj-shop':shop,
   'x-tj-signature':createHmac('sha256',webhookSecret).update(Buffer.concat([
    Buffer.from(`TJ-OFFLINE-LINEAGE-EVENT-1\0${shop}\0${eventId.toLowerCase()}\0`),rawBody])).digest('base64url')};
  assert.throws(()=>authenticateSyntheticLineageEvent({rawBody,headers,secret:webhookSecret,expectedShop:shop}));
 }
});
test('forged checkout session identity rejects before receipt nonce consumption',async t=>{
 const e=await setup(t),r=await e.issue();e.checkout(checkout({sessionId:'different-session-012345'}));
 await rejects(e.observe(r),'LINEAGE_CHECKOUT_UNTRUSTED');
 e.checkout(checkout());assert.equal((await e.observe(r)).outcome,'acquired');
});
test('independent principal mismatch with checkout rejects v2 receipt and does not create order',async t=>{
 const e=await setup(t),r=await e.issue();e.principal(principal({sessionId:'different-session-012345'}));
 await rejects(e.observe(r),'LINEAGE_CART_RECEIPT_REJECTED');
 assert.equal(await e.ledger.getLineage({shop,orderGid}),null);
 e.principal(principal());assert.equal((await e.observe(r)).outcome,'acquired');
});
test('owner substitution and alternate checkout ID reject',async t=>{
 const e=await setup(t),r=await e.issue();
 await rejects(e.observe(r,e.event({ownerSubject:'gid://shopify/Customer/99'})),'LINEAGE_CHECKOUT_UNTRUSTED');
 await rejects(e.observe(r,e.event({checkoutId:'offline-checkout:'+'D'.repeat(20)})),'LINEAGE_CHECKOUT_UNTRUSTED');
 assert.equal((await e.observe(r)).outcome,'acquired');
});
test('reference, revision, product, variant and digest substitutions reject expected binding',async t=>{
 const e=await setup(t),r=await e.issue();
 for(const change of [{reference:'TJ-'+'B'.repeat(24)},{revision:2},
  {productGid:'gid://shopify/Product/9'},{variantGid:'gid://shopify/ProductVariant/9'},
  {compositionSha256:'b'.repeat(64)}]){
  await rejects(e.observe(r,e.event(change)),'LINEAGE_EXPECTED_BINDING');
 }
 assert.equal((await e.observe(r)).outcome,'acquired');
});
test('stale revision after receipt issue rejects atomically',async t=>{
 const e=await setup(t),r=await e.issue();
 await e.ledger.putDesignCAS({design:design({revision:2}),expectedRevision:1});
 await rejects(e.observe(r),'LINEAGE_CART_RECEIPT_REJECTED');
 assert.equal(await e.ledger.getLineage({shop,orderGid}),null);
});
test('expired checkout and stale/future synthetic event reject',async t=>{
 const e=await setup(t),r=await e.issue();e.checkout(checkout({expiresAt:now}));
 await rejects(e.observe(r),'LINEAGE_CHECKOUT_UNTRUSTED');
 e.checkout(checkout());
 await rejects(e.observe(r,e.event({occurredAt:now-6*60_000})),'LINEAGE_EVENT_TIME_INVALID');
 await rejects(e.observe(r,e.event({occurredAt:now+60_001})),'LINEAGE_EVENT_TIME_INVALID');
 assert.equal((await e.observe(r)).outcome,'acquired');
});
test('synthetic cancellation transitions OBSERVED to CANCELLED without implying payment',async t=>{
 const e=await setup(t);await accepted(e);
 const cancel=e.event({action:'CANCELLATION_OBSERVED'},'123e4567-e89b-42d3-a456-426614174001');
 const result=await e.lineage.transition({verifiedEvent:cancel});
 assert.equal(result.outcome,'acquired');assert.equal(result.paymentVerified,false);
 assert.equal((await e.ledger.getLineage({shop,orderGid})).state,'CANCELLED');
 assert.equal((await e.lineage.transition({verifiedEvent:cancel})).outcome,'duplicate');
});
test('cancellation cannot inject cart receipt, expected binding or bearer context',async t=>{
 const e=await setup(t);await accepted(e);
 const cancel=e.event({action:'CANCELLATION_OBSERVED'},'123e4567-e89b-42d3-a456-426614174001');
 for(const change of [{properties:{}},{expectedBinding:binding},{authContext:'synthetic'}])
  await rejects(e.lineage.transition({verifiedEvent:cancel,...change}),'LINEAGE_CANCELLATION_CART_NOT_ALLOWED');
 assert.equal((await e.lineage.transition({verifiedEvent:cancel})).outcome,'acquired');
});
test('cancellation before observed order rejects without creating state',async t=>{
 const e=await setup(t),cancel=e.event({action:'CANCELLATION_OBSERVED'});
 await rejects(e.lineage.transition({verifiedEvent:cancel}),'LINEAGE_LEDGER_UNAVAILABLE');
 assert.equal(await e.ledger.getLineage({shop,orderGid}),null);
});
test('cancellation cannot substitute line, checkout, variant, owner or session',async t=>{
 const e=await setup(t);await accepted(e);
 for(const change of [{lineId:102},{checkoutId:'offline-checkout:'+'D'.repeat(20)},
  {variantGid:'gid://shopify/ProductVariant/99'},
  {ownerSubject:'gid://shopify/Customer/99'},{sessionId:'different-session-012345'}]){
  const ev=e.event({action:'CANCELLATION_OBSERVED',...change},'123e4567-e89b-42d3-a456-426614174002');
  await rejects(e.lineage.transition({verifiedEvent:ev}),change.ownerSubject||change.sessionId||change.checkoutId?
   'LINEAGE_CHECKOUT_UNTRUSTED':'LINEAGE_LEDGER_UNAVAILABLE');
 }
 assert.equal((await e.ledger.getLineage({shop,orderGid})).state,'OBSERVED');
});
test('order cannot be resurrected after cancellation',async t=>{
 const e=await setup(t),r=await e.issue();await e.observe(r);
 const cancel=e.event({action:'CANCELLATION_OBSERVED'},'123e4567-e89b-42d3-a456-426614174001');
 await e.lineage.transition({verifiedEvent:cancel});
 assert.equal((await e.observe(r)).outcome,'duplicate'); // historical event acknowledgment, no state mutation
 assert.equal((await e.ledger.getLineage({shop,orderGid})).state,'CANCELLED');
});
test('one checkout and design revision cannot attach to another order',async t=>{
 const e=await setup(t);await accepted(e);
 const args={shop,eventId:'123e4567-e89b-42d3-a456-426614174002',bodySha256:'b'.repeat(64),
  action:'ORDER_OBSERVED',orderGid:'gid://shopify/Order/123456',checkoutId,
  ownerSubject:owner,sessionHash:(await e.ledger.getLineage({shop,orderGid})).sessionHash,
  lineId:101,binding};
 await rejects(e.ledger.commitLineageTransition(args),'LEDGER_LINEAGE_ALREADY_CLAIMED');
 assert.equal((await e.ledger.getLineage({shop,orderGid})).state,'OBSERVED');
});
test('same event ID with conflicting digest or order rejects',async t=>{
 const e=await setup(t);await accepted(e);
 const old=await e.ledger.lookupLineageEvent({shop,eventId});
 const line=await e.ledger.getLineage({shop,orderGid});
 const args={shop,eventId,bodySha256:'b'.repeat(64),action:'ORDER_OBSERVED',orderGid,
  checkoutId,ownerSubject:owner,sessionHash:line.sessionHash,lineId:101,binding};
 assert.equal(await e.ledger.commitLineageTransition(args),'conflict');
 assert.equal(old.bodySha256.length,64);
});
test('legacy v0.9 claimed design cannot be reattached through v2 ledger',async t=>{
 const e=await setup(t),line=await e.ledger.getLineage({shop,orderGid});assert.equal(line,null);
 const file=join(e.directory,'ledger.json'),state=JSON.parse(await readFile(file,'utf8'));
 state.claims.push({shop,reference:binding.reference,revision:1,orderGid:'gid://shopify/Order/88888'});
 await writeFile(file,JSON.stringify(state));
 const r=await e.issue();await rejects(e.observe(r),'LINEAGE_LEDGER_UNAVAILABLE');
 assert.equal(await e.ledger.getLineage({shop,orderGid}),null);
});
test('corrupted lineage state fails closed without replacing existing data',async t=>{
 const e=await setup(t);await accepted(e);
 const file=join(e.directory,'ledger.json'),s=JSON.parse(await readFile(file,'utf8'));
 s.lineage.push({...s.lineage[0]});await writeFile(file,JSON.stringify(s));
 await rejects(e.ledger.getLineage({shop,orderGid}),'LEDGER_STATE_DUPLICATE');
});
test('v0.11 snapshot lacking lineage fields migrates on first observed order',async t=>{
 const e=await setup(t),file=join(e.directory,'ledger.json');
 const s=JSON.parse(await readFile(file,'utf8'));delete s.lineage;delete s.lineageEvents;
 await writeFile(file,JSON.stringify(s));
 await accepted(e);
 const next=JSON.parse(await readFile(file,'utf8'));
 assert.equal(next.lineage.length,1);assert.equal(next.lineageEvents.length,1);
});
test('fault before rename does not persist phantom lineage, retry requires new receipt',async t=>{
 const e=await setup(t),r=await e.issue();
 const bad=createOfflineDurableLedger({directory:e.directory,injectFault:stage=>{
  if(stage==='before-rename')throw Error('simulated crash');}});
 const badLineage=createOfflineOrderLineage({verifyCartReceipt:e.authority.verify,
  resolveCheckout:async()=>checkout(),commitTransition:bad.commitLineageTransition,
  lookupLineageEvent:bad.lookupLineageEvent,clock:()=>now});
 await rejects(badLineage.transition({properties:r.properties,authContext:'offline-only',
  expectedBinding:binding,verifiedEvent:e.event()}),'LINEAGE_LEDGER_UNAVAILABLE');
 assert.equal(await e.ledger.getLineage({shop,orderGid}),null);
 // The nonce was already consumed: a fresh receipt is needed. This is an
 // explicitly documented non-production two-phase crash gap.
 await rejects(e.observe(r),'LINEAGE_CART_RECEIPT_REJECTED');
 const r2=await e.issue();assert.equal((await e.observe(r2)).outcome,'acquired');
});
test('atomic order commit races across processes: one acquired, others duplicate',async t=>{
 const e=await setup(t),lineHash='b'.repeat(64);
 const args={shop,eventId,bodySha256:'c'.repeat(64),action:'ORDER_OBSERVED',orderGid,
  checkoutId,ownerSubject:owner,sessionHash:lineHash,lineId:101,binding};
 const url=new URL('../src/offline-durable-ledger.mjs',import.meta.url).href;
 const source=`import {createOfflineDurableLedger} from ${JSON.stringify(url)};const l=createOfflineDurableLedger({directory:process.argv[1],lockTimeoutMs:5000});try{console.log(await l.commitLineageTransition(JSON.parse(process.argv[2])))}catch(e){console.error(e.code);process.exitCode=1}`;
 const child=()=>new Promise((resolve,reject)=>{
  const p=spawn(process.execPath,['--input-type=module','-e',source,e.directory,JSON.stringify(args)]);
  let out='',err='';p.stdout.on('data',b=>out+=b);p.stderr.on('data',b=>err+=b);
  p.on('error',reject);p.on('close',code=>resolve({code,out:out.trim(),err:err.trim()}));
 });
 const results=await Promise.all(Array.from({length:6},child));
 assert.equal(results.filter(x=>x.code===0&&x.out==='acquired').length,1,JSON.stringify(results));
 assert.equal(results.filter(x=>x.code===0&&x.out==='duplicate').length,5,JSON.stringify(results));
});
test('unavailable checkout resolver and ledger lookup fail closed',async t=>{
 const e=await setup(t),r=await e.issue(),ev=e.event();
 const down=createOfflineOrderLineage({verifyCartReceipt:e.authority.verify,
  resolveCheckout:async()=>{throw Error('offline');},commitTransition:e.ledger.commitLineageTransition,
  lookupLineageEvent:e.ledger.lookupLineageEvent});
 await rejects(down.transition({properties:r.properties,authContext:'offline-only',expectedBinding:binding,verifiedEvent:ev}),
  'LINEAGE_CHECKOUT_UNAVAILABLE');
 const downLedger=createOfflineOrderLineage({verifyCartReceipt:e.authority.verify,
  resolveCheckout:async()=>checkout(),commitTransition:e.ledger.commitLineageTransition,
  lookupLineageEvent:async()=>{throw Error('disk');}});
 await rejects(downLedger.transition({properties:r.properties,authContext:'offline-only',expectedBinding:binding,verifiedEvent:ev}),
  'LINEAGE_LEDGER_UNAVAILABLE');
 assert.equal((await e.observe(r,ev)).outcome,'acquired');
});
test('constructor and adapter invalid outcomes fail closed',async t=>{
 assert.throws(()=>createOfflineOrderLineage({}),{code:'LINEAGE_CONFIGURATION'});
 const e=await setup(t),r=await e.issue();
 const invalid=createOfflineOrderLineage({verifyCartReceipt:e.authority.verify,
  resolveCheckout:async()=>checkout(),commitTransition:async()=> 'unrecognized',
  lookupLineageEvent:async()=>null,clock:()=>now});
 await rejects(invalid.transition({properties:r.properties,authContext:'offline-only',expectedBinding:binding,verifiedEvent:e.event()}),
  'LINEAGE_LEDGER_INVALID');
});
test('checkout identity assertion in v2 verifier rejects independent owner/session substitution',async t=>{
 const e=await setup(t),r=await e.issue();
 await rejects(e.authority.verify({properties:r.properties,authContext:'offline-only',
  expectedBinding:binding,expectedIdentity:{shop,subject:'gid://shopify/Customer/9',sessionId}}),
  'METADATA_CHECKOUT_IDENTITY_MISMATCH');
 await rejects(e.authority.verify({properties:r.properties,authContext:'offline-only',
  expectedBinding:binding,expectedIdentity:{shop,subject:owner,sessionId:'other-session-012345'}}),
  'METADATA_CHECKOUT_IDENTITY_MISMATCH');
 assert.equal((await e.observe(r)).outcome,'acquired');
});
test('design CAS is rechecked atomically after receipt verification',async t=>{
 const e=await setup(t),r=await e.issue();
 const racing=createOfflineOrderLineage({verifyCartReceipt:e.authority.verify,
  resolveCheckout:async()=>checkout(),lookupLineageEvent:e.ledger.lookupLineageEvent,
  commitTransition:async args=>{
   await e.ledger.putDesignCAS({design:design({revision:2}),expectedRevision:1});
   return e.ledger.commitLineageTransition(args);
  },clock:()=>now});
 await rejects(racing.transition({properties:r.properties,authContext:'offline-only',
  expectedBinding:binding,verifiedEvent:e.event()}),'LINEAGE_LEDGER_UNAVAILABLE');
 assert.equal(await e.ledger.getLineage({shop,orderGid}),null);
});
test('after-rename lost acknowledgment recovers as duplicate without reusing cart nonce',async t=>{
 const e=await setup(t),r=await e.issue(),ev=e.event();
 const fault=createOfflineDurableLedger({directory:e.directory,injectFault:stage=>{
  if(stage==='after-rename')throw Error('ack lost');}});
 const crashing=createOfflineOrderLineage({verifyCartReceipt:e.authority.verify,
  resolveCheckout:async()=>checkout(),commitTransition:fault.commitLineageTransition,
  lookupLineageEvent:fault.lookupLineageEvent,clock:()=>now});
 await rejects(crashing.transition({properties:r.properties,authContext:'offline-only',
  expectedBinding:binding,verifiedEvent:ev}),'LINEAGE_LEDGER_UNAVAILABLE');
 assert.equal((await e.ledger.getLineage({shop,orderGid})).state,'OBSERVED');
 assert.equal((await e.observe(r,ev)).outcome,'duplicate');
});
test('conflicting same-order line ID rejects without altering observed state',async t=>{
 const e=await setup(t);await accepted(e);
 const line=await e.ledger.getLineage({shop,orderGid});
 const args={shop,eventId:'123e4567-e89b-42d3-a456-426614174003',bodySha256:'d'.repeat(64),
  action:'ORDER_OBSERVED',orderGid,checkoutId,ownerSubject:owner,
  sessionHash:line.sessionHash,lineId:102,binding};
 assert.equal(await e.ledger.commitLineageTransition(args),'conflict');
 assert.equal((await e.ledger.getLineage({shop,orderGid})).lineId,101);
});
test('unknown order cancellation, then valid cancellation after observation',async t=>{
 const e=await setup(t),ev=e.event({action:'CANCELLATION_OBSERVED'},'123e4567-e89b-42d3-a456-426614174004');
 await rejects(e.lineage.transition({verifiedEvent:ev}),'LINEAGE_LEDGER_UNAVAILABLE');
 await accepted(e);
 assert.equal((await e.lineage.transition({verifiedEvent:ev})).outcome,'acquired');
});
test('malformed trusted checkout flags and missing records reject',async t=>{
 const e=await setup(t),r=await e.issue();
 for(const changes of [{checkoutEnabled:true},{paymentVerified:true},{status:'PAID'},
  {schema:'TJ-TRUSTED-CHECKOUT-PRODUCTION'},{expiresAt:-1}]){
  e.checkout(checkout(changes));await rejects(e.observe(r),'LINEAGE_CHECKOUT_UNTRUSTED');
 }
 e.checkout(checkout());assert.equal((await e.observe(r)).outcome,'acquired');
});
test('signed event cannot claim to authorize payment, production or checkout',async t=>{
 const e=await setup(t),r=await e.issue();
 for(const extra of [{paymentVerified:true},{checkoutEnabled:true},{productionApproved:true}]){
  assert.throws(()=>e.event(extra),{code:'LINEAGE_EVENT_BODY_INVALID'});
 }
 assert.equal((await e.observe(r)).paymentVerified,false);
});
test('synthetic event ID is cryptographically bound to signed raw body',()=>{
 const rawBody=Buffer.from(JSON.stringify(body()));
 const validId=eventId;
 const sig=createHmac('sha256',webhookSecret).update(Buffer.concat([
  Buffer.from(`TJ-OFFLINE-LINEAGE-EVENT-1\0${shop}\0${validId}\0`),rawBody])).digest('base64url');
 const headers={'x-tj-shop':shop,'x-tj-event-id':'123e4567-e89b-42d3-a456-426614174009',
  'x-tj-signature':sig};
 assert.throws(()=>authenticateSyntheticLineageEvent({rawBody,headers,secret:webhookSecret,expectedShop:shop}),
  {code:'LINEAGE_EVENT_HMAC_INVALID'});
});
test('legacy order claim cannot reuse a design already observed by v2 lineage',async t=>{
 const e=await setup(t);await accepted(e);
 const legacy={eventKey:`${shop}:orders/create:123e4567-e89b-42d3-a456-426614174008`,
  bodySha256:'f'.repeat(64),orderGid:'gid://shopify/Order/55555',matchedLines:[binding]};
 await rejects(e.ledger.claimOnce(legacy),'LEDGER_DESIGN_ALREADY_CLAIMED');
});
