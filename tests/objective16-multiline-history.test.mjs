import test from 'node:test';
import assert from 'node:assert/strict';
import {createHmac,randomBytes} from 'node:crypto';
import {mkdtemp,rm,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {createOfflineDurableLedger} from '../src/offline-durable-ledger.mjs';
import {createOfflineVersionedMetadataAuthority} from '../src/versioned-cart-metadata.mjs';
import {createOfflineMultiLineage,authenticateSyntheticMultiLineEvent} from '../src/offline-multiline-order.mjs';
const shop='gucgmp-bc.myshopify.com',owner='gid://shopify/Customer/45678';
const sessionId='offline-session-multiline-012345',checkoutId='offline-checkout:'+'M'.repeat(24);
const orderGid='gid://shopify/Order/987654',eventId='123e4567-e89b-42d3-a456-426614174015';
const now=Date.now(),secret=randomBytes(32),webhookSecret=randomBytes(32);
const bindings=[{reference:'TJ-'+'A'.repeat(24),revision:1,productGid:'gid://shopify/Product/100',
 variantGid:'gid://shopify/ProductVariant/200',compositionSha256:'a'.repeat(64)},
 {reference:'TJ-'+'B'.repeat(24),revision:1,productGid:'gid://shopify/Product/101',
 variantGid:'gid://shopify/ProductVariant/201',compositionSha256:'b'.repeat(64)},
 {reference:'TJ-'+'C'.repeat(24),revision:1,productGid:'gid://shopify/Product/102',
 variantGid:'gid://shopify/ProductVariant/202',compositionSha256:'c'.repeat(64)}];
const lines=(count=2)=>bindings.slice(0,count).map((b,i)=>({lineId:101+i,...b}));
const principal=(changes={})=>({schema:'TJ-TRUSTED-PRINCIPAL-1',shop,subject:owner,kind:'customer',
 sessionId,expiresAt:now+600_000,checkoutEnabled:false,productionReady:false,...changes});
const checkout=(changes={})=>({schema:'TJ-TRUSTED-OFFLINE-CHECKOUT-1',shop,ownerSubject:owner,sessionId,
 checkoutId,status:'BOUND_OFFLINE',expiresAt:now+600_000,checkoutEnabled:false,paymentVerified:false,...changes});
const body=(changes={})=>({schema:'TJ-SYNTHETIC-MULTILINE-EVENT-1',shop,action:'ORDER_OBSERVED',
 checkoutId,orderGid,ownerSubject:owner,sessionId,lines:lines(),occurredAt:now,...changes});
const rejects=(promise,code)=>assert.rejects(promise,e=>e?.code===code);
function signed(changes={},id=eventId){
 const rawBody=Buffer.from(JSON.stringify(body(changes)));
 return authenticateSyntheticMultiLineEvent({rawBody,headers:headers(rawBody,id),secret:webhookSecret,expectedShop:shop});
}
function headers(rawBody,id=eventId){return {'x-tj-event-id':id,'x-tj-shop':shop,
 'x-tj-signature':createHmac('sha256',webhookSecret).update(Buffer.concat([
  Buffer.from(`TJ-OFFLINE-MULTILINE-EVENT-1\0${shop}\0${id.toLowerCase()}\0`),rawBody])).digest('base64url')};}
async function setup(t,{injectFault,lockMode='mkdir'}={}){
 const directory=await mkdtemp(join(tmpdir(),'tj-multi15-'));
 t.after(()=>rm(directory,{recursive:true,force:true}));
 const ledger=createOfflineDurableLedger({directory,lockTimeoutMs:5000,lockMode});
 for(const b of bindings)await ledger.putDesignCAS({design:{shop,ownerSubject:owner,...b,status:'CURRENT'}});
 let who=principal(),check=checkout(),time=now;
 const authority=createOfflineVersionedMetadataAuthority({keys:[{id:'key-v2',secret,status:'ACTIVE',
  notBefore:now-60_000,verifyUntil:now+1_200_000}],activeKeyId:'key-v2',clock:()=>time,
  resolvePrincipal:async()=>who,lookupDesign:ledger.lookupDesign,consumeNonce:ledger.consumeNonce});
 const make=(l=ledger)=>createOfflineMultiLineage({prepareCartReceipt:authority.prepareForAtomicLineage,
  resolveCheckout:async()=>check,lookupEvent:l.lookupMultiLineageEvent,
  commitObserved:args=>l.commitMultiLineageWithReceipts({...args,assertPreparedReceipt:authority.assertPreparedForAtomicLineage}),
  commitCancellation:l.commitMultiLineageCancellation,clock:()=>time});
 const lineage=make();
 const issue=async(count=2)=>Promise.all(bindings.slice(0,count).map((binding,i)=>authority.issue({authContext:'offline',binding}).then(r=>({lineId:101+i,properties:r.properties,expectedBinding:binding}))));
 const observe=(items,verifiedEvent=signed())=>lineage.transition({verifiedEvent,items,authContext:'offline'});
 const snapshot=()=>readFile(join(directory,'ledger.json'),'utf8').then(JSON.parse);
 return {directory,ledger,authority,lineage,make,issue,observe,snapshot,
  principal:p=>who=p,checkout:c=>check=c,clock:n=>time=n};
}
// Objective 16 — offline history reconciliation and crash-conscious cancellation.
const id=n=>`123e4567-e89b-42d3-a456-${String(426614170000+n).padStart(12,'0')}`;
const cancel=n=>signed({action:'CANCELLATION_OBSERVED'},id(n));
const ledgerPath=e=>join(e.directory,'ledger.json');
async function corrupt(e,edit){const file=ledgerPath(e),s=await e.snapshot();edit(s);await writeFile(file,JSON.stringify(s));return readFile(file,'utf8');}
async function assertRejectsUnchanged(e,code){
 const before=await readFile(ledgerPath(e),'utf8');
 await rejects(e.ledger.getMultiLineageHistory({shop,orderGid}),code);
 assert.equal(await readFile(ledgerPath(e),'utf8'),before);
}
test('historical reconciliation returns immutable exact order-wide snapshot without authorization',async t=>{
 const e=await setup(t),items=await e.issue();await e.observe(items);
 const history=await e.ledger.getMultiLineageHistory({shop,orderGid});
 assert.equal(history.schema,'TJ-OFFLINE-MULTILINE-HISTORY-1');
 assert.equal(history.state,'OBSERVED');assert.equal(history.lineCount,2);
 assert.equal(history.events.length,1);assert.equal(history.cancellationCount,0);
 assert.equal(history.observedEventId,eventId);
 assert.deepEqual(history.lines,lines());
 for(const k of ['checkoutEnabled','paymentVerified','productionApproved','fulfillmentAuthorized'])assert.equal(history[k],false);
 assert.equal(Object.isFrozen(history),true);assert.equal(Object.isFrozen(history.events),true);
 assert.equal(Object.isFrozen(history.events[0]),true);assert.equal(Object.isFrozen(history.lines[0]),true);
 assert.throws(()=>{history.lines[0].variantGid='gid://shopify/ProductVariant/9';},TypeError);
 assert.equal((await e.ledger.getMultiLineage({shop,orderGid})).state,'OBSERVED');
});
test('cancellation history records exact event sequence and preserves every claimed line',async t=>{
 const e=await setup(t),items=await e.issue();await e.observe(items);
 const original=await e.ledger.getMultiLineageHistory({shop,orderGid});
 assert.equal((await e.lineage.transition({verifiedEvent:cancel(101)})).outcome,'acquired');
 assert.equal((await e.lineage.transition({verifiedEvent:cancel(102)})).outcome,'duplicate');
 const history=await e.ledger.getMultiLineageHistory({shop,orderGid});
 assert.equal(history.state,'CANCELLED');assert.equal(history.cancellationCount,2);
 assert.deepEqual(history.events.map(x=>x.action),['ORDER_OBSERVED','CANCELLATION_OBSERVED','CANCELLATION_OBSERVED']);
 assert.deepEqual(history.lines,original.lines);
 const s=await e.snapshot();assert.equal(s.nonces.length,2);assert.equal(s.multiOrders.length,1);
});
test('historical lookup of nonexistent order is null and does not create state',async t=>{
 const e=await setup(t);const before=await readFile(ledgerPath(e),'utf8');
 assert.equal(await e.ledger.getMultiLineageHistory({shop,orderGid}),null);
 assert.equal(await readFile(ledgerPath(e),'utf8'),before);
});
test('missing multi-order record with retained event is rejected without rewriting',async t=>{
 const e=await setup(t);await e.observe(await e.issue());
 await corrupt(e,s=>{s.multiOrders=[];});
 await assertRejectsUnchanged(e,'LEDGER_MULTI_HISTORY_ORPHAN');
});
test('missing observed event with order retained is rejected',async t=>{
 const e=await setup(t);await e.observe(await e.issue());
 await corrupt(e,s=>{s.multiEvents=[];});
 await assertRejectsUnchanged(e,'LEDGER_MULTI_HISTORY_STATE');
});
test('duplicate ORDER_OBSERVED under distinct event ID is rejected',async t=>{
 const e=await setup(t);await e.observe(await e.issue());
 await corrupt(e,s=>{s.multiEvents.push({...s.multiEvents[0],eventId:id(103)});});
 await assertRejectsUnchanged(e,'LEDGER_MULTI_HISTORY_ORDER');
});
test('cancellation event without corresponding order fails closed',async t=>{
 const e=await setup(t);await e.observe(await e.issue());
 await corrupt(e,s=>{s.multiEvents.push({shop,eventId:id(104),bodySha256:'b'.repeat(64),orderGid:'gid://shopify/Order/9',action:'CANCELLATION_OBSERVED'});});
 await assertRejectsUnchanged(e,'LEDGER_MULTI_HISTORY_ORPHAN');
});
test('cancellation event inserted before original observation fails closed',async t=>{
 const e=await setup(t);await e.observe(await e.issue());
 await corrupt(e,s=>{s.multiEvents.unshift({shop,eventId:id(105),bodySha256:'b'.repeat(64),orderGid,action:'CANCELLATION_OBSERVED'});});
 await assertRejectsUnchanged(e,'LEDGER_MULTI_HISTORY_ORDER');
});
test('state CANCELLED without cancellation evidence fails closed',async t=>{
 const e=await setup(t);await e.observe(await e.issue());
 await corrupt(e,s=>{s.multiOrders[0].state='CANCELLED';});
 await assertRejectsUnchanged(e,'LEDGER_MULTI_HISTORY_STATE');
});
test('state OBSERVED with cancellation evidence fails closed',async t=>{
 const e=await setup(t);await e.observe(await e.issue());await e.lineage.transition({verifiedEvent:cancel(106)});
 await corrupt(e,s=>{s.multiOrders[0].state='OBSERVED';});
 await assertRejectsUnchanged(e,'LEDGER_MULTI_HISTORY_STATE');
});
test('swapped event action order and invalid event sequence fail closed',async t=>{
 const e=await setup(t);await e.observe(await e.issue());await e.lineage.transition({verifiedEvent:cancel(107)});
 await corrupt(e,s=>{s.multiEvents.reverse();});
 await assertRejectsUnchanged(e,'LEDGER_MULTI_HISTORY_ORDER');
});
test('tampered order line count rejects before a cancellation can mutate state',async t=>{
 const e=await setup(t);await e.observe(await e.issue());
 const before=await corrupt(e,s=>{s.multiOrders[0].lines.pop();});
 await rejects(e.lineage.transition({verifiedEvent:cancel(108)}),'MULTI_LEDGER_UNAVAILABLE');
 assert.equal(await readFile(ledgerPath(e),'utf8'),before);
});
test('wrong order, checkout, or owner cancellation cannot partially change state',async t=>{
 const e=await setup(t);await e.observe(await e.issue());
 for(const changes of [{orderGid:'gid://shopify/Order/9'},
  {checkoutId:'offline-checkout:'+'Z'.repeat(24)},
  {ownerSubject:'gid://shopify/Customer/999'}]){
  await rejects(e.lineage.transition({verifiedEvent:signed({action:'CANCELLATION_OBSERVED',...changes},id(109+Object.keys(changes)[0].length))}),
   (Object.hasOwn(changes,'ownerSubject')||Object.hasOwn(changes,'checkoutId'))?'MULTI_CHECKOUT_UNTRUSTED':'MULTI_LEDGER_UNAVAILABLE');
 }
 const s=await e.snapshot();assert.equal(s.multiOrders[0].state,'OBSERVED');assert.equal(s.multiEvents.length,1);
});
test('before-rename cancellation failure leaves observed order and history untouched; retry commits',async t=>{
 const e=await setup(t),items=await e.issue();await e.observe(items);
 const broken=createOfflineDurableLedger({directory:e.directory,injectFault:stage=>{
  if(stage==='before-rename')throw Error('synthetic interruption');}});
 const ev=cancel(121),before=await readFile(ledgerPath(e),'utf8');
 await rejects(e.make(broken).transition({verifiedEvent:ev}),'MULTI_LEDGER_UNAVAILABLE');
 assert.equal(await readFile(ledgerPath(e),'utf8'),before);
 assert.equal((await e.lineage.transition({verifiedEvent:ev})).outcome,'acquired');
 assert.equal((await e.ledger.getMultiLineageHistory({shop,orderGid})).cancellationCount,1);
});
test('after-rename cancellation lost acknowledgment is durable and retry idempotent',async t=>{
 const e=await setup(t);await e.observe(await e.issue());
 const broken=createOfflineDurableLedger({directory:e.directory,injectFault:stage=>{
  if(stage==='after-rename')throw Error('synthetic lost acknowledgment');}});
 const ev=cancel(122);
 await rejects(e.make(broken).transition({verifiedEvent:ev}),'MULTI_LEDGER_UNAVAILABLE');
 const before=await readFile(ledgerPath(e),'utf8');
 assert.equal((await e.lineage.transition({verifiedEvent:ev})).outcome,'duplicate');
 assert.equal(await readFile(ledgerPath(e),'utf8'),before);
 assert.equal((await e.ledger.getMultiLineageHistory({shop,orderGid})).cancellationCount,1);
});
test('simultaneous independent cancellations serialize to one acquired and one duplicate',async t=>{
 const e=await setup(t);await e.observe(await e.issue());
 const l2=e.make(createOfflineDurableLedger({directory:e.directory,lockTimeoutMs:5000}));
 const out=await Promise.all([e.lineage.transition({verifiedEvent:cancel(123)}),
  l2.transition({verifiedEvent:cancel(124)})]);
 assert.deepEqual(out.map(x=>x.outcome).sort(),['acquired','duplicate']);
 const h=await e.ledger.getMultiLineageHistory({shop,orderGid});
 assert.equal(h.state,'CANCELLED');assert.equal(h.cancellationCount,2);
 assert.equal((await e.snapshot()).nonces.length,2);
});
test('cancellation flood stops at bounded 32-event history without corrupting claims',async t=>{
 const e=await setup(t);await e.observe(await e.issue());
 for(let n=0;n<31;n++){
  const r=await e.lineage.transition({verifiedEvent:cancel(200+n)});
  assert.equal(r.outcome,n===0?'acquired':'duplicate');
 }
 const before=await readFile(ledgerPath(e),'utf8');
 await rejects(e.lineage.transition({verifiedEvent:cancel(231)}),'MULTI_LEDGER_UNAVAILABLE');
 assert.equal(await readFile(ledgerPath(e),'utf8'),before);
 const h=await e.ledger.getMultiLineageHistory({shop,orderGid});
 assert.equal(h.events.length,32);assert.equal(h.cancellationCount,31);
 assert.equal((await e.lineage.transition({verifiedEvent:cancel(200)})).outcome,'duplicate');
 assert.equal(await readFile(ledgerPath(e),'utf8'),before);
});
test('oversized injected per-order history is rejected on reads and subsequent writes',async t=>{
 const e=await setup(t);await e.observe(await e.issue());await e.lineage.transition({verifiedEvent:cancel(240)});
 const before=await corrupt(e,s=>{
  for(let n=0;n<31;n++)s.multiEvents.push({...s.multiEvents[1],eventId:id(300+n)});
 });
 await assertRejectsUnchanged(e,'LEDGER_MULTI_HISTORY_CAPACITY');
 await rejects(e.lineage.transition({verifiedEvent:cancel(241)}),'MULTI_LEDGER_UNAVAILABLE');
 assert.equal(await readFile(ledgerPath(e),'utf8'),before);
});
test('cancellation never releases claims to a different synthetic order',async t=>{
 const e=await setup(t);await e.observe(await e.issue());await e.lineage.transition({verifiedEvent:cancel(242)});
 const items=await e.issue();
 await rejects(e.observe(items,signed({orderGid:'gid://shopify/Order/777',checkoutId:'offline-checkout:'+'Q'.repeat(24)},id(243))),
  'MULTI_CHECKOUT_UNTRUSTED');
 // Even a new trusted checkout cannot steal a previously claimed design revision.
 e.checkout(checkout({checkoutId:'offline-checkout:'+'Q'.repeat(24)}));
 await rejects(e.observe(items,signed({orderGid:'gid://shopify/Order/777',checkoutId:'offline-checkout:'+'Q'.repeat(24)},id(244))),
  'MULTI_LEDGER_UNAVAILABLE');
 assert.equal((await e.snapshot()).multiOrders.length,1);
});
test('history remains read-only for migrated pre-multi ledger state',async t=>{
 const e=await setup(t),file=ledgerPath(e),s=await e.snapshot();
 delete s.multiOrders;delete s.multiEvents;await writeFile(file,JSON.stringify(s));
 const before=await readFile(file,'utf8');
 assert.equal(await e.ledger.getMultiLineageHistory({shop,orderGid}),null);
 assert.equal(await readFile(file,'utf8'),before);
});
test('three-line order cancellation preserves all distinct product and variant claims',async t=>{
 const e=await setup(t),items=await e.issue(3);
 await e.observe(items,signed({lines:lines(3)}));
 const before=await e.ledger.getMultiLineageHistory({shop,orderGid});
 assert.equal((await e.lineage.transition({verifiedEvent:signed({action:'CANCELLATION_OBSERVED',lines:lines(3)},id(400))})).outcome,'acquired');
 const after=await e.ledger.getMultiLineageHistory({shop,orderGid});
 assert.equal(after.state,'CANCELLED');assert.equal(after.lineCount,3);
 assert.deepEqual(after.lines,before.lines);
 assert.equal((await e.snapshot()).nonces.length,3);
});
test('expired trusted checkout still permits matching historical cancellation only',async t=>{
 const e=await setup(t);await e.observe(await e.issue());
 e.checkout(checkout({expiresAt:now-1}));
 assert.equal((await e.lineage.transition({verifiedEvent:cancel(401)})).outcome,'acquired');
 assert.equal((await e.ledger.getMultiLineageHistory({shop,orderGid})).state,'CANCELLED');
});
test('unknown action and orphan event remain rejected without state modification',async t=>{
 const e=await setup(t);await e.observe(await e.issue());
 await corrupt(e,s=>{s.multiEvents[0].action='FULFILLMENT_AUTHORIZED';});
 await assertRejectsUnchanged(e,'LEDGER_LINEAGE_EVENT_INVALID');
});
