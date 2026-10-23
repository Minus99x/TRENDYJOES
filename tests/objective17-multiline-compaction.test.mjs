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
 const directory=await mkdtemp(join(tmpdir(),'tj-compact17-'));
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

// Objective 17 — lossless synthetic event-header compaction, not deletion/GC.
async function cancelled(t,{count=2}={}){
 const e=await setup(t);await e.observe(await e.issue(count),signed({lines:lines(count)}));
 await e.lineage.transition({verifiedEvent:signed({action:'CANCELLATION_OBSERVED',lines:lines(count)},id(501))});
 return e;
}
const compact=e=>e.ledger.compactMultiLineageHistory({shop,orderGid});
const eventList=e=>e.ledger.getMultiLineageHistory({shop,orderGid});
const bytes=e=>readFile(ledgerPath(e),'utf8');
test('compaction moves all event replay IDs and digests into compact archive without dropping claims',async t=>{
 const e=await cancelled(t),before=await e.snapshot(),old=await eventList(e);
 assert.equal(await compact(e),'acquired');const after=await e.snapshot();
 assert.equal(after.multiEvents.length,0);assert.equal(after.multiArchives.length,1);
 assert.deepEqual(after.multiArchives[0].entries,before.multiEvents.map(x=>[x.eventId,x.bodySha256]));
 assert.deepEqual(after.multiOrders,before.multiOrders);assert.deepEqual(after.nonces,before.nonces);
 assert.deepEqual(after.designs,before.designs);assert.deepEqual(after.claims,before.claims);
 assert.deepEqual(await eventList(e),old);
});
test('compact state is strictly smaller for a two-event cancellation history',async t=>{
 const e=await cancelled(t);const before=(await bytes(e)).length;await compact(e);
 assert.ok((await bytes(e)).length<before);
});
test('compaction is idempotent without rewriting bytes',async t=>{
 const e=await cancelled(t);await compact(e);const before=await bytes(e);
 assert.equal(await compact(e),'duplicate');assert.equal(await bytes(e),before);
});
test('compaction rejects an observed but not cancelled order without touching state',async t=>{
 const e=await setup(t);await e.observe(await e.issue());const before=await bytes(e);
 await rejects(compact(e),'LEDGER_MULTI_COMPACTION_STATE');assert.equal(await bytes(e),before);
});
test('compaction rejects an unknown order and malformed arguments',async t=>{
 const e=await setup(t);await rejects(compact(e),'LEDGER_MULTI_UNKNOWN_ORDER');
 await rejects(e.ledger.compactMultiLineageHistory({shop:'evil.example',orderGid}),'LEDGER_MULTI_COMPACTION_INPUT');
 await rejects(e.ledger.compactMultiLineageHistory({shop,orderGid:'gid://shopify/Order/0'}),'LEDGER_MULTI_COMPACTION_INPUT');
});
test('archived observed event remains replay-idempotent through authenticated adapter',async t=>{
 const e=await cancelled(t),items=await e.issue();await compact(e);
 assert.equal((await e.observe(items)).outcome,'duplicate');
 assert.equal((await e.snapshot()).multiOrders.length,1);
});
test('archived cancellation remains replay-idempotent and event lookup reconstructs original header',async t=>{
 const e=await cancelled(t);const old=(await eventList(e)).events[1];await compact(e);
 assert.deepEqual(await e.ledger.lookupMultiLineageEvent({shop,eventId:id(501)}),old);
 assert.equal((await e.lineage.transition({verifiedEvent:cancel(501)})).outcome,'duplicate');
});
test('same archived UUID with different body is conflict, not duplicate',async t=>{
 const e=await cancelled(t);await compact(e);
 const x=await e.ledger.commitMultiLineageCancellation({shop,eventId:id(501),bodySha256:'f'.repeat(64),
  action:'CANCELLATION_OBSERVED',orderGid,checkoutId,ownerSubject:owner,sessionHash:'a'.repeat(64),lines:lines()});
 assert.equal(x,'conflict');
});
test('new cancellation after compaction extends archive without unarchiving and remains idempotent',async t=>{
 const e=await cancelled(t);await compact(e);
 assert.equal((await e.lineage.transition({verifiedEvent:cancel(502)})).outcome,'duplicate');
 const s=await e.snapshot();assert.equal(s.multiEvents.length,0);assert.equal(s.multiArchives[0].entries.length,3);
 assert.equal((await eventList(e)).cancellationCount,2);
 assert.equal((await e.lineage.transition({verifiedEvent:cancel(502)})).outcome,'duplicate');
});
test('archived history preserves 32-event cap and duplicate retries at capacity',async t=>{
 const e=await cancelled(t);await compact(e);
 for(let n=0;n<30;n++)await e.lineage.transition({verifiedEvent:cancel(600+n)});
 const before=await bytes(e);
 await rejects(e.lineage.transition({verifiedEvent:cancel(630)}),'MULTI_LEDGER_UNAVAILABLE');
 assert.equal(await bytes(e),before);
 assert.equal((await e.lineage.transition({verifiedEvent:cancel(600)})).outcome,'duplicate');
 assert.equal(await bytes(e),before);
 assert.equal((await eventList(e)).events.length,32);
});
test('two simultaneous compactions serialize and retain a single archive',async t=>{
 const e=await cancelled(t);const other=createOfflineDurableLedger({directory:e.directory,lockTimeoutMs:5000});
 const outcomes=await Promise.all([compact(e),other.compactMultiLineageHistory({shop,orderGid})]);
 assert.deepEqual(outcomes.sort(),['acquired','duplicate']);
 assert.equal((await e.snapshot()).multiArchives.length,1);
});
test('before-rename compaction failure leaves original replay records intact and can retry',async t=>{
 const e=await cancelled(t),before=await bytes(e);
 const broken=createOfflineDurableLedger({directory:e.directory,injectFault:stage=>{
  if(stage==='before-rename')throw Error('synthetic ENOSPC');}});
 await assert.rejects(broken.compactMultiLineageHistory({shop,orderGid}),/synthetic ENOSPC/);
 assert.equal(await bytes(e),before);assert.equal(await compact(e),'acquired');
});
test('after-rename lost acknowledgment retains archive; retry reports duplicate',async t=>{
 const e=await cancelled(t);const broken=createOfflineDurableLedger({directory:e.directory,injectFault:stage=>{
  if(stage==='after-rename')throw Error('synthetic crash');}});
 await assert.rejects(broken.compactMultiLineageHistory({shop,orderGid}),/synthetic crash/);
 const before=await bytes(e);assert.equal(await compact(e),'duplicate');assert.equal(await bytes(e),before);
});
test('archived history retains all three product/variant bindings across new cancellations',async t=>{
 const e=await cancelled(t,{count:3}),before=await eventList(e);await compact(e);
 await e.lineage.transition({verifiedEvent:signed({action:'CANCELLATION_OBSERVED',lines:lines(3)},id(503))});
 const after=await eventList(e);assert.deepEqual(after.lines,before.lines);assert.equal(after.lineCount,3);
 assert.equal((await e.snapshot()).nonces.length,3);
});
test('orphaned archive fails closed without mutating disk',async t=>{
 const e=await cancelled(t);await compact(e);const before=await corrupt(e,s=>{s.multiOrders=[];});
 await rejects(eventList(e),'LEDGER_MULTI_ARCHIVE_STATE');assert.equal(await bytes(e),before);
});
test('archive cannot coexist with unarchived events for the same order',async t=>{
 const e=await cancelled(t);await compact(e);const before=await corrupt(e,s=>{
  s.multiEvents.push({shop,eventId:id(700),bodySha256:'a'.repeat(64),orderGid,action:'CANCELLATION_OBSERVED'});
 });
 await rejects(eventList(e),'LEDGER_MULTI_ARCHIVE_STATE');assert.equal(await bytes(e),before);
});
test('duplicate archive event ID across two entries is rejected',async t=>{
 const e=await cancelled(t);await compact(e);const before=await corrupt(e,s=>{
  s.multiArchives[0].entries[1][0]=s.multiArchives[0].entries[0][0];
 });
 await rejects(eventList(e),'LEDGER_STATE_DUPLICATE');assert.equal(await bytes(e),before);
});
test('malformed compact entry fails closed, preserving source bytes',async t=>{
 const e=await cancelled(t);await compact(e);const before=await corrupt(e,s=>{
  s.multiArchives[0].entries[0][1]='not-a-hash';
 });
 await rejects(eventList(e),'LEDGER_MULTI_ARCHIVE_INVALID');assert.equal(await bytes(e),before);
});
test('missing archived cancellation is rejected by state invariant',async t=>{
 const e=await cancelled(t);await compact(e);const before=await corrupt(e,s=>{
  s.multiArchives[0].entries.pop();
 });
 await rejects(eventList(e),'LEDGER_MULTI_ARCHIVE_INVALID');assert.equal(await bytes(e),before);
});
test('duplicate archive record for same order is rejected',async t=>{
 const e=await cancelled(t);await compact(e);const before=await corrupt(e,s=>{
  s.multiArchives.push(structuredClone(s.multiArchives[0]));
 });
 await rejects(eventList(e),'LEDGER_MULTI_ARCHIVE_DUPLICATE');assert.equal(await bytes(e),before);
});
test('archived event ID cannot be claimed by legacy order protocol',async t=>{
 const e=await cancelled(t);await compact(e);
 await rejects(e.ledger.claimOnce({eventKey:`${shop}:orders/create:${id(501)}`,
  bodySha256:'c'.repeat(64),orderGid:'gid://shopify/Order/777',matchedLines:[bindings[0]]}),
  'LEDGER_CROSS_PROTOCOL_CONFLICT');
});
test('archived event ID cannot be claimed by single-lineage protocol',async t=>{
 const e=await cancelled(t);await compact(e);
 await rejects(e.ledger.commitLineageTransition({shop,eventId:id(501),bodySha256:'c'.repeat(64),
  action:'ORDER_OBSERVED',orderGid:'gid://shopify/Order/777',checkoutId:'offline-checkout:'+'Q'.repeat(24),
  ownerSubject:owner,sessionHash:'a'.repeat(64),lineId:101,binding:bindings[0]}),
  'LEDGER_CROSS_PROTOCOL_CONFLICT');
});
test('oversized persisted ledger fails closed on compaction and cannot be rewritten',async t=>{
 const e=await cancelled(t),file=ledgerPath(e);
 await writeFile(file,'x'.repeat(2*1024*1024+1));
 const before=await readFile(file);
 await rejects(compact(e),'LEDGER_FILE_UNSAFE');assert.deepEqual(await readFile(file),before);
});
test('compaction does not free immutable design claims to a new authenticated synthetic order',async t=>{
 const e=await cancelled(t);await compact(e);const before=await bytes(e);
 const newCheckout='offline-checkout:'+'Q'.repeat(24);
 e.checkout(checkout({checkoutId:newCheckout}));
 const items=await e.issue();
 await rejects(e.observe(items,signed({orderGid:'gid://shopify/Order/777',checkoutId:newCheckout},id(800))),
  'MULTI_LEDGER_UNAVAILABLE');
 assert.equal(await bytes(e),before);
});
