import test from 'node:test';
import assert from 'node:assert/strict';
import {createHmac,randomBytes} from 'node:crypto';
import {mkdtemp,rm,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {createOfflineDurableLedger} from '../src/offline-durable-ledger.mjs';
import {createOfflineVersionedMetadataAuthority} from '../src/versioned-cart-metadata.mjs';
import {createOfflineOrderLineage,authenticateSyntheticLineageEvent} from '../src/offline-order-lineage.mjs';

const shop='gucgmp-bc.myshopify.com',owner='gid://shopify/Customer/45678';
const sessionId='offline-session-0123456789',checkoutId='offline-checkout:'+'C'.repeat(20);
const orderGid='gid://shopify/Order/99999',eventId='123e4567-e89b-42d3-a456-426614174000';
const binding={reference:'TJ-'+'A'.repeat(24),revision:1,productGid:'gid://shopify/Product/12345',
 variantGid:'gid://shopify/ProductVariant/67890',compositionSha256:'a'.repeat(64)};
const now=Date.now(),secret=randomBytes(32),webhookSecret=randomBytes(32);
const design=(changes={})=>({shop,ownerSubject:owner,...binding,status:'CURRENT',...changes});
const principal=(changes={})=>({schema:'TJ-TRUSTED-PRINCIPAL-1',shop,subject:owner,kind:'customer',
 sessionId,expiresAt:now+10*60_000,checkoutEnabled:false,productionReady:false,...changes});
const checkout=(changes={})=>({schema:'TJ-TRUSTED-OFFLINE-CHECKOUT-1',shop,ownerSubject:owner,sessionId,
 checkoutId,status:'BOUND_OFFLINE',expiresAt:now+10*60_000,checkoutEnabled:false,paymentVerified:false,...changes});
const body=(changes={})=>({schema:'TJ-SYNTHETIC-LINEAGE-EVENT-1',shop,action:'ORDER_OBSERVED',
 checkoutId,orderGid,ownerSubject:owner,sessionId,lineId:101,...binding,occurredAt:now,...changes});
const rejects=(promise,code)=>assert.rejects(promise,e=>e?.code===code);
function signed(changes={},id=eventId){
 const rawBody=Buffer.from(JSON.stringify(body(changes)));
 const headers={'x-tj-event-id':id,'x-tj-shop':shop,'x-tj-signature':createHmac('sha256',webhookSecret)
  .update(Buffer.concat([Buffer.from(`TJ-OFFLINE-LINEAGE-EVENT-1\0${shop}\0${id}\0`),rawBody])).digest('base64url')};
 return authenticateSyntheticLineageEvent({rawBody,headers,secret:webhookSecret,expectedShop:shop});
}
async function setup(t){
 const directory=await mkdtemp(join(tmpdir(),'tj-atomic13-'));t.after(()=>rm(directory,{recursive:true,force:true}));
 const ledger=createOfflineDurableLedger({directory,lockTimeoutMs:5000});await ledger.putDesignCAS({design:design()});
 let who=principal(),check=checkout(),time=now;
 const authority=createOfflineVersionedMetadataAuthority({keys:[{id:'key-v2',secret,status:'ACTIVE',
  notBefore:now-60_000,verifyUntil:now+20*60_000}],activeKeyId:'key-v2',clock:()=>time,
  resolvePrincipal:async()=>who,lookupDesign:ledger.lookupDesign,consumeNonce:ledger.consumeNonce});
 const makeLineage=(target=ledger,overrides={})=>createOfflineOrderLineage({
  verifyCartReceipt:authority.verify,prepareCartReceipt:authority.prepareForAtomicLineage,
  resolveCheckout:async()=>check,lookupLineageEvent:target.lookupLineageEvent,
  commitTransition:target.commitLineageTransition,
  commitAtomicObserved:args=>target.commitLineageWithReceipt({...args,
   assertPreparedReceipt:authority.assertPreparedForAtomicLineage}),clock:()=>time,...overrides});
 const lineage=makeLineage();
 const issue=()=>authority.issue({authContext:'offline-only',binding});
 const observe=(receipt,ev=signed(),expectedBinding=binding)=>lineage.transition({
  verifiedEvent:ev,properties:receipt.properties,authContext:'offline-only',expectedBinding});
 const snapshot=()=>readFile(join(directory,'ledger.json'),'utf8').then(JSON.parse);
 return {directory,ledger,authority,lineage,issue,observe,makeLineage,snapshot,
  who:p=>who=p,check:c=>check=c,clock:n=>time=n};
}
test('atomic observed order persists nonce, lineage and event in one ledger snapshot',async t=>{
 const e=await setup(t),receipt=await e.issue(),out=await e.observe(receipt);
 assert.equal(out.outcome,'acquired');assert.equal(out.paymentVerified,false);
 const s=await e.snapshot();assert.equal(s.nonces.length,1);assert.equal(s.lineage.length,1);
 assert.equal(s.lineageEvents.length,1);assert.equal(s.lineage[0].state,'OBSERVED');
 assert.equal(JSON.stringify(s).includes(sessionId),false);
});
test('identical authenticated event retries without consuming another nonce',async t=>{
 const e=await setup(t),receipt=await e.issue();await e.observe(receipt);
 assert.equal((await e.observe(receipt)).outcome,'duplicate');
 assert.equal((await e.snapshot()).nonces.length,1);
});
test('same receipt with different event ID is rejected and does not add a lineage event',async t=>{
 const e=await setup(t),r=await e.issue();await e.observe(r);
 await rejects(e.observe(r,signed({},'123e4567-e89b-42d3-a456-426614174001')),'LINEAGE_LEDGER_UNAVAILABLE');
 assert.equal((await e.snapshot()).lineageEvents.length,1);
});
test('prepared receipt is branded, immutable and cannot be fabricated by copying fields',async t=>{
 const e=await setup(t),r=await e.issue(),proof=await e.authority.prepareForAtomicLineage({
  properties:r.properties,authContext:'offline-only',expectedBinding:binding,
  expectedIdentity:{shop,subject:owner,sessionId}});
 assert.equal(Object.isFrozen(proof),true);assert.equal(Object.isFrozen(proof.expectedDesign),true);
 assert.throws(()=>e.authority.assertPreparedForAtomicLineage({...proof}),{code:'METADATA_PREPARED_UNTRUSTED'});
 const args={shop,eventId,bodySha256:'b'.repeat(64),action:'ORDER_OBSERVED',orderGid,
  checkoutId,ownerSubject:owner,sessionHash:proof.sessionHash,lineId:101,binding,
  preparedReceipt:{...proof},assertPreparedReceipt:e.authority.assertPreparedForAtomicLineage};
 await rejects(e.ledger.commitLineageWithReceipt(args),'METADATA_PREPARED_UNTRUSTED');
 assert.equal((await e.snapshot()).nonces.length,0);
});
test('HMAC tamper fails before nonce or lineage write',async t=>{
 const e=await setup(t),r=await e.issue(),token=r.properties['_TJ Cart Receipt'];
 await rejects(e.observe({properties:{...r.properties,'_TJ Cart Receipt':token.slice(0,-1)+(token.at(-1)==='A'?'B':'A')}}),'LINEAGE_CART_RECEIPT_REJECTED');
 const s=await e.snapshot();assert.equal(s.nonces.length,0);assert.equal(s.lineage.length,0);
 assert.equal((await e.observe(r)).outcome,'acquired');
});
test('owner and checkout identity mismatch does not consume receipt',async t=>{
 const e=await setup(t),r=await e.issue();e.who(principal({sessionId:'different-session-012345'}));
 await rejects(e.observe(r),'LINEAGE_CART_RECEIPT_REJECTED');
 e.who(principal());e.check(checkout({sessionId:'different-session-012345'}));
 await rejects(e.observe(r),'LINEAGE_CHECKOUT_UNTRUSTED');
 e.check(checkout());assert.equal((await e.observe(r)).outcome,'acquired');
});
test('revision changed after preparation is rejected atomically without consuming nonce',async t=>{
 const e=await setup(t),r=await e.issue();
 const proof=await e.authority.prepareForAtomicLineage({properties:r.properties,
  authContext:'offline-only',expectedBinding:binding,expectedIdentity:{shop,subject:owner,sessionId}});
 await e.ledger.putDesignCAS({design:design({revision:2}),expectedRevision:1});
 await rejects(e.ledger.commitLineageWithReceipt({shop,eventId,bodySha256:'b'.repeat(64),
  action:'ORDER_OBSERVED',orderGid,checkoutId,ownerSubject:owner,sessionHash:proof.sessionHash,
  lineId:101,binding,preparedReceipt:proof,assertPreparedReceipt:e.authority.assertPreparedForAtomicLineage}),
 'LEDGER_LINEAGE_DESIGN_CAS');
 const s=await e.snapshot();assert.equal(s.nonces.length,0);assert.equal(s.lineage.length,0);
});
test('crash before rename persists neither nonce nor lineage; same receipt retries',async t=>{
 const e=await setup(t),r=await e.issue();
 const bad=createOfflineDurableLedger({directory:e.directory,injectFault:stage=>{
  if(stage==='before-rename')throw Error('simulated power cut');}});
 await rejects(e.makeLineage(bad).transition({verifiedEvent:signed(),properties:r.properties,
  authContext:'offline-only',expectedBinding:binding}),'LINEAGE_LEDGER_UNAVAILABLE');
 const s=await e.snapshot();assert.equal(s.nonces.length,0);assert.equal(s.lineage.length,0);
 assert.equal((await e.observe(r)).outcome,'acquired');
});
test('crash after rename commits both records and identical event retry is duplicate',async t=>{
 const e=await setup(t),r=await e.issue();
 const bad=createOfflineDurableLedger({directory:e.directory,injectFault:stage=>{
  if(stage==='after-rename')throw Error('simulated lost ack');}});
 await rejects(e.makeLineage(bad).transition({verifiedEvent:signed(),properties:r.properties,
  authContext:'offline-only',expectedBinding:binding}),'LINEAGE_LEDGER_UNAVAILABLE');
 const s=await e.snapshot();assert.equal(s.nonces.length,1);assert.equal(s.lineage.length,1);
 assert.equal((await e.observe(r)).outcome,'duplicate');
});
test('two ledger adapters racing same receipt cannot both consume or double-claim',async t=>{
 const e=await setup(t),r=await e.issue(),other=createOfflineDurableLedger({directory:e.directory,lockTimeoutMs:5000});
 const args={verifiedEvent:signed(),properties:r.properties,authContext:'offline-only',expectedBinding:binding};
 const results=await Promise.allSettled([e.lineage.transition(args),e.makeLineage(other).transition(args)]);
 assert.equal(results.filter(x=>x.status==='fulfilled').length,2,JSON.stringify(results));
 assert.deepEqual(results.map(x=>x.value.outcome).sort(),['acquired','duplicate']);
 const s=await e.snapshot();assert.equal(s.nonces.length,1);assert.equal(s.lineage.length,1);
});
test('alternate receipt for claimed checkout cannot consume its nonce',async t=>{
 const e=await setup(t),r1=await e.issue();await e.observe(r1);
 const r2=await e.issue();await rejects(e.observe(r2,signed({},'123e4567-e89b-42d3-a456-426614174002')),'LINEAGE_LEDGER_UNAVAILABLE');
 assert.equal((await e.snapshot()).nonces.length,1);
});
test('cancellation remains non-authorizing and preserves original nonce claim',async t=>{
 const e=await setup(t),r=await e.issue();await e.observe(r);
 const cancel=signed({action:'CANCELLATION_OBSERVED'},'123e4567-e89b-42d3-a456-426614174003');
 const result=await e.lineage.transition({verifiedEvent:cancel});assert.equal(result.outcome,'acquired');
 const s=await e.snapshot();assert.equal(s.nonces.length,1);assert.equal(s.lineage[0].state,'CANCELLED');
});
test('v0.11-style snapshot without nonce or lineage arrays migrates atomically',async t=>{
 const e=await setup(t),file=join(e.directory,'ledger.json'),s=await e.snapshot();
 delete s.nonces;delete s.lineage;delete s.lineageEvents;await writeFile(file,JSON.stringify(s));
 assert.equal((await e.observe(await e.issue())).outcome,'acquired');
 const next=await e.snapshot();assert.equal(next.nonces.length,1);assert.equal(next.lineage.length,1);
});
test('corrupted nonce state blocks order and leaves existing file unchanged',async t=>{
 const e=await setup(t),r=await e.issue(),file=join(e.directory,'ledger.json'),s=await e.snapshot();
 s.nonces=[{nonceKey:'bad',receiptSha256:'a'.repeat(64),expiresAt:now+10000}];
 await writeFile(file,JSON.stringify(s));const before=await readFile(file,'utf8');
 await rejects(e.observe(r),'LINEAGE_LEDGER_UNAVAILABLE');
 assert.equal(await readFile(file,'utf8'),before);
});
test('atomic adapter configuration rejects partial installation',async t=>{
 const e=await setup(t);
 assert.throws(()=>createOfflineOrderLineage({verifyCartReceipt:e.authority.verify,
  resolveCheckout:async()=>checkout(),commitTransition:e.ledger.commitLineageTransition,
  lookupLineageEvent:e.ledger.lookupLineageEvent,prepareCartReceipt:e.authority.prepareForAtomicLineage}),
 {code:'LINEAGE_CONFIGURATION'});
});
test('legacy nonce consumption cannot be reused for atomic lineage',async t=>{
 const e=await setup(t),r=await e.issue();
 await e.authority.verify({properties:r.properties,authContext:'offline-only',expectedBinding:binding});
 await rejects(e.observe(r),'LINEAGE_LEDGER_UNAVAILABLE');
 const s=await e.snapshot();assert.equal(s.nonces.length,1);assert.equal(s.lineage.length,0);
});
test('cross-process atomic race: one acquired and one replay rejected, one durable order',async t=>{
 const e=await setup(t),r=await e.issue();
 const ledgerUrl=new URL('../src/offline-durable-ledger.mjs',import.meta.url).href;
 const authUrl=new URL('../src/versioned-cart-metadata.mjs',import.meta.url).href;
 const payload={directory:e.directory,secret:secret.toString('base64'),properties:r.properties,
  shop,owner,sessionId,now,binding,checkoutId,orderGid,eventId};
 const source=`import {createOfflineDurableLedger} from ${JSON.stringify(ledgerUrl)};
 import {createOfflineVersionedMetadataAuthority} from ${JSON.stringify(authUrl)};
 const a=JSON.parse(process.argv[1]),l=createOfflineDurableLedger({directory:a.directory,lockTimeoutMs:5000});
 const authority=createOfflineVersionedMetadataAuthority({keys:[{id:'key-v2',secret:Buffer.from(a.secret,'base64'),status:'ACTIVE',notBefore:a.now-60000,verifyUntil:a.now+1200000}],activeKeyId:'key-v2',clock:()=>a.now,resolvePrincipal:async()=>({schema:'TJ-TRUSTED-PRINCIPAL-1',shop:a.shop,subject:a.owner,kind:'customer',sessionId:a.sessionId,expiresAt:a.now+600000,checkoutEnabled:false,productionReady:false}),lookupDesign:l.lookupDesign,consumeNonce:l.consumeNonce});
 try{const p=await authority.prepareForAtomicLineage({properties:a.properties,authContext:'offline',expectedBinding:a.binding,expectedIdentity:{shop:a.shop,subject:a.owner,sessionId:a.sessionId}});
 const outcome=await l.commitLineageWithReceipt({shop:a.shop,eventId:a.eventId,bodySha256:'b'.repeat(64),action:'ORDER_OBSERVED',orderGid:a.orderGid,checkoutId:a.checkoutId,ownerSubject:a.owner,sessionHash:p.sessionHash,lineId:101,binding:a.binding,preparedReceipt:p,assertPreparedReceipt:authority.assertPreparedForAtomicLineage});console.log(outcome)}catch(e){console.error(e.code);process.exitCode=1}`;
 const child=()=>new Promise((resolve,reject)=>{
  const p=spawn(process.execPath,['--input-type=module','-e',source,JSON.stringify(payload)]);
  let out='',err='';p.stdout.on('data',x=>out+=x);p.stderr.on('data',x=>err+=x);
  p.on('error',reject);p.on('close',code=>resolve({code,out:out.trim(),err:err.trim()}));
 });
 const results=await Promise.all(Array.from({length:4},child));
 assert.equal(results.filter(x=>x.code===0&&x.out==='acquired').length,1,JSON.stringify(results));
 assert.equal(results.filter(x=>x.code===0&&x.out==='duplicate').length,3,JSON.stringify(results));
 const s=await e.snapshot();assert.equal(s.nonces.length,1);assert.equal(s.lineage.length,1);
});
test('prepared receipt expiry before atomic commit fails closed',async t=>{
 const e=await setup(t),r=await e.authority.issue({authContext:'offline-only',binding,ttlMs:1000});
 const proof=await e.authority.prepareForAtomicLineage({properties:r.properties,
  authContext:'offline-only',expectedBinding:binding,expectedIdentity:{shop,subject:owner,sessionId}});
 e.clock(now+1000);
 const args={shop,eventId,bodySha256:'b'.repeat(64),action:'ORDER_OBSERVED',orderGid,
  checkoutId,ownerSubject:owner,sessionHash:proof.sessionHash,lineId:101,binding,
  preparedReceipt:proof,assertPreparedReceipt:e.authority.assertPreparedForAtomicLineage};
 await rejects(e.ledger.commitLineageWithReceipt(args),'METADATA_PREPARED_UNTRUSTED');
 assert.equal((await e.snapshot()).nonces.length,0);
});
test('prepared receipt cannot be used with substituted session hash or variant',async t=>{
 const e=await setup(t),r=await e.issue(),proof=await e.authority.prepareForAtomicLineage({
  properties:r.properties,authContext:'offline-only',expectedBinding:binding,
  expectedIdentity:{shop,subject:owner,sessionId}});
 const args={shop,eventId,bodySha256:'b'.repeat(64),action:'ORDER_OBSERVED',orderGid,
  checkoutId,ownerSubject:owner,sessionHash:proof.sessionHash,lineId:101,binding,
  preparedReceipt:proof,assertPreparedReceipt:e.authority.assertPreparedForAtomicLineage};
 await rejects(e.ledger.commitLineageWithReceipt({...args,sessionHash:'b'.repeat(64)}),'LEDGER_ATOMIC_RECEIPT_INVALID');
 await rejects(e.ledger.commitLineageWithReceipt({...args,binding:{...binding,variantGid:'gid://shopify/ProductVariant/99'}}),'LEDGER_ATOMIC_RECEIPT_INVALID');
 assert.equal((await e.snapshot()).nonces.length,0);
});
test('existing legacy claim prevents atomic observed order without burning nonce',async t=>{
 const e=await setup(t),r=await e.issue();
 await e.ledger.claimOnce({eventKey:`${shop}:orders/create:123e4567-e89b-42d3-a456-426614174055`,
  bodySha256:'b'.repeat(64),orderGid:'gid://shopify/Order/77777',matchedLines:[binding]});
 await rejects(e.observe(r),'LINEAGE_LEDGER_UNAVAILABLE');
 assert.equal((await e.snapshot()).nonces.length,0);
});
test('different authenticated event with same ID and body conflict is rejected',async t=>{
 const e=await setup(t),r=await e.issue();await e.observe(r);
 await rejects(e.observe(r,signed({lineId:102})),'LINEAGE_TRANSITION_CONFLICT');
 assert.equal((await e.snapshot()).lineageEvents.length,1);
});
test('order observation cannot be used to authorize fulfillment or payment',async t=>{
 const e=await setup(t),r=await e.issue(),out=await e.observe(r);
 for(const field of ['checkoutEnabled','paymentVerified','productionApproved','fulfillmentAuthorized'])
  assert.equal(out[field],false);
 const s=await e.snapshot();assert.equal(s.lineage[0].state,'OBSERVED');
 assert.equal(Object.keys(s.lineage[0]).some(k=>/paid|fulfill|print|ship/i.test(k)),false);
});
