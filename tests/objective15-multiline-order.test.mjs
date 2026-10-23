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
test('two customized lines commit one event and two nonces atomically',async t=>{
 const e=await setup(t),items=await e.issue(),out=await e.observe(items);
 assert.equal(out.outcome,'acquired');assert.equal(out.lineCount,2);
 const s=await e.snapshot();assert.equal(s.nonces.length,2);assert.equal(s.multiOrders.length,1);
 assert.equal(s.multiOrders[0].lines.length,2);assert.equal(s.multiEvents.length,1);
 assert.equal(s.multiOrders[0].state,'OBSERVED');
 for(const k of ['checkoutEnabled','paymentVerified','productionApproved','fulfillmentAuthorized'])assert.equal(out[k],false);
 assert.equal(JSON.stringify(s).includes(sessionId),false);
});
test('three customized lines from distinct products commit together',async t=>{
 const e=await setup(t),items=await e.issue(3);
 assert.equal((await e.observe(items,signed({lines:lines(3)}))).outcome,'acquired');
 assert.equal((await e.snapshot()).nonces.length,3);
});
test('identical authenticated event retries without consuming another nonce',async t=>{
 const e=await setup(t),items=await e.issue();await e.observe(items);
 assert.equal((await e.observe(items)).outcome,'duplicate');
 assert.equal((await e.snapshot()).nonces.length,2);
});
test('forged event object cannot bypass authentication',async t=>{
 const e=await setup(t),items=await e.issue();await rejects(e.observe(items,{...signed()}),'MULTI_EVENT_UNTRUSTED');
 assert.equal((await e.snapshot()).nonces.length,0);
});
test('HMAC tamper, substituted event ID, and wrong shop header reject',()=>{
 const raw=Buffer.from(JSON.stringify(body())),h=headers(raw);
 const bad=Buffer.from(JSON.stringify(body({orderGid:'gid://shopify/Order/9'})));
 assert.throws(()=>authenticateSyntheticMultiLineEvent({rawBody:bad,headers:h,secret:webhookSecret,expectedShop:shop}),{code:'MULTI_HMAC_INVALID'});
 assert.throws(()=>authenticateSyntheticMultiLineEvent({rawBody:raw,headers:{...h,'x-tj-event-id':'123e4567-e89b-42d3-a456-426614174016'},secret:webhookSecret,expectedShop:shop}),{code:'MULTI_HMAC_INVALID'});
 assert.throws(()=>authenticateSyntheticMultiLineEvent({rawBody:raw,headers:{...h,'x-tj-shop':'other.myshopify.com'},secret:webhookSecret,expectedShop:shop}),{code:'MULTI_ENVELOPE_INVALID'});
});
test('duplicate JSON keys, noncanonical encoding and oversized body reject',()=>{
 const raw=JSON.stringify(body());
 for(const input of [raw.replace('"revision":1','"revision":1,"revision":2'),raw.replace('"revision":1','"revision": 1'),raw+' '.repeat(17_000)]){
  const bytes=Buffer.from(input);
  assert.throws(()=>authenticateSyntheticMultiLineEvent({rawBody:bytes,headers:headers(bytes),secret:webhookSecret,expectedShop:shop}));
 }
});
test('malformed, duplicated, and excessive line arrays reject before any write',()=>{
 for(const bad of [[lines()[0]],[lines()[0],lines()[0]],
  [{...lines()[0]},{...lines()[1],lineId:101}],
  [{...lines()[0]},{...lines()[1],reference:lines()[0].reference}],
  Array.from({length:26},(_,i)=>({...lines()[i%2],lineId:i+1,reference:'TJ-'+String(i).padStart(24,'A')}))]){
  assert.throws(()=>signed({lines:bad}),{code:'MULTI_BODY_INVALID'});
 }
});
test('authenticated event line objects are deeply immutable',()=>{
 const ev=signed();assert.equal(Object.isFrozen(ev.body.lines),true);
 assert.equal(Object.isFrozen(ev.body.lines[0]),true);
 assert.throws(()=>{ev.body.lines[0].variantGid='gid://shopify/ProductVariant/9';},TypeError);
});
test('missing receipt, swapped receipt positions, and unexpected extra item fail closed',async t=>{
 const e=await setup(t),items=await e.issue();
 for(const candidate of [items.slice(0,1),[items[1],items[0]],[...items,items[0]]])
  await rejects(e.observe(candidate),candidate.length===2?'MULTI_ITEMS_MISMATCH':'MULTI_ITEMS_INVALID');
 assert.equal((await e.snapshot()).nonces.length,0);
});
test('variant substitution and digest substitution reject before consumption',async t=>{
 const e=await setup(t),items=await e.issue();
 for(const changed of [{...lines()[1],variantGid:'gid://shopify/ProductVariant/999'},
  {...lines()[1],compositionSha256:'f'.repeat(64)}])
  await rejects(e.observe(items,signed({lines:[lines()[0],changed]})),'MULTI_ITEMS_MISMATCH');
 assert.equal((await e.snapshot()).nonces.length,0);
});
test('principal session and owner substitution reject without nonce use',async t=>{
 const e=await setup(t),items=await e.issue();
 e.principal(principal({sessionId:'different-session-012345'}));
 await rejects(e.observe(items),'MULTI_CART_RECEIPT_REJECTED');
 e.principal(principal());
 await rejects(e.observe(items,signed({ownerSubject:'gid://shopify/Customer/999'})),'MULTI_CHECKOUT_UNTRUSTED');
 assert.equal((await e.snapshot()).nonces.length,0);
});
test('checkout substitution, expiry, stale and future events fail closed',async t=>{
 const e=await setup(t),items=await e.issue();
 e.checkout(checkout({checkoutId:'offline-checkout:'+'X'.repeat(24)}));
 await rejects(e.observe(items),'MULTI_CHECKOUT_UNTRUSTED');
 e.checkout(checkout({expiresAt:now}));await rejects(e.observe(items),'MULTI_CHECKOUT_UNTRUSTED');
 e.checkout(checkout());
 await rejects(e.observe(items,signed({occurredAt:now-300_001})),'MULTI_EVENT_TIME_INVALID');
 await rejects(e.observe(items,signed({occurredAt:now+60_001})),'MULTI_EVENT_TIME_INVALID');
 assert.equal((await e.snapshot()).nonces.length,0);
});
test('stale second design revision prevents ALL line claims',async t=>{
 const e=await setup(t),items=await e.issue();
 await e.ledger.putDesignCAS({design:{shop,ownerSubject:owner,...bindings[1],revision:2,status:'CURRENT'},expectedRevision:1});
 await rejects(e.observe(items),'MULTI_CART_RECEIPT_REJECTED');
 const s=await e.snapshot();assert.equal(s.nonces.length,0);assert.equal(s.multiOrders.length,0);
});
test('replayed second receipt causes atomic rollback of first receipt',async t=>{
 const e=await setup(t),items=await e.issue();
 await e.authority.verify({properties:items[1].properties,authContext:'offline',expectedBinding:bindings[1]});
 await rejects(e.observe(items),'MULTI_LEDGER_UNAVAILABLE');
 const s=await e.snapshot();assert.equal(s.nonces.length,1);assert.equal(s.multiOrders.length,0);
});
test('same receipt reused twice in two lines is rejected without consuming',async t=>{
 const e=await setup(t),items=await e.issue();
 await rejects(e.observe([{...items[0]},{...items[1],properties:items[0].properties}]),'MULTI_CART_RECEIPT_REJECTED');
 assert.equal((await e.snapshot()).nonces.length,0);
});
test('two concurrent instances commit one order, one duplicate, never two',async t=>{
 const e=await setup(t),items=await e.issue(),args={verifiedEvent:signed(),items,authContext:'offline'};
 const l2=e.make(createOfflineDurableLedger({directory:e.directory,lockTimeoutMs:5000}));
 const results=await Promise.all([e.lineage.transition(args),l2.transition(args)]);
 assert.deepEqual(results.map(r=>r.outcome).sort(),['acquired','duplicate']);
 const s=await e.snapshot();assert.equal(s.nonces.length,2);assert.equal(s.multiOrders.length,1);
});
test('same event ID with different authenticated body rejects without new claims',async t=>{
 const e=await setup(t),items=await e.issue();await e.observe(items);
 await rejects(e.observe(items,signed({orderGid:'gid://shopify/Order/888'})),'MULTI_EVENT_CONFLICT');
 assert.equal((await e.snapshot()).multiEvents.length,1);
});
test('same order or checkout with new event cannot consume fresh receipts',async t=>{
 const e=await setup(t),items=await e.issue();await e.observe(items);
 const more=await e.issue();
 await rejects(e.observe(more,signed({},'123e4567-e89b-42d3-a456-426614174016')),'MULTI_LEDGER_UNAVAILABLE');
 assert.equal((await e.snapshot()).nonces.length,2);
});
test('cancel requires matching every line and forbids cart metadata',async t=>{
 const e=await setup(t),items=await e.issue();await e.observe(items);
 const cancel=signed({action:'CANCELLATION_OBSERVED'},'123e4567-e89b-42d3-a456-426614174017');
 await rejects(e.lineage.transition({verifiedEvent:cancel,items}),'MULTI_CANCEL_CART_NOT_ALLOWED');
 await rejects(e.lineage.transition({verifiedEvent:signed({action:'CANCELLATION_OBSERVED',lines:[lines()[0],{...lines()[1],lineId:888}]},'123e4567-e89b-42d3-a456-426614174018')}),'MULTI_LEDGER_UNAVAILABLE');
 assert.equal((await e.lineage.transition({verifiedEvent:cancel})).outcome,'acquired');
 assert.equal((await e.lineage.transition({verifiedEvent:cancel})).outcome,'duplicate');
 const s=await e.snapshot();assert.equal(s.multiOrders[0].state,'CANCELLED');assert.equal(s.nonces.length,2);
});
test('cancellation before observation cannot create a synthetic order',async t=>{
 const e=await setup(t);
 await rejects(e.lineage.transition({verifiedEvent:signed({action:'CANCELLATION_OBSERVED'})}),'MULTI_LEDGER_UNAVAILABLE');
 assert.equal((await e.snapshot()).multiOrders.length,0);
});
test('legacy single-line claim blocks multi-line commit without nonce loss',async t=>{
 const e=await setup(t),items=await e.issue();
 await e.ledger.claimOnce({eventKey:`${shop}:orders/create:123e4567-e89b-42d3-a456-426614174019`,
  bodySha256:'e'.repeat(64),orderGid:'gid://shopify/Order/123',matchedLines:[bindings[1]]});
 await rejects(e.observe(items),'MULTI_LEDGER_UNAVAILABLE');
 assert.equal((await e.snapshot()).nonces.length,0);
});
test('multi-line claims block legacy single-line claim and order reuse',async t=>{
 const e=await setup(t),items=await e.issue();await e.observe(items);
 await rejects(e.ledger.claimOnce({eventKey:`${shop}:orders/create:123e4567-e89b-42d3-a456-426614174020`,
  bodySha256:'e'.repeat(64),orderGid:'gid://shopify/Order/555',matchedLines:[bindings[1]]}),
  'LEDGER_DESIGN_ALREADY_CLAIMED');
 await rejects(e.ledger.claimOnce({eventKey:`${shop}:orders/create:123e4567-e89b-42d3-a456-426614174021`,
  bodySha256:'e'.repeat(64),orderGid,matchedLines:[bindings[2]]}),'LEDGER_CROSS_PROTOCOL_CONFLICT');
});
test('crash before rename persists no nonces, order or event; retry works',async t=>{
 const e=await setup(t),items=await e.issue();
 const broken=createOfflineDurableLedger({directory:e.directory,injectFault:stage=>{
  if(stage==='before-rename')throw Error('synthetic crash');}});
 await rejects(e.make(broken).transition({verifiedEvent:signed(),items,authContext:'offline'}),'MULTI_LEDGER_UNAVAILABLE');
 const s=await e.snapshot();assert.equal(s.nonces.length,0);assert.equal(s.multiOrders.length,0);
 assert.equal((await e.observe(items)).outcome,'acquired');
});
test('crash after rename commits all records; retry is idempotent',async t=>{
 const e=await setup(t),items=await e.issue();
 const broken=createOfflineDurableLedger({directory:e.directory,injectFault:stage=>{
  if(stage==='after-rename')throw Error('synthetic lost acknowledgment');}});
 await rejects(e.make(broken).transition({verifiedEvent:signed(),items,authContext:'offline'}),'MULTI_LEDGER_UNAVAILABLE');
 const s=await e.snapshot();assert.equal(s.nonces.length,2);assert.equal(s.multiOrders.length,1);
 assert.equal((await e.observe(items)).outcome,'duplicate');
});
test('legacy v0.14 snapshot without multi arrays migrates only on commit',async t=>{
 const e=await setup(t),file=join(e.directory,'ledger.json'),s=await e.snapshot();
 delete s.multiOrders;delete s.multiEvents;await writeFile(file,JSON.stringify(s));
 assert.equal((await e.observe(await e.issue())).outcome,'acquired');
 const migrated=await e.snapshot();assert.equal(migrated.multiOrders.length,1);
});
test('corrupt multi-order state rejects before changes and preserves bytes',async t=>{
 const e=await setup(t),items=await e.issue(),file=join(e.directory,'ledger.json'),s=await e.snapshot();
 s.multiOrders=[{shop,orderGid,checkoutId,ownerSubject:owner,sessionHash:'f'.repeat(64),state:'OBSERVED',lines:[lines()[0]]}];
 await writeFile(file,JSON.stringify(s));const before=await readFile(file,'utf8');
 await rejects(e.observe(items),'MULTI_LEDGER_UNAVAILABLE');
 assert.equal(await readFile(file,'utf8'),before);
});
test('synthetic event ID cannot be reused across legacy single-line and multi-line protocols',async t=>{
 const e=await setup(t),items=await e.issue();
 const s=await e.snapshot();s.lineageEvents=[{shop,eventId,bodySha256:'a'.repeat(64),orderGid:'gid://shopify/Order/9',action:'ORDER_OBSERVED'}];
 await writeFile(join(e.directory,'ledger.json'),JSON.stringify(s));
 await rejects(e.observe(items),'MULTI_LEDGER_UNAVAILABLE');
 assert.equal((await e.snapshot()).multiEvents.length,0);
});
test('kernel lock mode supports multi-line atomic commit without stale-lock theft',async t=>{
 if(process.platform!=='linux')return t.skip('Linux-only');
 const e=await setup(t,{lockMode:'kernel'}),items=await e.issue();
 assert.equal((await e.observe(items)).outcome,'acquired');
 assert.equal((await e.snapshot()).nonces.length,2);
});
test('three independent Node processes serialize multi-line commit without double claims',async t=>{
 const e=await setup(t),items=await e.issue(),rawBody=Buffer.from(JSON.stringify(body()));
 const ledgerUrl=new URL('../src/offline-durable-ledger.mjs',import.meta.url).href;
 const authUrl=new URL('../src/versioned-cart-metadata.mjs',import.meta.url).href;
 const multiUrl=new URL('../src/offline-multiline-order.mjs',import.meta.url).href;
 const payload={directory:e.directory,items,shop,owner,sessionId,checkoutId,now,
  secret:secret.toString('base64'),webhookSecret:webhookSecret.toString('base64'),
  rawBody:rawBody.toString('base64'),headers:headers(rawBody)};
 const source=`import {createOfflineDurableLedger} from ${JSON.stringify(ledgerUrl)};
 import {createOfflineVersionedMetadataAuthority} from ${JSON.stringify(authUrl)};
 import {createOfflineMultiLineage,authenticateSyntheticMultiLineEvent} from ${JSON.stringify(multiUrl)};
 const a=JSON.parse(process.argv[1]),l=createOfflineDurableLedger({directory:a.directory,lockTimeoutMs:5000});
 const authority=createOfflineVersionedMetadataAuthority({keys:[{id:'key-v2',secret:Buffer.from(a.secret,'base64'),status:'ACTIVE',notBefore:a.now-60000,verifyUntil:a.now+1200000}],activeKeyId:'key-v2',clock:()=>a.now,
 resolvePrincipal:async()=>({schema:'TJ-TRUSTED-PRINCIPAL-1',shop:a.shop,subject:a.owner,kind:'customer',sessionId:a.sessionId,expiresAt:a.now+600000,checkoutEnabled:false,productionReady:false}),lookupDesign:l.lookupDesign,consumeNonce:l.consumeNonce});
 const verifiedEvent=authenticateSyntheticMultiLineEvent({rawBody:Buffer.from(a.rawBody,'base64'),headers:a.headers,secret:Buffer.from(a.webhookSecret,'base64'),expectedShop:a.shop});
 const lineage=createOfflineMultiLineage({prepareCartReceipt:authority.prepareForAtomicLineage,
 resolveCheckout:async()=>({schema:'TJ-TRUSTED-OFFLINE-CHECKOUT-1',shop:a.shop,ownerSubject:a.owner,sessionId:a.sessionId,checkoutId:a.checkoutId,status:'BOUND_OFFLINE',expiresAt:a.now+600000,checkoutEnabled:false,paymentVerified:false}),
 lookupEvent:l.lookupMultiLineageEvent,commitObserved:args=>l.commitMultiLineageWithReceipts({...args,assertPreparedReceipt:authority.assertPreparedForAtomicLineage}),
 commitCancellation:l.commitMultiLineageCancellation,clock:()=>a.now});
 try{console.log((await lineage.transition({verifiedEvent,items:a.items,authContext:'offline'})).outcome)}
 catch(e){console.error(e.code);process.exitCode=1}`;
 const child=()=>new Promise((resolve,reject)=>{
  const p=spawn(process.execPath,['--input-type=module','-e',source,JSON.stringify(payload)]);
  let out='',err='';p.stdout.on('data',x=>out+=x);p.stderr.on('data',x=>err+=x);
  p.on('error',reject);p.on('close',code=>resolve({code,out:out.trim(),err:err.trim()}));
 });
 const results=await Promise.all(Array.from({length:3},child));
 assert.equal(results.filter(x=>x.code===0&&x.out==='acquired').length,1,JSON.stringify(results));
 assert.equal(results.filter(x=>x.code===0&&x.out==='duplicate').length,2,JSON.stringify(results));
 const s=await e.snapshot();assert.equal(s.nonces.length,2);assert.equal(s.multiOrders.length,1);
});
test('legacy single-line atomic transition cannot reuse multi-line order or claimed design',async t=>{
 const e=await setup(t),items=await e.issue();await e.observe(items);
 const stored=await e.ledger.getMultiLineage({shop,orderGid});
 await rejects(e.ledger.commitLineageTransition({shop,eventId:'123e4567-e89b-42d3-a456-426614174029',
  bodySha256:'f'.repeat(64),action:'ORDER_OBSERVED',orderGid:'gid://shopify/Order/555',
  checkoutId:'offline-checkout:'+'Z'.repeat(24),ownerSubject:owner,sessionHash:stored.sessionHash,
  lineId:101,binding:bindings[0]}),'LEDGER_CROSS_PROTOCOL_CONFLICT');
 assert.equal((await e.snapshot()).lineage.length,0);
});
test('repeat cancellation under a fresh authenticated event is idempotent without nonce loss',async t=>{
 const e=await setup(t),items=await e.issue();await e.observe(items);
 const first=signed({action:'CANCELLATION_OBSERVED'},'123e4567-e89b-42d3-a456-426614174030');
 const second=signed({action:'CANCELLATION_OBSERVED'},'123e4567-e89b-42d3-a456-426614174031');
 assert.equal((await e.lineage.transition({verifiedEvent:first})).outcome,'acquired');
 assert.equal((await e.lineage.transition({verifiedEvent:second})).outcome,'duplicate');
 const s=await e.snapshot();assert.equal(s.nonces.length,2);assert.equal(s.multiEvents.length,3);
});
test('already-acknowledged cancellation still rejects injected cart properties',async t=>{
 const e=await setup(t),items=await e.issue();await e.observe(items);
 const cancel=signed({action:'CANCELLATION_OBSERVED'},'123e4567-e89b-42d3-a456-426614174032');
 await e.lineage.transition({verifiedEvent:cancel});
 await rejects(e.lineage.transition({verifiedEvent:cancel,items,authContext:'offline'}),'MULTI_CANCEL_CART_NOT_ALLOWED');
});
test('legacy single-line claim for unrelated third design coexists with multi-line order',async t=>{
 const e=await setup(t),items=await e.issue();await e.observe(items);
 assert.equal(await e.ledger.claimOnce({eventKey:`${shop}:orders/create:123e4567-e89b-42d3-a456-426614174040`,
  bodySha256:'f'.repeat(64),orderGid:'gid://shopify/Order/555',matchedLines:[bindings[2]]}),'acquired');
 const s=await e.snapshot();assert.equal(s.multiOrders.length,1);assert.equal(s.orders.length,1);
});
test('multi-line order coexists with preexisting unrelated legacy claim',async t=>{
 const e=await setup(t),items=await e.issue();
 assert.equal(await e.ledger.claimOnce({eventKey:`${shop}:orders/create:123e4567-e89b-42d3-a456-426614174041`,
  bodySha256:'f'.repeat(64),orderGid:'gid://shopify/Order/555',matchedLines:[bindings[2]]}),'acquired');
 assert.equal((await e.observe(items)).outcome,'acquired');
 const s=await e.snapshot();assert.equal(s.nonces.length,2);assert.equal(s.orders.length,1);
});
test('revision changed after receipt preparation but before ledger lock rejects all lines',async t=>{
 const e=await setup(t),items=await e.issue();
 const prepared=await Promise.all(items.map(item=>e.authority.prepareForAtomicLineage({
  properties:item.properties,authContext:'offline',expectedBinding:item.expectedBinding,
  expectedIdentity:{shop,subject:owner,sessionId}})));
 await e.ledger.putDesignCAS({design:{shop,ownerSubject:owner,...bindings[1],revision:2,status:'CURRENT'},expectedRevision:1});
 await rejects(e.ledger.commitMultiLineageWithReceipts({shop,eventId,bodySha256:'f'.repeat(64),
  action:'ORDER_OBSERVED',orderGid,checkoutId,ownerSubject:owner,sessionHash:prepared[0].sessionHash,
  lines:lines(),preparedReceipts:prepared,assertPreparedReceipt:e.authority.assertPreparedForAtomicLineage}),
  'LEDGER_MULTI_DESIGN_CAS');
 const s=await e.snapshot();assert.equal(s.nonces.length,0);assert.equal(s.multiOrders.length,0);
});
