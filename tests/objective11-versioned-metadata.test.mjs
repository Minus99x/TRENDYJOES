import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,createHmac} from 'node:crypto';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {createOfflineVersionedMetadataAuthority} from '../src/versioned-cart-metadata.mjs';
import {createOfflineDurableLedger} from '../src/offline-durable-ledger.mjs';

const shop='gucgmp-bc.myshopify.com',owner='gid://shopify/Customer/45678';
const reference='TJ-'+'A'.repeat(24);
const binding={reference,revision:1,productGid:'gid://shopify/Product/12345',
 variantGid:'gid://shopify/ProductVariant/67890',compositionSha256:'a'.repeat(64)};
const secretA=randomBytes(32),secretB=randomBytes(32);
const initial=Date.now();
const key=(id,secret,status='ACTIVE',other={})=>({id,secret,status,notBefore:initial-60_000,verifyUntil:initial+30*60_000,...other});
const principal=(extra={})=>({schema:'TJ-TRUSTED-PRINCIPAL-1',shop,subject:owner,kind:'customer',
 sessionId:'offline-session-0123456789',expiresAt:initial+10*60_000,
 checkoutEnabled:false,productionReady:false,...extra});
const design=(extra={})=>({shop,ownerSubject:owner,...binding,status:'CURRENT',...extra});
const rejects=(promise,code)=>assert.rejects(promise,e=>e?.code===code);
const receipt=(properties)=>properties['_TJ Cart Receipt'];
function env(overrides={}){
 let now=initial,who=principal(),record=design(),lookups=0;
 const seen=new Map();
 const cfg={keys:[key('key-a',secretA)],activeKeyId:'key-a',clock:()=>now,
  resolvePrincipal:async()=>who,lookupDesign:async()=>{lookups++;return record;},
  consumeNonce:async({nonceKey,receiptSha256})=>{
   const old=seen.get(nonceKey);if(old)return old===receiptSha256?'duplicate':'conflict';
   seen.set(nonceKey,receiptSha256);return 'acquired';},...overrides};
 const authority=createOfflineVersionedMetadataAuthority(cfg);
 return {authority,cfg,clock:t=>now=t,identity:p=>who=p,record:r=>record=r,
  get lookups(){return lookups;},issue:()=>authority.issue({authContext:'synthetic-bearer',binding}),
  verify:properties=>authority.verify({properties,authContext:'synthetic-bearer',expectedBinding:binding})};
}
async function temp(fn){const dir=await mkdtemp(join(tmpdir(),'tj-metadata11-'));try{return await fn(dir);}finally{await rm(dir,{recursive:true,force:true});}}
const tokenPayload=t=>JSON.parse(Buffer.from(t.split('.')[1],'base64url').toString('utf8'));
const tamper=(token,transform)=>{
 const parts=token.split('.');const payload=tokenPayload(token);transform(payload);
 parts[1]=Buffer.from(JSON.stringify(payload)).toString('base64url');return parts.join('.');
};

test('version 2 issues privacy-preserving non-authorizing metadata; exact owner/session absent',async()=>{
 const e=env(),out=await e.issue();const p=tokenPayload(receipt(out.properties));
 assert.equal(out.checkoutEnabled,false);assert.equal(out.productionApproved,false);
 assert.equal(out.paymentVerified,false);assert.equal(out.fulfillmentAuthorized,false);
 assert.equal(p.purpose,'offline-cart-binding-only');assert.equal(p.version,2);
 assert.equal(p.shop,shop);assert.equal(p.kid,'key-a');
 assert.equal(JSON.stringify(out).includes(owner),false);
 assert.equal(JSON.stringify(out).includes(principal().sessionId),false);
 assert.equal(JSON.stringify(out).includes(secretA.toString('hex')),false);
 const v=await e.verify(out.properties);assert.equal(v.integrityVerified,true);
 assert.equal(v.nonceConsumed,true);assert.equal(v.checkoutEnabled,false);
});
test('same token is one-use; repeat verification rejects replay',async()=>{
 const e=env(),out=await e.issue();await e.verify(out.properties);
 await rejects(e.verify(out.properties),'METADATA_REPLAY');
});
test('parallel verifier races allow only one accepted token',async()=>{
 const e=env(),out=await e.issue();const all=await Promise.allSettled(Array.from({length:15},()=>e.verify(out.properties)));
 assert.equal(all.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(all.filter(x=>x.status==='rejected'&&x.reason.code==='METADATA_REPLAY').length,14);
});
test('cross-shop, owner, guest and session substitution fail before consuming nonce',async()=>{
 for(const changed of [{shop:'other.myshopify.com'},{subject:'gid://shopify/Customer/7'},
  {kind:'guest',subject:'guest:'+'Z'.repeat(24)},{sessionId:'different-session-012345'}]){
  const e=env(),out=await e.issue();e.identity(principal(changed));
  await rejects(e.verify(out.properties),'METADATA_CONTEXT_MISMATCH');
  e.identity(principal());assert.equal((await e.verify(out.properties)).integrityVerified,true);
 }
});
test('product, variant, revision, reference and digest substitutions fail',async()=>{
 for(const change of [{productGid:'gid://shopify/Product/9'},{variantGid:'gid://shopify/ProductVariant/9'},
  {revision:2},{reference:'TJ-'+'B'.repeat(24)},{compositionSha256:'b'.repeat(64)}]){
  const e=env(),out=await e.issue();
  await rejects(e.authority.verify({properties:out.properties,authContext:'synthetic-bearer',
   expectedBinding:{...binding,...change}}),'METADATA_CONTEXT_MISMATCH');
  assert.equal((await e.verify(out.properties)).integrityVerified,true);
 }
});
test('server design revision, status and ownership are rechecked on verification',async()=>{
 for(const change of [{revision:2},{status:'SUPERSEDED'},{ownerSubject:'gid://shopify/Customer/99'},
  {compositionSha256:'f'.repeat(64)},{variantGid:'gid://shopify/ProductVariant/99'}]){
  const e=env(),out=await e.issue();e.record(design(change));
  await rejects(e.verify(out.properties),'METADATA_DESIGN_STALE');
 }
});
test('issue fails closed for stale server records and untrusted bindings',async()=>{
 const e=env();e.record(design({revision:2}));await rejects(e.issue(),'METADATA_DESIGN_STALE');
 for(const changed of [{revision:0},{compositionSha256:'no'},{variantGid:'invalid'},{extra:true}]){
  await rejects(e.authority.issue({authContext:'synthetic',binding:{...binding,...changed}}),'METADATA_BINDING_INVALID');
 }
});
test('tampered signed payload cannot pass HMAC; failed attempt does not consume nonce',async()=>{
 const e=env(),out=await e.issue(),original=receipt(out.properties);
 for(const change of [p=>p.revision++,p=>p.kid='key-b',p=>p.shop='other.myshopify.com',
  p=>p.ownerTag='b'.repeat(64),p=>p.expiresAt+=1000,p=>p.nonce='B'.repeat(32)]){
  const changed=tamper(original,change);
  await assert.rejects(e.verify({...out.properties,'_TJ Cart Receipt':changed}));
 }
 assert.equal((await e.verify(out.properties)).integrityVerified,true);
});
test('extra/missing properties, legacy HMAC and forged checkout flags reject',async()=>{
 const e=env(),out=await e.issue();
 for(const props of [{...out.properties,extra:'yes'},{'_TJ Protocol':'TJ-OFFLINE-CART-2'},
  {...out.properties,'_TJ Protocol':'TJ-SHOPIFY-AUTHORIZED-CHECKOUT-1'},
  {'_TJ Design Reference':reference,'_TJ Binding HMAC':'a'.repeat(64)},
  {...out.properties,checkoutEnabled:true}])await rejects(e.verify(props),'METADATA_PROPERTIES_INVALID');
});
test('expired receipt rejects at boundary, without nonce consumption',async()=>{
 const e=env(),out=await e.authority.issue({binding,ttlMs:1000});
 e.clock(initial+1000);await rejects(e.verify(out.properties),'METADATA_EXPIRED_OR_FUTURE');
});
test('future-issued token rejects under backward clock drift',async()=>{
 const e=env(),out=await e.issue();e.clock(initial-1);
 await rejects(e.verify(out.properties),'METADATA_EXPIRED_OR_FUTURE');
});
test('receipt expiry is clipped to trusted principal and key lifetime',async()=>{
 const e=env({keys:[key('key-a',secretA,'ACTIVE',{verifyUntil:initial+400})]});
 const out=await e.authority.issue({binding,ttlMs:5000});
 assert.equal(out.expiresAt,initial+400);
 const e2=env({resolvePrincipal:async()=>principal({expiresAt:initial+350})});
 assert.equal((await e2.authority.issue({binding,ttlMs:5000})).expiresAt,initial+350);
});
test('ttl bounds, invalid clocks and signing-disabled configurations reject',async()=>{
 const e=env();for(const ttlMs of [0,-1,15*60_000+1,'100',NaN]){
  await rejects(e.authority.issue({binding,ttlMs}),'METADATA_TTL_INVALID');
 }
 const bad=env({clock:()=>NaN});await rejects(bad.issue(),'METADATA_CLOCK_INVALID');
 const readonly=env({activeKeyId:null});await rejects(readonly.issue(),'METADATA_SIGNING_DISABLED');
});
test('key rotation: old receipt verifies under VERIFY_ONLY, new ACTIVE signs',async()=>{
 const e=env(),old=await e.issue();
 const newer=env({keys:[key('key-a',secretA,'VERIFY_ONLY'),key('key-b',secretB)],activeKeyId:'key-b'});
 const newReceipt=await newer.issue();
 assert.equal(tokenPayload(receipt(newReceipt.properties)).kid,'key-b');
 assert.equal((await newer.verify(old.properties)).integrityVerified,true);
 assert.equal((await newer.verify(newReceipt.properties)).integrityVerified,true);
});
test('revoked or removed old key denies previous receipt',async()=>{
 const e=env(),out=await e.issue();
 for(const keys of [[key('key-a',secretA,'REVOKED'),key('key-b',secretB)],
  [key('key-b',secretB)]]){
  const rotated=env({keys,activeKeyId:'key-b'});
  await rejects(rotated.verify(out.properties),'METADATA_KEY_UNTRUSTED');
 }
});
test('key verify window expiration rejects even a signed token',async()=>{
 const e=env({keys:[key('key-a',secretA,'ACTIVE',{verifyUntil:initial+1000})]});
 const out=await e.authority.issue({binding,ttlMs:1000});e.clock(initial+1000);
 await rejects(e.verify(out.properties),'METADATA_KEY_UNTRUSTED');
});
test('weak, duplicate, invalid, revoked active and mutated key configuration fail',()=>{
 const base={keys:[key('key-a',secretA)],activeKeyId:'key-a',resolvePrincipal:async()=>principal(),
  lookupDesign:async()=>design(),consumeNonce:async()=> 'acquired'};
 for(const changes of [{keys:[key('key-a',Buffer.alloc(8))]},
  {keys:[key('key-a',secretA),key('key-a',secretB)]},
  {keys:[key('key-a',secretA,'REVOKED')]},
  {keys:[key('key-a',secretA,'ACTIVE',{verifyUntil:initial-10*60_000})]},
  {activeKeyId:'missing'}, {consumeNonce:undefined},{resolvePrincipal:undefined}]){
  assert.throws(()=>createOfflineVersionedMetadataAuthority({...base,...changes}));
 }
});
test('caller mutating original signing secret does not alter authority signing key',async()=>{
 const mutable=Buffer.from(secretA),e=env({keys:[key('key-a',mutable)]});
 const out=await e.issue();mutable.fill(0);
 assert.equal((await e.verify(out.properties)).integrityVerified,true);
});
test('malformed token encoding, duplicate keys, and extra claims reject canonical parse',async()=>{
 const e=env(),out=await e.issue(),token=receipt(out.properties),parts=token.split('.');
 const malformed=['',token+'=',token.replace(/\./g,'-'),`${parts[0]}.=.${parts[2]}`,
  `${parts[0]}.${parts[1]}.A`,`${parts[0]}.${parts[1]}=.${parts[2]}`];
 for(const t of malformed)await assert.rejects(e.verify({...out.properties,'_TJ Cart Receipt':t}));
 const duplicateRaw=Buffer.from(JSON.stringify(tokenPayload(token)).replace('"version":2','"version":2,"version":2'));
 const duplicate=`${parts[0]}.${duplicateRaw.toString('base64url')}.${parts[2]}`;
 await rejects(e.verify({...out.properties,'_TJ Cart Receipt':duplicate}),'METADATA_CANONICAL');
 const extra=tamper(token,p=>p.admin=true);
 await rejects(e.verify({...out.properties,'_TJ Cart Receipt':extra}),'METADATA_CANONICAL');
});
test('invalid identity, verifier outages, design lookup outages fail closed',async()=>{
 for(const overrides of [{resolvePrincipal:async()=>({...principal(),checkoutEnabled:true})},
  {resolvePrincipal:async()=>({...principal(),subject:'not-customer'})},
  {resolvePrincipal:async()=>{throw Error('unavailable');}},
  {lookupDesign:async()=>{throw Error('unavailable');}}]){
  const e=env(overrides);await assert.rejects(e.issue());
 }
});
test('nonce store outage, malformed responses and collision fail closed',async()=>{
 for(const adapter of [async()=>{throw Error('down');},async()=>null,async()=> 'conflict']){
  const e=env({consumeNonce:adapter}),out=await e.issue();await assert.rejects(e.verify(out.properties));
 }
});
test('nonce source malformed, collisions and exhaustion reject or replay',async()=>{
 const bad=env({nonceSource:()=> 'predictable'});await rejects(bad.issue(),'METADATA_NONCE_INVALID');
 const e=env({nonceSource:()=> 'Z'.repeat(32)}),a=await e.issue(),b=await e.issue();
 assert.equal((await e.verify(a.properties)).integrityVerified,true);
 await rejects(e.verify(b.properties),'METADATA_REPLAY');
});
test('single-host durable nonce ledger survives fresh process adapter and rejects replay',()=>temp(async directory=>{
 const ledger=createOfflineDurableLedger({directory});await ledger.putDesignCAS({design:design()});
 const e=env({consumeNonce:ledger.consumeNonce});const out=await e.issue();
 assert.equal((await e.verify(out.properties)).nonceConsumed,true);
 const another=env({consumeNonce:createOfflineDurableLedger({directory}).consumeNonce});
 await rejects(another.verify(out.properties),'METADATA_REPLAY');
 const persisted=JSON.parse(await readFile(join(directory,'ledger.json'),'utf8'));
 assert.equal(persisted.nonces.length,1);
}));
test('v0.10 ledger snapshot migrates without losing order/design records',()=>temp(async directory=>{
 const ledger=createOfflineDurableLedger({directory});
 await ledger.putDesignCAS({design:design()});
 const state=JSON.parse(await readFile(join(directory,'ledger.json'),'utf8'));
 delete state.nonces;await writeFile(join(directory,'ledger.json'),JSON.stringify(state));
 const e=env({consumeNonce:ledger.consumeNonce,lookupDesign:ledger.lookupDesign});
 const out=await e.issue();await e.verify(out.properties);
 const next=JSON.parse(await readFile(join(directory,'ledger.json'),'utf8'));
 assert.equal(next.designs.length,1);assert.equal(next.nonces.length,1);
}));
test('atomic durable nonce adapter races across processes; exactly one acquisition',()=>temp(async directory=>{
 const nonceKey='b'.repeat(64),receiptSha256='c'.repeat(64),expiresAt=Date.now()+30_000;
 const initialLedger=createOfflineDurableLedger({directory});await initialLedger.putDesignCAS({design:design()});
 const url=new URL('../src/offline-durable-ledger.mjs',import.meta.url).href;
 const code=`import {createOfflineDurableLedger} from ${JSON.stringify(url)};const l=createOfflineDurableLedger({directory:process.argv[1],lockTimeoutMs:5000});try{console.log(await l.consumeNonce(JSON.parse(process.argv[2])));}catch(e){console.error(e.code);process.exitCode=1;}`;
 const jobs=Array.from({length:7},()=>new Promise((resolve,reject)=>{
  const p=spawn(process.execPath,['--input-type=module','-e',code,directory,JSON.stringify({nonceKey,receiptSha256,expiresAt,expectedDesign:design()})],{stdio:['ignore','pipe','pipe']});
  let output='';p.stdout.on('data',d=>output+=d);p.on('error',reject);p.on('close',exit=>resolve({exit,output:output.trim()}));
 }));
 const all=await Promise.all(jobs);
 assert.equal(all.filter(x=>x.exit===0&&x.output==='acquired').length,1,JSON.stringify(all));
 assert.equal(all.filter(x=>x.exit===0&&x.output==='duplicate').length,6,JSON.stringify(all));
}));
test('durable nonce collision with different receipt digest returns conflict',()=>temp(async directory=>{
 const ledger=createOfflineDurableLedger({directory}),nonceKey='a'.repeat(64),expiresAt=Date.now()+30_000;
 await ledger.putDesignCAS({design:design()});
 assert.equal(await ledger.consumeNonce({nonceKey,receiptSha256:'b'.repeat(64),expiresAt,expectedDesign:design()}),'acquired');
 assert.equal(await ledger.consumeNonce({nonceKey,receiptSha256:'c'.repeat(64),expiresAt,expectedDesign:design()}),'conflict');
}));
test('revision CAS after lookup and before nonce claim fails closed without consuming receipt',()=>temp(async directory=>{
 const ledger=createOfflineDurableLedger({directory});await ledger.putDesignCAS({design:design()});
 const e=env({lookupDesign:ledger.lookupDesign,consumeNonce:async args=>{
  await ledger.putDesignCAS({design:design({revision:2}),expectedRevision:1});
  return ledger.consumeNonce(args);
 }});
 const out=await e.issue();await rejects(e.verify(out.properties),'METADATA_NONCE_STORE_UNAVAILABLE');
 const persisted=JSON.parse(await readFile(join(directory,'ledger.json'),'utf8'));
 assert.equal(persisted.nonces.length,0);assert.equal(persisted.designs[0].revision,2);
}));
test('legacy HMAC-only order metadata is not accepted as a v2 cart receipt',async()=>{
 const e=env();await rejects(e.verify({'_TJ Design Reference':reference,'_TJ Design Revision':'1',
  '_TJ Binding HMAC':'a'.repeat(64)}),'METADATA_PROPERTIES_INVALID');
});
