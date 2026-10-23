import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,randomBytes,generateKeyPairSync,sign} from 'node:crypto';
import {deflateSync} from 'node:zlib';
import {createOfflinePrivateRevisionRegistry,computePrivateRegistryMutationDigest} from '../src/offline-private-revision-registry.mjs';
import {computeArtworkDesignSha256} from '../src/manufacturing-artwork-evidence.mjs';

const shop='gucgmp-bc.myshopify.com',pid='gid://shopify/Product/123',vid='gid://shopify/ProductVariant/456';
const session='trusted-synthetic-session-objective27';
const keyId='objective27-encryption-key';
const schema='TJ-OFFLINE-PRIVATE-REGISTRY-MUTATION-1';
const fields=['schema','registryId','action','opId','shop','ownerId','requestSha256','issuedAt','expiresAt'];
const recoverySchema='TJ-OFFLINE-PRIVATE-REGISTRY-RECOVERY-1';
const recoveryFields=['schema','registryId','authorizationId','issuedAt','expiresAt','expectedAnchor','targetAnchor','reason'];
const id=()=>`mutation27-${randomBytes(10).toString('hex')}`;
const rejects=(p,code)=>assert.rejects(p,e=>e?.code===code);
const crcTable=Array.from({length:256},(_,i)=>{let c=i;for(let j=0;j<8;j++)c=c&1?0xedb88320^(c>>>1):c>>>1;return c>>>0;});
function chunk(type,data){const t=Buffer.from(type),b=Buffer.alloc(12+data.length);b.writeUInt32BE(data.length,0);t.copy(b,4);data.copy(b,8);let c=0xffffffff;for(const x of Buffer.concat([t,data]))c=crcTable[(c^x)&255]^(c>>>8);b.writeUInt32BE((c^0xffffffff)>>>0,8+data.length);return b;}
function png(w=12,h=12){const head=Buffer.alloc(13);head.writeUInt32BE(w,0);head.writeUInt32BE(h,4);head[8]=8;head[9]=2;return Buffer.concat([Buffer.from('89504e470d0a1a0a','hex'),chunk('IHDR',head),chunk('IDAT',deflateSync(Buffer.alloc(h*(w*3+1)))),chunk('IEND',Buffer.alloc(0))]);}
const layer=(id='layer-A',artworkId='art-A')=>({id,type:'artwork',artworkId,surfaceId:'front',x:.2,y:.2,width:.3,height:.3,rotationDeg:0,sourceWidthPx:100,sourceHeightPx:100});
function record(revision=1,changes={}){const design={layers:[layer()]};return{schema:'TJ-CURRENT-IMMUTABLE-DESIGN-1',shop,productGid:pid,variantGid:vid,manifestId:'concept-crew-tee',ownerId:'owner-1',designId:'design-1',revision,designSha256:computeArtworkDesignSha256(design),status:'CURRENT_IMMUTABLE',design,...changes};}
const identity=(r=record())=>Object.fromEntries(['shop','productGid','variantGid','ownerId','designId','revision'].map(k=>[k,r[k]]));
const artwork=(storageKey='PrivateArtwork0001',bytes=png())=>({storageKey,artworkId:'art-A',layerId:'layer-A',bytes});
const commitRequest=(r=record(),artworks=[artwork()])=>({record:r,artworks,expectedRevision:r.revision===1?null:r.revision-1,opId:id()});
const revokeArtworkRequest=(r=record(),storageKey='PrivateArtwork0001')=>({...identity(r),storageKey,artworkId:'art-A',layerId:'layer-A',opId:id()});
const revokeRevisionRequest=(r=record())=>({identity:identity(r),opId:id()});
const principal=(overrides={})=>({shop,ownerId:'owner-1',issuedAt:Date.now()-1000,expiresAt:Date.now()+60000,...overrides});
const digest=computePrivateRegistryMutationDigest;
async function fixture(t){
 const directory=await mkdtemp(join(tmpdir(),'tj-mut27-'));t.after(()=>rm(directory,{recursive:true,force:true}));
 const secret=randomBytes(32),key=randomBytes(32),{publicKey,privateKey}=generateKeyPairSync('ed25519');
 const {publicKey:recoveryPublic,privateKey:recoveryPrivate}=generateKeyPairSync('ed25519');
 const registryId='objective-27-registry-verified',recoveryId='objective-27-recovery-verified';
 let anchor=null,injectFault,verifier=token=>token===session?principal():null,anchorDown=false,anchorDelay=0;
 const adapters={readAnchor:async()=>{if(anchorDown)throw Error('offline');if(anchorDelay)await new Promise(r=>setTimeout(r,anchorDelay));return structuredClone(anchor);},compareAndSetAnchor:async(expected,next)=>{if(JSON.stringify(anchor)!==JSON.stringify(expected))return false;anchor=structuredClone(next);return true;}};
 const encryption={activeKeyId:keyId,resolveKey:requested=>requested===keyId?key:null};
 const mutationAuthorization={registryId,publicKey};
 const recovery={registryId:recoveryId,publicKey:recoveryPublic};
 const open=(extra={})=>createOfflinePrivateRevisionRegistry({directory,secret,...adapters,encryption,injectFault,...extra});
 const secure=(extra={})=>open({verifyArtworkAccess:verifier,mutationAuthorization,...extra});
 const grant=(action,request,changes={},signer=privateKey)=>{
  const now=Date.now(),body={schema,registryId,action,opId:request.opId,shop:action==='commit-revision'?request.record.shop:action==='revoke-revision'?request.identity.shop:request.shop,ownerId:action==='commit-revision'?request.record.ownerId:action==='revoke-revision'?request.identity.ownerId:request.ownerId,requestSha256:digest(action,request),issuedAt:now-1000,expiresAt:now+60000,...changes};
  const canonical=Object.fromEntries(fields.map(k=>[k,body[k]]));
  return {...body,signature:sign(null,Buffer.from(`${schema}\0${JSON.stringify(canonical)}`),signer).toString('base64url')};
 };
 const envelope=(action,request,changes={})=>({sessionToken:session,permit:grant(action,request,changes),request});
 const recoveryPermit=(expectedAnchor,targetAnchor,changes={})=>{
  const now=Date.now(),body={schema:recoverySchema,registryId:recoveryId,authorizationId:id(),issuedAt:now-1000,expiresAt:now+60000,expectedAnchor,targetAnchor,reason:'Independent operator checked transaction and previous anchor',...changes};
  const canonical=Object.fromEntries(recoveryFields.map(k=>[k,body[k]]));
  return {...body,signature:sign(null,Buffer.from(`${recoverySchema}\0${JSON.stringify(canonical)}`),recoveryPrivate).toString('base64url')};
 };
 const commit=async(r=record(),assets=[artwork()])=>open().commitRevision(commitRequest(r,assets));
 const state=async()=>JSON.parse(await readFile(join(directory,'private-registry.json'),'utf8'));
 return{directory,open,secure,grant,envelope,commit,state,recovery,recoveryPermit,mutationAuthorization,privateKey,registryId,getAnchor:()=>structuredClone(anchor),setFault:x=>{injectFault=x;},setVerifier:x=>{verifier=x;},setAnchorDown:x=>{anchorDown=x;},setAnchorDelay:x=>{anchorDelay=x;}};
}

// Happy paths and enforced boundary: never fall back to legacy unauthenticated writes.
test('signed authenticated initial revision commits encrypted artwork and exact digest',async t=>{const f=await fixture(t),q=commitRequest(),r=f.secure();assert.equal((await r.commitAuthenticatedRevision(f.envelope('commit-revision',q))).revision,1);const s=await f.state();assert.ok(s.assets[0].encryption);assert.equal(s.opIds[0],q.opId);});
test('authenticated second immutable revision succeeds with matching expectedRevision',async t=>{const f=await fixture(t);await f.commit();const q=commitRequest(record(2),[artwork('PrivateArtwork0002')]);assert.equal((await f.secure().commitAuthenticatedRevision(f.envelope('commit-revision',q))).revision,2);});
test('authenticated artwork revocation persists and blocks authenticated read',async t=>{const f=await fixture(t);await f.commit();const q=revokeArtworkRequest();assert.deepEqual(await f.secure().revokeAuthenticatedArtwork(f.envelope('revoke-artwork',q)),{revoked:true});await rejects(f.open().readPrivateArtwork({storageKey:q.storageKey,ownerId:q.ownerId,designId:q.designId,revision:q.revision,artworkId:q.artworkId}),'REGISTRY_ARTWORK_UNAVAILABLE');});
test('authenticated revision revocation persists and removes current revision',async t=>{const f=await fixture(t);await f.commit();const q=revokeRevisionRequest();assert.deepEqual(await f.secure().revokeAuthenticatedRevision(f.envelope('revoke-revision',q)),{revoked:true});assert.equal(await f.open().loadCurrentRevision(identity()),null);});
test('authenticated mode blocks legacy revision commit',async t=>{const f=await fixture(t);await rejects(f.secure().commitRevision(commitRequest()),'REGISTRY_AUTH_REQUIRED');assert.equal(f.getAnchor(),null);});
test('authenticated mode blocks legacy artwork revocation',async t=>{const f=await fixture(t);await f.commit();await rejects(f.secure().revokeArtwork({...revokeArtworkRequest()}),'REGISTRY_AUTH_REQUIRED');});
test('authenticated mode blocks legacy revision revocation',async t=>{const f=await fixture(t);await f.commit();await rejects(f.secure().revokeRevision(revokeRevisionRequest()),'REGISTRY_AUTH_REQUIRED');});
test('unconfigured registry cannot accept authenticated mutation',async t=>{const f=await fixture(t),q=commitRequest();await rejects(f.open().commitAuthenticatedRevision(f.envelope('commit-revision',q)),'REGISTRY_AUTH_REQUIRED');});
test('mutation authorization requires encrypted storage',async t=>{const f=await fixture(t);assert.throws(()=>f.open({encryption:undefined,verifyArtworkAccess:()=>principal(),mutationAuthorization:f.mutationAuthorization}),e=>e.code==='REGISTRY_MUTATION_CONFIGURATION');});
test('mutation authorization requires trusted session verifier',async t=>{const f=await fixture(t);assert.throws(()=>f.open({mutationAuthorization:f.mutationAuthorization}),e=>e.code==='REGISTRY_MUTATION_CONFIGURATION');});
test('mutation authorization rejects malformed signing public key',async t=>{const f=await fixture(t);assert.throws(()=>f.secure({mutationAuthorization:{registryId:f.registryId,publicKey:f.privateKey}}),e=>e.code==='REGISTRY_MUTATION_CONFIGURATION');});
test('mutation authorization rejects malformed registry identity',async t=>{const f=await fixture(t);assert.throws(()=>f.secure({mutationAuthorization:{registryId:'x',publicKey:f.mutationAuthorization.publicKey}}),e=>e.code==='REGISTRY_MUTATION_CONFIGURATION');});

// Each field is signed, and session principal is independently established.
for(const [label,change] of [
 ['wrong registry',{registryId:'another-registry-identity'}],['wrong action',{action:'revoke-artwork'}],['wrong opId',{opId:id()}],
 ['wrong shop',{shop:'other.myshopify.com'}],['wrong owner',{ownerId:'attacker'}],['wrong digest',{requestSha256:'a'.repeat(64)}],
 ['expired',{issuedAt:Date.now()-120000,expiresAt:Date.now()-1000}],['future',{issuedAt:Date.now()+60000,expiresAt:Date.now()+120000}],
 ['overlong lifetime',{issuedAt:Date.now()-1000,expiresAt:Date.now()+901000}],['zero lifetime',{issuedAt:Date.now()-1000,expiresAt:Date.now()-1000}]
])test(`signed mutation permit rejects ${label}`,async t=>{const f=await fixture(t),q=commitRequest();await rejects(f.secure().commitAuthenticatedRevision(f.envelope('commit-revision',q,change)),'REGISTRY_MUTATION_DENIED');assert.equal(f.getAnchor(),null);});
test('tampering signed permit after issuance is rejected',async t=>{const f=await fixture(t),q=commitRequest(),e=f.envelope('commit-revision',q);e.permit.expiresAt+=1000;await rejects(f.secure().commitAuthenticatedRevision(e),'REGISTRY_MUTATION_DENIED');});
test('permit signed by an unrelated key is rejected',async t=>{const f=await fixture(t),q=commitRequest(),{privateKey}=generateKeyPairSync('ed25519'),e=f.envelope('commit-revision',q);e.permit=f.grant('commit-revision',q,{},privateKey);await rejects(f.secure().commitAuthenticatedRevision(e),'REGISTRY_MUTATION_DENIED');});
test('extra unsigned permit field is rejected',async t=>{const f=await fixture(t),q=commitRequest(),e=f.envelope('commit-revision',q);e.permit.admin=true;await rejects(f.secure().commitAuthenticatedRevision(e),'REGISTRY_MUTATION_DENIED');});
test('malformed permit signature is rejected',async t=>{const f=await fixture(t),q=commitRequest(),e=f.envelope('commit-revision',q);e.permit.signature='not-a-valid-signature';await rejects(f.secure().commitAuthenticatedRevision(e),'REGISTRY_MUTATION_DENIED');});
test('extra envelope field including client principal is rejected',async t=>{const f=await fixture(t),q=commitRequest();await rejects(f.secure().commitAuthenticatedRevision({...f.envelope('commit-revision',q),principal:principal()}),'REGISTRY_MUTATION_DENIED');});
test('unknown session cannot use valid signed mutation permit',async t=>{const f=await fixture(t),q=commitRequest(),e=f.envelope('commit-revision',q);e.sessionToken='unknown-synthetic-session-token';await rejects(f.secure().commitAuthenticatedRevision(e),'REGISTRY_MUTATION_DENIED');});
for(const [label,value] of [['short token','short'],['missing token',undefined],['control character','valid-session\ncredential'],['oversized token','x'.repeat(513)]])test(`session rejects ${label}`,async t=>{const f=await fixture(t),q=commitRequest(),e=f.envelope('commit-revision',q);e.sessionToken=value;await rejects(f.secure().commitAuthenticatedRevision(e),'REGISTRY_MUTATION_DENIED');});
for(const [label,overrides] of [['foreign owner',{ownerId:'attacker'}],['foreign shop',{shop:'foreign.myshopify.com'}],['expired principal',{issuedAt:Date.now()-120000,expiresAt:Date.now()-1000}],['future principal',{issuedAt:Date.now()+10000,expiresAt:Date.now()+20000}],['overlong principal',{issuedAt:Date.now()-1000,expiresAt:Date.now()+901000}],['unexpected role',{admin:true}]])test(`trusted principal rejects ${label}`,async t=>{const f=await fixture(t),q=commitRequest();f.setVerifier(()=>principal(overrides));await rejects(f.secure().commitAuthenticatedRevision(f.envelope('commit-revision',q)),'REGISTRY_MUTATION_DENIED');});
test('trusted verifier exception is masked and no state is written',async t=>{const f=await fixture(t),q=commitRequest();f.setVerifier(()=>{throw Error('secret session provider details');});await rejects(f.secure().commitAuthenticatedRevision(f.envelope('commit-revision',q)),'REGISTRY_MUTATION_DENIED');assert.equal(f.getAnchor(),null);});
test('trusted verifier asynchronous rejection fails closed',async t=>{const f=await fixture(t),q=commitRequest();f.setVerifier(async()=>{throw Error('provider unavailable');});await rejects(f.secure().commitAuthenticatedRevision(f.envelope('commit-revision',q)),'REGISTRY_MUTATION_DENIED');});

// Exact request hashes cover artwork bytes, revisions, product variants, layer and storage.
for(const [label,change] of [
 ['owner',q=>q.record.ownerId='attacker'],['product',q=>q.record.productGid='gid://shopify/Product/999'],
 ['variant',q=>q.record.variantGid='gid://shopify/ProductVariant/999'],['design ID',q=>q.record.designId='different-design'],
 ['revision',q=>q.record.revision=2],['expected revision',q=>q.expectedRevision=1],
 ['storage key',q=>q.artworks[0].storageKey='PrivateArtwork9999'],
 ['artwork bytes',q=>q.artworks[0].bytes=png(14,14)]
])test(`signed commit rejects substituted ${label}`,async t=>{const f=await fixture(t),q=commitRequest(),e=f.envelope('commit-revision',q);change(q);await assert.rejects(f.secure().commitAuthenticatedRevision(e),error=>['REGISTRY_MUTATION_DENIED','REGISTRY_REVISION_INVALID'].includes(error?.code));assert.equal(f.getAnchor(),null);});
test('request digest canonicalizes insertion order of equivalent records',async()=>{const q=commitRequest();const r=Object.fromEntries(Object.entries(q.record).reverse());assert.equal(digest('commit-revision',q),digest('commit-revision',{...q,record:r}));});
test('request digest rejects forged extra metadata',async()=>{const q=commitRequest();q.productionApproved=true;assert.throws(()=>digest('commit-revision',q),e=>e.code==='REGISTRY_MUTATION_REQUEST');});
test('request digest rejects invalid artwork bytes',async()=>{const q=commitRequest();q.artworks[0].bytes=Buffer.alloc(80);assert.throws(()=>digest('commit-revision',q),e=>e.code==='REGISTRY_MUTATION_REQUEST');});
test('request digest rejects wrong artwork layer binding',async()=>{const q=commitRequest();q.artworks[0].layerId='foreign-layer';assert.throws(()=>digest('commit-revision',q),e=>e.code==='REGISTRY_MUTATION_REQUEST');});
test('request digest rejects unknown action',async()=>{assert.throws(()=>digest('grant-admin',commitRequest()),e=>e.code==='REGISTRY_MUTATION_REQUEST');});
test('request digest rejects unsafe operation identifier',async()=>{const q=commitRequest();q.opId='../bad';assert.throws(()=>digest('commit-revision',q),e=>e.code==='REGISTRY_OPERATION_ID');});

test('replay of same authenticated revision permit is denied after commit',async t=>{const f=await fixture(t),q=commitRequest(),e=f.envelope('commit-revision',q);await f.secure().commitAuthenticatedRevision(e);await rejects(f.secure().commitAuthenticatedRevision(e),'REGISTRY_REPLAY');});
test('same operation ID cannot be reused across authenticated mutation actions',async t=>{const f=await fixture(t),q=commitRequest();await f.secure().commitAuthenticatedRevision(f.envelope('commit-revision',q));const rev=revokeRevisionRequest();rev.opId=q.opId;await rejects(f.secure().revokeAuthenticatedRevision(f.envelope('revoke-revision',rev)),'REGISTRY_REPLAY');});
test('replay remains blocked after registry reopened',async t=>{const f=await fixture(t),q=commitRequest(),e=f.envelope('commit-revision',q);await f.secure().commitAuthenticatedRevision(e);await rejects(f.secure().commitAuthenticatedRevision(e),'REGISTRY_REPLAY');});
test('concurrent authenticated commits with same expected revision have one winner',async t=>{const f=await fixture(t);await f.commit();const a=commitRequest(record(2),[artwork('PrivateArtwork0002')]),b=commitRequest(record(2),[artwork('PrivateArtwork0003')]);const outcomes=await Promise.allSettled([f.secure().commitAuthenticatedRevision(f.envelope('commit-revision',a)),f.secure().commitAuthenticatedRevision(f.envelope('commit-revision',b))]);assert.equal(outcomes.filter(x=>x.status==='fulfilled').length,1);assert.equal(outcomes.filter(x=>x.reason?.code==='REGISTRY_STALE_REVISION').length,1);});
test('concurrent authenticated artwork revocations allow only one winner',async t=>{const f=await fixture(t);await f.commit();const a=revokeArtworkRequest(),b=revokeArtworkRequest();const outcomes=await Promise.allSettled([f.secure().revokeAuthenticatedArtwork(f.envelope('revoke-artwork',a)),f.secure().revokeAuthenticatedArtwork(f.envelope('revoke-artwork',b))]);assert.equal(outcomes.filter(x=>x.status==='fulfilled').length,1);assert.equal(outcomes.filter(x=>x.reason?.code==='REGISTRY_ALREADY_REVOKED').length,1);});
test('authenticated artwork revocation refuses substituted variant even with newly signed permit',async t=>{const f=await fixture(t);await f.commit();const q=revokeArtworkRequest();q.variantGid='gid://shopify/ProductVariant/999';await rejects(f.secure().revokeAuthenticatedArtwork(f.envelope('revoke-artwork',q)),'REGISTRY_ARTWORK_UNAVAILABLE');});
test('authenticated artwork revocation refuses substituted layer even with signed permit',async t=>{const f=await fixture(t);await f.commit();const q=revokeArtworkRequest();q.layerId='other-layer';await rejects(f.secure().revokeAuthenticatedArtwork(f.envelope('revoke-artwork',q)),'REGISTRY_ARTWORK_UNAVAILABLE');});
test('authenticated artwork revocation refuses substituted product even with signed permit',async t=>{const f=await fixture(t);await f.commit();const q=revokeArtworkRequest();q.productGid='gid://shopify/Product/999';await rejects(f.secure().revokeAuthenticatedArtwork(f.envelope('revoke-artwork',q)),'REGISTRY_ARTWORK_UNAVAILABLE');});
test('authenticated artwork revocation rejects cross-owner principal',async t=>{const f=await fixture(t);await f.commit();const q=revokeArtworkRequest();f.setVerifier(()=>principal({ownerId:'intruder'}));await rejects(f.secure().revokeAuthenticatedArtwork(f.envelope('revoke-artwork',q)),'REGISTRY_MUTATION_DENIED');});
test('authenticated artwork revocation rejects permit for different artwork',async t=>{const f=await fixture(t);await f.commit();const q=revokeArtworkRequest(),e=f.envelope('revoke-artwork',q);q.storageKey='PrivateArtwork9999';await rejects(f.secure().revokeAuthenticatedArtwork(e),'REGISTRY_MUTATION_DENIED');});
test('authenticated revision revocation rejects stale revision',async t=>{const f=await fixture(t);await f.commit();await f.commit(record(2),[artwork('PrivateArtwork0002')]);const q=revokeRevisionRequest();await rejects(f.secure().revokeAuthenticatedRevision(f.envelope('revoke-revision',q)),'REGISTRY_REVISION_NOT_CURRENT');});
test('authenticated revision revocation rejects altered identity after signing',async t=>{const f=await fixture(t);await f.commit();const q=revokeRevisionRequest(),e=f.envelope('revoke-revision',q);q.identity.variantGid='gid://shopify/ProductVariant/999';await rejects(f.secure().revokeAuthenticatedRevision(e),'REGISTRY_MUTATION_DENIED');});
test('authenticated revision revocation rejects forged extra identity flag',async t=>{const f=await fixture(t);await f.commit();const q=revokeRevisionRequest();q.identity.admin=true;await rejects(f.secure().revokeAuthenticatedRevision({sessionToken:session,permit:{},request:q}),'REGISTRY_MUTATION_REQUEST');});
test('revoke permit cannot be replayed for another action',async t=>{const f=await fixture(t);await f.commit();const q=revokeRevisionRequest(),permit=f.grant('revoke-revision',q);await rejects(f.secure().revokeAuthenticatedArtwork({sessionToken:session,permit,request:revokeArtworkRequest()}),'REGISTRY_MUTATION_DENIED');});
test('failed authorization never consumes operation ID',async t=>{const f=await fixture(t),q=commitRequest(),e=f.envelope('commit-revision',q);e.permit.signature='a'.repeat(86);await rejects(f.secure().commitAuthenticatedRevision(e),'REGISTRY_MUTATION_DENIED');assert.equal((await f.secure().commitAuthenticatedRevision(f.envelope('commit-revision',q))).revision,1);});
test('anchor read outage blocks authenticated mutation without advancing',async t=>{const f=await fixture(t);await f.commit();f.setAnchorDown(true);const q=revokeRevisionRequest();await rejects(f.secure().revokeAuthenticatedRevision(f.envelope('revoke-revision',q)),'REGISTRY_ANCHOR_UNAVAILABLE');});
test('crash before rename leaves no mutation and permits retry with same signed grant',async t=>{const f=await fixture(t);await f.commit();const q=revokeRevisionRequest(),e=f.envelope('revoke-revision',q);f.setFault(stage=>{if(stage==='before-rename')throw Error('synthetic crash');});await assert.rejects(f.secure().revokeAuthenticatedRevision(e));f.setFault(undefined);assert.ok(await f.open().loadCurrentRevision(identity()));assert.deepEqual(await f.secure().revokeAuthenticatedRevision(e),{revoked:true});});
test('crash after rename fails closed until independently signed recovery',async t=>{const f=await fixture(t);await f.commit();const before=f.getAnchor(),q=revokeArtworkRequest(),e=f.envelope('revoke-artwork',q);f.setFault(stage=>{if(stage==='after-rename')throw Error('synthetic crash');});await assert.rejects(f.secure().revokeAuthenticatedArtwork(e));f.setFault(undefined);const state=await f.state(),target={sequence:state.sequence,mac:state.mac};await rejects(f.secure().revokeAuthenticatedArtwork(e),'REGISTRY_ROLLBACK');const recovered=f.secure({recovery:f.recovery});assert.equal(await recovered.recoverInterruptedRegistry({authorization:f.recoveryPermit(before,target)}),'recovered');await rejects(recovered.revokeAuthenticatedArtwork(e),'REGISTRY_REPLAY');assert.equal(state.revocations.length,1);});
test('forged recovery permit cannot bypass blocked authenticated revision mutation',async t=>{const f=await fixture(t);await f.commit();const before=f.getAnchor(),q=revokeRevisionRequest(),e=f.envelope('revoke-revision',q);f.setFault(stage=>{if(stage==='after-rename')throw Error('crash');});await assert.rejects(f.secure().revokeAuthenticatedRevision(e));f.setFault(undefined);const s=await f.state(),target={sequence:s.sequence,mac:s.mac},permit=f.recoveryPermit(before,target);permit.reason='forged reason';await rejects(f.secure({recovery:f.recovery}).recoverInterruptedRegistry({authorization:permit}),'REGISTRY_RECOVERY_SIGNATURE');await rejects(f.secure().revokeAuthenticatedRevision(e),'REGISTRY_ROLLBACK');});
test('two-layer authenticated revision commit binds both PNG byte streams',async t=>{const f=await fixture(t),r=record();r.design.layers.push(layer('layer-B','art-B'));r.designSha256=computeArtworkDesignSha256(r.design);const q=commitRequest(r,[artwork(),{storageKey:'PrivateArtwork0002',artworkId:'art-B',layerId:'layer-B',bytes:png(14,14)}]);const e=f.envelope('commit-revision',q);assert.equal((await f.secure().commitAuthenticatedRevision(e)).artworkCount,2);assert.equal((await f.state()).assets.length,2);});
test('two-layer authenticated commit refuses second PNG substituted after signing',async t=>{const f=await fixture(t),r=record();r.design.layers.push(layer('layer-B','art-B'));r.designSha256=computeArtworkDesignSha256(r.design);const q=commitRequest(r,[artwork(),{storageKey:'PrivateArtwork0002',artworkId:'art-B',layerId:'layer-B',bytes:png(14,14)}]),e=f.envelope('commit-revision',q);q.artworks[1].bytes=png(16,16);await rejects(f.secure().commitAuthenticatedRevision(e),'REGISTRY_MUTATION_DENIED');assert.equal(f.getAnchor(),null);});

test('secure user-facing instance blocks privileged unauthenticated key rotation',async t=>{const f=await fixture(t);await f.commit();await rejects(f.secure().rotateArtworkKey({opId:id()}),'REGISTRY_AUTH_REQUIRED');});
test('secure user-facing instance blocks privileged unauthenticated plaintext migration',async t=>{const f=await fixture(t);await f.commit();await rejects(f.secure().migratePlaintextArtwork({opId:id()}),'REGISTRY_AUTH_REQUIRED');});
test('session expiring while anchor read is pending is denied before persistence',async t=>{
 const f=await fixture(t);await f.commit();const q=revokeRevisionRequest(),e=f.envelope('revoke-revision',q);
 f.setVerifier(()=>principal({issuedAt:Date.now()-1000,expiresAt:Date.now()+130}));f.setAnchorDelay(280);
 await rejects(f.secure().revokeAuthenticatedRevision(e),'REGISTRY_MUTATION_DENIED');
 f.setAnchorDelay(0);assert.ok(await f.open().loadCurrentRevision(identity()));
 assert.equal((await f.state()).revocations.length,0);
});

test('signed permit expiring during slow anchor read cannot persist a revocation',async t=>{
 const f=await fixture(t);await f.commit();const q=revokeRevisionRequest();
 const e=f.envelope('revoke-revision',q,{issuedAt:Date.now()-1000,expiresAt:Date.now()+140});
 f.setAnchorDelay(290);
 await rejects(f.secure().revokeAuthenticatedRevision(e),'REGISTRY_MUTATION_DENIED');
 f.setAnchorDelay(0);assert.ok(await f.open().loadCurrentRevision(identity()));
 assert.equal((await f.state()).revocations.length,0);
});
test('authenticated commit crash after rename requires signed recovery and retains replay protection',async t=>{
 const f=await fixture(t),q=commitRequest(),e=f.envelope('commit-revision',q),before=f.getAnchor();
 f.setFault(stage=>{if(stage==='after-rename')throw Error('synthetic crash');});
 await assert.rejects(f.secure().commitAuthenticatedRevision(e));f.setFault(undefined);
 const s=await f.state(),target={sequence:s.sequence,mac:s.mac};
 await rejects(f.secure().commitAuthenticatedRevision(e),'REGISTRY_ROLLBACK');
 assert.equal(await f.secure({recovery:f.recovery}).recoverInterruptedRegistry({authorization:f.recoveryPermit(before,target)}),'recovered');
 await rejects(f.secure().commitAuthenticatedRevision(e),'REGISTRY_REPLAY');
 assert.deepEqual(await f.open().loadCurrentRevision(identity()),record());
});
