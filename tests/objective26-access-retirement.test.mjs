import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,createHmac,randomBytes,generateKeyPairSync,sign} from 'node:crypto';
import {deflateSync} from 'node:zlib';
import {createOfflinePrivateRevisionRegistry} from '../src/offline-private-revision-registry.mjs';
import {computeArtworkDesignSha256} from '../src/manufacturing-artwork-evidence.mjs';
const hash=x=>createHash('sha256').update(x).digest('hex');
const crcTable=Array.from({length:256},(_,i)=>{let c=i;for(let j=0;j<8;j++)c=c&1?0xedb88320^(c>>>1):c>>>1;return c>>>0;});
function crc32(b){let c=0xffffffff;for(const x of b)c=crcTable[(c^x)&255]^(c>>>8);return(c^0xffffffff)>>>0;}
function chunk(type,data){const t=Buffer.from(type),b=Buffer.alloc(12+data.length);b.writeUInt32BE(data.length,0);t.copy(b,4);data.copy(b,8);b.writeUInt32BE(crc32(Buffer.concat([t,data])),8+data.length);return b;}
function png(w=12,h=12){const head=Buffer.alloc(13);head.writeUInt32BE(w,0);head.writeUInt32BE(h,4);head[8]=8;head[9]=2;const scan=Buffer.alloc(h*(w*3+1));return Buffer.concat([Buffer.from('89504e470d0a1a0a','hex'),chunk('IHDR',head),chunk('IDAT',deflateSync(scan)),chunk('IEND',Buffer.alloc(0))]);}
const shop='gucgmp-bc.myshopify.com';
const layer=(id='layer-A',artworkId='art-A')=>({id,type:'artwork',artworkId,surfaceId:'front',x:.2,y:.2,width:.3,height:.3,rotationDeg:0,sourceWidthPx:100,sourceHeightPx:100});
function record(revision=1,changes={}){const design={layers:[layer()]};return{schema:'TJ-CURRENT-IMMUTABLE-DESIGN-1',shop,productGid:'gid://shopify/Product/123',variantGid:'gid://shopify/ProductVariant/456',manifestId:'concept-crew-tee',ownerId:'owner-1',designId:'design-1',revision,designSha256:computeArtworkDesignSha256(design),status:'CURRENT_IMMUTABLE',design,...changes};}
const identity=r=>Object.fromEntries(['shop','productGid','variantGid','ownerId','designId','revision'].map(k=>[k,r[k]]));
const asset=(storageKey='PrivateArtwork0001',bytes=png())=>({storageKey,artworkId:'art-A',layerId:'layer-A',bytes});
const readArgs=(r=record(),storageKey='PrivateArtwork0001')=>({storageKey,ownerId:r.ownerId,designId:r.designId,revision:r.revision,artworkId:'art-A'});
let n=0;const op=()=>`encrypt-op-${++n}-${randomBytes(6).toString('hex')}`;
const reject=(p,code)=>assert.rejects(p,e=>e?.code===code);
const kidA='key-2026-alpha',kidB='key-2026-bravo';
async function fixture(t){
 const directory=await mkdtemp(join(tmpdir(),'tj-enc25-'));t.after(()=>rm(directory,{recursive:true,force:true}));
 const secret=randomBytes(32),keys=new Map([[kidA,randomBytes(32)],[kidB,randomBytes(32)]]);
 let anchor=null,failRead=false,failWrite=false,injectFault;
 const adapters={readAnchor:async()=>{if(failRead)throw Error('unavailable');return structuredClone(anchor);},compareAndSetAnchor:async(old,next)=>{if(failWrite)throw Error('unavailable');if(JSON.stringify(old)!==JSON.stringify(anchor))return false;anchor=structuredClone(next);return true;}};
 const config=(activeKeyId=kidA)=>({activeKeyId,resolveKey:keyId=>keys.get(keyId)});
 const open=(encryption=config(),extra={})=>createOfflinePrivateRevisionRegistry({directory,secret,...adapters,injectFault,...(encryption===null?{}:{encryption}),...extra});
 const commit=({r=record(),a=[asset()],encryption=config(),extra={}}={})=>open(encryption).commitRevision({record:r,artworks:a,expectedRevision:r.revision===1?null:r.revision-1,opId:op(),...extra});
 const state=async()=>JSON.parse(await readFile(join(directory,'private-registry.json'),'utf8'));
 const store=async s=>writeFile(join(directory,'private-registry.json'),JSON.stringify(s));
 const resign=async s=>{const{mac,...body}=s;s.mac=createHmac('sha256',secret).update('TJ-PRIVATE-REGISTRY-1\0'+JSON.stringify(body)).digest('hex');await store(s);anchor={sequence:s.sequence,mac:s.mac};};
 return{directory,secret,keys,config,open,commit,state,store,resign,getAnchor:()=>structuredClone(anchor),setAnchor:x=>{anchor=x;},setFault:x=>{injectFault=x;},failRead:x=>{failRead=x;},failWrite:x=>{failWrite=x;}};
}
const encrypted=s=>s.assets[0].encryption;


const authRequest=(r=record(),storageKey='PrivateArtwork0001')=>({...identity(r),storageKey,artworkId:'art-A',layerId:'layer-A'});
const sessionToken='synthetic-session-verified-26';
const verifiedPrincipal=(overrides={})=>({shop,ownerId:'owner-1',issuedAt:Date.now()-1000,expiresAt:Date.now()+60000,...overrides});
const verified=f=>f.open(f.config(),{verifyArtworkAccess:async token=>token===sessionToken?verifiedPrincipal():null});
const auth=(r=record(),storageKey)=>({sessionToken,request:authRequest(r,storageKey)});

// Trusted callback contract and strict principal boundaries.
test('authenticated artwork read decrypts exact current owner and full identity',async t=>{const f=await fixture(t);await f.commit();assert.deepEqual(await verified(f).readAuthenticatedArtwork(auth()),png());});
test('authenticated read never returns token or metadata in place of bytes',async t=>{const f=await fixture(t);await f.commit();const bytes=await verified(f).readAuthenticatedArtwork(auth());assert.ok(Buffer.isBuffer(bytes));assert.equal(bytes.toString('hex'),png().toString('hex'));});
test('secure mode disables weak legacy owner-only read path',async t=>{const f=await fixture(t);await f.commit();await reject(verified(f).readPrivateArtwork(readArgs()),'REGISTRY_AUTH_REQUIRED');});
test('unconfigured verifier refuses authenticated access',async t=>{const f=await fixture(t);await f.commit();await reject(f.open().readAuthenticatedArtwork(auth()),'REGISTRY_AUTH_REQUIRED');});
test('verifier must be a function',async t=>{const f=await fixture(t);for(const verifyArtworkAccess of [null,1,'yes',{},[]])assert.throws(()=>f.open(f.config(),{verifyArtworkAccess}),e=>e.code==='REGISTRY_ACCESS_CONFIGURATION');});
test('unknown token cannot impersonate owner',async t=>{const f=await fixture(t);await f.commit();await reject(verified(f).readAuthenticatedArtwork({...auth(),sessionToken:'unknown-session-credential-26'}),'REGISTRY_ACCESS_DENIED');});
test('short or missing session tokens fail before verifier',async t=>{const f=await fixture(t);await f.commit();let calls=0;const r=f.open(f.config(),{verifyArtworkAccess:()=>{calls++;return verifiedPrincipal();}});for(const token of [undefined,null,'short','a'.repeat(513),'abc\n'.padEnd(16,'x')])await reject(r.readAuthenticatedArtwork({...auth(),sessionToken:token}),'REGISTRY_ACCESS_DENIED');assert.equal(calls,0);});
test('verifier exception is denied without leaking exception details',async t=>{const f=await fixture(t);await f.commit();const r=f.open(f.config(),{verifyArtworkAccess:()=>{throw Error('secret internal provider failure');}});await reject(r.readAuthenticatedArtwork(auth()),'REGISTRY_ACCESS_DENIED');});
test('async verifier rejection fails closed',async t=>{const f=await fixture(t);await f.commit();const r=f.open(f.config(),{verifyArtworkAccess:async()=>{throw Error('network outage');}});await reject(r.readAuthenticatedArtwork(auth()),'REGISTRY_ACCESS_DENIED');});
test('missing principal fails closed',async t=>{const f=await fixture(t);await f.commit();const r=f.open(f.config(),{verifyArtworkAccess:()=>undefined});await reject(r.readAuthenticatedArtwork(auth()),'REGISTRY_ACCESS_DENIED');});
test('untrusted principal supplied in request is rejected',async t=>{const f=await fixture(t);await f.commit();await reject(verified(f).readAuthenticatedArtwork({...auth(),principal:verifiedPrincipal()}),'REGISTRY_ACCESS_DENIED');});
test('forged extra request property rejected',async t=>{const f=await fixture(t);await f.commit();await reject(verified(f).readAuthenticatedArtwork({...auth(),request:{...authRequest(),approved:true}}),'REGISTRY_ACCESS_DENIED');});
for(const [field,value] of [['shop','wrong.myshopify.com'],['ownerId','attacker'],['productGid','gid://shopify/Product/999'],['variantGid','gid://shopify/ProductVariant/999'],['designId','another-design'],['revision',2],['storageKey','PrivateArtwork9999'],['artworkId','art-other'],['layerId','layer-other']]){
 test(`exact authenticated request binding rejects substituted ${field}`,async t=>{const f=await fixture(t);await f.commit();await reject(verified(f).readAuthenticatedArtwork({...auth(),request:{...authRequest(),[field]:value}}),['shop','ownerId'].includes(field)?'REGISTRY_ACCESS_DENIED':'REGISTRY_ARTWORK_UNAVAILABLE');});
}
for(const [field,value] of [['ownerId','attacker'],['shop','other.myshopify.com'],['expiresAt',Date.now()-1000],['issuedAt',Date.now()+300000],['expiresAt',Date.now()+1_000_000],['ownerId',null]]){
 test(`verified principal rejects invalid ${field} (${String(value)})`,async t=>{const f=await fixture(t);await f.commit();const r=f.open(f.config(),{verifyArtworkAccess:()=>verifiedPrincipal({[field]:value})});await reject(r.readAuthenticatedArtwork(auth()),'REGISTRY_ACCESS_DENIED');});
}
test('verifier output with extra untrusted fields rejected',async t=>{const f=await fixture(t);await f.commit();const r=f.open(f.config(),{verifyArtworkAccess:()=>({...verifiedPrincipal(),admin:true})});await reject(r.readAuthenticatedArtwork(auth()),'REGISTRY_ACCESS_DENIED');});
test('zero-length or overlong verifier lifetime rejected',async t=>{const f=await fixture(t);await f.commit();const now=Date.now();for(const p of [{issuedAt:now,expiresAt:now},{issuedAt:now-1000,expiresAt:now+900001}]){const r=f.open(f.config(),{verifyArtworkAccess:()=>verifiedPrincipal(p)});await reject(r.readAuthenticatedArtwork(auth()),'REGISTRY_ACCESS_DENIED');}});
test('revoked artwork remains inaccessible via verified read',async t=>{const f=await fixture(t);await f.commit();await f.open().revokeArtwork({...readArgs(),opId:op()});await reject(verified(f).readAuthenticatedArtwork(auth()),'REGISTRY_ARTWORK_UNAVAILABLE');});
test('revoked revision remains inaccessible via verified read',async t=>{const f=await fixture(t);await f.commit();await f.open().revokeRevision({identity:identity(record()),opId:op()});await reject(verified(f).readAuthenticatedArtwork(auth()),'REGISTRY_ARTWORK_UNAVAILABLE');});
test('superseded revision is inaccessible but current revision remains readable',async t=>{const f=await fixture(t);await f.commit();await f.commit({r:record(2),a:[asset('PrivateArtwork0002')]});await reject(verified(f).readAuthenticatedArtwork(auth()),'REGISTRY_ARTWORK_UNAVAILABLE');assert.deepEqual(await verified(f).readAuthenticatedArtwork(auth(record(2),'PrivateArtwork0002')),png());});
test('authenticated read works after AES-GCM key rotation',async t=>{const f=await fixture(t);await f.commit();await f.open(f.config(kidB)).rotateArtworkKey({opId:op()});const r=f.open(f.config(kidB),{verifyArtworkAccess:()=>verifiedPrincipal()});assert.deepEqual(await r.readAuthenticatedArtwork(auth()),png());});
test('authenticated read works after explicit legacy plaintext migration',async t=>{const f=await fixture(t);await f.commit({encryption:null});await f.open().migratePlaintextArtwork({opId:op()});assert.deepEqual(await verified(f).readAuthenticatedArtwork(auth()),png());});
test('authenticated read refuses plaintext registry before migration',async t=>{const f=await fixture(t);await f.commit({encryption:null});await reject(verified(f).readAuthenticatedArtwork(auth()),'REGISTRY_ENCRYPTION_REQUIRED');});
test('authenticated read refuses unavailable historical decryption key',async t=>{const f=await fixture(t);await f.commit();f.keys.delete(kidA);await reject(verified(f).readAuthenticatedArtwork(auth()),'REGISTRY_KEY_UNAVAILABLE');});
test('authenticated read refuses interrupted anchor commit',async t=>{const f=await fixture(t);await f.commit();f.setFault(stage=>{if(stage==='after-rename')throw Error('crash');});await assert.rejects(f.open(f.config(kidB)).rotateArtworkKey({opId:op()}));f.setFault(undefined);await reject(verified(f).readAuthenticatedArtwork(auth()),'REGISTRY_ROLLBACK');});

// Key retirement is only a read-only snapshot assessment, never a destroy operation.
test('key retirement inspection lists historical encrypted asset references',async t=>{const f=await fixture(t);await f.commit();const out=await f.open().inspectArtworkKeyRetirement({keyId:kidA});assert.equal(out.referencedAssets,1);assert.equal(out.activeKey,true);assert.equal(out.safeToDestroy,false);assert.equal(out.backupsVerified,false);assert.equal(out.productionApproved,false);});
test('key retirement assessment counts revoked assets too',async t=>{const f=await fixture(t);await f.commit();await f.open().revokeArtwork({...readArgs(),opId:op()});assert.equal((await f.open().inspectArtworkKeyRetirement({keyId:kidA})).referencedAssets,1);});
test('key retirement assessment counts superseded historical revisions',async t=>{const f=await fixture(t);await f.commit();await f.commit({r:record(2),a:[asset('PrivateArtwork0002')]});assert.equal((await f.open().inspectArtworkKeyRetirement({keyId:kidA})).referencedAssets,2);});
test('old key becomes unreferenced after successful complete rotation',async t=>{const f=await fixture(t);await f.commit();await f.open(f.config(kidB)).rotateArtworkKey({opId:op()});const r=f.open(f.config(kidB));const out=await r.inspectArtworkKeyRetirement({keyId:kidA});assert.equal(out.referencedAssets,0);assert.equal(out.unusedInCurrentRegistry,true);assert.equal(out.safeToDestroy,false);assert.equal(out.backupsVerified,false);});
test('unreferenced inactive key still cannot be declared safe to destroy',async t=>{const f=await fixture(t);await f.commit();const out=await f.open().inspectArtworkKeyRetirement({keyId:kidB});assert.equal(out.referencedAssets,0);assert.equal(out.unusedInCurrentRegistry,true);assert.equal(out.safeToDestroy,false);});
test('active key after rotation is not marked unused',async t=>{const f=await fixture(t);await f.commit();await f.open(f.config(kidB)).rotateArtworkKey({opId:op()});const out=await f.open(f.config(kidB)).inspectArtworkKeyRetirement({keyId:kidB});assert.equal(out.activeKey,true);assert.equal(out.unusedInCurrentRegistry,false);});
test('inspection does not write registry or anchor',async t=>{const f=await fixture(t);await f.commit();const before=await readFile(join(f.directory,'private-registry.json')),anchor=f.getAnchor();await f.open().inspectArtworkKeyRetirement({keyId:kidA});assert.deepEqual(await readFile(join(f.directory,'private-registry.json')),before);assert.deepEqual(f.getAnchor(),anchor);});
test('inspection rejects malformed key IDs',async t=>{const f=await fixture(t);await f.commit();for(const keyId of [undefined,null,'x','../../secret',kidA+'!'])await reject(f.open().inspectArtworkKeyRetirement({keyId}),'REGISTRY_KEY_ID_INVALID');});
test('inspection without encryption contract fails closed',async t=>{const f=await fixture(t);await f.commit({encryption:null});await reject(f.open(null).inspectArtworkKeyRetirement({keyId:kidA}),'REGISTRY_ENCRYPTION_REQUIRED');});
test('inspection requires trusted anchor availability',async t=>{const f=await fixture(t);await f.commit();f.failRead(true);await reject(f.open().inspectArtworkKeyRetirement({keyId:kidA}),'REGISTRY_ANCHOR_UNAVAILABLE');});
test('inspection refuses interrupted rotation until signed recovery',async t=>{const f=await fixture(t);await f.commit();f.setFault(stage=>{if(stage==='after-rename')throw Error('crash');});await assert.rejects(f.open(f.config(kidB)).rotateArtworkKey({opId:op()}));f.setFault(undefined);await reject(f.open(f.config(kidB)).inspectArtworkKeyRetirement({keyId:kidA}),'REGISTRY_ROLLBACK');});
test('inspection rejects missing decryption keys rather than reporting unsafe success',async t=>{const f=await fixture(t);await f.commit();f.keys.delete(kidA);await reject(f.open().inspectArtworkKeyRetirement({keyId:kidA}),'REGISTRY_KEY_UNAVAILABLE');});
test('retirement evidence remains cautious after plaintext migration',async t=>{const f=await fixture(t);await f.commit({encryption:null});await f.open().migratePlaintextArtwork({opId:op()});const out=await f.open().inspectArtworkKeyRetirement({keyId:kidB});assert.equal(out.unusedInCurrentRegistry,true);assert.equal(out.backupsVerified,false);assert.equal(out.safeToDestroy,false);});
test('concurrent authenticated reads and rotation preserve anchor safety',async t=>{const f=await fixture(t);await f.commit();const old=verified(f),rotated=f.open(f.config(kidB),{verifyArtworkAccess:()=>verifiedPrincipal()});const results=await Promise.allSettled([old.readAuthenticatedArtwork(auth()),rotated.rotateArtworkKey({opId:op()}),rotated.readAuthenticatedArtwork(auth())]);assert.equal(results[1].status,'fulfilled');assert.deepEqual(await rotated.readAuthenticatedArtwork(auth()),png());assert.ok(results.every(r=>r.status==='fulfilled'));});

const recoverySchema26='TJ-OFFLINE-PRIVATE-REGISTRY-RECOVERY-1';
const recoveryFields26=['schema','registryId','authorizationId','issuedAt','expiresAt','expectedAnchor','targetAnchor','reason'];
function recoverySetup(){
 const {publicKey,privateKey}=generateKeyPairSync('ed25519'),registryId='trendyjoes-registry-objective-26';
 const permit=(expectedAnchor,targetAnchor)=>{
  const now=Date.now(),payload={schema:recoverySchema26,registryId,authorizationId:'recovery-26-'+randomBytes(8).toString('hex'),issuedAt:now-1000,expiresAt:now+60000,expectedAnchor,targetAnchor,reason:'Independent local operator verified recovery evidence'};
  const canonical=Object.fromEntries(recoveryFields26.map(k=>[k,payload[k]]));
  return {...payload,signature:sign(null,Buffer.from(`${recoverySchema26}\0${JSON.stringify(canonical)}`),privateKey).toString('base64url')};
 };
 return {recovery:{registryId,publicKey},permit};
}
test('signed recovery of interrupted encrypted rotation restores authenticated reads',async t=>{
 const f=await fixture(t);await f.commit();const before=f.getAnchor(),r=recoverySetup();
 f.setFault(stage=>{if(stage==='after-rename')throw Error('synthetic crash');});
 await assert.rejects(f.open(f.config(kidB)).rotateArtworkKey({opId:op()}));f.setFault(undefined);
 const s=await f.state(),target={sequence:s.sequence,mac:s.mac};
 const secure=f.open(f.config(kidB),{recovery:r.recovery,verifyArtworkAccess:()=>verifiedPrincipal()});
 await reject(secure.readAuthenticatedArtwork(auth()),'REGISTRY_ROLLBACK');
 assert.equal(await secure.recoverInterruptedRegistry({authorization:r.permit(before,target)}),'recovered');
 assert.deepEqual(await secure.readAuthenticatedArtwork(auth()),png());
 assert.equal((await secure.inspectArtworkKeyRetirement({keyId:kidA})).referencedAssets,0);
});
test('forged recovery permit cannot unlock encrypted authenticated read',async t=>{
 const f=await fixture(t);await f.commit();const before=f.getAnchor(),r=recoverySetup();
 f.setFault(stage=>{if(stage==='after-rename')throw Error('synthetic crash');});
 await assert.rejects(f.open(f.config(kidB)).rotateArtworkKey({opId:op()}));f.setFault(undefined);
 const s=await f.state(),target={sequence:s.sequence,mac:s.mac},secure=f.open(f.config(kidB),{recovery:r.recovery,verifyArtworkAccess:()=>verifiedPrincipal()});
 const permit=r.permit(before,target);permit.reason='Forgery rather than independently approved recovery';
 await reject(secure.recoverInterruptedRegistry({authorization:permit}),'REGISTRY_RECOVERY_SIGNATURE');
 await reject(secure.readAuthenticatedArtwork(auth()),'REGISTRY_ROLLBACK');
});
test('signed recovery of interrupted plaintext migration enables encrypted authorized read',async t=>{
 const f=await fixture(t);await f.commit({encryption:null});const before=f.getAnchor(),r=recoverySetup();
 f.setFault(stage=>{if(stage==='after-rename')throw Error('synthetic crash');});
 await assert.rejects(f.open().migratePlaintextArtwork({opId:op()}));f.setFault(undefined);
 const s=await f.state(),target={sequence:s.sequence,mac:s.mac};
 const secure=f.open(f.config(),{recovery:r.recovery,verifyArtworkAccess:()=>verifiedPrincipal()});
 await reject(secure.readAuthenticatedArtwork(auth()),'REGISTRY_ROLLBACK');
 assert.equal(await secure.recoverInterruptedRegistry({authorization:r.permit(before,target)}),'recovered');
 assert.deepEqual(await secure.readAuthenticatedArtwork(auth()),png());
 assert.equal((await secure.inspectArtworkKeyRetirement({keyId:kidA})).referencedAssets,1);
});

test('authenticated access seam refuses plaintext-only configuration',async t=>{const f=await fixture(t);await f.commit({encryption:null});const r=f.open(null,{verifyArtworkAccess:()=>verifiedPrincipal()});await reject(r.readAuthenticatedArtwork(auth()),'REGISTRY_ENCRYPTION_REQUIRED');});
