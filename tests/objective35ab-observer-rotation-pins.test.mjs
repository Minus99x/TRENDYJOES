import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {issueLocalReviewObserverReceipt as issue} from '../src/preview-local-artwork-review-observer.mjs';
import {localArtworkReviewJournalGenesisHead as genesis} from '../src/preview-local-artwork-review-journal.mjs';
import {LOCAL_REVIEW_ROTATION_SCHEMA,createLocalReviewObserverKeyRotation as create,
 verifyLocalReviewObserverKeyRotation as verify,exportLocalReviewRotationPin as exportPin,
 importLocalReviewRotationPin as importPin} from '../src/preview-local-artwork-review-observer-rotation.mjs';
const old=generateKeyPairSync('ed25519'),next=generateKeyPairSync('ed25519'),other=generateKeyPairSync('ed25519');
const keys={'old-key':old.publicKey,'new-key':next.publicKey,'other-key':other.publicKey};
const resolver=async(id,key)=>id==='alice'?keys[key]:undefined;
const hash=s=>createHash('sha256').update(s).digest('hex');
const rootPin=hash('local-artwork-root');
const h=n=>hash(String(n));
const reject=(p,code)=>assert.rejects(p,e=>e?.code===code);
const clone=x=>structuredClone(x);
const history=[h('first'),h('second'),h('third')];
async function receipt(keyId,records=history.slice(0,2),extra={}){
 const head={count:records.length,headDigest:records.at(-1)||genesis().headDigest};
 return issue({journal:{inspect:async()=>({head,historySignaturesVerified:true,
  independentlyWitnessed:false,shopifyWritesAllowed:false,authorizesProduction:false,
  entries:records.map((recordDigest,i)=>({index:i+1,rootPin,recordDigest,authority:'NONE'}))})},
  expectedHead:head,resolveReviewPublicKey:async()=>null,rootPin,
  observerId:'alice',keyId,signingKey:{'old-key':old,'new-key':next,'other-key':other}[keyId].privateKey,
  observedAt:1800000000000,resolveObserverPublicKey:resolver,...extra});
}
async function fixture(){
 const previousReceipt=await receipt('old-key'),successorReceipt=await receipt('new-key',history);
 const opts={previousReceipt,successorReceipt,expectedRootPin:rootPin,resolveObserverPublicKey:resolver};
 const rotation=await create({...opts,oldSigningKey:old.privateKey,newSigningKey:next.privateKey});
 return {...opts,rotation};
}
const importArgs=(f,exported)=>({bytes:exported.bytes,expectedSha256:exported.sha256,
 expectedPreviousReceiptDigest:f.previousReceipt.receiptDigest,expectedRootPin:rootPin,
 resolveObserverPublicKey:resolver});
test('35AB dual signed rotation binds the prior and successor signed receipts',async()=>{
 const f=await fixture(),v=await verify(f.rotation,f);
 assert.equal(f.rotation.schema,LOCAL_REVIEW_ROTATION_SCHEMA);
 assert.equal(v.dualSignatureVerified,true);assert.equal(v.historyPrefixVerified,true);
 assert.equal(v.independentKeyCustodyVerified,false);assert.equal(v.shopifyWritesAllowed,false);
});
test('35AB portable pin round trip verifies external SHA and prior receipt anchor',async()=>{
 const f=await fixture(),out=await exportPin(f),result=await importPin(importArgs(f,out));
 assert.equal(result.dualSignatureVerified,true);assert.equal(result.externallySuppliedDigestMatched,true);
 assert.equal(result.independentDigestCustodyVerified,false);assert.equal(result.authorizesProduction,false);
});
test('35AB export is canonical and repeatable without secret keys',async()=>{
 const f=await fixture(),a=await exportPin(f),b=await exportPin(f);
 assert.equal(a.sha256,b.sha256);assert.deepEqual(a.bytes,b.bytes);
 assert.equal(a.bytes.includes(Buffer.from('PRIVATE KEY')),false);
});
test('35AB tampered pin bytes rejected against separately retained digest',async()=>{
 const f=await fixture(),out=await exportPin(f),args=importArgs(f,out);
 args.bytes=Buffer.from(args.bytes);args.bytes[25]^=1;
 await reject(importPin(args),'LOCAL_REVIEW_PIN_DIGEST_MISMATCH');
});
test('35AB digest cannot be substituted by attacker',async()=>{
 const f=await fixture(),out=await exportPin(f);
 await reject(importPin({...importArgs(f,out),expectedSha256:h('fake')}),'LOCAL_REVIEW_PIN_DIGEST_MISMATCH');
});
test('35AB previous receipt external anchor cannot be substituted',async()=>{
 const f=await fixture(),out=await exportPin(f);
 await reject(importPin({...importArgs(f,out),expectedPreviousReceiptDigest:h('fake')}),'LOCAL_REVIEW_PIN_ANCHOR_MISMATCH');
});
test('35AB pin rejects incorrect root binding',async()=>{
 const f=await fixture(),out=await exportPin(f);
 await reject(importPin({...importArgs(f,out),expectedRootPin:h('other')}),'LOCAL_REVIEW_PIN_MALFORMED');
});
test('35AB import refuses digest omitted by caller',async()=>{
 const f=await fixture(),out=await exportPin(f);
 await reject(importPin({...importArgs(f,out),expectedSha256:undefined}),'LOCAL_REVIEW_PIN_INVALID_OPTIONS');
});
test('35AB import refuses missing prior independently anchored receipt digest',async()=>{
 const f=await fixture(),out=await exportPin(f);
 await reject(importPin({...importArgs(f,out),expectedPreviousReceiptDigest:undefined}),'LOCAL_REVIEW_PIN_INVALID_OPTIONS');
});
test('35AB import rejects noncanonical JSON despite matching digest',async()=>{
 const f=await fixture(),out=await exportPin(f),bytes=Buffer.from(JSON.stringify(JSON.parse(out.bytes.toString()),null,2));
 await reject(importPin({...importArgs(f,out),bytes,expectedSha256:hash(bytes)}),'LOCAL_REVIEW_PIN_MALFORMED');
});
test('35AB import rejects duplicate top-level JSON keys despite matching digest',async()=>{
 const f=await fixture(),out=await exportPin(f),raw=out.bytes.toString();
 const bytes=Buffer.from(raw.replace('{','{"schema":"malicious",'));
 await reject(importPin({...importArgs(f,out),bytes,expectedSha256:hash(bytes)}),'LOCAL_REVIEW_PIN_MALFORMED');
});
test('35AB import rejects oversized payload',async()=>{
 const f=await fixture(),out=await exportPin(f);
 await reject(importPin({...importArgs(f,out),bytes:Buffer.alloc(262145)}),'LOCAL_REVIEW_PIN_INVALID_OPTIONS');
});
test('35AB import rejects malformed JSON with externally supplied matching digest',async()=>{
 const f=await fixture(),out=await exportPin(f),bytes=Buffer.from('{');
 await reject(importPin({...importArgs(f,out),bytes,expectedSha256:hash(bytes)}),'LOCAL_REVIEW_PIN_INVALID_OPTIONS');
});
test('35AB rotation rejects same key used twice',async()=>{
 const a=await receipt('old-key'),b=await receipt('old-key',history);
 await reject(create({previousReceipt:a,successorReceipt:b,expectedRootPin:rootPin,
 resolveObserverPublicKey:resolver,oldSigningKey:old.privateKey,newSigningKey:old.privateKey}),
 'LOCAL_REVIEW_ROTATION_NON_EXTENSION');
});
test('35AB rotation rejects rollback successor history',async()=>{
 const a=await receipt('old-key',history),b=await receipt('new-key',history.slice(0,2));
 await reject(create({previousReceipt:a,successorReceipt:b,expectedRootPin:rootPin,
 resolveObserverPublicKey:resolver,oldSigningKey:old.privateKey,newSigningKey:next.privateKey}),
 'LOCAL_REVIEW_ROTATION_NON_EXTENSION');
});
test('35AB rotation rejects divergent journal prefix',async()=>{
 const a=await receipt('old-key'),b=await receipt('new-key',[h('fork'),h('second'),h('third')]);
 await reject(create({previousReceipt:a,successorReceipt:b,expectedRootPin:rootPin,
 resolveObserverPublicKey:resolver,oldSigningKey:old.privateKey,newSigningKey:next.privateKey}),
 'LOCAL_REVIEW_ROTATION_NON_EXTENSION');
});
test('35AB rotation refuses an old key replaced by an unrelated signer',async()=>{
 const f=await fixture();await reject(create({...f,oldSigningKey:other.privateKey,newSigningKey:next.privateKey}),
 'LOCAL_REVIEW_ROTATION_BAD_SIGNATURE');
});
test('35AB rotation refuses an unauthorized new signer',async()=>{
 const f=await fixture();await reject(create({...f,oldSigningKey:old.privateKey,newSigningKey:other.privateKey}),
 'LOCAL_REVIEW_ROTATION_BAD_SIGNATURE');
});
test('35AB verification rejects altered old signature',async()=>{
 const f=await fixture(),bad={...f.rotation,oldSignature:Buffer.alloc(64).toString('base64url')};
 await reject(verify(bad,f),'LOCAL_REVIEW_ROTATION_TAMPERED');
});
test('35AB verification rejects altered new signature',async()=>{
 const f=await fixture(),bad={...f.rotation,newSignature:Buffer.alloc(64).toString('base64url')};
 await reject(verify(bad,f),'LOCAL_REVIEW_ROTATION_TAMPERED');
});
test('35AB verification rejects forged authority',async()=>{
 const f=await fixture(),bad={...f.rotation,authority:'PRODUCTION'};
 await reject(verify(bad,f),'LOCAL_REVIEW_ROTATION_MALFORMED');
});
test('35AB verification rejects extra privilege fields',async()=>{
 const f=await fixture();await reject(verify({...f.rotation,canWriteShopify:true},f),
 'LOCAL_REVIEW_ROTATION_MALFORMED');
});
test('35AB verification rejects altered receipt digest binding',async()=>{
 const f=await fixture();await reject(verify({...f.rotation,previousReceiptDigest:h('wrong')},f),
 'LOCAL_REVIEW_ROTATION_MALFORMED');
});
test('35AB verification rejects substituted successor receipt',async()=>{
 const f=await fixture(),bad=await receipt('new-key',[...history,h('fourth')]);
 await reject(verify(f.rotation,{...f,successorReceipt:bad}),'LOCAL_REVIEW_ROTATION_MALFORMED');
});
test('35AB verification rejects untrusted resolver for new key',async()=>{
 const f=await fixture();await reject(verify(f.rotation,{...f,
 resolveObserverPublicKey:async(id,key)=>key==='new-key'?other.publicKey:keys[key]}),
 'LOCAL_REVIEW_OBSERVER_BAD_SIGNATURE');
});
test('35AB verification rejects malformed signature alphabet',async()=>{
 const f=await fixture();await reject(verify({...f.rotation,newSignature:'!'.repeat(86)},f),
 'LOCAL_REVIEW_ROTATION_MALFORMED');
});
test('35AB verification rejects rotation with missing old private key',async()=>{
 const f=await fixture();await reject(create({...f,oldSigningKey:undefined,newSigningKey:next.privateKey}),
 'LOCAL_REVIEW_ROTATION_INVALID_OPTIONS');
});
test('35AB receipt from new key can begin at same pinned head without losing history',async()=>{
 const a=await receipt('old-key'),b=await receipt('new-key');
 const opts={previousReceipt:a,successorReceipt:b,expectedRootPin:rootPin,
 resolveObserverPublicKey:resolver,oldSigningKey:old.privateKey,newSigningKey:next.privateKey};
 const rotation=await create(opts);assert.equal((await verify(rotation,opts)).historyPrefixVerified,true);
});
