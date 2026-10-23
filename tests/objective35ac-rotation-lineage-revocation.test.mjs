import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {issueLocalReviewObserverReceipt as issue} from '../src/preview-local-artwork-review-observer.mjs';
import {localArtworkReviewJournalGenesisHead as genesis} from '../src/preview-local-artwork-review-journal.mjs';
import {createLocalReviewObserverKeyRotation as rotate} from '../src/preview-local-artwork-review-observer-rotation.mjs';
import {LOCAL_REVIEW_REVOCATION_SCHEMA,LOCAL_REVIEW_LINEAGE_SCHEMA,
 digestLocalReviewRevocationPolicy as policyDigest,
 exportLocalReviewRotationLineage as exportLineage,
 importLocalReviewRotationLineage as importLineage} from '../src/preview-local-artwork-review-rotation-lineage.mjs';
const pairs=Object.fromEntries(['a','b','c','d','e'].map(x=>[x,generateKeyPairSync('ed25519')]));
const digest=s=>createHash('sha256').update(s).digest('hex');
const fingerprint=k=>digest(pairs[k].publicKey.export({type:'spki',format:'der'}));
const rootPin=digest('35ac-root'),records=Array.from({length:6},(_,i)=>digest(`entry-${i}`));
const resolve=async(id,key)=>id==='alice'?pairs[key]?.publicKey:undefined;
const reject=(p,code)=>assert.rejects(p,e=>e?.code===code);
const policy=(revokedKeyFingerprints=[],revokedRotationDigests=[],revision=1)=>({
 schema:LOCAL_REVIEW_REVOCATION_SCHEMA,revision,revokedKeyFingerprints,
 revokedRotationDigests,authority:'NONE'});
async function receipt(key,n,observerId='alice'){
 const history=records.slice(0,n),head={count:n,headDigest:history.at(-1)||genesis().headDigest};
 return issue({journal:{inspect:async()=>({head,historySignaturesVerified:true,
  independentlyWitnessed:false,shopifyWritesAllowed:false,authorizesProduction:false,
  entries:history.map((recordDigest,i)=>({index:i+1,rootPin,recordDigest,authority:'NONE'}))})},
  expectedHead:head,resolveReviewPublicKey:async()=>null,rootPin,
  observerId,keyId:key,signingKey:pairs[key].privateKey,observedAt:1800000000000,
  resolveObserverPublicKey:resolve});
}
async function fixture(){
 const r0=await receipt('a',2),r1=await receipt('b',3),r2=await receipt('c',4);
 const make=async(a,b,ka,kb)=>({previousReceipt:a,successorReceipt:b,
  rotation:await rotate({previousReceipt:a,successorReceipt:b,oldSigningKey:pairs[ka].privateKey,
   newSigningKey:pairs[kb].privateKey,expectedRootPin:rootPin,resolveObserverPublicKey:resolve})});
 const hops=[await make(r0,r1,'a','b'),await make(r1,r2,'b','c')],p=policy();
 const opts={hops,expectedRootPin:rootPin,resolveObserverPublicKey:resolve,
  expectedInitialReceiptDigest:r0.receiptDigest,expectedInitialKeyFingerprint:fingerprint('a'),
  policy:p,expectedPolicySha256:policyDigest(p)};
 const exported=await exportLineage(opts);
 const args={bytes:exported.bytes,expectedSha256:exported.sha256,
  expectedRootPin:rootPin,resolveObserverPublicKey:resolve,
  expectedInitialReceiptDigest:r0.receiptDigest,expectedInitialKeyFingerprint:fingerprint('a'),
  expectedTerminalReceiptDigest:r2.receiptDigest,expectedTerminalKeyFingerprint:fingerprint('c'),
  policy:p,expectedPolicySha256:policyDigest(p)};
 return {r0,r1,r2,hops,opts,exported,args,make};
}
test('35AC verifies two consecutive dual-signed transitions',async()=>{
 const f=await fixture(),v=await importLineage(f.args);
 assert.equal(v.schema,LOCAL_REVIEW_LINEAGE_SCHEMA);assert.equal(v.hopCount,2);
 assert.equal(v.observerId,'alice');assert.equal(v.externallySuppliedAnchorsMatched,true);
 assert.equal(v.independentAnchorCustodyVerified,false);assert.equal(v.revocationRegistryAuthenticated,false);
 assert.equal(v.trustedTime,false);assert.equal(v.shopifyWritesAllowed,false);
});
test('35AC canonical export deterministic',async()=>{
 const f=await fixture(),b=await exportLineage(f.opts);
 assert.equal(f.exported.sha256,b.sha256);assert.deepEqual(f.exported.bytes,b.bytes);
 assert.equal(b.independentlyRetained,false);assert.equal(b.authorizesProduction,false);
});
test('35AC requires caller supplied initial digest',async()=>{
 const f=await fixture();await reject(exportLineage({...f.opts,expectedInitialReceiptDigest:undefined}),
  'LOCAL_REVIEW_LINEAGE_EXTERNAL_ANCHORS_REQUIRED');
});
test('35AC requires caller supplied initial fingerprint',async()=>{
 const f=await fixture();await reject(exportLineage({...f.opts,expectedInitialKeyFingerprint:undefined}),
  'LOCAL_REVIEW_LINEAGE_EXTERNAL_ANCHORS_REQUIRED');
});
test('35AC requires authenticated key resolver seam',async()=>{
 const f=await fixture();await reject(exportLineage({...f.opts,resolveObserverPublicKey:undefined}),
  'LOCAL_REVIEW_LINEAGE_EXTERNAL_ANCHORS_REQUIRED');
});
test('35AC refuses wrong first receipt external pin',async()=>{
 const f=await fixture();await reject(exportLineage({...f.opts,expectedInitialReceiptDigest:digest('wrong')}),
  'LOCAL_REVIEW_LINEAGE_INITIAL_ANCHOR_MISMATCH');
});
test('35AC refuses wrong first key fingerprint pin',async()=>{
 const f=await fixture();await reject(exportLineage({...f.opts,expectedInitialKeyFingerprint:fingerprint('e')}),
  'LOCAL_REVIEW_LINEAGE_INITIAL_ANCHOR_MISMATCH');
});
test('35AC import requires external SHA pin',async()=>{
 const f=await fixture();await reject(importLineage({...f.args,expectedSha256:undefined}),
  'LOCAL_REVIEW_LINEAGE_EXTERNAL_ANCHORS_REQUIRED');
});
test('35AC import requires external terminal receipt pin',async()=>{
 const f=await fixture();await reject(importLineage({...f.args,expectedTerminalReceiptDigest:undefined}),
  'LOCAL_REVIEW_LINEAGE_EXTERNAL_ANCHORS_REQUIRED');
});
test('35AC import requires external terminal key pin',async()=>{
 const f=await fixture();await reject(importLineage({...f.args,expectedTerminalKeyFingerprint:undefined}),
  'LOCAL_REVIEW_LINEAGE_EXTERNAL_ANCHORS_REQUIRED');
});
test('35AC tampered bytes rejected against retained digest',async()=>{
 const f=await fixture(),bytes=Buffer.from(f.exported.bytes);bytes[33]^=1;
 await reject(importLineage({...f.args,bytes}),'LOCAL_REVIEW_LINEAGE_DIGEST_MISMATCH');
});
test('35AC substituted externally pinned SHA rejected',async()=>{
 const f=await fixture();await reject(importLineage({...f.args,expectedSha256:digest('fake')}),
  'LOCAL_REVIEW_LINEAGE_DIGEST_MISMATCH');
});
test('35AC substituted final receipt rejected even with valid bundle',async()=>{
 const f=await fixture();await reject(importLineage({...f.args,expectedTerminalReceiptDigest:digest('fake')}),
  'LOCAL_REVIEW_LINEAGE_TERMINAL_ANCHOR_MISMATCH');
});
test('35AC substituted terminal key rejected even with valid bundle',async()=>{
 const f=await fixture();await reject(importLineage({...f.args,expectedTerminalKeyFingerprint:fingerprint('d')}),
  'LOCAL_REVIEW_LINEAGE_TERMINAL_ANCHOR_MISMATCH');
});
test('35AC policy digest is deterministic',()=>{
 const p=policy();assert.equal(policyDigest(p),policyDigest(structuredClone(p)));
});
test('35AC refuses missing external policy digest',async()=>{
 const f=await fixture();await reject(importLineage({...f.args,expectedPolicySha256:undefined}),
  'LOCAL_REVIEW_LINEAGE_EXTERNAL_ANCHORS_REQUIRED');
});
test('35AC refuses substituted policy under retained digest',async()=>{
 const f=await fixture();await reject(importLineage({...f.args,policy:policy([fingerprint('b')])}),
  'LOCAL_REVIEW_LINEAGE_POLICY_ANCHOR_MISMATCH');
});
test('35AC revokes intermediate key without historical grandfathering',async()=>{
 const f=await fixture(),p=policy([fingerprint('b')]);
 await reject(importLineage({...f.args,policy:p,expectedPolicySha256:policyDigest(p)}),
  'LOCAL_REVIEW_LINEAGE_REVOKED');
});
test('35AC revokes initial key fail closed',async()=>{
 const f=await fixture(),p=policy([fingerprint('a')]);
 await reject(importLineage({...f.args,policy:p,expectedPolicySha256:policyDigest(p)}),
  'LOCAL_REVIEW_LINEAGE_REVOKED');
});
test('35AC revokes terminal key fail closed',async()=>{
 const f=await fixture(),p=policy([fingerprint('c')]);
 await reject(importLineage({...f.args,policy:p,expectedPolicySha256:policyDigest(p)}),
  'LOCAL_REVIEW_LINEAGE_REVOKED');
});
test('35AC revokes one signed transition digest',async()=>{
 const f=await fixture(),p=policy([],[f.hops[0].rotation.rotationDigest]);
 await reject(importLineage({...f.args,policy:p,expectedPolicySha256:policyDigest(p)}),
  'LOCAL_REVIEW_LINEAGE_REVOKED');
});
test('35AC revokes final transition digest',async()=>{
 const f=await fixture(),p=policy([],[f.hops[1].rotation.rotationDigest]);
 await reject(importLineage({...f.args,policy:p,expectedPolicySha256:policyDigest(p)}),
  'LOCAL_REVIEW_LINEAGE_REVOKED');
});
test('35AC policy forbids unsorted revocation arrays',()=>{
 assert.throws(()=>policyDigest(policy([fingerprint('c'),fingerprint('a')].sort().reverse())),
  {code:'LOCAL_REVIEW_LINEAGE_INVALID_POLICY'});
});
test('35AC policy forbids duplicate revocations',()=>{
 assert.throws(()=>policyDigest(policy([fingerprint('a'),fingerprint('a')])),
  {code:'LOCAL_REVIEW_LINEAGE_INVALID_POLICY'});
});
test('35AC policy forbids malformed key fingerprints',()=>{
 assert.throws(()=>policyDigest(policy(['not-a-hash'])),
  {code:'LOCAL_REVIEW_LINEAGE_INVALID_POLICY'});
});
test('35AC policy forbids untrusted authority elevation',()=>{
 assert.throws(()=>policyDigest({...policy(),authority:'SHOPIFY_WRITE'}),
  {code:'LOCAL_REVIEW_LINEAGE_INVALID_POLICY'});
});
test('35AC policy forbids implicit time-based revocation bypass',()=>{
 assert.throws(()=>policyDigest({...policy(),effectiveAfter:Date.now()}),
  {code:'LOCAL_REVIEW_LINEAGE_INVALID_POLICY'});
});
test('35AC policy requires positive integer revision',()=>{
 assert.throws(()=>policyDigest(policy([],[],0)),{code:'LOCAL_REVIEW_LINEAGE_INVALID_POLICY'});
});
test('35AC rejects reversed rotation order',async()=>{
 const f=await fixture();await reject(exportLineage({...f.opts,hops:[...f.hops].reverse()}),
  'LOCAL_REVIEW_LINEAGE_INITIAL_ANCHOR_MISMATCH');
});
test('35AC rejects repeated hop replay',async()=>{
 const f=await fixture();await reject(exportLineage({...f.opts,hops:[f.hops[0],f.hops[0]]}),
  'LOCAL_REVIEW_LINEAGE_BROKEN_LINK');
});
test('35AC rejects missing intermediate transition',async()=>{
 const f=await fixture(),r3=await receipt('d',5),jump=await f.make(f.r2,r3,'c','d');
 await reject(exportLineage({...f.opts,hops:[f.hops[0],jump]}),
  'LOCAL_REVIEW_LINEAGE_BROKEN_LINK');
});
test('35AC rejects second hop fork from same predecessor',async()=>{
 const f=await fixture(),fork=await receipt('c',5);
 const second=await f.make(f.r1,fork,'b','c');
 await reject(exportLineage({...f.opts,hops:[f.hops[0],f.hops[1],second]}),
  'LOCAL_REVIEW_LINEAGE_BROKEN_LINK');
});
test('35AC rejects valid cycle back to previously used key',async()=>{
 const f=await fixture(),r3=await receipt('a',5),cycle=await f.make(f.r2,r3,'c','a');
 await reject(exportLineage({...f.opts,hops:[...f.hops,cycle]}),
  'LOCAL_REVIEW_LINEAGE_REPLAY_OR_CYCLE');
});
test('35AC rejects malformed hop with privilege field',async()=>{
 const f=await fixture(),hops=[{...f.hops[0],canPublish:true},f.hops[1]];
 await reject(exportLineage({...f.opts,hops}),'LOCAL_REVIEW_LINEAGE_MALFORMED');
});
test('35AC rejects zero-hop lineage',async()=>{
 const f=await fixture();await reject(exportLineage({...f.opts,hops:[]}),
  'LOCAL_REVIEW_LINEAGE_MALFORMED');
});
test('35AC rejects oversized hop count',async()=>{
 const f=await fixture();await reject(exportLineage({...f.opts,hops:Array(17).fill(f.hops[0])}),
  'LOCAL_REVIEW_LINEAGE_MALFORMED');
});
test('35AC import rejects malformed JSON with matching external digest',async()=>{
 const f=await fixture(),bytes=Buffer.from('{x');
 await reject(importLineage({...f.args,bytes,expectedSha256:digest(bytes)}),
  'LOCAL_REVIEW_LINEAGE_MALFORMED');
});
test('35AC import rejects noncanonical JSON with matching external digest',async()=>{
 const f=await fixture(),bytes=Buffer.from(JSON.stringify(JSON.parse(f.exported.bytes),null,2));
 await reject(importLineage({...f.args,bytes,expectedSha256:digest(bytes)}),
  'LOCAL_REVIEW_LINEAGE_MALFORMED');
});
test('35AC import rejects duplicate top-level keys with matching digest',async()=>{
 const f=await fixture(),bytes=Buffer.from(f.exported.bytes.toString().replace('{','{"schema":"fake",'));
 await reject(importLineage({...f.args,bytes,expectedSha256:digest(bytes)}),
  'LOCAL_REVIEW_LINEAGE_MALFORMED');
});
test('35AC import rejects oversized bytes before JSON parsing',async()=>{
 const f=await fixture();await reject(importLineage({...f.args,bytes:Buffer.alloc(1048577)}),
  'LOCAL_REVIEW_LINEAGE_INVALID_BYTES');
});
test('35AC import rejects untrusted resolver substitution',async()=>{
 const f=await fixture();await reject(importLineage({...f.args,
  resolveObserverPublicKey:async(id,key)=>key==='b'?pairs.e.publicKey:resolve(id,key)}),
  'LOCAL_REVIEW_OBSERVER_BAD_SIGNATURE');
});
test('35AC rejects key-id reuse across valid successive signatures',async()=>{
 const f=await fixture(),r3=await receipt('b',5),again=await f.make(f.r2,r3,'c','b');
 await reject(exportLineage({...f.opts,hops:[...f.hops,again]}),
  'LOCAL_REVIEW_LINEAGE_REPLAY_OR_CYCLE');
});
test('35AC rejects accessor-based revocation arrays',()=>{
 const a=[fingerprint('a')];Object.defineProperty(a,0,{get:()=>fingerprint('a'),enumerable:true});
 assert.throws(()=>policyDigest(policy(a)),{code:'LOCAL_REVIEW_LINEAGE_INVALID_POLICY'});
});
test('35AC rejects accessor-based lineage hop arrays',async()=>{
 const f=await fixture(),hops=[...f.hops];
 Object.defineProperty(hops,0,{get:()=>f.hops[0],enumerable:true});
 await reject(exportLineage({...f.opts,hops}),'LOCAL_REVIEW_LINEAGE_MALFORMED');
});
test('35AC rejects sparse lineage hop arrays',async()=>{
 const f=await fixture(),hops=[f.hops[0],f.hops[1]];delete hops[1];
 await reject(exportLineage({...f.opts,hops}),'LOCAL_REVIEW_LINEAGE_MALFORMED');
});
test('35AC snapshots export before asynchronous key resolution mutates caller input',async()=>{
 const f=await fixture(),hops=structuredClone(f.hops);
 let changed=false;
 const resolver=async(id,key)=>{
  if(!changed){changed=true;hops[0].rotation.authority='SHOPIFY_WRITE';}
  return resolve(id,key);
 };
 const result=await exportLineage({...f.opts,hops,resolveObserverPublicKey:resolver});
 assert.equal(JSON.parse(result.bytes).hops[0].rotation.authority,'NONE');
 assert.equal(hops[0].rotation.authority,'SHOPIFY_WRITE');
});
