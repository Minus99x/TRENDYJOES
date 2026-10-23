import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {LOCAL_REVIEW_REVOCATION_SCHEMA} from '../src/preview-local-artwork-review-rotation-lineage.mjs';
import {createLocalReviewPolicyCheckpoint as create,
 verifyLocalReviewPolicyCheckpointAdvancement as verify,
 LOCAL_REVIEW_POLICY_GENESIS_DIGEST as GENESIS,
 LOCAL_REVIEW_RETAINED_HEAD_SCHEMA as HEAD_SCHEMA} from '../src/preview-local-artwork-review-policy-checkpoints.mjs';
const hash=s=>createHash('sha256').update(s).digest('hex');
const rootPin=hash('root-35ad'),registryId=hash('registry-35ad');
const {privateKey,publicKey}=generateKeyPairSync('ed25519');
const other=generateKeyPairSync('ed25519');
const keyA=hash('revoked-A'),keyB=hash('revoked-B'),keyC=hash('revoked-C');
const rotationA=hash('rotation-A'),rotationB=hash('rotation-B');
const policy=(revision,keys=[],rotations=[])=>({schema:LOCAL_REVIEW_REVOCATION_SCHEMA,
 revision,revokedKeyFingerprints:[...keys].sort(),revokedRotationDigests:[...rotations].sort(),authority:'NONE'});
const issue=(p,prev=GENESIS,opts={})=>create({policy:p,rootPin,registryId,
 previousCheckpointSha256:prev,signingKey:privateKey,...opts});
const head=c=>({schema:HEAD_SCHEMA,rootPin,registryId,signerFingerprint:c.signerFingerprint,
 checkpointSha256:c.sha256,revision:c.revision});
const fixture=()=>{
 const a=issue(policy(1,[keyA],[rotationA]));
 const b=issue(policy(2,[keyA,keyB],[rotationA]),a.sha256);
 const c=issue(policy(3,[keyA,keyB,keyC],[rotationA,rotationB]),b.sha256);
 const h=head(a);
 const opts={checkpointBytes:[a.bytes,b.bytes,c.bytes],readRetainedHead:async()=>structuredClone(h),
  signerPublicKey:publicKey,expectedRootPin:rootPin,expectedRegistryId:registryId,
  expectedSignerFingerprint:a.signerFingerprint};
 return {a,b,c,h,opts};
};
const rejected=async(opts,code)=>assert.rejects(verify(opts),{code});
test('35AD verifies 2 signed policy advancements from externally retained head',async()=>{
 const f=fixture(),r=await verify(f.opts);
 assert.equal(r.retainedRevision,1);assert.equal(r.candidateRevision,3);
 assert.equal(r.checkedSuccessors,2);assert.equal(r.signaturesVerified,true);
 assert.equal(r.revocationsMonotonic,true);assert.equal(r.candidateSha256,f.c.sha256);
 assert.equal(r.candidateExternallyRetained,false);assert.equal(r.authenticatedRegistry,false);
 assert.equal(r.independentCustodyVerified,false);assert.equal(r.authorizesProduction,false);
 assert.equal(r.shopifyWritesAllowed,false);
});
test('35AD checkpoint generation deterministic with fixed signing key',()=>{
 const f=fixture();assert.deepEqual(f.a.bytes,issue(policy(1,[keyA],[rotationA])).bytes);
});
test('35AD rejects missing external retained-head adapter',async()=>{
 const f=fixture();await rejected({...f.opts,readRetainedHead:undefined},'LOCAL_REVIEW_POLICY_INVALID_OPTIONS');
});
test('35AD rejects missing pinned registry identity',async()=>{
 const f=fixture();await rejected({...f.opts,expectedRegistryId:undefined},'LOCAL_REVIEW_POLICY_INVALID_OPTIONS');
});
test('35AD rejects missing pinned root identity',async()=>{
 const f=fixture();await rejected({...f.opts,expectedRootPin:undefined},'LOCAL_REVIEW_POLICY_INVALID_OPTIONS');
});
test('35AD rejects missing pinned signer fingerprint',async()=>{
 const f=fixture();await rejected({...f.opts,expectedSignerFingerprint:undefined},'LOCAL_REVIEW_POLICY_INVALID_OPTIONS');
});
test('35AD rejects untrusted public signing key substitution',async()=>{
 const f=fixture();await rejected({...f.opts,signerPublicKey:other.publicKey},'LOCAL_REVIEW_POLICY_UNTRUSTED_SIGNER');
});
test('35AD rejects forged signature with intact policy and recalculated bytes hash',async()=>{
 const f=fixture(),v=JSON.parse(f.b.bytes);v.signature=(v.signature[0]==='A'?'B':'A')+v.signature.slice(1);
 await rejected({...f.opts,checkpointBytes:[f.a.bytes,Buffer.from(JSON.stringify(v))]},'LOCAL_REVIEW_POLICY_BAD_SIGNATURE');
});
test('35AD rejects a modified policy with stale signature',async()=>{
 const f=fixture(),v=JSON.parse(f.b.bytes);v.policy.revision=99;
 await rejected({...f.opts,checkpointBytes:[f.a.bytes,Buffer.from(JSON.stringify(v))]},'LOCAL_REVIEW_POLICY_INVALID_CHECKPOINT');
});
test('35AD rejects altered signature after canonical byte reconstruction',async()=>{
 const f=fixture(),v=JSON.parse(f.b.bytes);v.signature=(v.signature[0]==='C'?'D':'C')+v.signature.slice(1);
 await rejected({...f.opts,checkpointBytes:[f.a.bytes,Buffer.from(JSON.stringify(v))]},'LOCAL_REVIEW_POLICY_BAD_SIGNATURE');
});
test('35AD rejects noncanonical pretty-printed bytes',async()=>{
 const f=fixture();await rejected({...f.opts,checkpointBytes:[f.a.bytes,Buffer.from(JSON.stringify(JSON.parse(f.b.bytes),null,2))]},'LOCAL_REVIEW_POLICY_MALFORMED');
});
test('35AD rejects duplicate JSON keys',async()=>{
 const f=fixture(),s=f.b.bytes.toString().replace('{','{"schema":"duplicate",');
 await rejected({...f.opts,checkpointBytes:[f.a.bytes,Buffer.from(s)]},'LOCAL_REVIEW_POLICY_MALFORMED');
});
test('35AD rejects oversized checkpoint before parsing',async()=>{
 const f=fixture();await rejected({...f.opts,checkpointBytes:[f.a.bytes,Buffer.alloc(16385)]},'LOCAL_REVIEW_POLICY_INVALID_BYTES');
});
test('35AD rejects sparse checkpoint array',async()=>{
 const f=fixture(),a=[f.a.bytes,f.b.bytes];delete a[1];
 await rejected({...f.opts,checkpointBytes:a},'LOCAL_REVIEW_POLICY_INVALID_OPTIONS');
});
test('35AD rejects accessor-based checkpoint array',async()=>{
 const f=fixture(),a=[f.a.bytes,f.b.bytes];Object.defineProperty(a,1,{get:()=>f.b.bytes,enumerable:true});
 await rejected({...f.opts,checkpointBytes:a},'LOCAL_REVIEW_POLICY_INVALID_OPTIONS');
});
test('35AD rejects missing pinned predecessor',async()=>{
 const f=fixture();await rejected({...f.opts,checkpointBytes:[f.b.bytes,f.c.bytes]},'LOCAL_REVIEW_POLICY_RETAINED_HEAD_MISMATCH');
});
test('35AD rejects forged external head digest',async()=>{
 const f=fixture();await rejected({...f.opts,readRetainedHead:async()=>({...f.h,checkpointSha256:hash('fake')})},'LOCAL_REVIEW_POLICY_RETAINED_HEAD_MISMATCH');
});
test('35AD rejects externally pinned predecessor revision rollback',async()=>{
 const f=fixture();await rejected({...f.opts,readRetainedHead:async()=>({...f.h,revision:2})},'LOCAL_REVIEW_POLICY_RETAINED_HEAD_MISMATCH');
});
test('35AD rejects changed registry identity in retained head',async()=>{
 const f=fixture();await rejected({...f.opts,readRetainedHead:async()=>({...f.h,registryId:hash('other')})},'LOCAL_REVIEW_POLICY_UNTRUSTED_RETAINED_HEAD');
});
test('35AD rejects extra retained-head privilege',async()=>{
 const f=fixture();await rejected({...f.opts,readRetainedHead:async()=>({...f.h,canPublish:true})},'LOCAL_REVIEW_POLICY_UNTRUSTED_RETAINED_HEAD');
});
test('35AD rejects adapter read failure',async()=>{
 const f=fixture();await rejected({...f.opts,readRetainedHead:async()=>{throw Error('offline');}},'LOCAL_REVIEW_POLICY_RETAINED_HEAD_UNAVAILABLE');
});
test('35AD rejects head change between initial and final external reads',async()=>{
 const f=fixture();let n=0;
 await rejected({...f.opts,readRetainedHead:async()=>++n===1?f.h:head(f.b)},'LOCAL_REVIEW_POLICY_RETAINED_HEAD_CHANGED');
});
test('35AD rejects revision skip despite valid signer',async()=>{
 const f=fixture(),jump=issue(policy(4,[keyA,keyB,keyC],[rotationA]),f.a.sha256);
 await rejected({...f.opts,checkpointBytes:[f.a.bytes,jump.bytes]},'LOCAL_REVIEW_POLICY_REVISION_OR_LINK_ROLLBACK');
});
test('35AD rejects replay of same signed revision',async()=>{
 const f=fixture();await rejected({...f.opts,checkpointBytes:[f.a.bytes,f.a.bytes]},'LOCAL_REVIEW_POLICY_REVISION_OR_LINK_ROLLBACK');
});
test('35AD rejects fork with wrong predecessor digest',async()=>{
 const f=fixture(),fork=issue(policy(2,[keyA,keyB],[rotationA]),hash('wrong-parent'));
 await rejected({...f.opts,checkpointBytes:[f.a.bytes,fork.bytes]},'LOCAL_REVIEW_POLICY_REVISION_OR_LINK_ROLLBACK');
});
test('35AD rejects key revocation rollback even when signer is valid',async()=>{
 const f=fixture(),rollback=issue(policy(2,[],[rotationA]),f.a.sha256);
 await rejected({...f.opts,checkpointBytes:[f.a.bytes,rollback.bytes]},'LOCAL_REVIEW_POLICY_REVOCATION_ROLLBACK');
});
test('35AD rejects rotation revocation rollback even when signer is valid',async()=>{
 const f=fixture(),rollback=issue(policy(2,[keyA],[]),f.a.sha256);
 await rejected({...f.opts,checkpointBytes:[f.a.bytes,rollback.bytes]},'LOCAL_REVIEW_POLICY_REVOCATION_ROLLBACK');
});
test('35AD rejects revocation removal in a later valid signed hop',async()=>{
 const f=fixture(),rollback=issue(policy(3,[keyB],[rotationA]),f.b.sha256);
 await rejected({...f.opts,checkpointBytes:[f.a.bytes,f.b.bytes,rollback.bytes]},'LOCAL_REVIEW_POLICY_REVOCATION_ROLLBACK');
});
test('35AD accepts unchanged revocations across contiguous revision',async()=>{
 const f=fixture(),same=issue(policy(2,[keyA],[rotationA]),f.a.sha256);
 const r=await verify({...f.opts,checkpointBytes:[f.a.bytes,same.bytes]});
 assert.equal(r.candidateRevision,2);
});
test('35AD refuses checkpoint with untrusted write authority',()=>{
 assert.throws(()=>issue({...policy(1),authority:'PUBLISH'}),{code:'LOCAL_REVIEW_POLICY_INVALID_POLICY'});
});
test('35AD refuses malformed policy revocation list',()=>{
 assert.throws(()=>issue({...policy(1),revokedKeyFingerprints:[keyA,keyA]}),{code:'LOCAL_REVIEW_POLICY_INVALID_POLICY'});
});
test('35AD refuses invalid private signing key',()=>{
 assert.throws(()=>create({policy:policy(1),rootPin,registryId,previousCheckpointSha256:GENESIS,signingKey:publicKey}),{code:'LOCAL_REVIEW_POLICY_INVALID_SIGNING_KEY'});
});
test('35AD refuses invalid predecessor hash',()=>{
 assert.throws(()=>issue(policy(1),'fake'),{code:'LOCAL_REVIEW_POLICY_INVALID_CHECKPOINT'});
});
test('35AD rejects substituted checkpoint root with valid signature',async()=>{
 const f=fixture(),bad=issue(policy(2,[keyA],[rotationA]),f.a.sha256,{rootPin:hash('other-root')});
 await rejected({...f.opts,checkpointBytes:[f.a.bytes,bad.bytes]},'LOCAL_REVIEW_POLICY_INVALID_CHECKPOINT');
});
test('35AD rejects substituted checkpoint registry with valid signature',async()=>{
 const f=fixture(),bad=issue(policy(2,[keyA],[rotationA]),f.a.sha256,{registryId:hash('other-registry')});
 await rejected({...f.opts,checkpointBytes:[f.a.bytes,bad.bytes]},'LOCAL_REVIEW_POLICY_INVALID_CHECKPOINT');
});
test('35AD refuses empty chain without successor',async()=>{
 const f=fixture();await rejected({...f.opts,checkpointBytes:[f.a.bytes]},'LOCAL_REVIEW_POLICY_INVALID_OPTIONS');
});
test('35AD refuses more than 16 successors',async()=>{
 const f=fixture();await rejected({...f.opts,checkpointBytes:Array(18).fill(f.a.bytes)},'LOCAL_REVIEW_POLICY_INVALID_OPTIONS');
});
test('35AD fails closed if head adapter returns null',async()=>{
 const f=fixture();await rejected({...f.opts,readRetainedHead:async()=>null},'LOCAL_REVIEW_POLICY_UNTRUSTED_RETAINED_HEAD');
});
test('35AD snapshots candidate bytes before asynchronous retained-head read',async()=>{
 const f=fixture(),candidate=Buffer.from(f.b.bytes),list=[f.a.bytes,candidate];
 const r=await verify({...f.opts,checkpointBytes:list,readRetainedHead:async()=>{
  candidate.fill(0);list[1]=Buffer.alloc(4);return f.h;
 }});
 assert.equal(r.candidateSha256,f.b.sha256);
});
test('35AD never promotes or writes retained head',async()=>{
 const f=fixture();let reads=0;const h=structuredClone(f.h);
 const r=await verify({...f.opts,readRetainedHead:async()=>{reads++;return h;}});
 assert.equal(reads,2);assert.deepEqual(h,f.h);assert.equal(r.candidateExternallyRetained,false);
});
