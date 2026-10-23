import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {LOCAL_REVIEW_REVOCATION_SCHEMA} from '../src/preview-local-artwork-review-rotation-lineage.mjs';
import {createLocalReviewPolicyCheckpoint,LOCAL_REVIEW_RETAINED_HEAD_SCHEMA,
 LOCAL_REVIEW_POLICY_GENESIS_DIGEST} from '../src/preview-local-artwork-review-policy-checkpoints.mjs';
import {createOfflineWitnessAcknowledgement,verifyOfflineWitnessAcknowledgement,
 inspectOfflineWitnessedPolicyFork,verifyPortableOfflineWitnessedPolicyForkEvidence,
 OFFLINE_WITNESS_ACK_SCHEMA,OFFLINE_WITNESSED_FORK_SCHEMA}
 from '../src/preview-local-artwork-review-witness-acknowledgements.mjs';
const digest=x=>createHash('sha256').update(x).digest('hex');
const signer=generateKeyPairSync('ed25519');
const observerA=generateKeyPairSync('ed25519');
const observerB=generateKeyPairSync('ed25519');
const observerC=generateKeyPairSync('ed25519');
const fp=k=>digest(k.export({type:'spki',format:'der'}));
const rootPin=digest('35AF root'),registryId=digest('35AF registry');
const audience=digest('35AF auditor session');
const challengeA=digest('35AF challenge A'),challengeB=digest('35AF challenge B');
const witnessIdA=digest('35AF witness A'),witnessIdB=digest('35AF witness B');
const now=1700000000000;
const keyA=digest('35AF key A'),keyB=digest('35AF key B'),keyC=digest('35AF key C');
const policy=(revision,revoked=[])=>({schema:LOCAL_REVIEW_REVOCATION_SCHEMA,
 revision,revokedKeyFingerprints:[...revoked].sort(),revokedRotationDigests:[],authority:'NONE'});
const issue=(p,prev=LOCAL_REVIEW_POLICY_GENESIS_DIGEST)=>createLocalReviewPolicyCheckpoint({
 policy:p,rootPin,registryId,previousCheckpointSha256:prev,signingKey:signer.privateKey});
const first=issue(policy(1,[keyA]));
const left=issue(policy(2,[keyA,keyB]),first.sha256);
const right=issue(policy(2,[keyA,keyC]),first.sha256);
const h={schema:LOCAL_REVIEW_RETAINED_HEAD_SCHEMA,rootPin,registryId,
 signerFingerprint:first.signerFingerprint,checkpointSha256:first.sha256,revision:1};
const wa={witnessId:witnessIdA,challenge:challengeA,publicKey:observerA.publicKey};
const wb={witnessId:witnessIdB,challenge:challengeB,publicKey:observerB.publicKey};
const ack=(observer,witnessId,challenge,candidate,extra={})=>createOfflineWitnessAcknowledgement({
 signingKey:observer.privateKey,witnessId,head:h,candidateCheckpointSha256:candidate.sha256,
 challenge,audience,issuedAtMs:now-1000,expiresAtMs:now+1000,...extra});
const a=ack(observerA,witnessIdA,challengeA,left);
const b=ack(observerB,witnessIdB,challengeB,right);
const replay=()=>{const used=new Set();return async token=>{
 if(used.has(token))return false;used.add(token);return true;
};};
const verifyArgs=(receiptBytes=a.bytes,extra={})=>({receiptBytes,
 witnessPublicKey:observerA.publicKey,expectedWitnessId:witnessIdA,
 expectedWitnessKeyFingerprint:fp(observerA.publicKey),expectedRootPin:rootPin,
 expectedRegistryId:registryId,expectedPolicySignerFingerprint:first.signerFingerprint,
 expectedParentCheckpointSha256:first.sha256,expectedParentRevision:1,
 expectedCandidateSha256:left.sha256,expectedCandidateRevision:2,
 expectedChallenge:challengeA,expectedAudience:audience,trustedNowMs:now,
 consumeOnce:replay(),...extra});
const forkArgs=(extra={})=>({leftCheckpointBytes:[first.bytes,left.bytes],
 rightCheckpointBytes:[first.bytes,right.bytes],pinnedHead:h,
 policySignerPublicKey:signer.publicKey,leftReceiptBytes:a.bytes,rightReceiptBytes:b.bytes,
 leftWitness:wa,rightWitness:wb,expectedAudience:audience,trustedNowMs:now,
 consumeOnce:replay(),...extra});
const rejects=(p,code)=>assert.rejects(p,{code});
const corrupt=(bytes,edit)=>{const o=JSON.parse(bytes);edit(o);return Buffer.from(JSON.stringify(o));};

test('35AF signed acknowledgement binds policy head and observer',()=>{
 const parsed=JSON.parse(a.bytes);
 assert.equal(parsed.schema,OFFLINE_WITNESS_ACK_SCHEMA);
 assert.equal(parsed.parentCheckpointSha256,first.sha256);
 assert.equal(parsed.candidateCheckpointSha256,left.sha256);
 assert.equal(parsed.witnessKeyFingerprint,fp(observerA.publicKey));
 assert.equal(a.independentlyWitnessed,false);
});
test('35AF independently pinned receipt verifies and consumes replay token',async()=>{
 const r=await verifyOfflineWitnessAcknowledgement(verifyArgs());
 assert.equal(r.signatureVerified,true);assert.equal(r.replayTokenConsumed,true);
 assert.equal(r.externalCustodyVerified,false);assert.equal(r.authorizesProduction,false);
 assert.equal(r.shopifyWritesAllowed,false);
});
test('35AF same receipt replay fails with atomic consumeOnce',async()=>{
 const once=replay(),args=verifyArgs(a.bytes,{consumeOnce:once});
 await verifyOfflineWitnessAcknowledgement(args);
 await rejects(verifyOfflineWitnessAcknowledgement(args),'OFFLINE_WITNESS_REPLAY');
});
test('35AF concurrent replay races yield one accepted receipt',async()=>{
 const once=replay(),args=verifyArgs(a.bytes,{consumeOnce:once});
 const r=await Promise.allSettled([verifyOfflineWitnessAcknowledgement(args),verifyOfflineWitnessAcknowledgement(args)]);
 assert.equal(r.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(r.filter(x=>x.status==='rejected').length,1);
});
test('35AF refuses missing replay store',async()=>{
 await rejects(verifyOfflineWitnessAcknowledgement(verifyArgs(a.bytes,{consumeOnce:null})),
 'OFFLINE_WITNESS_INVALID_TRUST_BOUNDARY');
});
test('35AF refuses replay-store errors',async()=>{
 await rejects(verifyOfflineWitnessAcknowledgement(verifyArgs(a.bytes,{consumeOnce:async()=>{throw Error('offline');}})),
 'OFFLINE_WITNESS_REPLAY_STORE_UNAVAILABLE');
});
test('35AF refuses ambiguous replay-store result',async()=>{
 await rejects(verifyOfflineWitnessAcknowledgement(verifyArgs(a.bytes,{consumeOnce:async()=>1})),
 'OFFLINE_WITNESS_REPLAY_STORE_UNCERTAIN');
});
test('35AF refuses expired witness receipt',async()=>{
 await rejects(verifyOfflineWitnessAcknowledgement(verifyArgs(a.bytes,{trustedNowMs:now+1000})),
 'OFFLINE_WITNESS_EXPIRED');
});
test('35AF refuses future-dated witness receipt',async()=>{
 await rejects(verifyOfflineWitnessAcknowledgement(verifyArgs(a.bytes,{trustedNowMs:now-1001})),
 'OFFLINE_WITNESS_NOT_YET_VALID');
});
test('35AF rejects untrusted clock',async()=>{
 await rejects(verifyOfflineWitnessAcknowledgement(verifyArgs(a.bytes,{trustedNowMs:NaN})),
 'OFFLINE_WITNESS_INVALID_TRUST_BOUNDARY');
});
test('35AF rejects swapped witness public key',async()=>{
 await rejects(verifyOfflineWitnessAcknowledgement(verifyArgs(a.bytes,{witnessPublicKey:observerC.publicKey})),
 'OFFLINE_WITNESS_INVALID_TRUST_BOUNDARY');
});
test('35AF rejects substituted pinned witness fingerprint',async()=>{
 await rejects(verifyOfflineWitnessAcknowledgement(verifyArgs(a.bytes,{expectedWitnessKeyFingerprint:fp(observerC.publicKey)})),
 'OFFLINE_WITNESS_INVALID_TRUST_BOUNDARY');
});
for(const [label,field,value] of [
 ['witness identity','expectedWitnessId',witnessIdB],
 ['registry','expectedRegistryId',digest('other registry')],
 ['root pin','expectedRootPin',digest('other root')],
 ['policy signer','expectedPolicySignerFingerprint',digest('other signer')],
 ['parent checkpoint','expectedParentCheckpointSha256',digest('other parent')],
 ['candidate checkpoint','expectedCandidateSha256',right.sha256],
 ['challenge','expectedChallenge',challengeB],
 ['audience','expectedAudience',digest('other audience')],
 ['parent revision','expectedParentRevision',2],
 ['candidate revision','expectedCandidateRevision',3]
])test(`35AF rejects substituted pinned ${label}`,async()=>{
 await rejects(verifyOfflineWitnessAcknowledgement(verifyArgs(a.bytes,{[field]:value})),
 'OFFLINE_WITNESS_PIN_MISMATCH');
});
test('35AF rejects signature tampering',async()=>{
 const forged=corrupt(a.bytes,o=>o.signature=(o.signature[0]==='A'?'B':'A')+o.signature.slice(1));
 await rejects(verifyOfflineWitnessAcknowledgement(verifyArgs(forged)),
 'OFFLINE_WITNESS_BAD_SIGNATURE');
});
test('35AF rejects signed-body tampering',async()=>{
 const forged=corrupt(a.bytes,o=>o.issuedAtMs-=100);
 await rejects(verifyOfflineWitnessAcknowledgement(verifyArgs(forged)),
 'OFFLINE_WITNESS_BAD_SIGNATURE');
});
test('35AF rejects extra privilege field',async()=>{
 const forged=corrupt(a.bytes,o=>o.canPublish=true);
 await rejects(verifyOfflineWitnessAcknowledgement(verifyArgs(forged)),
 'OFFLINE_WITNESS_MALFORMED');
});
test('35AF rejects reordered JSON envelope',async()=>{
 const o=JSON.parse(a.bytes),rev=Object.fromEntries(Object.entries(o).reverse());
 await rejects(verifyOfflineWitnessAcknowledgement(verifyArgs(Buffer.from(JSON.stringify(rev)))),
 'OFFLINE_WITNESS_MALFORMED');
});
test('35AF rejects noncanonical whitespace',async()=>{
 await rejects(verifyOfflineWitnessAcknowledgement(verifyArgs(Buffer.from(JSON.stringify(JSON.parse(a.bytes),null,2)))),
 'OFFLINE_WITNESS_MALFORMED');
});
test('35AF rejects malformed signature encoding',async()=>{
 const forged=corrupt(a.bytes,o=>o.signature+='=');
 await rejects(verifyOfflineWitnessAcknowledgement(verifyArgs(forged)),
 'OFFLINE_WITNESS_MALFORMED');
});
test('35AF rejects oversized receipt',async()=>{
 await rejects(verifyOfflineWitnessAcknowledgement(verifyArgs(Buffer.alloc(4097))),
 'OFFLINE_WITNESS_INVALID_BYTES');
});
test('35AF rejects signing keys of wrong type',()=>{
 assert.throws(()=>ack({privateKey:observerA.publicKey},witnessIdA,challengeA,left),
 {code:'OFFLINE_WITNESS_INVALID_SIGNER'});
});
test('35AF rejects acknowledgements longer than 5 minutes',()=>{
 assert.throws(()=>ack(observerA,witnessIdA,challengeA,left,{expiresAtMs:now+300001}),
 {code:'OFFLINE_WITNESS_INVALID_BODY'});
});
test('35AF rejects invalid revision in signing head',()=>{
 assert.throws(()=>ack(observerA,witnessIdA,challengeA,left,{head:{...h,revision:0}}),
 {code:'OFFLINE_WITNESS_INVALID_HEAD'});
});
test('35AF rejects identical parent and candidate digests',()=>{
 assert.throws(()=>ack(observerA,witnessIdA,challengeA,first),
 {code:'OFFLINE_WITNESS_INVALID_BODY'});
});
test('35AF rejects accessors and prototype tricks in head',()=>{
 const bad={...h};Object.defineProperty(bad,'revision',{get(){return 1;},enumerable:true});
 assert.throws(()=>ack(observerA,witnessIdA,challengeA,left,{head:bad}),
 {code:'OFFLINE_WITNESS_INVALID_HEAD'});
});
test('35AF verifies two independent witness signatures on a signer-valid fork',async()=>{
 const r=await inspectOfflineWitnessedPolicyFork(forkArgs());
 assert.equal(r.schema,OFFLINE_WITNESSED_FORK_SCHEMA);
 assert.equal(r.observerSignaturesVerified,true);assert.equal(r.policySignaturesVerified,true);
 assert.equal(r.externallyWitnessed,false);assert.equal(r.globalForkPreventionVerified,false);
 assert.equal(r.authorizesProduction,false);assert.equal(r.shopifyWritesAllowed,false);
});
test('35AF portable evidence independently re-verifies with parent and pins',async()=>{
 const evidence=portable(await inspectOfflineWitnessedPolicyFork(forkArgs()));
 const r=await verifyPortableOfflineWitnessedPolicyForkEvidence({evidence,
  parentCheckpointBytes:first.bytes,pinnedHead:h,policySignerPublicKey:signer.publicKey,
  leftWitness:wa,rightWitness:wb,expectedAudience:audience,trustedNowMs:now,
  consumeOnce:replay()});
 assert.equal(r.evidenceSha256,evidence.evidenceSha256);
});
test('35AF portable evidence cannot be replayed with same atomic store',async()=>{
 const evidence=portable(await inspectOfflineWitnessedPolicyFork(forkArgs())),once=replay();
 const args={evidence,parentCheckpointBytes:first.bytes,pinnedHead:h,
  policySignerPublicKey:signer.publicKey,leftWitness:wa,rightWitness:wb,
  expectedAudience:audience,trustedNowMs:now,consumeOnce:once};
 await verifyPortableOfflineWitnessedPolicyForkEvidence(args);
 await rejects(verifyPortableOfflineWitnessedPolicyForkEvidence(args),'OFFLINE_WITNESS_REPLAY');
});
test('35AF rejects forged portable evidence digest',async()=>{
 const e=portable(await inspectOfflineWitnessedPolicyFork(forkArgs()));
 await rejects(verifyPortableOfflineWitnessedPolicyForkEvidence({evidence:{...e,evidenceSha256:digest('fake')},
  parentCheckpointBytes:first.bytes,pinnedHead:h,policySignerPublicKey:signer.publicKey,
  leftWitness:wa,rightWitness:wb,expectedAudience:audience,trustedNowMs:now,consumeOnce:replay()}),
 'OFFLINE_WITNESS_EVIDENCE_DIGEST_MISMATCH');
});
test('35AF rejects evidence with changed externally pinned audience',async()=>{
 const e=await inspectOfflineWitnessedPolicyFork(forkArgs());
 await rejects(verifyPortableOfflineWitnessedPolicyForkEvidence({evidence:portable(e),
  parentCheckpointBytes:first.bytes,pinnedHead:h,policySignerPublicKey:signer.publicKey,
  leftWitness:wa,rightWitness:wb,expectedAudience:digest('different'),trustedNowMs:now,
  consumeOnce:replay()}),'OFFLINE_WITNESS_PIN_MISMATCH');
});
const portable=e=>Object.fromEntries(['schema','rootPin','registryId','policySignerFingerprint',
 'parentCheckpointSha256','parentRevision','forkRevision','audience',
 'leftCheckpointBytesBase64url','rightCheckpointBytesBase64url',
 'leftReceiptBase64url','rightReceiptBase64url','evidenceSha256'].map(k=>[k,e[k]]));
test('35AF portable evidence verifies without local status flags',async()=>{
 const e=portable(await inspectOfflineWitnessedPolicyFork(forkArgs()));
 const r=await verifyPortableOfflineWitnessedPolicyForkEvidence({evidence:e,
  parentCheckpointBytes:first.bytes,pinnedHead:h,policySignerPublicKey:signer.publicKey,
  leftWitness:wa,rightWitness:wb,expectedAudience:audience,trustedNowMs:now,consumeOnce:replay()});
 assert.equal(r.observerSignaturesVerified,true);
});
test('35AF rejects self-asserted privilege on portable evidence',async()=>{
 const e=portable(await inspectOfflineWitnessedPolicyFork(forkArgs()));
 await rejects(verifyPortableOfflineWitnessedPolicyForkEvidence({evidence:{...e,authorizesProduction:true},
  parentCheckpointBytes:first.bytes,pinnedHead:h,policySignerPublicKey:signer.publicKey,
  leftWitness:wa,rightWitness:wb,expectedAudience:audience,trustedNowMs:now,consumeOnce:replay()}),
 'OFFLINE_WITNESS_INVALID_EVIDENCE');
});
test('35AF rejects identical witness identities in fork claim',async()=>{
 await rejects(inspectOfflineWitnessedPolicyFork(forkArgs({rightWitness:{...wb,witnessId:witnessIdA}})),
 'OFFLINE_WITNESS_DISTINCT_OBSERVERS_REQUIRED');
});
test('35AF rejects same witness key for both branches',async()=>{
 await rejects(inspectOfflineWitnessedPolicyFork(forkArgs({rightWitness:{...wb,publicKey:observerA.publicKey}})),
 'OFFLINE_WITNESS_DISTINCT_OBSERVERS_REQUIRED');
});
test('35AF rejects reused challenge across observers',async()=>{
 await rejects(inspectOfflineWitnessedPolicyFork(forkArgs({rightWitness:{...wb,challenge:challengeA}})),
 'OFFLINE_WITNESS_DISTINCT_OBSERVERS_REQUIRED');
});
test('35AF rejects witness on wrong fork branch',async()=>{
 await rejects(inspectOfflineWitnessedPolicyFork(forkArgs({leftReceiptBytes:b.bytes})),
 'OFFLINE_WITNESS_PIN_MISMATCH');
});
test('35AF rejects witness receipt whose candidate disagrees with signed policy',async()=>{
 const falseReceipt=ack(observerA,witnessIdA,challengeA,right);
 await rejects(inspectOfflineWitnessedPolicyFork(forkArgs({leftReceiptBytes:falseReceipt.bytes})),
 'OFFLINE_WITNESS_PIN_MISMATCH');
});
test('35AF rejects fork whose policy signer is forged',async()=>{
 const forged=corrupt(right.bytes,o=>o.signature=(o.signature[0]==='A'?'B':'A')+o.signature.slice(1));
 await rejects(inspectOfflineWitnessedPolicyFork(forkArgs({rightCheckpointBytes:[first.bytes,forged]})),
 'LOCAL_REVIEW_POLICY_BAD_SIGNATURE');
});
test('35AF rejects identical branches despite two signed witnesses',async()=>{
 await rejects(inspectOfflineWitnessedPolicyFork(forkArgs({rightCheckpointBytes:[first.bytes,left.bytes]})),
 'LOCAL_REVIEW_CAS_NO_FORK');
});
test('35AF rejects changed parent pin',async()=>{
 await rejects(inspectOfflineWitnessedPolicyFork(forkArgs({pinnedHead:{...h,checkpointSha256:digest('changed')}})),
 'LOCAL_REVIEW_POLICY_RETAINED_HEAD_MISMATCH');
});
test('35AF rejects sparse chain before verification',async()=>{
 const c=[first.bytes,left.bytes];delete c[1];
 await rejects(inspectOfflineWitnessedPolicyFork(forkArgs({leftCheckpointBytes:c})),
 'OFFLINE_WITNESS_INVALID_CHAIN');
});
test('35AF snapshots receipts before first asynchronous verification',async()=>{
 const bytes=Buffer.from(a.bytes),args=forkArgs({leftReceiptBytes:bytes});
 const p=inspectOfflineWitnessedPolicyFork(args);bytes.fill(0);
 const r=await p;assert.equal(r.observerSignaturesVerified,true);
});
test('35AF reports replay-store failure on second observer without producing fork proof',async()=>{
 let calls=0;await rejects(inspectOfflineWitnessedPolicyFork(forkArgs({
  consumeOnce:async()=>++calls===1})), 'OFFLINE_WITNESS_REPLAY');
});

test('35AF snapshots witness pins before asynchronous checkpoint verification',async()=>{
 const leftWitness={...wa},rightWitness={...wb};
 const p=inspectOfflineWitnessedPolicyFork(forkArgs({leftWitness,rightWitness}));
 leftWitness.challenge=digest('changed');rightWitness.witnessId=digest('changed');
 const r=await p;assert.equal(r.observerSignaturesVerified,true);
});
test('35AF rejects accessor-supplied observer identity',async()=>{
 const w={...wa};Object.defineProperty(w,'witnessId',{get(){return witnessIdA;},enumerable:true});
 await rejects(inspectOfflineWitnessedPolicyFork(forkArgs({leftWitness:w})),
 'OFFLINE_WITNESS_DISTINCT_OBSERVERS_REQUIRED');
});
test('35AF rejects reordered portable evidence envelope',async()=>{
 const e=portable(await inspectOfflineWitnessedPolicyFork(forkArgs()));
 const swapped=Object.fromEntries(Object.entries(e).reverse());
 await rejects(verifyPortableOfflineWitnessedPolicyForkEvidence({evidence:swapped,
  parentCheckpointBytes:first.bytes,pinnedHead:h,policySignerPublicKey:signer.publicKey,
  leftWitness:wa,rightWitness:wb,expectedAudience:audience,trustedNowMs:now,consumeOnce:replay()}),
 'OFFLINE_WITNESS_INVALID_EVIDENCE');
});

test('35AF exports a canonical portable envelope directly consumable by verifier',async()=>{
 const r=await inspectOfflineWitnessedPolicyFork(forkArgs());
 assert.equal(Object.isFrozen(r.portableEvidence),true);
 const v=await verifyPortableOfflineWitnessedPolicyForkEvidence({evidence:r.portableEvidence,
  parentCheckpointBytes:first.bytes,pinnedHead:h,policySignerPublicKey:signer.publicKey,
  leftWitness:wa,rightWitness:wb,expectedAudience:audience,trustedNowMs:now,
  consumeOnce:replay()});
 assert.equal(v.evidenceSha256,r.evidenceSha256);
});
