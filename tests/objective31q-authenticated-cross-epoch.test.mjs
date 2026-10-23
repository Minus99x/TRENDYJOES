import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createOfflineAcquisitionCrossSessionIndex} from '../src/offline-acquisition-cross-session-index.mjs';
import {createOfflineAcquisitionSessionJournal} from '../src/offline-acquisition-session-journal.mjs';
import {createOfflineForensicPortableReviewBundle} from '../src/offline-forensic-portable-review.mjs';
import {OFFLINE_ACQUISITION_RECEIPT_SCHEMA,offlineAcquisitionReceiptSigningBytes,createOfflineAcquisitionReceipt,createOfflineForensicAcquisitionManifest} from '../src/offline-forensic-acquisition-provenance.mjs';
import {OFFLINE_ACQUISITION_ATTESTATION_SCHEMA,offlineAcquisitionIndexAttestationPolicyDigest,offlineAcquisitionIndexAttestationSigningBytes,} from '../src/offline-acquisition-index-attestations.mjs';
import {OFFLINE_ACQUISITION_WITNESS_TRANSITION_SCHEMA,offlineAcquisitionWitnessTransitionSigningBytes,offlineAcquisitionWitnessTransitionPossessionBytes,reviewOfflineAcquisitionCrossEpochBranches} from '../src/offline-acquisition-witness-rotation.mjs';
import {verifyOfflineAcquisitionCrossEpochAuthenticatedEvidence} from '../src/offline-acquisition-authenticated-cross-epoch.mjs';
const ROOT='0'.repeat(64),zero={count:0,headDigest:ROOT},heads={forensic:zero,publication:zero,outbox:zero};
const key=()=>generateKeyPairSync('ed25519');
const hash=x=>createHash('sha256').update(x).digest('hex');
const pin=h=>h.length?{count:h.length,headDigest:h.at(-1).digest}:zero;
const clone=structuredClone;
const rejects=(fn,code)=>assert.throws(fn,e=>e?.code===code);
const registryId='synthetic-acquisition-31q',anchorType='registry',nowMs=1700000100000;
const mkKeys=(prefix)=>Array.from({length:3},(_,i)=>({id:`${prefix}_witness_${i}`, ...key()}));
function signed(keys,bytes,count=2){return keys.slice(0,count).map(k=>({witnessId:k.id,signature:sign(null,bytes(k.id),k.privateKey).toString('base64url')}));}
async function fixture(t){
 const root=await mkdtemp(join(tmpdir(),'tj31q-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const retention=mkKeys('retention_31q'),forensic=mkKeys('forensic_31q'),review=mkKeys('review_31q');
 const retentionTrust={registryId,anchorType,retentionWitnesses:retention.map(k=>({id:k.id,publicKey:k.publicKey})),retentionQuorum:2};
 const reviewers=review.slice(0,2).map(k=>({id:k.id,publicKey:k.publicKey,readLatest:async()=>null}));
 const policy={reviewers,quorum:2};
 const forensicTrust={registryId,anchorType,witnesses:forensic.map(k=>({id:k.id,publicKey:k.publicKey})),witnessQuorum:2,reviewerPolicies:[policy],reviewerEpochs:[{startIndex:1,...policy}]};
 const envelope=createOfflineForensicPortableReviewBundle({registryId,anchorType,forensicEvents:[],publications:[],transitionCertificates:[],outboxEvents:[],declaredHeads:heads});
 const journal=createOfflineAcquisitionCrossSessionIndex({directory:join(root,'index')});
 const history=[],evidence=[],receipts=[];
 for(let n=0;n<2;n++){
  const acquisitionId=`acquisition-31q-${n+1}`;
  const previousRetentionHead=receipts.length?{count:receipts.length,headDigest:receipts.at(-1).digest}:zero;
  for(const phase of ['PRE','POST']){
   const body={schema:OFFLINE_ACQUISITION_RECEIPT_SCHEMA,registryId,anchorType,index:receipts.length+1,previousDigest:receipts.at(-1)?.digest??ROOT,acquisitionId,phase,heads:clone(heads),bundleDigest:phase==='PRE'?ROOT:envelope.transportDigest,observedAt:1700000000000+receipts.length*1000};
   receipts.push(createOfflineAcquisitionReceipt({body,signatures:signed(retention,()=>offlineAcquisitionReceiptSigningBytes(body))}));
  }
  const manifest=createOfflineForensicAcquisitionManifest({acquisitionId,envelope,receiptHistory:clone(receipts)});
  const independentRetentionHead={count:receipts.length,headDigest:receipts.at(-1).digest};
  const sessionDirectory=join(root,`session-${n}`),session=createOfflineAcquisitionSessionJournal({directory:sessionDirectory});
  const begun=await session.begin({acquisitionId,independentPins:heads,priorRetentionHead:previousRetentionHead,expectedSessionHead:zero});
  const done=await session.record({manifest,independentPins:heads,forensicTrust,retentionTrust,independentRetentionHead,expectedSessionHead:{count:begun.count,headDigest:begun.headDigest}});
  const sessionHead={count:done.count,headDigest:done.headDigest};
  const result=await journal.append({acquisitionId,sessionDirectory,sessionHead,manifest,independentPins:heads,independentRetentionHead,forensicTrust,retentionTrust,expectedIndexHead:pin(history)});
  const entry=JSON.parse(await readFile(join(root,'index',String(n+1).padStart(4,'0')+'.json'),'utf8'));
  assert.equal(result.headDigest,entry.digest);history.push(entry);
  const sessionEvents=[];for(let i=1;i<=3;i++)sessionEvents.push(JSON.parse(await readFile(join(sessionDirectory,String(i).padStart(4,'0')+'.json'),'utf8')));
  evidence.push({manifest,sessionEvents});
 }
 const old=mkKeys('epoch0_31q'),next=mkKeys('epoch1_31q');
 const policies=[old,next].map(keys=>({witnesses:keys.map(k=>({id:k.id,publicKey:k.publicKey})),quorum:2}));
 const digests=policies.map(offlineAcquisitionIndexAttestationPolicyDigest);
 const transitionBody={schema:OFFLINE_ACQUISITION_WITNESS_TRANSITION_SCHEMA,registryId,fromEpoch:0,toEpoch:1,fromPolicyDigest:digests[0],toPolicyDigest:digests[1],anchorHead:pin(history.slice(0,1)),issuedAt:nowMs-5000,expiresAt:nowMs+30000,nonce:'transition_nonce_31q'};
 const transition={body:transitionBody,outgoingSignatures:signed(old,()=>offlineAcquisitionWitnessTransitionSigningBytes(transitionBody)),incomingProofs:signed(next,id=>offlineAcquisitionWitnessTransitionPossessionBytes(transitionBody,id),3),history:clone(history.slice(0,1))};
 function branch(epoch,count,nonce){const h=clone(history.slice(0,count));const body={schema:OFFLINE_ACQUISITION_ATTESTATION_SCHEMA,registryId,head:pin(h),previousHead:pin(h.slice(0,-1)),issuedAt:nowMs-(epoch?1000:10000),expiresAt:nowMs+30000,nonce,policyDigest:digests[epoch]};return {epoch,attestation:{body,signatures:signed(epoch?next:old,()=>offlineAcquisitionIndexAttestationSigningBytes(body))},history:h};}
 const branches=[branch(0,1,'old_attestation_31q'),branch(1,2,'new_attestation_31q')];
 const args={policies,transitions:[transition],branches,branchEvidence:[[evidence[0]],evidence],registryId,nowMs,trustedAnchor:zero,expectedGenesisPolicyDigest:digests[0],expectedFinalPolicyDigest:digests[1],expectedFinalEpoch:1,forensicTrust,retentionTrust};
 return {args,history,evidence,retention,old,next,branch,root};
}
const verify=a=>verifyOfflineAcquisitionCrossEpochAuthenticatedEvidence(a);

test('31Q valid rotated signed histories authenticate every original acquisition evidence record',async t=>{
 const {args}=await fixture(t),v=verify(args);
 assert.equal(v.verified,true);assert.equal(v.verifiedEvidenceRecords,3);assert.equal(v.underlyingRetentionSignaturesVerified,true);assert.equal(v.sessionHashesBoundToSignedIndex,true);
 assert.equal(v.mayRetry,false);assert.equal(v.mayAcknowledge,false);assert.equal(v.mayManufacture,false);assert.equal(v.productionApproved,false);
});
test('31Q 31P structural review is explicitly not full cryptographic evidence authentication',async t=>{const {args}=await fixture(t);const r=reviewOfflineAcquisitionCrossEpochBranches(args);assert.equal(r.signaturesOfSessionsVerified,false);assert.equal(verify(args).underlyingRetentionSignaturesVerified,true);});
test('31Q valid history requires complete evidence on BOTH branches including shared prefixes',async t=>{const {args}=await fixture(t);args.branchEvidence[0]=[];rejects(()=>verify(args),'INDEX_AUTH_EVIDENCE_INCOMPLETE');});
test('31Q rejects evidence missing for newest signed head',async t=>{const {args}=await fixture(t);args.branchEvidence[1].pop();rejects(()=>verify(args),'INDEX_AUTH_EVIDENCE_INCOMPLETE');});
test('31Q rejects missing evidence array',async t=>{const {args}=await fixture(t);delete args.branchEvidence;rejects(()=>verify(args),'INDEX_AUTH_EVIDENCE_INCOMPLETE');});
test('31Q rejects null evidence',async t=>{const {args}=await fixture(t);args.branchEvidence[1][1]=null;rejects(()=>verify(args),'INDEX_AUTH_EVIDENCE_INVALID');});
test('31Q rejects extra evidence fields',async t=>{const {args}=await fixture(t);args.branchEvidence[1][1]={...args.branchEvidence[1][1],trusted:true};rejects(()=>verify(args),'INDEX_AUTH_EVIDENCE_INVALID');});
test('31Q rejects forged retention signature while 31P structural review remains valid',async t=>{const {args}=await fixture(t);const proof=args.branchEvidence[1][1];proof.manifest=clone(proof.manifest);proof.manifest.receiptHistory.at(-1).signatures[0].signature='A'.repeat(86);assert.equal(reviewOfflineAcquisitionCrossEpochBranches(args).classification,'CONSISTENT_SIGNED_PREFIXES_ONLY');rejects(()=>verify(args),'INDEX_AUTH_MANIFEST_BINDING_INVALID');});
test('31Q rejects unsigned replacement of manifest even when original index remains valid',async t=>{const {args}=await fixture(t);args.branchEvidence[1][1].manifest.envelope.transportDigest='a'.repeat(64);rejects(()=>verify(args),'INDEX_AUTH_MANIFEST_BINDING_INVALID');});
test('31Q rejects independently trusted retention-key substitution',async t=>{const {args}=await fixture(t);args.retentionTrust={...args.retentionTrust,retentionWitnesses:args.retentionTrust.retentionWitnesses.map((w,i)=>i===0?{...w,publicKey:key().publicKey}:w)};rejects(()=>verify(args),'ACQUISITION_RECEIPT_SIGNATURE_INVALID');});
test('31Q rejects independent forensic trust registry substitution',async t=>{const {args}=await fixture(t);args.forensicTrust={...args.forensicTrust,registryId:'other_registry_31q'};assert.throws(()=>verify(args));});
test('31Q rejects swapped signed retention histories between index records',async t=>{const {args}=await fixture(t);args.branchEvidence[1][1].manifest=clone(args.branchEvidence[1][0].manifest);rejects(()=>verify(args),'INDEX_AUTH_MANIFEST_BINDING_INVALID');});
test('31Q rejects session journal missing POST',async t=>{const {args}=await fixture(t);args.branchEvidence[1][1].sessionEvents.pop();rejects(()=>verify(args),'INDEX_AUTH_SESSION_INCOMPLETE');});
test('31Q rejects session action reorder',async t=>{const {args}=await fixture(t);const e=args.branchEvidence[1][1].sessionEvents;[e[1],e[2]]=[e[2],e[1]];rejects(()=>verify(args),'INDEX_AUTH_SESSION_INVALID');});
test('31Q rejects session hash-chain tamper',async t=>{const {args}=await fixture(t);args.branchEvidence[1][1].sessionEvents[1].previousDigest='f'.repeat(64);rejects(()=>verify(args),'INDEX_AUTH_SESSION_INVALID');});
test('31Q rejects session journal payload substitution',async t=>{const {args}=await fixture(t);args.branchEvidence[1][1].sessionEvents[0].payload.acquisitionId='forged_acquisition_31q';rejects(()=>verify(args),'INDEX_AUTH_SESSION_INVALID');});
test('31Q rejects session journal digest substitution',async t=>{const {args}=await fixture(t);args.branchEvidence[1][1].sessionEvents[2].digest='a'.repeat(64);rejects(()=>verify(args),'INDEX_AUTH_SESSION_INVALID');});
test('31Q rejects swapped session journal even with correctly signed receipts',async t=>{const {args}=await fixture(t);args.branchEvidence[1][1].sessionEvents=clone(args.branchEvidence[1][0].sessionEvents);rejects(()=>verify(args),'INDEX_AUTH_SESSION_PIN_MISMATCH');});
test('31Q rejects session payload field insertion',async t=>{const {args}=await fixture(t);args.branchEvidence[1][1].sessionEvents[0].payload.authorized=true;rejects(()=>verify(args),'INDEX_AUTH_SESSION_INVALID');});
test('31Q rejects independent index witness and retention key reuse',async t=>{const {args}=await fixture(t);args.retentionTrust.retentionWitnesses[0].publicKey=args.policies[0].witnesses[0].publicKey;rejects(()=>verify(args),'INDEX_AUTH_WITNESS_NOT_INDEPENDENT');});
test('31Q rejects index witness and forensic reviewer key reuse',async t=>{const {args}=await fixture(t);args.forensicTrust.reviewerPolicies[0].reviewers[0].publicKey=args.policies[1].witnesses[0].publicKey;rejects(()=>verify(args),'INDEX_AUTH_WITNESS_NOT_INDEPENDENT');});
test('31Q rejects missing independent retention trust',async t=>{const {args}=await fixture(t);delete args.retentionTrust;rejects(()=>verify(args),'INDEX_AUTH_TRUST_REQUIRED');});
test('31Q rejects missing independent forensic trust',async t=>{const {args}=await fixture(t);delete args.forensicTrust;rejects(()=>verify(args),'INDEX_AUTH_TRUST_REQUIRED');});
test('31Q rejects forged witness policy transition',async t=>{const {args}=await fixture(t);args.transitions[0].outgoingSignatures[0].signature=sign(null,offlineAcquisitionWitnessTransitionSigningBytes(args.transitions[0].body),key().privateKey).toString('base64url');rejects(()=>verify(args),'INDEX_ROTATION_OUTGOING_SIGNATURE_INVALID');});
test('31Q rejects forged rotated-epoch attestation',async t=>{const {args}=await fixture(t);args.branches[1].attestation.signatures[0].signature=sign(null,offlineAcquisitionIndexAttestationSigningBytes(args.branches[1].attestation.body),key().privateKey).toString('base64url');rejects(()=>verify(args),'INDEX_ATTESTATION_SIGNATURE_INVALID');});
test('31Q rejects independently pinned ancestor mismatch',async t=>{const {args}=await fixture(t);args.trustedAnchor={count:1,headDigest:'a'.repeat(64)};rejects(()=>verify(args),'INDEX_ATTESTATION_ANCHOR_MISMATCH');});
test('31Q rejects untrusted index-history manifest digest tamper',async t=>{const {args}=await fixture(t);args.branches[1].history[1].payload.manifestDigest='a'.repeat(64);rejects(()=>verify(args),'INDEX_ATTESTATION_HISTORY_INVALID');});
test('31Q rejects signed but unauthenticated acquisition payload, even if structural 31P review accepts it',async t=>{
 const {args,next}=await fixture(t);
 // A compromised index quorum can sign a structurally correct alternate index
 // entry; it still cannot forge the original retention witnesses or session pin.
 const b=args.branches[1],e=b.history[1];e.payload.manifestDigest=hash('forged_manifest_31q');
 const {digest:discard,...body}=e;e.digest=hash(Buffer.from(`TJ-OFFLINE-ACQUISITION-CROSS-SESSION-1\0${JSON.stringify(body)}`));
 b.attestation.body.head=pin(b.history);
 b.attestation.signatures=signed(next,()=>offlineAcquisitionIndexAttestationSigningBytes(b.attestation.body));
 assert.equal(reviewOfflineAcquisitionCrossEpochBranches(args).classification,'CONSISTENT_SIGNED_PREFIXES_ONLY');
 rejects(()=>verify(args),'INDEX_AUTH_MANIFEST_BINDING_INVALID');
});
test('31Q valid signed fork still cannot be called authenticated without independent evidence for fork',async t=>{
 const {args,next}=await fixture(t),b=args.branches[1];
 b.history[1].payload.acquisitionId='alternate_acquisition_31q';
 const {digest:discard,...body}=b.history[1];b.history[1].digest=hash(Buffer.from(`TJ-OFFLINE-ACQUISITION-CROSS-SESSION-1\0${JSON.stringify(body)}`));
 b.attestation.body.head=pin(b.history);b.attestation.signatures=signed(next,()=>offlineAcquisitionIndexAttestationSigningBytes(b.attestation.body));
 assert.equal(reviewOfflineAcquisitionCrossEpochBranches(args).classification,'CONSISTENT_SIGNED_PREFIXES_ONLY');
 rejects(()=>verify(args),'INDEX_AUTH_MANIFEST_BINDING_INVALID');
});
function resignNewestIndex(args,keys){
 const b=args.branches[1],e=b.history[1],{digest:unused,...body}=e;
 e.digest=hash(Buffer.from(`TJ-OFFLINE-ACQUISITION-CROSS-SESSION-1\0${JSON.stringify(body)}`));
 b.attestation.body.head=pin(b.history);
 b.attestation.signatures=signed(keys,()=>offlineAcquisitionIndexAttestationSigningBytes(b.attestation.body));
}
test('31Q detects forged retention signature even when compromised index quorum re-signs matching manifest and session hashes',async t=>{
 const {args,next}=await fixture(t),proof=args.branchEvidence[1][1],record=proof.manifest.receiptHistory.at(-1);
 record.signatures[0].signature=sign(null,offlineAcquisitionReceiptSigningBytes(Object.fromEntries(Object.keys(record).filter(k=>!['signatures','digest'].includes(k)).map(k=>[k,record[k]]))),key().privateKey).toString('base64url');
 const unsigned={...record};delete unsigned.digest;
 record.digest=hash(Buffer.from(`TJ-OFFLINE-ACQUISITION-RECEIPT-1\0${JSON.stringify(unsigned)}`));
 proof.sessionEvents[2].payload=clone(proof.manifest);
 const s=proof.sessionEvents[2],{digest:sd,...sb}=s;s.digest=hash(Buffer.from(`TJ-OFFLINE-ACQUISITION-SESSION-1\0${JSON.stringify(sb)}`));
 const p=args.branches[1].history[1].payload;
 p.sessionHead.headDigest=s.digest;
 p.retentionHead.headDigest=record.digest;
 p.manifestDigest=hash(Buffer.from(`TJ-OFFLINE-ACQUISITION-MANIFEST-SNAPSHOT-1\0${JSON.stringify(proof.manifest)}`));
 resignNewestIndex(args,next);
 assert.equal(reviewOfflineAcquisitionCrossEpochBranches(args).classification,'CONSISTENT_SIGNED_PREFIXES_ONLY');
 rejects(()=>verify(args),'ACQUISITION_RECEIPT_SIGNATURE_INVALID');
});
test('31Q rejects fully rehashed and quorum re-signed but falsely bound BEGIN session',async t=>{
 const {args,next}=await fixture(t),proof=args.branchEvidence[1][1],events=proof.sessionEvents;
 events[0].payload.acquisitionId='substituted_begin_31q';
 for(let i=0;i<3;i++){
  if(i)events[i].previousDigest=events[i-1].digest;
  const {digest:unused,...body}=events[i];events[i].digest=hash(Buffer.from(`TJ-OFFLINE-ACQUISITION-SESSION-1\0${JSON.stringify(body)}`));
 }
 args.branches[1].history[1].payload.sessionHead.headDigest=events[2].digest;
 resignNewestIndex(args,next);
 assert.equal(reviewOfflineAcquisitionCrossEpochBranches(args).classification,'CONSISTENT_SIGNED_PREFIXES_ONLY');
 rejects(()=>verify(args),'INDEX_AUTH_SESSION_BINDING_INVALID');
});
