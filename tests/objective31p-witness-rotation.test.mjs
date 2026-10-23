import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {OFFLINE_ACQUISITION_INDEX_SCHEMA} from '../src/offline-acquisition-cross-session-index.mjs';
import {OFFLINE_ACQUISITION_ATTESTATION_SCHEMA,offlineAcquisitionIndexAttestationPolicyDigest,offlineAcquisitionIndexAttestationSigningBytes} from '../src/offline-acquisition-index-attestations.mjs';
import {OFFLINE_ACQUISITION_WITNESS_TRANSITION_SCHEMA,offlineAcquisitionWitnessTransitionSigningBytes,offlineAcquisitionWitnessTransitionPossessionBytes,verifyOfflineAcquisitionWitnessTransitionChain,reviewOfflineAcquisitionCrossEpochBranches} from '../src/offline-acquisition-witness-rotation.mjs';

const ROOT='0'.repeat(64),zero={count:0,headDigest:ROOT},registryId='trendyjoes-31p-registry',nowMs=1700000000000;
const hash=x=>createHash('sha256').update(x).digest('hex');
const keysets=Array.from({length:3},(_,e)=>Array.from({length:3},(_,i)=>({...generateKeyPairSync('ed25519'),id:`witness_31p_${e}_${i}`})));
const policies=keysets.map(k=>({witnesses:k.map(({id,publicKey})=>({id,publicKey})),quorum:2}));
const digests=policies.map(offlineAcquisitionIndexAttestationPolicyDigest);
const clone=x=>structuredClone(x);
const rejects=(fn,code)=>assert.throws(fn,e=>e.code===code,code);
const pin=h=>h.length?{count:h.length,headDigest:h.at(-1).digest}:zero;
function history(labels){
 const entries=[];let previous=ROOT,retention=zero;
 for(const [i,label] of labels.entries()){
  const p={acquisitionId:`acquisition_${label}_0000000`,sessionHead:{count:3,headDigest:hash('session:'+label)},previousRetentionHead:retention,retentionHead:{count:2*i+2,headDigest:hash('retention:'+label)},forensicHeads:{forensic:{count:i+1,headDigest:hash('forensic:'+i)},publication:{count:i+1,headDigest:hash('publication:'+i)},outbox:{count:i+1,headDigest:hash('outbox:'+i)}},manifestDigest:hash('manifest:'+label)};
  const body={schema:OFFLINE_ACQUISITION_INDEX_SCHEMA,index:i+1,previousDigest:previous,payload:p};const digest=hash(Buffer.from(`${OFFLINE_ACQUISITION_INDEX_SCHEMA}\0${JSON.stringify(body)}`));
  entries.push({...body,digest});previous=digest;retention=p.retentionHead;
 }
 return entries;
}
const alpha=history(['alpha']),beta=history(['alpha','beta']),gamma=history(['alpha','gamma']);
function signed(keys,bytes,indices=[0,1]){return indices.map(i=>({witnessId:keys[i].id,signature:sign(null,bytes(keys[i].id),keys[i].privateKey).toString('base64url')})).sort((a,b)=>a.witnessId.localeCompare(b.witnessId,'en'));}
function transition(epoch,h,overrides={}){
 const body={schema:OFFLINE_ACQUISITION_WITNESS_TRANSITION_SCHEMA,registryId,fromEpoch:epoch,toEpoch:epoch+1,fromPolicyDigest:digests[epoch],toPolicyDigest:digests[epoch+1],anchorHead:pin(h),issuedAt:nowMs-5000+epoch*2000,expiresAt:nowMs+60000,nonce:`transition_31p_${epoch}_0000`,...overrides};
 return {body,outgoingSignatures:signed(keysets[epoch],()=>offlineAcquisitionWitnessTransitionSigningBytes(body)),incomingProofs:signed(keysets[epoch+1],id=>offlineAcquisitionWitnessTransitionPossessionBytes(body,id),[0,1,2]),history:clone(h)};
}
function attest(epoch,h,issuedAt,nonce){
 const body={schema:OFFLINE_ACQUISITION_ATTESTATION_SCHEMA,registryId,head:pin(h),previousHead:pin(h.slice(0,-1)),issuedAt,expiresAt:nowMs+60000,nonce,policyDigest:digests[epoch]};
 return {body,signatures:signed(keysets[epoch],()=>offlineAcquisitionIndexAttestationSigningBytes(body))};
}
const t0=transition(0,alpha),t1=transition(1,beta);
const params=(ts=[t0],ps=policies.slice(0,ts.length+1))=>({policies:ps,transitions:ts,registryId,nowMs,trustedAnchor:zero,expectedGenesisPolicyDigest:digests[0],expectedFinalPolicyDigest:digests[ts.length],expectedFinalEpoch:ts.length});
const verify=(ts=[t0],ps)=>verifyOfflineAcquisitionWitnessTransitionChain(params(ts,ps));
const branch=(epoch,h,issuedAt,nonce)=>({epoch,history:clone(h),attestation:attest(epoch,h,issuedAt,nonce)});
const old=()=>branch(0,gamma,nowMs-10000,'old_attestation_0001');
const fresh=()=>branch(1,beta,nowMs-1000,'new_attestation_0001');
const review=(branches=[old(),fresh()],ts=[t0])=>reviewOfflineAcquisitionCrossEpochBranches({...params(ts),branches});

test('31P valid rotation requires outgoing quorum and every incoming proof',()=>{const v=verify();assert.equal(v.verifiedTransitionChain,true);assert.equal(v.epoch,1);assert.equal(v.productionApproved,false);assert.equal(v.mayRetry,false);});
test('31P policy transition bytes are domain separated',()=>assert.match(offlineAcquisitionWitnessTransitionSigningBytes(t0.body).toString(),/^TJ-OFFLINE-ACQUISITION-WITNESS-TRANSITION-1\0/));
test('31P incoming proof is bound to witness identity',()=>assert.notDeepEqual(offlineAcquisitionWitnessTransitionPossessionBytes(t0.body,keysets[1][0].id),offlineAcquisitionWitnessTransitionPossessionBytes(t0.body,keysets[1][1].id)));
test('31P independent genesis policy pin cannot be substituted',()=>rejects(()=>verifyOfflineAcquisitionWitnessTransitionChain({...params(),expectedGenesisPolicyDigest:hash('wrong')}),'INDEX_ROTATION_EXTERNAL_PIN_MISMATCH'));
test('31P independent final policy pin prevents truncation',()=>rejects(()=>verifyOfflineAcquisitionWitnessTransitionChain({...params(),expectedFinalPolicyDigest:hash('wrong')}),'INDEX_ROTATION_EXTERNAL_PIN_MISMATCH'));
test('31P externally pinned final epoch prevents truncation',()=>rejects(()=>verifyOfflineAcquisitionWitnessTransitionChain({...params(),expectedFinalEpoch:2}),'INDEX_ROTATION_REQUEST_INVALID'));
test('31P cannot silently drop all transitions',()=>rejects(()=>verifyOfflineAcquisitionWitnessTransitionChain({...params(),policies:[policies[0]],transitions:[],expectedFinalEpoch:0}),'INDEX_ROTATION_REQUEST_INVALID'));
test('31P forged outgoing signature rejected',()=>{const t=clone(t0);t.outgoingSignatures[0].signature=sign(null,offlineAcquisitionWitnessTransitionSigningBytes(t.body),generateKeyPairSync('ed25519').privateKey).toString('base64url');rejects(()=>verify([t]),'INDEX_ROTATION_OUTGOING_SIGNATURE_INVALID');});
test('31P missing outgoing quorum rejected',()=>{const t=clone(t0);t.outgoingSignatures.pop();rejects(()=>verify([t]),'INDEX_ROTATION_OUTGOING_SIGNATURE_INVALID');});
test('31P duplicate outgoing signer rejected',()=>{const t=clone(t0);t.outgoingSignatures[1]=clone(t.outgoingSignatures[0]);rejects(()=>verify([t]),'INDEX_ROTATION_OUTGOING_SIGNATURE_INVALID');});
test('31P missing incoming proof rejected',()=>{const t=clone(t0);t.incomingProofs.pop();rejects(()=>verify([t]),'INDEX_ROTATION_PROOF_INVALID');});
test('31P forged incoming proof rejected',()=>{const t=clone(t0);t.incomingProofs[0].signature=sign(null,offlineAcquisitionWitnessTransitionPossessionBytes(t.body,t.incomingProofs[0].witnessId),generateKeyPairSync('ed25519').privateKey).toString('base64url');rejects(()=>verify([t]),'INDEX_ROTATION_PROOF_INVALID');});
test('31P swapped incoming proof identities rejected',()=>{const t=clone(t0);t.incomingProofs[0].witnessId='witness_31p_1_9';rejects(()=>verify([t]),'INDEX_ROTATION_PROOF_INVALID');});
test('31P signature tamper to policy digest rejected',()=>{const t=clone(t0);t.body.toPolicyDigest=hash('wrong');rejects(()=>verify([t]),'INDEX_ROTATION_POLICY_MISMATCH');});
test('31P signature tamper to anchor rejected',()=>{const t=clone(t0);t.body.anchorHead.headDigest=hash('wrong');rejects(()=>verify([t]),'INDEX_ROTATION_OUTGOING_SIGNATURE_INVALID');});
test('31P certificate registry substitution rejected',()=>{const t=clone(t0);t.body.registryId='different_31p_registry';rejects(()=>verify([t]),'INDEX_ROTATION_POLICY_MISMATCH');});
test('31P invalid transition epoch rejected',()=>{const t=clone(t0);t.body.fromEpoch=1;t.body.toEpoch=2;rejects(()=>verify([t]),'INDEX_ROTATION_POLICY_MISMATCH');});
test('31P unexpected certificate field rejected',()=>{const t=clone(t0);t.body.mayRetry=true;rejects(()=>verify([t]),'INDEX_ROTATION_BODY_INVALID');});
test('31P altered history rejected even with unchanged signed anchor',()=>{const t=clone(t0);t.history[0].payload.manifestDigest=hash('tamper');rejects(()=>verify([t]),'INDEX_ATTESTATION_HISTORY_INVALID');});
test('31P independently pinned nonzero ancestor mismatch rejected',()=>rejects(()=>verifyOfflineAcquisitionWitnessTransitionChain({...params(),trustedAnchor:{count:1,headDigest:hash('wrong')}}),'INDEX_ATTESTATION_ANCHOR_MISMATCH'));
test('31P disallows reusing retired witness public keys across epochs',()=>{const bad=[policies[0],{witnesses:[{id:'new_witness_reused',publicKey:keysets[0][0].publicKey},...policies[1].witnesses.slice(1)],quorum:2}];rejects(()=>verify([t0],bad),'INDEX_ROTATION_RETIRED_KEY_REUSE');});
test('31P disallows reusing retired witness ID across epochs',()=>{const bad=[policies[0],{witnesses:[{id:keysets[0][0].id,publicKey:keysets[1][0].publicKey},...policies[1].witnesses.slice(1)],quorum:2}];rejects(()=>verify([t0],bad),'INDEX_ROTATION_RETIRED_KEY_REUSE');});
test('31P valid two-step policy chain with monotonic history',()=>{const v=verify([t0,t1]);assert.equal(v.epoch,2);assert.deepEqual(v.anchors,[pin(alpha),pin(beta)]);});
test('31P rejects second transition with divergent signed history',()=>{const t=transition(1,gamma);rejects(()=>verify([transition(0,beta),t]),'INDEX_ROTATION_HISTORY_FORK');});
test('31P rejects second transition with rolled-back signed history',()=>{const t=transition(1,alpha);rejects(()=>verify([transition(0,beta),t]),'INDEX_ROTATION_HISTORY_FORK');});
test('31P rejects reused transition nonce across epochs',()=>{const t=transition(1,beta,{nonce:t0.body.nonce});rejects(()=>verify([t0,t]),'INDEX_ROTATION_TIME_OR_REPLAY');});
test('31P rejects nonmonotonic transition times',()=>{const t=transition(1,beta,{issuedAt:t0.body.issuedAt});rejects(()=>verify([t0,t]),'INDEX_ROTATION_TIME_OR_REPLAY');});
test('31P rejects future transition issuance',()=>{const t=transition(0,alpha,{issuedAt:nowMs+100});rejects(()=>verify([t]),'INDEX_ROTATION_TIME_OR_REPLAY');});
test('31P rejects overly long certificate validity',()=>{const t=clone(t0);t.body.expiresAt=t0.body.issuedAt+8*86400000;rejects(()=>verify([t]),'INDEX_ROTATION_BODY_INVALID');});
test('31P signed fork across retired and new witness epochs is evidence only',()=>{const v=review();assert.equal(v.classification,'CROSS_EPOCH_SIGNED_FORK_EVIDENCE');assert.equal(v.conflict.firstConflictingIndex,2);assert.equal(v.conflict.epochA,0);assert.equal(v.conflict.epochB,1);assert.equal(v.mayAcknowledge,false);});
test('31P compatible historical signed prefix is not proof of no unseen fork',()=>{const v=review([branch(0,alpha,nowMs-10000,'old_attestation_0002'),fresh()]);assert.equal(v.classification,'CONSISTENT_SIGNED_PREFIXES_ONLY');assert.equal(v.signaturesOfSessionsVerified,false);});
test('31P retired witness signing after transition rejected',()=>{const b=old();b.attestation=attest(0,gamma,nowMs-1000,'old_attestation_0003');rejects(()=>review([b,fresh()]),'INDEX_ROTATION_RETIRED_EPOCH_SIGNATURE');});
test('31P new witness signing before transition rejected',()=>{const b=fresh();b.attestation=attest(1,beta,nowMs-10000,'new_attestation_0003');rejects(()=>review([old(),b]),'INDEX_ROTATION_RETIRED_EPOCH_SIGNATURE');});
test('31P new epoch cannot attest pre-transition history',()=>{const b=branch(1,history(['other']),nowMs-1000,'new_attestation_0004');rejects(()=>review([old(),b]),'INDEX_ROTATION_EPOCH_ANCHOR_MISMATCH');});
test('31P new epoch cannot attest conflicting transition ancestor',()=>{const b=branch(1,gamma,nowMs-1000,'new_attestation_0005');const t=transition(0,beta);rejects(()=>review([old(),b],[t]),'INDEX_ROTATION_EPOCH_ANCHOR_MISMATCH');});
test('31P same attestation nonce replay across epochs rejected',()=>{const b=fresh();b.attestation=attest(1,beta,nowMs-1000,old().attestation.body.nonce);rejects(()=>review([old(),b]),'INDEX_ROTATION_ATTESTATION_REPLAY');});
test('31P attestation nonce collision with transition rejected',()=>{const b=fresh();b.attestation=attest(1,beta,nowMs-1000,t0.body.nonce);rejects(()=>review([old(),b]),'INDEX_ROTATION_ATTESTATION_REPLAY');});
test('31P forged attestation rejected by epoch-specific keys',()=>{const b=fresh();b.attestation.signatures[0].signature=sign(null,offlineAcquisitionIndexAttestationSigningBytes(b.attestation.body),keysets[0][0].privateKey).toString('base64url');rejects(()=>review([old(),b]),'INDEX_ATTESTATION_SIGNATURE_INVALID');});
test('31P signed immediate predecessor substitution rejected',()=>{const b=fresh();b.attestation=attest(1,beta,nowMs-1000,'new_attestation_0006');b.attestation.body.previousHead.headDigest=hash('wrong');rejects(()=>review([old(),b]),'INDEX_ATTESTATION_SIGNATURE_INVALID');});
test('31P cannot use an unpinned alternate genesis history',()=>{const b=branch(1,history(['other','beta']),nowMs-1000,'new_attestation_0007');rejects(()=>review([old(),b]),'INDEX_ROTATION_EPOCH_ANCHOR_MISMATCH');});
test('31P no valid branch review with one branch',()=>rejects(()=>review([fresh()]),'INDEX_ROTATION_REVIEW_INVALID'));
