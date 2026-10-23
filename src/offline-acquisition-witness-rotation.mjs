/**
 * Objective 31P: offline historical witness-policy transitions and cross-epoch
 * signed index branch review. All policies, pins and time come from an
 * independent caller. Signatures are evidence, NEVER operational permission.
 */
import {createHash, verify as verifySignature} from 'node:crypto';
import {
 offlineAcquisitionIndexAttestationPolicyDigest,
 verifyOfflineAcquisitionIndexHeadAttestation,
 verifyOfflineAcquisitionIndexPortableHistory
} from './offline-acquisition-index-attestations.mjs';

export const OFFLINE_ACQUISITION_WITNESS_TRANSITION_SCHEMA='TJ-OFFLINE-ACQUISITION-WITNESS-TRANSITION-1';
const ROOT='0'.repeat(64),HEX=/^[0-9a-f]{64}$/,ID=/^[A-Za-z0-9_-]{12,80}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>obj(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const sha=b=>createHash('sha256').update(b).digest('hex');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=2000&&HEX.test(h.headDigest)&&(h.count===0)===(h.headDigest===ROOT);
const signature=s=>typeof s==='string'&&/^[A-Za-z0-9_-]{86}$/.test(s)&&Buffer.from(s,'base64url').length===64&&Buffer.from(s,'base64url').toString('base64url')===s;
const pubDigest=k=>sha(k.export({format:'der',type:'spki'}));
const pin=h=>h.length?{count:h.length,headDigest:h.at(-1).digest}:{count:0,headDigest:ROOT};
function normalize(p){
 if(!exact(p,['witnesses','quorum']))fail('INDEX_ROTATION_POLICY_INVALID');
 const digest=offlineAcquisitionIndexAttestationPolicyDigest(p);
 const members=new Map(p.witnesses.map(w=>[w.id,w.publicKey]));
 return {digest,members,quorum:p.quorum,witnesses:p.witnesses};
}
function bodyValid(b){
 if(!exact(b,['schema','registryId','fromEpoch','toEpoch','fromPolicyDigest','toPolicyDigest','anchorHead','issuedAt','expiresAt','nonce'])||
  b.schema!==OFFLINE_ACQUISITION_WITNESS_TRANSITION_SCHEMA||!ID.test(b.registryId||'')||!ID.test(b.nonce||'')||
  !Number.isSafeInteger(b.fromEpoch)||b.fromEpoch<0||b.fromEpoch>100||b.toEpoch!==b.fromEpoch+1||
  !HEX.test(b.fromPolicyDigest||'')||!HEX.test(b.toPolicyDigest||'')||b.fromPolicyDigest===b.toPolicyDigest||
  !head(b.anchorHead)||b.anchorHead.count<1||!Number.isSafeInteger(b.issuedAt)||b.issuedAt<0||
  !Number.isSafeInteger(b.expiresAt)||b.expiresAt<=b.issuedAt||b.expiresAt-b.issuedAt>7*86400000)fail('INDEX_ROTATION_BODY_INVALID');
}
export function offlineAcquisitionWitnessTransitionSigningBytes(body){
 bodyValid(body);
 return Buffer.from(`${OFFLINE_ACQUISITION_WITNESS_TRANSITION_SCHEMA}\0${JSON.stringify(body)}`);
}
export function offlineAcquisitionWitnessTransitionPossessionBytes(body,witnessId){
 const bytes=offlineAcquisitionWitnessTransitionSigningBytes(body);
 if(!ID.test(witnessId||''))fail('INDEX_ROTATION_PROOF_INVALID');
 return Buffer.concat([Buffer.from(`${OFFLINE_ACQUISITION_WITNESS_TRANSITION_SCHEMA}-POP\0`),bytes,Buffer.from(`\0${witnessId}`)]);
}
function verifySignedSet(signatures,members,minimum,bytes,code){
 if(!Array.isArray(signatures)||signatures.length<minimum||signatures.length>members.size)fail(code);
 let previous='';const ids=[];
 for(const s of signatures){
  if(!exact(s,['witnessId','signature'])||!members.has(s.witnessId)||s.witnessId<=previous||!signature(s.signature)||
   !verifySignature(null,bytes(s.witnessId),members.get(s.witnessId),Buffer.from(s.signature,'base64url')))fail(code);
  previous=s.witnessId;ids.push(previous);
 }
 return ids;
}
/** Verify complete, externally pinned chain, never trust keys embedded in evidence. */
export function verifyOfflineAcquisitionWitnessTransitionChain({policies,transitions,registryId,nowMs,trustedAnchor,expectedGenesisPolicyDigest,expectedFinalPolicyDigest,expectedFinalEpoch}={}){
 if(!Array.isArray(policies)||!Array.isArray(transitions)||transitions.length<1||transitions.length>20||policies.length!==transitions.length+1||
  !ID.test(registryId||'')||!Number.isSafeInteger(nowMs)||nowMs<0||!head(trustedAnchor)||!HEX.test(expectedGenesisPolicyDigest||'')||
  !HEX.test(expectedFinalPolicyDigest||'')||!Number.isSafeInteger(expectedFinalEpoch)||expectedFinalEpoch!==transitions.length)fail('INDEX_ROTATION_REQUEST_INVALID');
 const normalized=policies.map(normalize);
 const usedKeys=new Set(),usedIds=new Set();
 for(const p of normalized)for(const w of p.witnesses){
  const kd=pubDigest(w.publicKey);
  if(usedKeys.has(kd)||usedIds.has(w.id))fail('INDEX_ROTATION_RETIRED_KEY_REUSE');
  usedKeys.add(kd);usedIds.add(w.id);
 }
 if(normalized[0].digest!==expectedGenesisPolicyDigest||normalized.at(-1).digest!==expectedFinalPolicyDigest)fail('INDEX_ROTATION_EXTERNAL_PIN_MISMATCH');
 const seenNonces=new Set(),anchors=[],times=[];let previousHistory=null,previousTime=-1;
 for(let i=0;i<transitions.length;i++){
  const t=transitions[i];
  if(!exact(t,['body','outgoingSignatures','incomingProofs','history']))fail('INDEX_ROTATION_CERTIFICATE_INVALID');
  const b=t.body,bytes=offlineAcquisitionWitnessTransitionSigningBytes(b);
  if(b.registryId!==registryId||b.fromEpoch!==i||b.toEpoch!==i+1||b.fromPolicyDigest!==normalized[i].digest||b.toPolicyDigest!==normalized[i+1].digest)fail('INDEX_ROTATION_POLICY_MISMATCH');
  if(b.issuedAt<=previousTime||b.issuedAt>nowMs||seenNonces.has(b.nonce))fail('INDEX_ROTATION_TIME_OR_REPLAY');
  seenNonces.add(b.nonce);previousTime=b.issuedAt;times.push(b.issuedAt);
  verifySignedSet(t.outgoingSignatures,normalized[i].members,normalized[i].quorum,()=>bytes,'INDEX_ROTATION_OUTGOING_SIGNATURE_INVALID');
  // EVERY incoming key must demonstrate possession of its own private key.
  if(!Array.isArray(t.incomingProofs)||t.incomingProofs.length!==normalized[i+1].members.size)fail('INDEX_ROTATION_PROOF_INVALID');
  verifySignedSet(t.incomingProofs,normalized[i+1].members,normalized[i+1].members.size,id=>offlineAcquisitionWitnessTransitionPossessionBytes(b,id),'INDEX_ROTATION_PROOF_INVALID');
  verifyOfflineAcquisitionIndexPortableHistory({history:t.history,expectedHead:b.anchorHead,trustedAnchor});
  if(previousHistory){
   if(t.history.length<previousHistory.length||previousHistory.some((e,j)=>e.digest!==t.history[j].digest))fail('INDEX_ROTATION_HISTORY_FORK');
  }
  previousHistory=t.history;anchors.push(structuredClone(b.anchorHead));
 }
 return Object.freeze({verifiedTransitionChain:true,epoch:transitions.length,policyDigests:Object.freeze(normalized.map(p=>p.digest)),anchors:Object.freeze(anchors),transitionTimes:Object.freeze(times),readOnly:true,mayRetry:false,mayAcknowledge:false,productionApproved:false});
}
/** Cross-epoch comparison with retired-key cutoffs and signed policy chain. */
export function reviewOfflineAcquisitionCrossEpochBranches({policies,transitions,branches,registryId,nowMs,trustedAnchor,expectedGenesisPolicyDigest,expectedFinalPolicyDigest,expectedFinalEpoch}={}){
 const chain=verifyOfflineAcquisitionWitnessTransitionChain({policies,transitions,registryId,nowMs,trustedAnchor,expectedGenesisPolicyDigest,expectedFinalPolicyDigest,expectedFinalEpoch});
 if(!Array.isArray(branches)||branches.length<2||branches.length>10)fail('INDEX_ROTATION_REVIEW_INVALID');
 const checked=[],nonces=new Set(transitions.map(t=>t.body.nonce));
 for(const branch of branches){
  if(!exact(branch,['epoch','attestation','history'])||!Number.isSafeInteger(branch.epoch)||branch.epoch<0||branch.epoch>=policies.length)fail('INDEX_ROTATION_REVIEW_INVALID');
  const {witnesses,quorum}=policies[branch.epoch];
  const v=verifyOfflineAcquisitionIndexHeadAttestation({attestation:branch.attestation,witnesses,quorum,registryId,nowMs});
  const b=branch.attestation.body,begin=branch.epoch?chain.transitionTimes[branch.epoch-1]:0,end=chain.transitionTimes[branch.epoch]??Infinity;
  if(b.issuedAt<begin||b.issuedAt>=end)fail('INDEX_ROTATION_RETIRED_EPOCH_SIGNATURE');
  if(nonces.has(b.nonce))fail('INDEX_ROTATION_ATTESTATION_REPLAY');nonces.add(b.nonce);
  verifyOfflineAcquisitionIndexPortableHistory({history:branch.history,expectedHead:v.head,trustedAnchor});
  if(!same(v.previousHead,pin(branch.history.slice(0,-1))))fail('INDEX_ROTATION_PREDECESSOR_MISMATCH');
  // New epoch cannot attest a history that predates or forks its signed transition anchor.
  if(branch.epoch){const a=chain.anchors[branch.epoch-1];if(branch.history.length<a.count||!same(pin(branch.history.slice(0,a.count)),a))fail('INDEX_ROTATION_EPOCH_ANCHOR_MISMATCH');}
  checked.push({epoch:branch.epoch,history:branch.history,head:v.head,signers:v.signerIds});
 }
 let conflict=null;
 for(let i=0;i<checked.length;i++)for(let j=i+1;j<checked.length;j++){
  const a=checked[i],b=checked[j];
  for(let k=0;k<Math.min(a.history.length,b.history.length);k++)if(a.history[k].digest!==b.history[k].digest){
   const found={branchA:i,branchB:j,epochA:a.epoch,epochB:b.epoch,firstConflictingIndex:k+1};
   if(!conflict||found.firstConflictingIndex<conflict.firstConflictingIndex)conflict=found;
   break;
  }
 }
 return Object.freeze({classification:conflict?'CROSS_EPOCH_SIGNED_FORK_EVIDENCE':'CONSISTENT_SIGNED_PREFIXES_ONLY',conflict,verifiedEpochs:chain.epoch+1,reviewedBranches:checked.length,readOnly:true,mayRetry:false,mayAcknowledge:false,productionApproved:false,signaturesOfSessionsVerified:false});
}
