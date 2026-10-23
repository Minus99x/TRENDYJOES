/**
 * Objective 31Q — portable, independent evidence verification for 31P signed
 * cross-epoch acquisition histories. This is forensic review, not authority.
 * All policy keys, retention/forensic trust, pins and time are caller supplied.
 * Session journal hashes are NOT signatures: their integrity is authenticated
 * only by their inclusion in a quorum-attested acquisition index head.
 */
import {createHash} from 'node:crypto';
import {OFFLINE_ACQUISITION_SESSION_SCHEMA} from './offline-acquisition-session-journal.mjs';
import {verifyOfflineForensicAcquisitionManifest} from './offline-forensic-acquisition-provenance.mjs';
import {reviewOfflineAcquisitionCrossEpochBranches} from './offline-acquisition-witness-rotation.mjs';
import {recoveryReviewKeyDigest} from './offline-recovery-adjudication.mjs';

const ROOT='0'.repeat(64),HEX=/^[0-9a-f]{64}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>obj(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const sha=b=>createHash('sha256').update(b).digest('hex');
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=2000&&HEX.test(h.headDigest)&&(h.count===0)===(h.headDigest===ROOT);
const hashSession=b=>sha(Buffer.from(`${OFFLINE_ACQUISITION_SESSION_SCHEMA}\0${JSON.stringify(b)}`));
const hashManifest=m=>sha(Buffer.from(`TJ-OFFLINE-ACQUISITION-MANIFEST-SNAPSHOT-1\0${JSON.stringify(m)}`));

function verifySession(events,payload,manifest){
 if(!Array.isArray(events)||events.length!==3||!head(payload.sessionHead)||payload.sessionHead.count!==3)fail('INDEX_AUTH_SESSION_INCOMPLETE');
 let previous=ROOT;
 for(let i=0;i<3;i++){
  const e=events[i];
  if(!exact(e,['schema','index','previousDigest','action','payload','digest'])||
   e.schema!==OFFLINE_ACQUISITION_SESSION_SCHEMA||e.index!==i+1||
   e.action!==['BEGIN','PRE','POST'][i]||e.previousDigest!==previous||!HEX.test(e.digest||''))fail('INDEX_AUTH_SESSION_INVALID');
  const {digest,...body}=e;
  if(hashSession(body)!==digest)fail('INDEX_AUTH_SESSION_INVALID');
  previous=digest;
 }
 if(previous!==payload.sessionHead.headDigest)fail('INDEX_AUTH_SESSION_PIN_MISMATCH');
 const begin=events[0].payload;
 if(!exact(begin,['acquisitionId','independentPins','priorRetentionHead'])||
  begin.acquisitionId!==payload.acquisitionId||!same(begin.independentPins,payload.forensicHeads)||
  !same(begin.priorRetentionHead,payload.previousRetentionHead)||
  !same(events[1].payload,manifest.receiptHistory.at(-2))||
  !same(events[2].payload,manifest))fail('INDEX_AUTH_SESSION_BINDING_INVALID');
}
function checkTrustSeparation(policies,retentionTrust,forensicTrust){
 const forensic=[...(forensicTrust?.witnesses??[]),...(forensicTrust?.reviewerPolicies??[]).flatMap(p=>p.reviewers??[])];
 const retention=retentionTrust?.retentionWitnesses;
 if(!Array.isArray(retention)||!Array.isArray(forensicTrust?.witnesses)||!Array.isArray(forensicTrust?.reviewerPolicies))fail('INDEX_AUTH_TRUST_REQUIRED');
 const occupied=new Set();
 try{
  for(const w of [...retention,...forensic])occupied.add(recoveryReviewKeyDigest(w.publicKey));
  for(const p of policies)for(const w of p.witnesses)if(occupied.has(recoveryReviewKeyDigest(w.publicKey)))fail('INDEX_AUTH_WITNESS_NOT_INDEPENDENT');
 }catch(e){if(e.code==='INDEX_AUTH_WITNESS_NOT_INDEPENDENT')throw e;fail('INDEX_AUTH_TRUST_INVALID');}
}
/**
 * branchEvidence[i][j] contains portable sessionEvents + manifest for the jth
 * record in branches[i].history. All evidence is mandatory, including common
 * prefixes: structural verification alone never produces an authenticated result.
 */
export function verifyOfflineAcquisitionCrossEpochAuthenticatedEvidence({
 policies,transitions,branches,branchEvidence,registryId,nowMs,trustedAnchor,
 expectedGenesisPolicyDigest,expectedFinalPolicyDigest,expectedFinalEpoch,
 forensicTrust,retentionTrust
}={}){
 const review=reviewOfflineAcquisitionCrossEpochBranches({policies,transitions,branches,registryId,nowMs,trustedAnchor,expectedGenesisPolicyDigest,expectedFinalPolicyDigest,expectedFinalEpoch});
 checkTrustSeparation(policies,retentionTrust,forensicTrust);
 if(!Array.isArray(branchEvidence)||branchEvidence.length!==branches.length)fail('INDEX_AUTH_EVIDENCE_INCOMPLETE');
 let verifiedRecords=0;
 for(let i=0;i<branches.length;i++){
  const history=branches[i].history,evidence=branchEvidence[i];
  if(!Array.isArray(evidence)||evidence.length!==history.length)fail('INDEX_AUTH_EVIDENCE_INCOMPLETE');
  for(let j=0;j<history.length;j++){
   const p=history[j].payload,proof=evidence[j];
   if(!exact(proof,['manifest','sessionEvents']))fail('INDEX_AUTH_EVIDENCE_INVALID');
   const m=proof.manifest;
   if(!obj(m)||m.acquisitionId!==p.acquisitionId||hashManifest(m)!==p.manifestDigest||
    !Array.isArray(m.receiptHistory)||m.receiptHistory.length!==p.retentionHead.count||
    m.receiptHistory.at(-2)?.previousDigest!==p.previousRetentionHead.headDigest)fail('INDEX_AUTH_MANIFEST_BINDING_INVALID');
   // Verify the actual forensic bundle and each independent retention signature.
   const result=verifyOfflineForensicAcquisitionManifest({manifest:m,independentPins:p.forensicHeads,
    independentRetentionHead:p.retentionHead,forensicTrust,retentionTrust});
   if(!result.verified)fail('INDEX_AUTH_FORENSIC_UNVERIFIED');
   verifySession(proof.sessionEvents,p,m);
   verifiedRecords++;
  }
 }
 return Object.freeze({verified:true,classification:review.classification,conflict:review.conflict,
  reviewedBranches:review.reviewedBranches,verifiedEvidenceRecords:verifiedRecords,
  underlyingRetentionSignaturesVerified:true,underlyingForensicEvidenceVerified:true,
  sessionHashesBoundToSignedIndex:true,readOnly:true,mayRetry:false,mayAcknowledge:false,
  mayManufacture:false,productionApproved:false});
}
