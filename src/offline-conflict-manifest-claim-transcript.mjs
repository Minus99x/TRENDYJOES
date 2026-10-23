/** Objective 32Y: bounded canonical byte transcript of a 32X read-only inspection.
 * A transcript is a portable representation of locally inspected evidence, NOT
 * an independent witness, repair authorization, or durable recovery receipt.
 */
import {createHash} from 'node:crypto';
import {TextDecoder} from 'node:util';
import {verifyOfflineConflictManifestClaimDecision} from './offline-conflict-manifest-claim-adjudication.mjs';

export const OFFLINE_CONFLICT_MANIFEST_CLAIM_TRANSCRIPT_SCHEMA='TJ-OFFLINE-CONFLICT-MANIFEST-CLAIM-TRANSCRIPT-1';
export const OFFLINE_CONFLICT_MANIFEST_CLAIM_TRANSCRIPT_MAX_BYTES=4096;
const HEX=/^[0-9a-f]{64}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hash=(domain,bytes)=>createHash('sha256').update(domain+'\0').update(bytes).digest('hex');
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value' in d&&d.enumerable;})&&
 Object.keys(o).every(k=>keys.includes(k));
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=4096&&HEX.test(h.headDigest);
const snapshotFields=['priorHead','observedHead','pendingIndex','pendingRecordDigest','pendingBytesDigest','observedState','decisionDigest','observedAt'];
const transcriptFields=['schema','decisionDigest','reviewerGroupADigest','reviewerGroupBDigest',...snapshotFields.filter(x=>x!=='decisionDigest'),
 'snapshotDigest','requiresIndependentResolution','authorizesRepair','authorizesProduction','independentlyWitnessed'];
function snapshotValid(s){
 return exact(s,snapshotFields)&&head(s.priorHead)&&head(s.observedHead)&&
 Number.isSafeInteger(s.pendingIndex)&&s.pendingIndex===s.priorHead.count+1&&
 s.pendingIndex<=4096&&HEX.test(s.pendingRecordDigest)&&HEX.test(s.pendingBytesDigest)&&
 HEX.test(s.decisionDigest)&&['pending-only','linked-pending'].includes(s.observedState)&&
 Number.isSafeInteger(s.observedAt)&&s.observedAt>=0&&
 (s.observedState==='pending-only'?
  s.observedHead.count===s.priorHead.count&&s.observedHead.headDigest===s.priorHead.headDigest:
  s.observedHead.count===s.pendingIndex&&s.observedHead.headDigest===s.pendingRecordDigest);
}
export function offlineConflictManifestClaimSnapshotDigest(snapshot){
 if(!snapshotValid(snapshot))fail('EXCHANGE32Y_SNAPSHOT_INVALID');
 return hash('TJ-32Y-INSPECTION-SNAPSHOT',Buffer.from(JSON.stringify(Object.fromEntries(snapshotFields.map(k=>[k,snapshot[k]])))));
}
function bodyValid(b){
 if(!exact(b,transcriptFields)||b.schema!==OFFLINE_CONFLICT_MANIFEST_CLAIM_TRANSCRIPT_SCHEMA||
  !HEX.test(b.reviewerGroupADigest)||!HEX.test(b.reviewerGroupBDigest)||
  b.reviewerGroupADigest===b.reviewerGroupBDigest||!HEX.test(b.snapshotDigest)||
  b.requiresIndependentResolution!==true||b.authorizesRepair!==false||
  b.authorizesProduction!==false||b.independentlyWitnessed!==false)
  fail('EXCHANGE32Y_TRANSCRIPT_INVALID');
 const s=Object.fromEntries(snapshotFields.map(k=>[k,b[k]]));
 if(!snapshotValid(s)||offlineConflictManifestClaimSnapshotDigest(s)!==b.snapshotDigest)
  fail('EXCHANGE32Y_SNAPSHOT_INVALID');
 return s;
}
function canonicalBytes(b){
 bodyValid(b);
 const bytes=Buffer.from(JSON.stringify(Object.fromEntries(transcriptFields.map(k=>[k,b[k]]))),'utf8');
 if(bytes.length>OFFLINE_CONFLICT_MANIFEST_CLAIM_TRANSCRIPT_MAX_BYTES)
  fail('EXCHANGE32Y_TRANSCRIPT_TOO_LARGE');
 return bytes;
}
export function offlineConflictManifestClaimTranscriptDigest(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length===0||bytes.length>OFFLINE_CONFLICT_MANIFEST_CLAIM_TRANSCRIPT_MAX_BYTES)
  fail('EXCHANGE32Y_TRANSCRIPT_BYTES_INVALID');
 return hash('TJ-32Y-INSPECTION-TRANSCRIPT',bytes);
}
/** The journal invokes this only after its 32X locked read-only inspection. */
export function encodeOfflineConflictManifestClaimTranscript({inspection,decision,observedAt}={}){
 if(!inspection||inspection.verified!==true||inspection.readOnly!==true||
  inspection.requiresIndependentResolution!==true||inspection.authorizesRepair!==false||
  inspection.authorizesProduction!==false||inspection.independentlyWitnessed!==false||
  !Number.isSafeInteger(observedAt)||observedAt<0||!decision?.body)
  fail('EXCHANGE32Y_INSPECTION_REQUIRED');
 const s={priorHead:inspection.priorHead,
  observedHead:inspection.observedState==='linked-pending'?
   {count:inspection.pendingIndex,headDigest:inspection.pendingRecordDigest}:inspection.priorHead,
  pendingIndex:inspection.pendingIndex,pendingRecordDigest:inspection.pendingRecordDigest,
  pendingBytesDigest:inspection.pendingBytesDigest,observedState:inspection.observedState,
  decisionDigest:inspection.decisionDigest,observedAt};
 const snapshotDigest=offlineConflictManifestClaimSnapshotDigest(s);
 const b={schema:OFFLINE_CONFLICT_MANIFEST_CLAIM_TRANSCRIPT_SCHEMA,
  decisionDigest:s.decisionDigest,reviewerGroupADigest:decision.body.reviewerGroupADigest,
  reviewerGroupBDigest:decision.body.reviewerGroupBDigest,
  priorHead:s.priorHead,observedHead:s.observedHead,pendingIndex:s.pendingIndex,
  pendingRecordDigest:s.pendingRecordDigest,pendingBytesDigest:s.pendingBytesDigest,
  observedState:s.observedState,observedAt:s.observedAt,snapshotDigest,
  requiresIndependentResolution:true,authorizesRepair:false,authorizesProduction:false,
  independentlyWitnessed:false};
 if(decision.body.journalHead.count!==s.priorHead.count||
  decision.body.journalHead.headDigest!==s.priorHead.headDigest||
  decision.body.pendingIndex!==s.pendingIndex||
  decision.body.pendingRecordDigest!==s.pendingRecordDigest||
  decision.body.pendingBytesDigest!==s.pendingBytesDigest||
  decision.body.expectedPendingState!==s.observedState||
  observedAt<decision.body.issuedAt||observedAt>decision.body.expiresAt)
  fail('EXCHANGE32Y_DECISION_SNAPSHOT_MISMATCH');
 const bytes=canonicalBytes(b);
 return Object.freeze({bytes,transcriptDigest:offlineConflictManifestClaimTranscriptDigest(bytes),snapshotDigest});
}
/** Requires EXTERNALLY retained transcript and snapshot pins and re-verifies
 * the exact two-group Ed25519 authorization. Does not read any filesystem. */
export function verifyOfflineConflictManifestClaimTranscript({bytes,expectedTranscriptDigest,
 expectedSnapshotDigest,decision,reviewerGroupA,reviewerGroupB,expectedDecisionDigest,
 expectedReviewerGroupADigest,expectedReviewerGroupBDigest,expectedHead,
 expectedPendingBytesDigest}={}){
 if(![expectedTranscriptDigest,expectedSnapshotDigest,expectedDecisionDigest,
  expectedReviewerGroupADigest,expectedReviewerGroupBDigest,expectedPendingBytesDigest]
  .every(x=>typeof x==='string'&&HEX.test(x))||!head(expectedHead))
  fail('EXCHANGE32Y_EXTERNAL_PINS_REQUIRED');
 const digest=offlineConflictManifestClaimTranscriptDigest(bytes);
 if(digest!==expectedTranscriptDigest)fail('EXCHANGE32Y_TRANSCRIPT_PIN_MISMATCH');
 let b;
 try{b=JSON.parse(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes));}
 catch{fail('EXCHANGE32Y_TRANSCRIPT_INVALID');}
 const canonical=canonicalBytes(b);
 // Reject duplicate keys, noncanonical key order, BOM, whitespace, invalid UTF-8,
 // trailing bytes, and any JSON serialization ambiguity.
 if(!canonical.equals(bytes))fail('EXCHANGE32Y_NONCANONICAL_BYTES');
 const s=bodyValid(b);
 if(b.snapshotDigest!==expectedSnapshotDigest||b.decisionDigest!==expectedDecisionDigest||
  b.reviewerGroupADigest!==expectedReviewerGroupADigest||
  b.reviewerGroupBDigest!==expectedReviewerGroupBDigest||
  s.priorHead.count!==expectedHead.count||s.priorHead.headDigest!==expectedHead.headDigest||
  s.pendingBytesDigest!==expectedPendingBytesDigest)
  fail('EXCHANGE32Y_SNAPSHOT_PIN_MISMATCH');
 const authorization=verifyOfflineConflictManifestClaimDecision({decision,reviewerGroupA,reviewerGroupB,
  expectedDecisionDigest,expectedReviewerGroupADigest,expectedReviewerGroupBDigest,
  expectedHead,expectedPendingBytesDigest,nowMs:s.observedAt});
 if(authorization.pendingIndex!==s.pendingIndex||
  authorization.pendingRecordDigest!==s.pendingRecordDigest||
  authorization.expectedPendingState!==s.observedState)
  fail('EXCHANGE32Y_DECISION_SNAPSHOT_MISMATCH');
 return Object.freeze({verified:true,readOnly:true,transcriptDigest:digest,
  snapshotDigest:s.snapshotDigest,observedState:s.observedState,priorHead:Object.freeze({...s.priorHead}),
  observedHead:Object.freeze({...s.observedHead}),pendingIndex:s.pendingIndex,
  requiresIndependentResolution:true,authorizesRepair:false,authorizesProduction:false,
  independentlyWitnessed:false});
}
