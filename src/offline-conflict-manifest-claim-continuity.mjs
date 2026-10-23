/** Objective 32Z: offline, read-only continuity checks over independently pinned
 * 32Y transcripts. This is NOT an external anchor, clock, witness or recovery.
 */
import {createHash} from 'node:crypto';
import {verifyOfflineConflictManifestClaimTranscript} from './offline-conflict-manifest-claim-transcript.mjs';

export const OFFLINE_CONFLICT_MANIFEST_CLAIM_CONTINUITY_SCHEMA='TJ-OFFLINE-CONFLICT-MANIFEST-CLAIM-CONTINUITY-1';
export const OFFLINE_CONFLICT_MANIFEST_CLAIM_CONTINUITY_MAX_ENTRIES=64;
const HEX=/^[0-9a-f]{64}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hash=(domain,payload)=>createHash('sha256').update(domain+'\0').update(JSON.stringify(payload)).digest('hex');
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value' in d&&d.enumerable;})&&
 Object.keys(o).every(k=>keys.includes(k));
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&
 h.count<=OFFLINE_CONFLICT_MANIFEST_CLAIM_CONTINUITY_MAX_ENTRIES&&HEX.test(h.headDigest);
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const fields=['bytes','expectedTranscriptDigest','expectedSnapshotDigest','decision','reviewerGroupA',
 'reviewerGroupB','expectedDecisionDigest','expectedReviewerGroupADigest','expectedReviewerGroupBDigest',
 'expectedHead','expectedPendingBytesDigest'];
function evaluate(entries){
 if(!Array.isArray(entries)||Object.getPrototypeOf(entries)!==Array.prototype||
  entries.length<1||entries.length>OFFLINE_CONFLICT_MANIFEST_CLAIM_CONTINUITY_MAX_ENTRIES||
  Object.keys(entries).length!==entries.length)fail('EXCHANGE32Z_ENTRIES_INVALID');
 let root,anchor,previousAt=-1,previousState,previousHead,states=[],checkpoints=[],seenTranscripts=new Set(),seenDecisions=new Set();
 for(const entry of entries){
  if(!exact(entry,fields))fail('EXCHANGE32Z_ENTRY_INVALID');
  // The 32Y verifier rechecks every independent digest pin and both Ed25519 quorums.
  const verified=verifyOfflineConflictManifestClaimTranscript(entry);
  const b=JSON.parse(entry.bytes.toString('utf8')); // already canonical and authenticated by 32Y
  const claim={priorHead:b.priorHead,pendingIndex:b.pendingIndex,pendingRecordDigest:b.pendingRecordDigest,
   pendingBytesDigest:b.pendingBytesDigest,reviewerGroupADigest:b.reviewerGroupADigest,
   reviewerGroupBDigest:b.reviewerGroupBDigest};
  if(!anchor){
   anchor=claim;
   root=hash('TJ-32Z-CONTINUITY-GENESIS',{schema:OFFLINE_CONFLICT_MANIFEST_CLAIM_CONTINUITY_SCHEMA,claim});
  }else if(!same(anchor,claim))fail('EXCHANGE32Z_CLAIM_FORK');
  if(b.observedAt<=previousAt)fail('EXCHANGE32Z_TIME_ORDER');
  if(previousState==='linked-pending'&&b.observedState!=='linked-pending')fail('EXCHANGE32Z_STATE_ROLLBACK');
  if(seenTranscripts.has(verified.transcriptDigest)||seenDecisions.has(b.decisionDigest))
   fail('EXCHANGE32Z_REPLAY');
  if(previousHead){
   // Same pending claim may only retain its head or advance to its signed linked record.
   if(b.observedHead.count<previousHead.count||
    (b.observedHead.count===previousHead.count&&b.observedHead.headDigest!==previousHead.headDigest))
    fail('EXCHANGE32Z_HEAD_ROLLBACK');
  }
  seenTranscripts.add(verified.transcriptDigest);seenDecisions.add(b.decisionDigest);
  root=hash('TJ-32Z-CONTINUITY-STEP',{previousDigest:root,index:checkpoints.length+1,
   transcriptDigest:verified.transcriptDigest,snapshotDigest:verified.snapshotDigest,
   decisionDigest:b.decisionDigest,observedAt:b.observedAt,observedState:b.observedState,
   observedHead:b.observedHead});
  checkpoints.push(Object.freeze({count:checkpoints.length+1,headDigest:root}));
  states.push(b.observedState);previousAt=b.observedAt;previousState=b.observedState;previousHead=b.observedHead;
 }
 return {checkpoints,states,anchor,observedAt:previousAt};
}
/** Calculates a *candidate* local checkpoint; caller must preserve it elsewhere.
 * A candidate computed from the same untrusted input is not an independent pin. */
export function calculateOfflineConflictManifestClaimContinuity({entries}={}){
 const r=evaluate(entries);return Object.freeze({schema:OFFLINE_CONFLICT_MANIFEST_CLAIM_CONTINUITY_SCHEMA,
  head:r.checkpoints.at(-1),anchor:Object.freeze({...r.anchor}),lastObservedState:r.states.at(-1),
  independentlyWitnessed:false,authorizesRepair:false,authorizesProduction:false});
}
/** The expected final checkpoint MUST be independently retained. Optional
 * previous checkpoint requires an exact matching prefix, not just a digest. */
export function verifyOfflineConflictManifestClaimContinuity({entries,expectedHead,expectedPreviousHead}={}){
 if(!head(expectedHead)||(expectedPreviousHead!==undefined&&(!head(expectedPreviousHead)||
  expectedPreviousHead.count<1||expectedPreviousHead.count>=expectedHead.count)))
  fail('EXCHANGE32Z_EXTERNAL_CHECKPOINT_REQUIRED');
 const r=evaluate(entries),last=r.checkpoints.at(-1);
 if(!same(last,expectedHead))fail('EXCHANGE32Z_CHECKPOINT_MISMATCH');
 if(expectedPreviousHead!==undefined&&
  !same(r.checkpoints[expectedPreviousHead.count-1],expectedPreviousHead))
  fail('EXCHANGE32Z_PREFIX_MISMATCH');
 return Object.freeze({verified:true,readOnly:true,schema:OFFLINE_CONFLICT_MANIFEST_CLAIM_CONTINUITY_SCHEMA,
  head:Object.freeze({...last}),previousCheckpointVerified:expectedPreviousHead!==undefined,
  claim:Object.freeze({...r.anchor}),lastObservedState:r.states.at(-1),
  requiresIndependentResolution:true,independentlyWitnessed:false,
  authorizesRepair:false,authorizesProduction:false,authorizesCheckout:false});
}
