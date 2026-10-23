/**
 * Objective 32S: portable, READ-ONLY cryptographic audit of a 32R cutover
 * resolution ATTEMPT. The proof is not evidence that pending unlink completed.
 * Pins MUST be obtained independently of the supplied proof. No disk writes.
 */
import {createHash} from 'node:crypto';
import {verifyOfflineConflictRecoveryPolicyEpochHistory} from './offline-conflict-recovery-policy-epochs.mjs';
import {offlineConflictRecoveryCutoverDigest,OFFLINE_CONFLICT_RECOVERY_CUTOVER_SCHEMA} from './offline-conflict-recovery-policy-cutover.mjs';
import {offlineConflictCutoverAdjudicationDigest,verifyOfflineConflictCutoverAdjudication} from './offline-conflict-recovery-cutover-adjudication.mjs';

export const OFFLINE_CONFLICT_CUTOVER_RESOLUTION_PROOF_SCHEMA='TJ-OFFLINE-CONFLICT-CUTOVER-RESOLUTION-PROOF-1';
const HEX=/^[0-9a-f]{64}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Object.keys(o).length===keys.length&&
 keys.every(k=>Object.getOwnPropertyDescriptor(o,k)?.value!==undefined&&Object.getOwnPropertyDescriptor(o,k)?.enumerable)&&
 Object.keys(o).every(k=>keys.includes(k));
const sha=b=>createHash('sha256').update(b).digest('hex');
const hash=(domain,b)=>sha(Buffer.concat([Buffer.from(domain+'\0'),Buffer.from(b)]));
const head=(a,b)=>a?.count===b?.count&&a?.headDigest===b?.headDigest;
const receiptKeys=['schema','action','genesisExchangeDigest','cutoverDigest','pendingBytesDigest','decisionDigest','resolvedAt','receiptDigest'];
const cutoverKeys=['schema','genesisExchangeDigest','previousPolicyDigest','activePolicyDigest','transitionHead','receiptHead','activatedAt','cutoverDigest'];
const proofKeys=['schema','history','cutoverMarker','pendingMarkerBase64url','decision','resolutionReceipt'];
const pinKeys=['proofDigest','decisionDigest','resolutionDigest','cutoverDigest','pendingBytesDigest',
 'genesisExchangeDigest','transitionHead','receiptHead','finalPolicyDigest','exchangeJournalHead'];

export function offlineConflictCutoverResolutionProofDigest(proof){
 if(!exact(proof,proofKeys)||proof.schema!==OFFLINE_CONFLICT_CUTOVER_RESOLUTION_PROOF_SCHEMA)
  fail('EXCHANGE32S_PROOF_INVALID');
 const raw=JSON.stringify(proof);
 if(typeof raw!=='string'||Buffer.byteLength(raw)>131072)fail('EXCHANGE32S_PROOF_INVALID');
 return hash('TJ-32S-CUTOVER-RESOLUTION-PROOF',raw);
}
/** Verification is retrospective: validate the decision at receipt.resolvedAt,
 * not at audit time, and reject any receipt claiming a time after audit time. */
export function verifyOfflineConflictCutoverResolutionProof({proof,pins,nowMs}={}){
 if(!exact(pins,pinKeys)||!pinKeys.slice(0,6).every(k=>HEX.test(pins[k]||''))||
 !HEX.test(pins.finalPolicyDigest||'')||
 ![pins.transitionHead,pins.receiptHead,pins.exchangeJournalHead].every(h=>
  exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&HEX.test(h.headDigest))||
 !Number.isSafeInteger(nowMs)||nowMs<0)fail('EXCHANGE32S_EXTERNAL_PINS_REQUIRED');
 if(offlineConflictCutoverResolutionProofDigest(proof)!==pins.proofDigest)
  fail('EXCHANGE32S_PROOF_PIN_MISMATCH');
 const {history,cutoverMarker,decision,resolutionReceipt:r,pendingMarkerBase64url:encoded}=proof;
 if(!history||!exact(cutoverMarker,cutoverKeys)||!exact(r,receiptKeys)||
 typeof encoded!=='string'||encoded.length<4||encoded.length>2800||
 !/^[A-Za-z0-9_-]+$/.test(encoded))fail('EXCHANGE32S_PROOF_INVALID');
 const pending=Buffer.from(encoded,'base64url');
 if(pending.length<2||pending.length>2048||pending.toString('base64url')!==encoded||
 sha(pending)!==pins.pendingBytesDigest)fail('EXCHANGE32S_PENDING_PIN_MISMATCH');
 if(!Buffer.from(JSON.stringify(cutoverMarker)).equals(pending))fail('EXCHANGE32S_PENDING_INVALID');
 if(cutoverMarker.schema!==OFFLINE_CONFLICT_RECOVERY_CUTOVER_SCHEMA||
 cutoverMarker.genesisExchangeDigest!==pins.genesisExchangeDigest||
 cutoverMarker.cutoverDigest!==pins.cutoverDigest||
 offlineConflictRecoveryCutoverDigest(Object.fromEntries(cutoverKeys.slice(0,-1).map(k=>[k,cutoverMarker[k]])))!==pins.cutoverDigest)
 fail('EXCHANGE32S_CUTOVER_INVALID');
 if(!exact(history,['genesisExchangeDigest','reviewerPolicies','transitions','segments','expectedTransitionHead',
 'expectedFinalReceiptHead','expectedFinalPolicyDigest','nowMs'])||
 history.genesisExchangeDigest!==pins.genesisExchangeDigest||
 !head(history.expectedTransitionHead,pins.transitionHead)||
 !head(history.expectedFinalReceiptHead,pins.receiptHead)||
 history.expectedFinalPolicyDigest!==pins.finalPolicyDigest||
 !Number.isSafeInteger(history.nowMs)||history.nowMs!==cutoverMarker.activatedAt||
 history.nowMs>nowMs)fail('EXCHANGE32S_HISTORY_PIN_MISMATCH');
 const verified=verifyOfflineConflictRecoveryPolicyEpochHistory({...history,nowMs});
 if(history.transitions.length!==1||history.reviewerPolicies.length!==2||
 history.segments.length!==2||history.segments[1].length!==0||
 !head(cutoverMarker.transitionHead,pins.transitionHead)||
 !head(cutoverMarker.receiptHead,pins.receiptHead)||
 cutoverMarker.activePolicyDigest!==pins.finalPolicyDigest||
 cutoverMarker.previousPolicyDigest!==history.transitions[0].body.fromPolicyDigest||
 cutoverMarker.activePolicyDigest!==verified.activeReviewerPolicyDigest)
 fail('EXCHANGE32S_HISTORY_CUTOVER_MISMATCH');
 if(offlineConflictCutoverAdjudicationDigest(decision)!==pins.decisionDigest)
 fail('EXCHANGE32S_DECISION_PIN_MISMATCH');
 if(r.schema!=='TJ-OFFLINE-CONFLICT-CUTOVER-RESOLUTION-1'||
 !['abort','finalize'].includes(r.action)||
 ![r.genesisExchangeDigest,r.cutoverDigest,r.pendingBytesDigest,r.decisionDigest,r.receiptDigest].every(x=>HEX.test(x||''))||
 !Number.isSafeInteger(r.resolvedAt)||r.resolvedAt<cutoverMarker.activatedAt||r.resolvedAt>nowMs||
 r.receiptDigest!==pins.resolutionDigest||
 hash('TJ-32R-RESOLUTION-RECEIPT',JSON.stringify(Object.fromEntries(receiptKeys.slice(0,-1).map(k=>[k,r[k]]))))!==r.receiptDigest)
 fail('EXCHANGE32S_RESOLUTION_INVALID');
 const approved=verifyOfflineConflictCutoverAdjudication({decision,
  previousReviewers:history.reviewerPolicies[0],activeReviewers:history.reviewerPolicies[1],
  expectedDecisionDigest:pins.decisionDigest,expectedCutoverDigest:pins.cutoverDigest,
  expectedGenesisExchangeDigest:pins.genesisExchangeDigest,nowMs:r.resolvedAt});
 if(r.action!==approved.action||r.genesisExchangeDigest!==pins.genesisExchangeDigest||
 r.cutoverDigest!==pins.cutoverDigest||r.pendingBytesDigest!==pins.pendingBytesDigest||
 r.decisionDigest!==pins.decisionDigest||
 !head(approved.exchangeJournalHead,pins.exchangeJournalHead)||
 !head(approved.receiptHead,pins.receiptHead)||
 approved.previousPolicyDigest!==cutoverMarker.previousPolicyDigest||
 approved.activePolicyDigest!==cutoverMarker.activePolicyDigest||
 approved.pendingBytesDigest!==pins.pendingBytesDigest)
 fail('EXCHANGE32S_EVIDENCE_CONFLICT');
 return Object.freeze({proofDigest:pins.proofDigest,decisionDigest:pins.decisionDigest,
  resolutionDigest:pins.resolutionDigest,cutoverDigest:pins.cutoverDigest,
  signedQuorumsVerified:true,policyTransitionVerified:true,receiptAttemptVerified:true,
  localCompletionVerified:false,externalPublicationVerified:false,authorizesProduction:false,
  status:'authenticated-attempt-only',action:r.action});
}
