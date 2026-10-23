/** Objective 32X: two independently pinned Ed25519 reviewer groups authorize
 * a READ-ONLY look at an interrupted 32W manifest claim. Not a repair permit.
 * This module has no filesystem, network, Shopify, or signing-key writes.
 */
import {createHash,createPublicKey,KeyObject,verify as verifySignature} from 'node:crypto';
import {offlineConflictExchangeRecoveryReviewerPolicyDigest} from './offline-conflict-exchange-recovery.mjs';
export const OFFLINE_CONFLICT_MANIFEST_CLAIM_ADJUDICATION_SCHEMA='TJ-OFFLINE-CONFLICT-MANIFEST-CLAIM-ADJUDICATION-1';
const HEX=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9_-]{8,80}$/;
const fields=['schema','action','journalHead','pendingBytesDigest','pendingRecordDigest',
 'pendingIndex','expectedPendingState','reviewerGroupADigest','reviewerGroupBDigest',
 'issuedAt','expiresAt','nonce'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value' in d&&d.enumerable;})&&
 Object.keys(o).every(k=>keys.includes(k));
const sha=x=>createHash('sha256').update(x).digest('hex');
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=4096&&HEX.test(h.headDigest);
export function offlineConflictManifestClaimDecisionBytes(body){
 if(!exact(body,fields)||body.schema!==OFFLINE_CONFLICT_MANIFEST_CLAIM_ADJUDICATION_SCHEMA||
  body.action!=='inspect-only'||!head(body.journalHead)||
  ![body.pendingBytesDigest,body.pendingRecordDigest,body.reviewerGroupADigest,body.reviewerGroupBDigest].every(x=>HEX.test(x||''))||
  body.reviewerGroupADigest===body.reviewerGroupBDigest||
  !Number.isSafeInteger(body.pendingIndex)||body.pendingIndex!==body.journalHead.count+1||
  !['pending-only','linked-pending'].includes(body.expectedPendingState)||
  !Number.isSafeInteger(body.issuedAt)||body.issuedAt<0||
  !Number.isSafeInteger(body.expiresAt)||body.expiresAt<=body.issuedAt||
  body.expiresAt-body.issuedAt>3600000||!ID.test(body.nonce||''))fail('EXCHANGE32X_DECISION_INVALID');
 return Buffer.from('TJ-32X-MANIFEST-CLAIM-INSPECTION\0'+JSON.stringify(body));
}
export function offlineConflictManifestClaimDecisionDigest(decision){
 if(!exact(decision,['body','groupASignatures','groupBSignatures']))fail('EXCHANGE32X_DECISION_INVALID');
 offlineConflictManifestClaimDecisionBytes(decision.body);
 return sha(Buffer.from('TJ-32X-MANIFEST-CLAIM-DECISION\0'+JSON.stringify(decision)));
}
function verifyQuorum(signatures,roster,bytes){
 if(!Array.isArray(signatures)||Object.getPrototypeOf(signatures)!==Array.prototype||
  signatures.length<Math.floor(roster.length/2)+1||signatures.length>roster.length)
  fail('EXCHANGE32X_QUORUM_REQUIRED');
 const keys=new Map(roster.map(x=>[x.reviewerId,x.publicKey instanceof KeyObject?x.publicKey:createPublicKey(x.publicKey)]));
 let prev='';
 for(const sig of signatures){
  if(!exact(sig,['reviewerId','signature'])||!ID.test(sig.reviewerId||'')||
   sig.reviewerId<=prev||!keys.has(sig.reviewerId)||typeof sig.signature!=='string'||
   !/^[A-Za-z0-9_-]{86}$/.test(sig.signature))fail('EXCHANGE32X_SIGNATURE_INVALID');
  const raw=Buffer.from(sig.signature,'base64url');
  if(raw.length!==64||raw.toString('base64url')!==sig.signature||
   !verifySignature(null,bytes,keys.get(sig.reviewerId),raw))fail('EXCHANGE32X_SIGNATURE_INVALID');
  prev=sig.reviewerId;
 }
}
export function verifyOfflineConflictManifestClaimDecision({decision,reviewerGroupA,reviewerGroupB,
 expectedDecisionDigest,expectedReviewerGroupADigest,expectedReviewerGroupBDigest,
 expectedHead,expectedPendingBytesDigest,nowMs}={}){
 if(!exact(decision,['body','groupASignatures','groupBSignatures'])||
  ![expectedDecisionDigest,expectedReviewerGroupADigest,expectedReviewerGroupBDigest,expectedPendingBytesDigest].every(x=>HEX.test(x||''))||
  !head(expectedHead)||!Number.isSafeInteger(nowMs)||nowMs<0)
  fail('EXCHANGE32X_EXTERNAL_PINS_REQUIRED');
 const body=decision.body,bytes=offlineConflictManifestClaimDecisionBytes(body);
 if(offlineConflictExchangeRecoveryReviewerPolicyDigest(reviewerGroupA)!==expectedReviewerGroupADigest||
  offlineConflictExchangeRecoveryReviewerPolicyDigest(reviewerGroupB)!==expectedReviewerGroupBDigest||
  expectedReviewerGroupADigest===expectedReviewerGroupBDigest)
  fail('EXCHANGE32X_REVIEWER_PIN_MISMATCH');
 // Independent quorums cannot be satisfied by overlapping reviewer keys or IDs.
 const ids=new Set(reviewerGroupA.map(x=>x.reviewerId));
 const keys=new Set(reviewerGroupA.map(x=>sha((x.publicKey instanceof KeyObject?x.publicKey:createPublicKey(x.publicKey)).export({type:'spki',format:'der'}))));
 for(const r of reviewerGroupB){
  const k=r.publicKey instanceof KeyObject?r.publicKey:createPublicKey(r.publicKey);
  if(ids.has(r.reviewerId)||keys.has(sha(k.export({type:'spki',format:'der'}))))fail('EXCHANGE32X_REVIEWER_OVERLAP');
 }
 if(body.reviewerGroupADigest!==expectedReviewerGroupADigest||body.reviewerGroupBDigest!==expectedReviewerGroupBDigest||
  body.journalHead.count!==expectedHead.count||body.journalHead.headDigest!==expectedHead.headDigest||
  body.pendingBytesDigest!==expectedPendingBytesDigest||
  offlineConflictManifestClaimDecisionDigest(decision)!==expectedDecisionDigest)
  fail('EXCHANGE32X_EXTERNAL_PIN_MISMATCH');
 if(nowMs<body.issuedAt||nowMs>body.expiresAt)fail('EXCHANGE32X_DECISION_EXPIRED');
 verifyQuorum(decision.groupASignatures,reviewerGroupA,bytes);
 verifyQuorum(decision.groupBSignatures,reviewerGroupB,bytes);
 return Object.freeze({...body,decisionDigest:expectedDecisionDigest});
}
