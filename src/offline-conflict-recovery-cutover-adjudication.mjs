/** Objective 32R: offline dual-quorum authorization of interrupted cutover adjudication. */
import {createHash,createPublicKey,KeyObject,verify as verifySignature} from 'node:crypto';
import {offlineConflictExchangeRecoveryReviewerPolicyDigest} from './offline-conflict-exchange-recovery.mjs';
export const OFFLINE_CONFLICT_CUTOVER_ADJUDICATION_SCHEMA='TJ-OFFLINE-CONFLICT-CUTOVER-ADJUDICATION-1';
const HEX=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9_-]{8,80}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Object.keys(o).length===keys.length&&
 keys.every(k=>Object.getOwnPropertyDescriptor(o,k)?.value!==undefined&&Object.getOwnPropertyDescriptor(o,k)?.enumerable)&&
 Object.keys(o).every(k=>keys.includes(k));
const fields=['schema','action','genesisExchangeDigest','cutoverDigest','pendingBytesDigest','previousPolicyDigest',
 'activePolicyDigest','exchangeJournalHead','receiptHead','issuedAt','expiresAt','nonce'];
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=4096&&HEX.test(h.headDigest);
const sha=x=>createHash('sha256').update(x).digest('hex');
export function offlineConflictCutoverAdjudicationBytes(body){
 if(!exact(body,fields)||body.schema!==OFFLINE_CONFLICT_CUTOVER_ADJUDICATION_SCHEMA||
 !['abort','finalize'].includes(body.action)||
 ![body.genesisExchangeDigest,body.cutoverDigest,body.pendingBytesDigest,body.previousPolicyDigest,body.activePolicyDigest].every(x=>HEX.test(x||''))||
 body.previousPolicyDigest===body.activePolicyDigest||!head(body.exchangeJournalHead)||!head(body.receiptHead)||
 !Number.isSafeInteger(body.issuedAt)||body.issuedAt<0||!Number.isSafeInteger(body.expiresAt)||
 body.expiresAt<=body.issuedAt||body.expiresAt-body.issuedAt>3600000||!ID.test(body.nonce||''))
 fail('EXCHANGE32R_DECISION_INVALID');
 return Buffer.from('TJ-32R-CUTOVER-ADJUDICATION\0'+JSON.stringify(body));
}
export function offlineConflictCutoverAdjudicationDigest(decision){
 if(!exact(decision,['body','outgoingSignatures','incomingSignatures']))fail('EXCHANGE32R_DECISION_INVALID');
 offlineConflictCutoverAdjudicationBytes(decision.body);
 return sha(Buffer.from('TJ-32R-CUTOVER-DECISION-DIGEST\0'+JSON.stringify(decision)));
}
function quorum(signatures,roster,bytes){
 if(!Array.isArray(signatures)||signatures.length<Math.floor(roster.length/2)+1||signatures.length>roster.length)
 fail('EXCHANGE32R_QUORUM_REQUIRED');
 const keys=new Map(roster.map(x=>[x.reviewerId,x.publicKey instanceof KeyObject?x.publicKey:createPublicKey(x.publicKey)]));
 let previous='';for(const s of signatures){
  if(!exact(s,['reviewerId','signature'])||!ID.test(s.reviewerId||'')||s.reviewerId<=previous||
   !keys.has(s.reviewerId)||typeof s.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(s.signature))fail('EXCHANGE32R_SIGNATURE_INVALID');
  const raw=Buffer.from(s.signature,'base64url');
  if(raw.length!==64||raw.toString('base64url')!==s.signature||!verifySignature(null,bytes,keys.get(s.reviewerId),raw))fail('EXCHANGE32R_SIGNATURE_INVALID');
  previous=s.reviewerId;
 }
}
export function verifyOfflineConflictCutoverAdjudication({decision,previousReviewers,activeReviewers,
 expectedDecisionDigest,expectedCutoverDigest,expectedGenesisExchangeDigest,nowMs}={}){
 if(!exact(decision,['body','outgoingSignatures','incomingSignatures'])||!HEX.test(expectedDecisionDigest||'')||
 !HEX.test(expectedCutoverDigest||'')||!HEX.test(expectedGenesisExchangeDigest||'')||
 !Number.isSafeInteger(nowMs)||nowMs<0)fail('EXCHANGE32R_EXTERNAL_PINS_REQUIRED');
 const bytes=offlineConflictCutoverAdjudicationBytes(decision.body),b=decision.body;
 if(b.genesisExchangeDigest!==expectedGenesisExchangeDigest||b.cutoverDigest!==expectedCutoverDigest||
 b.previousPolicyDigest!==offlineConflictExchangeRecoveryReviewerPolicyDigest(previousReviewers)||
 b.activePolicyDigest!==offlineConflictExchangeRecoveryReviewerPolicyDigest(activeReviewers)||
 offlineConflictCutoverAdjudicationDigest(decision)!==expectedDecisionDigest)fail('EXCHANGE32R_EXTERNAL_PIN_MISMATCH');
 if(nowMs<b.issuedAt||nowMs>b.expiresAt)fail('EXCHANGE32R_DECISION_EXPIRED');
 quorum(decision.outgoingSignatures,previousReviewers,bytes);
 quorum(decision.incomingSignatures,activeReviewers,bytes);
 return Object.freeze({...b,decisionDigest:expectedDecisionDigest});
}
