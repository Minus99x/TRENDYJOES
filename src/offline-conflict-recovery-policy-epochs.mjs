/**
 * Objective 32P: OFFLINE, read-only, independently pinned recovery reviewer
 * policy-epoch history. This verifies majority authorization by BOTH old and
 * new independent Ed25519 rosters at an exact recovery-receipt head, and
 * validates every supplied receipt link between policy transitions.
 *
 * This does NOT rotate the policy used by the live journal, publish a pin,
 * verify the original recovery decision signatures from receipt digests,
 * resolve uncertain commits, or authorize Shopify/production activity.
 */
import {createHash,createPublicKey,KeyObject,verify as verifySignature} from 'node:crypto';
import {offlineConflictExchangeRecoveryReviewerPolicyDigest} from './offline-conflict-exchange-recovery.mjs';
import {offlineConflictRecoveryReceiptGenesisHead} from './offline-conflict-exchange-recovery-receipts.mjs';

export const OFFLINE_CONFLICT_RECOVERY_POLICY_EPOCH_SCHEMA='TJ-OFFLINE-CONFLICT-RECOVERY-POLICY-EPOCH-1';
const HEX=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9_-]{8,80}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const sha=b=>createHash('sha256').update(b).digest('hex');
const hash=(domain,body)=>sha(Buffer.from(domain+'\0'+JSON.stringify(body)));
const object=o=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&[Object.prototype,null].includes(Object.getPrototypeOf(o));
const exact=(o,fields)=>object(o)&&Object.keys(o).length===fields.length&&fields.every(k=>
 Object.prototype.hasOwnProperty.call(o,k)&&Object.getOwnPropertyDescriptor(o,k)?.enumerable&&Object.getOwnPropertyDescriptor(o,k)?.value!==undefined)&&Object.keys(o).every(k=>fields.includes(k));
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=4096&&HEX.test(h.headDigest);
const same=(a,b)=>a.count===b.count&&a.headDigest===b.headDigest;
const fields=['schema','sequence','previousTransitionDigest','genesisExchangeDigest','fromPolicyDigest','toPolicyDigest',
 'receiptHead','issuedAt','expiresAt','nonce'];
const signatureFields=['reviewerId','signature'];

export function offlineConflictRecoveryPolicyEpochGenesisDigest({genesisExchangeDigest,initialPolicyDigest}={}){
 if(!HEX.test(genesisExchangeDigest||'')||!HEX.test(initialPolicyDigest||''))fail('EXCHANGE32P_GENESIS_INVALID');
 return hash('TJ-32P-POLICY-EPOCH-GENESIS',{genesisExchangeDigest,initialPolicyDigest,
  receiptHead:offlineConflictRecoveryReceiptGenesisHead(genesisExchangeDigest)});
}
export function offlineConflictRecoveryPolicyTransitionBytes(body){
 if(!exact(body,fields)||body.schema!==OFFLINE_CONFLICT_RECOVERY_POLICY_EPOCH_SCHEMA||
 !Number.isSafeInteger(body.sequence)||body.sequence<1||body.sequence>64||
 ![body.previousTransitionDigest,body.genesisExchangeDigest,body.fromPolicyDigest,body.toPolicyDigest].every(x=>HEX.test(x||''))||
 body.fromPolicyDigest===body.toPolicyDigest||!head(body.receiptHead)||
 !Number.isSafeInteger(body.issuedAt)||body.issuedAt<0||!Number.isSafeInteger(body.expiresAt)||
 body.expiresAt<=body.issuedAt||body.expiresAt-body.issuedAt>3600000||!ID.test(body.nonce||''))
 fail('EXCHANGE32P_TRANSITION_INVALID');
 return Buffer.from('TJ-32P-POLICY-TRANSITION\0'+JSON.stringify(body));
}
export function offlineConflictRecoveryPolicyTransitionDigest({transition}={}){
 if(!exact(transition,['body','outgoingSignatures','incomingSignatures'])||
 !Array.isArray(transition.outgoingSignatures)||!Array.isArray(transition.incomingSignatures))
 fail('EXCHANGE32P_TRANSITION_INVALID');
 offlineConflictRecoveryPolicyTransitionBytes(transition.body);
 return hash('TJ-32P-POLICY-TRANSITION-DIGEST',transition);
}
function policyKeys(policy){
 const digest=offlineConflictExchangeRecoveryReviewerPolicyDigest(policy);
 const keys=new Map(),fingerprints=new Set();
 for(const reviewer of policy){
  const key=reviewer.publicKey instanceof KeyObject&&reviewer.publicKey.type==='public'?reviewer.publicKey:createPublicKey(reviewer.publicKey);
  const fingerprint=sha(key.export({format:'der',type:'spki'}));
  keys.set(reviewer.reviewerId,key);fingerprints.add(fingerprint);
 }
 return {digest,keys,fingerprints,ids:new Set(keys.keys())};
}
function checkQuorum(signatures,policy,bytes){
 if(!Array.isArray(signatures)||signatures.length<Math.floor(policy.keys.size/2)+1||
 signatures.length>policy.keys.size)fail('EXCHANGE32P_QUORUM_REQUIRED');
 let previous='';
 for(const s of signatures){
  if(!exact(s,signatureFields)||!ID.test(s.reviewerId||'')||s.reviewerId<=previous||
   !policy.keys.has(s.reviewerId)||typeof s.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(s.signature))
   fail('EXCHANGE32P_SIGNATURE_INVALID');
  const raw=Buffer.from(s.signature,'base64url');
  if(raw.length!==64||raw.toString('base64url')!==s.signature||
   !verifySignature(null,bytes,policy.keys.get(s.reviewerId),raw))fail('EXCHANGE32P_SIGNATURE_INVALID');
  previous=s.reviewerId;
 }
}
const receiptFields=['schema','index','previousReceiptDigest','decisionDigest','reviewerPolicyDigest','nonce','action',
 'genesisExchangeDigest','preHead','postHead','pendingRecordDigest','pendingBytesDigest','attemptAt','receiptDigest'];
const receiptBody=receiptFields.filter(k=>k!=='receiptDigest');
function verifyReceipt(record,prior,genesis,nonces,pending){
 if(!exact(record,receiptFields)||record.schema!=='TJ-OFFLINE-CONFLICT-RECOVERY-ATTEMPT-1'||
 record.index!==prior.count+1||record.previousReceiptDigest!==prior.headDigest||
 record.genesisExchangeDigest!==genesis||
 ![record.decisionDigest,record.reviewerPolicyDigest,record.pendingRecordDigest,record.pendingBytesDigest,record.receiptDigest].every(x=>HEX.test(x||''))||
 !ID.test(record.nonce||'')||!['abort','finalize'].includes(record.action)||
 !head(record.preHead)||!head(record.postHead)||record.postHead.count!==record.preHead.count+1||
 record.postHead.headDigest!==record.pendingRecordDigest||!Number.isSafeInteger(record.attemptAt)||record.attemptAt<0||
 nonces.has(record.nonce)||pending.has(record.pendingBytesDigest))fail('EXCHANGE32P_RECEIPT_INVALID');
 const body=Object.fromEntries(receiptBody.map(k=>[k,record[k]]));
 if(hash('TJ-32O-RECEIPT',body)!==record.receiptDigest)fail('EXCHANGE32P_RECEIPT_INVALID');
 nonces.add(record.nonce);pending.add(record.pendingBytesDigest);
 return {count:record.index,headDigest:record.receiptDigest};
}
/**
 * segments[i] are the actual canonical 32O receipt records after epoch i's
 * policy starts and before transition i; the final segment follows the last
 * transition. Receipt policy digests MUST equal the active epoch policy.
 * Every supplied record is checked; independently supplied terminal pins
 * detect omissions, substitutions and historical rollback.
 */
export function verifyOfflineConflictRecoveryPolicyEpochHistory({genesisExchangeDigest,reviewerPolicies,
 transitions,segments,expectedTransitionHead,expectedFinalReceiptHead,expectedFinalPolicyDigest,nowMs}={}){
 if(!HEX.test(genesisExchangeDigest||'')||!Array.isArray(transitions)||transitions.length>64||
 !Array.isArray(reviewerPolicies)||reviewerPolicies.length!==transitions.length+1||
 !Array.isArray(segments)||segments.length!==reviewerPolicies.length||
 !head(expectedFinalReceiptHead)||!exact(expectedTransitionHead,['count','headDigest'])||
 !Number.isSafeInteger(expectedTransitionHead.count)||expectedTransitionHead.count<0||expectedTransitionHead.count>64||
 !HEX.test(expectedTransitionHead.headDigest)||!HEX.test(expectedFinalPolicyDigest||'')||
 !Number.isSafeInteger(nowMs)||nowMs<0)fail('EXCHANGE32P_EXTERNAL_PINS_REQUIRED');
 const policies=reviewerPolicies.map(policyKeys);
 const genesis=offlineConflictRecoveryReceiptGenesisHead(genesisExchangeDigest);
 let current={...genesis},transitionDigest=offlineConflictRecoveryPolicyEpochGenesisDigest({genesisExchangeDigest,initialPolicyDigest:policies[0].digest});
 let lastTime=-1,lastReceiptAt=-1;const nonces=new Set(),pending=new Set(),transitionNonces=new Set();
 for(let i=0;i<segments.length;i++){
  const records=segments[i];
  if(!Array.isArray(records)||records.length>4096-current.count)fail('EXCHANGE32P_RECEIPT_INVALID');
  for(const record of records){
   if(record?.reviewerPolicyDigest!==policies[i].digest)fail('EXCHANGE32P_RECEIPT_POLICY_MISMATCH');
   if(record.attemptAt<lastTime||record.attemptAt<lastReceiptAt||record.attemptAt>nowMs)fail('EXCHANGE32P_RECEIPT_TIME_ROLLBACK');
   lastReceiptAt=record.attemptAt;
   current=verifyReceipt(record,current,genesisExchangeDigest,nonces,pending);
  }
  if(i===transitions.length)break;
  const transition=transitions[i];
  if(!exact(transition,['body','outgoingSignatures','incomingSignatures']))fail('EXCHANGE32P_TRANSITION_INVALID');
  const bytes=offlineConflictRecoveryPolicyTransitionBytes(transition.body),b=transition.body;
  if(b.sequence!==i+1||b.genesisExchangeDigest!==genesisExchangeDigest||
   b.previousTransitionDigest!==transitionDigest||b.fromPolicyDigest!==policies[i].digest||
   b.toPolicyDigest!==policies[i+1].digest||!same(b.receiptHead,current)||
   b.issuedAt<=lastTime||b.issuedAt<lastReceiptAt||b.issuedAt>nowMs||transitionNonces.has(b.nonce))
   fail('EXCHANGE32P_EPOCH_FORK_OR_ROLLBACK');
  // Require fully disjoint rosters to prevent old compromised keys retaining
  // authority over the successor. Both majorities must independently consent.
  if([...policies[i].ids].some(id=>policies[i+1].ids.has(id))||
   [...policies[i].fingerprints].some(pin=>policies[i+1].fingerprints.has(pin)))
   fail('EXCHANGE32P_RETIRED_KEY_REUSE');
  checkQuorum(transition.outgoingSignatures,policies[i],bytes);
  checkQuorum(transition.incomingSignatures,policies[i+1],bytes);
  transitionDigest=offlineConflictRecoveryPolicyTransitionDigest({transition});
  transitionNonces.add(b.nonce);lastTime=b.issuedAt;
 }
 if(expectedTransitionHead.count!==transitions.length||expectedTransitionHead.headDigest!==transitionDigest||
 !same(current,expectedFinalReceiptHead)||expectedFinalPolicyDigest!==policies.at(-1).digest)
 fail('EXCHANGE32P_EXTERNAL_PIN_MISMATCH');
 return Object.freeze({transitionHead:Object.freeze({count:transitions.length,headDigest:transitionDigest}),
  receiptHead:Object.freeze({...current}),activeReviewerPolicyDigest:policies.at(-1).digest,
  verifiedTransitions:transitions.length,verifiedReceiptRecords:current.count,
  historicalVerificationOnly:true,localOnly:true,independentlyPublished:false,
  authorizesRecovery:false,productionApproved:false});
}
