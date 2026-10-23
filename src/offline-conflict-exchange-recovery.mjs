/**
 * Objective 32N: quorum-authorized offline adjudication of an interrupted 32M
 * exchange journal. Independent reviewer keys/head pins MUST come from outside
 * the journal. This is not a hosted identity service or offsite anchor.
 */
import {createHash,createPublicKey,KeyObject,verify as verifySignature} from 'node:crypto';
export const OFFLINE_CONFLICT_EXCHANGE_RECOVERY_SCHEMA='TJ-OFFLINE-CONFLICT-EXCHANGE-RECOVERY-1';
const HEX=/^[a-f0-9]{64}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const exact=(o,fields)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Object.keys(o).length===fields.length&&
 fields.every(k=>Object.getOwnPropertyDescriptor(o,k)?.value!==undefined&&Object.getOwnPropertyDescriptor(o,k)?.enumerable)&&
 Object.keys(o).every(k=>fields.includes(k));
const fields=['schema','action','genesisExchangeDigest','reviewerPolicyDigest','preHead','postHead','pendingRecordDigest',
 'pendingBytesDigest','issuedAt','expiresAt','nonce'];
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=4096&&HEX.test(h.headDigest);
const id=v=>typeof v==='string'&&/^[a-zA-Z0-9_-]{8,80}$/.test(v);
const sha=b=>createHash('sha256').update(b).digest('hex');
export function offlineConflictExchangeRecoveryReviewerPolicyDigest(reviewers){
 if(!Array.isArray(reviewers)||reviewers.length<3||reviewers.length>15)fail('EXCHANGE32N_POLICY_INVALID');
 const roster=[],seenIds=new Set(),seenKeys=new Set();
 for(const r of reviewers){
  if(!exact(r,['reviewerId','publicKey'])||!id(r.reviewerId)||seenIds.has(r.reviewerId))
   fail('EXCHANGE32N_POLICY_INVALID');
  let key;try{key=r.publicKey instanceof KeyObject&&r.publicKey.type==='public'?r.publicKey:createPublicKey(r.publicKey);}catch{fail('EXCHANGE32N_POLICY_INVALID');}
  if(key.asymmetricKeyType!=='ed25519')fail('EXCHANGE32N_POLICY_INVALID');
  const pin=sha(key.export({format:'der',type:'spki'}));
  if(seenKeys.has(pin))fail('EXCHANGE32N_POLICY_INVALID');
  seenIds.add(r.reviewerId);seenKeys.add(pin);roster.push({reviewerId:r.reviewerId,keyDigest:pin});
 }
 roster.sort((a,b)=>a.reviewerId.localeCompare(b.reviewerId));
 return sha(Buffer.from('TJ-32N-REVIEWER-POLICY\0'+JSON.stringify(roster)));
}
export function offlineConflictExchangeRecoveryDecisionBytes(body){
 if(!exact(body,fields)||body.schema!==OFFLINE_CONFLICT_EXCHANGE_RECOVERY_SCHEMA||
 !['abort','finalize'].includes(body.action)||!HEX.test(body.genesisExchangeDigest)||!HEX.test(body.reviewerPolicyDigest)||
 !head(body.preHead)||!head(body.postHead)||body.postHead.count!==body.preHead.count+1||
 body.postHead.headDigest!==body.pendingRecordDigest||!HEX.test(body.pendingBytesDigest)||
 !Number.isSafeInteger(body.issuedAt)||!Number.isSafeInteger(body.expiresAt)||
 body.issuedAt<0||body.expiresAt<=body.issuedAt||body.expiresAt-body.issuedAt>3600000||!id(body.nonce))
 fail('EXCHANGE32N_DECISION_INVALID');
 return Buffer.from('TJ-32N-RECOVERY-DECISION\0'+JSON.stringify(body));
}
export function verifyOfflineConflictExchangeRecoveryDecision({decision,reviewers,expectedReviewerPolicyDigest,nowMs}={}){
 if(!exact(decision,['body','signatures'])||!Array.isArray(decision.signatures)||
 !Array.isArray(reviewers)||reviewers.length<3||reviewers.length>15||
 !Number.isSafeInteger(nowMs)||nowMs<0||!HEX.test(expectedReviewerPolicyDigest||''))fail('EXCHANGE32N_POLICY_INVALID');
 const actualPolicyDigest=offlineConflictExchangeRecoveryReviewerPolicyDigest(reviewers);
 if(actualPolicyDigest!==expectedReviewerPolicyDigest)fail('EXCHANGE32N_POLICY_PIN_MISMATCH');
 const bytes=offlineConflictExchangeRecoveryDecisionBytes(decision.body);
 if(decision.body.reviewerPolicyDigest!==expectedReviewerPolicyDigest)fail('EXCHANGE32N_POLICY_PIN_MISMATCH');
 if(nowMs<decision.body.issuedAt||nowMs>decision.body.expiresAt)fail('EXCHANGE32N_DECISION_EXPIRED');
 const keys=new Map(),fingerprints=new Set();
 for(const r of reviewers){
  if(!exact(r,['reviewerId','publicKey'])||!id(r.reviewerId)||keys.has(r.reviewerId))
   fail('EXCHANGE32N_POLICY_INVALID');
  let key;try{key=r.publicKey instanceof KeyObject&&r.publicKey.type==='public'?r.publicKey:createPublicKey(r.publicKey);}catch{fail('EXCHANGE32N_POLICY_INVALID');}
  if(key.asymmetricKeyType!=='ed25519')fail('EXCHANGE32N_POLICY_INVALID');
  const pin=sha(key.export({format:'der',type:'spki'}));
  if(fingerprints.has(pin))fail('EXCHANGE32N_POLICY_INVALID');
  fingerprints.add(pin);keys.set(r.reviewerId,key);
 }
 const seen=new Set();let previous='';
 for(const sig of decision.signatures){
  if(!exact(sig,['reviewerId','signature'])||!id(sig.reviewerId)||
   sig.reviewerId<=previous||seen.has(sig.reviewerId)||!keys.has(sig.reviewerId)||
   typeof sig.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(sig.signature))
   fail('EXCHANGE32N_SIGNATURE_INVALID');
  const raw=Buffer.from(sig.signature,'base64url');
  if(raw.length!==64||raw.toString('base64url')!==sig.signature||
   !verifySignature(null,bytes,keys.get(sig.reviewerId),raw))fail('EXCHANGE32N_SIGNATURE_INVALID');
  seen.add(sig.reviewerId);previous=sig.reviewerId;
 }
 if(seen.size<Math.floor(reviewers.length/2)+1)fail('EXCHANGE32N_QUORUM_REQUIRED');
 return Object.freeze({...decision.body,reviewerCount:seen.size,requiredReviewers:Math.floor(reviewers.length/2)+1});
}
