/** Objective 33C: independently pinned, dual-quorum authority policy rotation.
 * Offline verification only. External custody of anchors, trusted time, and
 * globally consistent epoch/transition heads remain the caller's responsibility.
 */
import {createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
import {offlineConflictNamespaceAuthorityPolicyDigest,
 verifyOfflineConflictSignedNamespaceRoster} from './offline-conflict-signed-namespace-roster.mjs';

export const OFFLINE_CONFLICT_AUTHORITY_ROTATION_SCHEMA='TJ-OFFLINE-CONFLICT-AUTHORITY-ROTATION-1';
const HEX=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9_-]{8,64}$/;
const SIG=/^[A-Za-z0-9_-]{86}$/;
const fields=['schema','namespaceId','journalScopeDigest','fromEpoch','toEpoch',
 'predecessorAuthorityPolicyDigest','successorAuthorityPolicyDigest',
 'predecessorCommitmentDigest','successorCommitmentDigest',
 'previousTransitionDigest','issuedAt','expiresAt','nonce'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hex=x=>typeof x==='string'&&HEX.test(x);
const id=x=>typeof x==='string'&&ID.test(x);
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value' in d&&d.enumerable;})&&
 Object.keys(o).every(k=>keys.includes(k));
const arr=(a,min,max)=>Array.isArray(a)&&Object.getPrototypeOf(a)===Array.prototype&&
 a.length>=min&&a.length<=max&&Reflect.ownKeys(a).length===a.length+1&&
 Array.from({length:a.length},(_,i)=>Object.getOwnPropertyDescriptor(a,String(i)))
 .every(d=>d&&'value' in d&&d.enumerable);
const sha=x=>createHash('sha256').update(x).digest('hex');
function bodyValid(b){
 if(!exact(b,fields)||b.schema!==OFFLINE_CONFLICT_AUTHORITY_ROTATION_SCHEMA||
  !id(b.namespaceId)||!hex(b.journalScopeDigest)||
  !Number.isSafeInteger(b.fromEpoch)||b.fromEpoch<1||
  !Number.isSafeInteger(b.toEpoch)||b.toEpoch!==b.fromEpoch+1||
  !hex(b.predecessorAuthorityPolicyDigest)||!hex(b.successorAuthorityPolicyDigest)||
  b.predecessorAuthorityPolicyDigest===b.successorAuthorityPolicyDigest||
  !hex(b.predecessorCommitmentDigest)||!hex(b.successorCommitmentDigest)||
  b.predecessorCommitmentDigest===b.successorCommitmentDigest||
  !hex(b.previousTransitionDigest)||!Number.isSafeInteger(b.issuedAt)||b.issuedAt<0||
  !Number.isSafeInteger(b.expiresAt)||b.expiresAt<=b.issuedAt||
  b.expiresAt-b.issuedAt>3600000||!id(b.nonce))fail('EXCHANGE33C_BODY_INVALID');
}
export function offlineConflictAuthorityRotationBodyBytes(body){
 bodyValid(body);
 return Buffer.from('TJ-33C-AUTHORITY-ROTATION\0'+JSON.stringify(body),'utf8');
}
export function offlineConflictAuthorityRotationDigest(body){
 return sha(Buffer.concat([Buffer.from('TJ-33C-ROTATION-DIGEST\0'),offlineConflictAuthorityRotationBodyBytes(body)]));
}
function publicKeys(roster){
 if(!arr(roster,3,9))fail('EXCHANGE33C_AUTHORITY_ROSTER_INVALID');
 const keys=new Map();let prev='';const seen=new Set();
 for(const a of roster){
  if(!exact(a,['authorityId','publicKey'])||!id(a.authorityId)||a.authorityId<=prev||
   typeof a.publicKey!=='string'||a.publicKey.length>256||
   !/^[A-Za-z0-9_-]+$/.test(a.publicKey))fail('EXCHANGE33C_AUTHORITY_ROSTER_INVALID');
  const der=Buffer.from(a.publicKey,'base64url');
  if(der.toString('base64url')!==a.publicKey)fail('EXCHANGE33C_AUTHORITY_ROSTER_INVALID');
  let key;try{key=createPublicKey({key:der,format:'der',type:'spki'});}catch{fail('EXCHANGE33C_AUTHORITY_ROSTER_INVALID');}
  if(key.asymmetricKeyType!=='ed25519'||key.export({format:'der',type:'spki'}).toString('base64url')!==a.publicKey)
   fail('EXCHANGE33C_AUTHORITY_ROSTER_INVALID');
  const fingerprint=sha(der);
  if(seen.has(fingerprint))fail('EXCHANGE33C_DUPLICATE_AUTHORITY_KEY');
  seen.add(fingerprint);keys.set(a.authorityId,key);prev=a.authorityId;
 }
 return keys;
}
function verifyQuorum(sigs,keys,bytes,kind){
 const needed=Math.floor(keys.size/2)+1;
 if(!arr(sigs,needed,keys.size))fail('EXCHANGE33C_'+kind+'_QUORUM_REQUIRED');
 let prev='';
 for(const s of sigs){
  if(!exact(s,['authorityId','signature'])||!id(s.authorityId)||s.authorityId<=prev||
   !keys.has(s.authorityId)||typeof s.signature!=='string'||!SIG.test(s.signature))
   fail('EXCHANGE33C_'+kind+'_SIGNATURE_INVALID');
  const raw=Buffer.from(s.signature,'base64url');
  if(raw.length!==64||raw.toString('base64url')!==s.signature||
   !verifySignature(null,bytes,keys.get(s.authorityId),raw))
   fail('EXCHANGE33C_'+kind+'_SIGNATURE_INVALID');
  prev=s.authorityId;
 }
}
/** Requires caller-retained external pins for BOTH commitments and both policy
 * digests, scope/namespace/epoch, prior transition and THIS transition.
 * Re-verifies all underlying signed 33B/33A/32Z/32Y evidence; no shortcut.
 */
export function verifyOfflineConflictAuthorityPolicyRotation({transition,predecessor,successor,
 expectedNamespaceId,expectedJournalScopeDigest,expectedFromEpoch,
 expectedPredecessorAuthorityPolicyDigest,expectedSuccessorAuthorityPolicyDigest,
 expectedPredecessorCommitmentDigest,expectedSuccessorCommitmentDigest,
 expectedPreviousTransitionDigest,expectedTransitionDigest,nowMs}={}){
 if(!id(expectedNamespaceId)||!hex(expectedJournalScopeDigest)||
  !Number.isSafeInteger(expectedFromEpoch)||expectedFromEpoch<1||
  !hex(expectedPredecessorAuthorityPolicyDigest)||!hex(expectedSuccessorAuthorityPolicyDigest)||
  !hex(expectedPredecessorCommitmentDigest)||!hex(expectedSuccessorCommitmentDigest)||
  !hex(expectedPreviousTransitionDigest)||!hex(expectedTransitionDigest)||
  !Number.isSafeInteger(nowMs)||nowMs<0)
  fail('EXCHANGE33C_EXTERNAL_PINS_REQUIRED');
 if(!exact(transition,['body','predecessorSignatures','successorSignatures']))
  fail('EXCHANGE33C_TRANSITION_INVALID');
 const b=transition.body,bytes=offlineConflictAuthorityRotationBodyBytes(b);
 if(b.namespaceId!==expectedNamespaceId||b.journalScopeDigest!==expectedJournalScopeDigest||
  b.fromEpoch!==expectedFromEpoch||b.predecessorAuthorityPolicyDigest!==expectedPredecessorAuthorityPolicyDigest||
  b.successorAuthorityPolicyDigest!==expectedSuccessorAuthorityPolicyDigest||
  b.predecessorCommitmentDigest!==expectedPredecessorCommitmentDigest||
  b.successorCommitmentDigest!==expectedSuccessorCommitmentDigest||
  b.previousTransitionDigest!==expectedPreviousTransitionDigest||
  offlineConflictAuthorityRotationDigest(b)!==expectedTransitionDigest)
  fail('EXCHANGE33C_EXTERNAL_PIN_MISMATCH');
 if(nowMs<b.issuedAt||nowMs>b.expiresAt)fail('EXCHANGE33C_TRANSITION_EXPIRED');
 if(!exact(predecessor,['verification'])||!exact(successor,['verification']))
  fail('EXCHANGE33C_COMMITMENT_ARGS_INVALID');
 const p=predecessor.verification,s=successor.verification;
 if(!p||!s||p.expectedNamespaceId!==expectedNamespaceId||s.expectedNamespaceId!==expectedNamespaceId||
  p.expectedJournalScopeDigest!==expectedJournalScopeDigest||s.expectedJournalScopeDigest!==expectedJournalScopeDigest||
  p.expectedEpoch!==b.fromEpoch||s.expectedEpoch!==b.toEpoch||
  p.expectedAuthorityPolicyDigest!==expectedPredecessorAuthorityPolicyDigest||
  s.expectedAuthorityPolicyDigest!==expectedSuccessorAuthorityPolicyDigest||
  p.expectedCommitmentDigest!==expectedPredecessorCommitmentDigest||
  s.expectedCommitmentDigest!==expectedSuccessorCommitmentDigest||
  p.nowMs!==nowMs||s.nowMs!==nowMs)
  fail('EXCHANGE33C_COMMITMENT_BINDING_MISMATCH');
 // Authenticated commitments must both be valid at the same externally supplied time.
 const pv=verifyOfflineConflictSignedNamespaceRoster(p);
 const sv=verifyOfflineConflictSignedNamespaceRoster(s);
 const oldDigest=offlineConflictNamespaceAuthorityPolicyDigest(p.authorities);
 const newDigest=offlineConflictNamespaceAuthorityPolicyDigest(s.authorities);
 if(oldDigest!==expectedPredecessorAuthorityPolicyDigest||newDigest!==expectedSuccessorAuthorityPolicyDigest)
  fail('EXCHANGE33C_AUTHORITY_PIN_MISMATCH');
 verifyQuorum(transition.predecessorSignatures,publicKeys(p.authorities),bytes,'PREDECESSOR');
 verifyQuorum(transition.successorSignatures,publicKeys(s.authorities),bytes,'SUCCESSOR');
 return Object.freeze({verified:true,readOnly:true,namespaceId:b.namespaceId,
  fromEpoch:b.fromEpoch,toEpoch:b.toEpoch,transitionDigest:expectedTransitionDigest,
  predecessorCommitmentDigest:pv.commitmentDigest,successorCommitmentDigest:sv.commitmentDigest,
  predecessorSigners:transition.predecessorSignatures.length,
  successorSigners:transition.successorSignatures.length,independentlyPublished:false,
  trustedTimestamp:false,globalForkPrevention:false,authorizesRepair:false,
  authorizesProduction:false,authorizesCheckout:false});
}
