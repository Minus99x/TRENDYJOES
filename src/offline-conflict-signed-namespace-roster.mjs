/** Objective 33B: signed, bounded namespace and observer-roster commitments.
 * Verifies COMPLETE locally supplied 33A observer inventories against a
 * separately pinned Ed25519 authority policy and a signed complete roster.
 * No network, storage, signing-key management, trusted clock or repair rights.
 */
import {createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
import {verifyOfflineConflictManifestMultiClaimReconciliation} from './offline-conflict-manifest-multi-claim-inventory.mjs';

export const OFFLINE_CONFLICT_SIGNED_NAMESPACE_SCHEMA='TJ-OFFLINE-CONFLICT-SIGNED-NAMESPACE-ROSTER-1';
const HEX=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9_-]{8,64}$/;
const B64=/^[A-Za-z0-9_-]+$/;
const bodyFields=['schema','namespaceId','journalScopeDigest','epoch','issuedAt','expiresAt','nonce','authorityPolicyDigest','reconciliationDigest','observers'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value' in d&&d.enumerable;})&&
 Object.keys(o).every(k=>keys.includes(k));
const array=(a,min,max)=>Array.isArray(a)&&Object.getPrototypeOf(a)===Array.prototype&&
 a.length>=min&&a.length<=max&&Reflect.ownKeys(a).length===a.length+1&&
 Array.from({length:a.length},(_,i)=>Object.getOwnPropertyDescriptor(a,String(i)))
 .every(d=>d&&'value' in d&&d.enumerable);
const sha=x=>createHash('sha256').update(x).digest('hex');
const validId=x=>typeof x==='string'&&ID.test(x);
function publicKey(s){
 if(typeof s!=='string'||!B64.test(s)||s.length>256)fail('EXCHANGE33B_PUBLIC_KEY_INVALID');
 const der=Buffer.from(s,'base64url');
 if(der.toString('base64url')!==s)fail('EXCHANGE33B_PUBLIC_KEY_INVALID');
 let k;try{k=createPublicKey({key:der,format:'der',type:'spki'});}catch{fail('EXCHANGE33B_PUBLIC_KEY_INVALID');}
 if(k.asymmetricKeyType!=='ed25519'||k.export({format:'der',type:'spki'}).toString('base64url')!==s)
  fail('EXCHANGE33B_PUBLIC_KEY_INVALID');
 return k;
}
function rosterKeys(roster,idField,min,max){
 if(!array(roster,min,max))fail('EXCHANGE33B_ROSTER_INVALID');
 const keys=new Map(),fingerprints=new Set();let prev='';
 for(const member of roster){
  if(!exact(member,[idField,'publicKey'])||!validId(member[idField])||member[idField]<=prev)
   fail('EXCHANGE33B_ROSTER_INVALID');
  const key=publicKey(member.publicKey),fingerprint=sha(key.export({type:'spki',format:'der'}));
  if(fingerprints.has(fingerprint))fail('EXCHANGE33B_DUPLICATE_KEY');
  fingerprints.add(fingerprint);keys.set(member[idField],key);prev=member[idField];
 }
 return {keys,fingerprints};
}
/** Candidate policy digest; its independent publication is caller's job. */
export function offlineConflictNamespaceAuthorityPolicyDigest(authorities){
 const {keys}=rosterKeys(authorities,'authorityId',3,9);
 return sha('TJ-33B-AUTHORITY-POLICY\0'+JSON.stringify(authorities.map(a=>({
  authorityId:a.authorityId,keyDigest:sha(keys.get(a.authorityId).export({format:'der',type:'spki'}))}))));
}
function validateBody(body){
 if(!exact(body,bodyFields)||body.schema!==OFFLINE_CONFLICT_SIGNED_NAMESPACE_SCHEMA||
  !validId(body.namespaceId)||!HEX.test(body.journalScopeDigest||'')||
  !Number.isSafeInteger(body.epoch)||body.epoch<1||
  !Number.isSafeInteger(body.issuedAt)||body.issuedAt<0||
  !Number.isSafeInteger(body.expiresAt)||body.expiresAt<=body.issuedAt||
  body.expiresAt-body.issuedAt>3600000||!validId(body.nonce)||
  !HEX.test(body.authorityPolicyDigest||'')||!HEX.test(body.reconciliationDigest||'')||
  !array(body.observers,2,8))fail('EXCHANGE33B_BODY_INVALID');
 let prev='';const seenKeys=new Set();
 for(const o of body.observers){
  if(!exact(o,['observerId','publicKey','inventoryDigest','claimCount'])||
   !validId(o.observerId)||o.observerId<=prev||!HEX.test(o.inventoryDigest||'')||
   !Number.isSafeInteger(o.claimCount)||o.claimCount<1||o.claimCount>32)
   fail('EXCHANGE33B_ROSTER_INVALID');
  const k=publicKey(o.publicKey),fingerprint=sha(k.export({format:'der',type:'spki'}));
  if(seenKeys.has(fingerprint))fail('EXCHANGE33B_DUPLICATE_KEY');
  seenKeys.add(fingerprint);prev=o.observerId;
 }
}
/** Byte string signed by both the pinned namespace authority quorum and EVERY
 * observer. JSON member ordering is intentionally part of the signed contract. */
export function offlineConflictSignedNamespaceBodyBytes(body){
 validateBody(body);
 return Buffer.from('TJ-33B-NAMESPACE-COMMITMENT\0'+JSON.stringify(body),'utf8');
}
export function offlineConflictSignedNamespaceCommitmentDigest(body){
 return sha(Buffer.concat([Buffer.from('TJ-33B-COMMITMENT-DIGEST\0'),offlineConflictSignedNamespaceBodyBytes(body)]));
}
function verifySignatures(signatures,keys,bytes,required,kind){
 if(!array(signatures,required,keys.size))fail('EXCHANGE33B_'+kind+'_QUORUM_REQUIRED');
 let prev='';
 for(const sig of signatures){
  const field=kind==='AUTHORITY'?'authorityId':'observerId';
  if(!exact(sig,[field,'signature'])||!validId(sig[field])||sig[field]<=prev||
   !keys.has(sig[field])||typeof sig.signature!=='string'||
   !/^[A-Za-z0-9_-]{86}$/.test(sig.signature))fail('EXCHANGE33B_'+kind+'_SIGNATURE_INVALID');
  const raw=Buffer.from(sig.signature,'base64url');
  if(raw.length!==64||raw.toString('base64url')!==sig.signature||
   !verifySignature(null,bytes,keys.get(sig[field]),raw))
   fail('EXCHANGE33B_'+kind+'_SIGNATURE_INVALID');
  prev=sig[field];
 }
}
/** Fail closed if a member, signed inventory, namespace or external pin differs.
 * Caller must supply an independently authenticated authority-policy digest,
 * namespace/epoch, and reconciliation/commitment digests. */
export function verifyOfflineConflictSignedNamespaceRoster({commitment,authorities,observations,
 expectedAuthorityPolicyDigest,expectedCommitmentDigest,expectedJournalScopeDigest,
 expectedNamespaceId,expectedEpoch,expectedReconciliationDigest,expectedObserverCount,nowMs}={}){
 if(!HEX.test(expectedAuthorityPolicyDigest||'')||!HEX.test(expectedCommitmentDigest||'')||
  !HEX.test(expectedJournalScopeDigest||'')||!HEX.test(expectedReconciliationDigest||'')||
  !validId(expectedNamespaceId)||!Number.isSafeInteger(expectedEpoch)||expectedEpoch<1||
  !Number.isSafeInteger(expectedObserverCount)||expectedObserverCount<2||expectedObserverCount>8||
  !Number.isSafeInteger(nowMs)||nowMs<0)
  fail('EXCHANGE33B_EXTERNAL_PINS_REQUIRED');
 if(!exact(commitment,['body','authoritySignatures','observerSignatures']))
  fail('EXCHANGE33B_COMMITMENT_INVALID');
 const bytes=offlineConflictSignedNamespaceBodyBytes(commitment.body),body=commitment.body;
 if(body.namespaceId!==expectedNamespaceId||body.journalScopeDigest!==expectedJournalScopeDigest||
  body.epoch!==expectedEpoch||body.authorityPolicyDigest!==expectedAuthorityPolicyDigest||
  body.reconciliationDigest!==expectedReconciliationDigest||
  body.observers.length!==expectedObserverCount||
  offlineConflictSignedNamespaceCommitmentDigest(body)!==expectedCommitmentDigest)
  fail('EXCHANGE33B_EXTERNAL_PIN_MISMATCH');
 if(nowMs<body.issuedAt||nowMs>body.expiresAt)fail('EXCHANGE33B_COMMITMENT_EXPIRED');
 const policy=offlineConflictNamespaceAuthorityPolicyDigest(authorities);
 if(policy!==expectedAuthorityPolicyDigest)fail('EXCHANGE33B_AUTHORITY_POLICY_PIN_MISMATCH');
 const authority=rosterKeys(authorities,'authorityId',3,9);
 const observer=rosterKeys(body.observers.map(x=>({observerId:x.observerId,publicKey:x.publicKey})),'observerId',2,8);
 for(const f of observer.fingerprints)if(authority.fingerprints.has(f))fail('EXCHANGE33B_AUTHORITY_OBSERVER_KEY_OVERLAP');
 verifySignatures(commitment.authoritySignatures,authority.keys,bytes,
  Math.floor(authority.keys.size/2)+1,'AUTHORITY');
 verifySignatures(commitment.observerSignatures,observer.keys,bytes,observer.keys.size,'OBSERVER');
 if(!array(observations,2,8)||observations.length!==body.observers.length)
  fail('EXCHANGE33B_OBSERVATION_SET_MISMATCH');
 const observed=new Map();
 for(const o of observations){
  if(!exact(o,['observerId','claims','expectedInventoryDigest','expectedClaimCount'])||
   !validId(o.observerId)||observed.has(o.observerId))fail('EXCHANGE33B_OBSERVATION_SET_MISMATCH');
  observed.set(o.observerId,o);
 }
 for(const r of body.observers){
  const o=observed.get(r.observerId);
  if(!o||o.expectedInventoryDigest!==r.inventoryDigest||o.expectedClaimCount!==r.claimCount)
   fail('EXCHANGE33B_OBSERVATION_SET_MISMATCH');
 }
 // Revalidate actual 32Y/32Z signatures, every 33A claim, and observer parity.
 verifyOfflineConflictManifestMultiClaimReconciliation({journalScopeDigest:body.journalScopeDigest,
  observations,expectedJournalScopeDigest,expectedReconciliationDigest,expectedObserverCount});
 return Object.freeze({verified:true,readOnly:true,namespaceId:body.namespaceId,
  epoch:body.epoch,commitmentDigest:expectedCommitmentDigest,observerCount:body.observers.length,
  authoritySigners:commitment.authoritySignatures.length,
  independentlyPublished:false,authorizesRepair:false,authorizesProduction:false,
  authorizesCheckout:false});
}
/** A bounded full-roster membership/nonmembership assertion, NOT global proof. */
export function inspectOfflineConflictSignedNamespaceMembership(args){
 const {targetObserverId,...verification}=args??{};
 if(!validId(targetObserverId))fail('EXCHANGE33B_MEMBER_ID_INVALID');
 const result=verifyOfflineConflictSignedNamespaceRoster(verification);
 const member=verification.commitment.body.observers.some(o=>o.observerId===targetObserverId);
 return Object.freeze({verified:true,namespaceId:result.namespaceId,epoch:result.epoch,
  targetObserverId,member,proofKind:'complete-signed-local-roster',
  globallyComplete:false,authorizesRepair:false,authorizesProduction:false});
}
