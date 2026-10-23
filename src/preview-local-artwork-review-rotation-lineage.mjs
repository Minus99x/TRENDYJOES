/** Objective 35AC: bounded, read-only, externally anchored multi-hop observer
 * rotation lineage. Caller owns trusted key resolution and off-journal anchors.
 * No clock, custody, revocation service, external witness or Shopify authority.
 */
import {createHash,timingSafeEqual} from 'node:crypto';
import {verifyLocalReviewObserverKeyRotation} from './preview-local-artwork-review-observer-rotation.mjs';

export const LOCAL_REVIEW_LINEAGE_SCHEMA='TJ-LOCAL-REVIEW-ROTATION-LINEAGE-35AC-1';
export const LOCAL_REVIEW_REVOCATION_SCHEMA='TJ-LOCAL-REVIEW-REVOCATION-POLICY-35AC-1';
const HEX=/^[a-f0-9]{64}$/;
const MAX_HOPS=16;
const MAX_BYTES=1048576;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hash=x=>createHash('sha256').update(x).digest('hex');
const exact=(x,keys)=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(x))&&
 Reflect.ownKeys(x).length===keys.length&&keys.every(k=>{
  const d=Object.getOwnPropertyDescriptor(x,k);return d&&'value'in d&&d.enumerable;
 });
const hex=x=>typeof x==='string'&&HEX.test(x);
const sortedUnique=a=>{
 if(!Array.isArray(a)||a.length>128||Reflect.ownKeys(a).length!==a.length+1)return false;
 let previous=null;
 for(let i=0;i<a.length;i++){
  const d=Object.getOwnPropertyDescriptor(a,i);
  if(!d||!('value'in d)||!d.enumerable||!hex(d.value)||
   (previous!==null&&previous>=d.value))return false;
  previous=d.value;
 }
 return true;
};
const POLICY_FIELDS=['schema','revision','revokedKeyFingerprints','revokedRotationDigests','authority'];
const LINEAGE_FIELDS=['schema','rootPin','hops','authority'];
const HOP_FIELDS=['previousReceipt','successorReceipt','rotation'];
function checkPolicy(policy){
 if(!exact(policy,POLICY_FIELDS)||policy.schema!==LOCAL_REVIEW_REVOCATION_SCHEMA||
  !Number.isSafeInteger(policy.revision)||policy.revision<1||
  !sortedUnique(policy.revokedKeyFingerprints)||!sortedUnique(policy.revokedRotationDigests)||
  policy.authority!=='NONE')fail('LOCAL_REVIEW_LINEAGE_INVALID_POLICY');
 return hash('TJ-35AC-REVOCATION-POLICY\n'+JSON.stringify(policy));
}
/** A policy hash must be pinned separately. A local digest alone is not proof of custody. */
export function digestLocalReviewRevocationPolicy(policy){return checkPolicy(policy);}
const pinCheck=(value,code)=>{if(!hex(value))fail(code);};
function verifyPolicyAnchor(policy,expectedPolicySha256){
 pinCheck(expectedPolicySha256,'LOCAL_REVIEW_LINEAGE_EXTERNAL_ANCHORS_REQUIRED');
 const actual=checkPolicy(policy);
 if(!timingSafeEqual(Buffer.from(actual,'hex'),Buffer.from(expectedPolicySha256,'hex')))
  fail('LOCAL_REVIEW_LINEAGE_POLICY_ANCHOR_MISMATCH');
}
async function inspectLineage(envelope,{expectedRootPin,resolveObserverPublicKey,
 expectedInitialReceiptDigest,expectedInitialKeyFingerprint,policy,expectedPolicySha256}={}){
 for(const value of [expectedRootPin,expectedInitialReceiptDigest,expectedInitialKeyFingerprint])
  pinCheck(value,'LOCAL_REVIEW_LINEAGE_EXTERNAL_ANCHORS_REQUIRED');
 if(typeof resolveObserverPublicKey!=='function')fail('LOCAL_REVIEW_LINEAGE_EXTERNAL_ANCHORS_REQUIRED');
 verifyPolicyAnchor(policy,expectedPolicySha256);
 if(!exact(envelope,LINEAGE_FIELDS)||envelope.schema!==LOCAL_REVIEW_LINEAGE_SCHEMA||
  envelope.rootPin!==expectedRootPin||envelope.authority!=='NONE'||
  !Array.isArray(envelope.hops)||!envelope.hops.length||envelope.hops.length>MAX_HOPS||
  Reflect.ownKeys(envelope.hops).length!==envelope.hops.length+1||
  !Array.from({length:envelope.hops.length},(_,i)=>{
   const d=Object.getOwnPropertyDescriptor(envelope.hops,i);
   return d&&'value'in d&&d.enumerable;}).every(Boolean))
  fail('LOCAL_REVIEW_LINEAGE_MALFORMED');
 const usedKeyIds=new Set(),usedFingerprints=new Set(),usedRotations=new Set(),usedPredecessors=new Set();
 const revokedKeys=new Set(policy.revokedKeyFingerprints),revokedRotations=new Set(policy.revokedRotationDigests);
 let previous=null,observerId=null,firstReceipt=null,lastReceipt=null;
 for(const hop of envelope.hops){
  if(!exact(hop,HOP_FIELDS))fail('LOCAL_REVIEW_LINEAGE_MALFORMED');
  const checked=await verifyLocalReviewObserverKeyRotation(hop.rotation,{
   previousReceipt:hop.previousReceipt,successorReceipt:hop.successorReceipt,
   expectedRootPin,resolveObserverPublicKey});
  const old=hop.previousReceipt,newer=hop.successorReceipt;
  if(observerId!==null&&checked.observerId!==observerId)fail('LOCAL_REVIEW_LINEAGE_IDENTITY_CHANGED');
  if(previous!==null&&(checked.previousReceiptDigest!==previous.successorReceiptDigest||
    checked.oldKeyFingerprint!==previous.newKeyFingerprint||old.keyId!==previous.newKeyId))
   fail('LOCAL_REVIEW_LINEAGE_BROKEN_LINK');
  if(usedPredecessors.has(checked.previousReceiptDigest)||usedRotations.has(checked.rotationDigest)||
   usedKeyIds.has(newer.keyId)||usedFingerprints.has(checked.newKeyFingerprint)||
   (previous===null&&(usedKeyIds.has(old.keyId)||usedFingerprints.has(checked.oldKeyFingerprint))))
   fail('LOCAL_REVIEW_LINEAGE_REPLAY_OR_CYCLE');
  if(revokedKeys.has(checked.oldKeyFingerprint)||revokedKeys.has(checked.newKeyFingerprint)||
   revokedRotations.has(checked.rotationDigest))fail('LOCAL_REVIEW_LINEAGE_REVOKED');
  if(previous===null){
   if(checked.previousReceiptDigest!==expectedInitialReceiptDigest||
    checked.oldKeyFingerprint!==expectedInitialKeyFingerprint)
    fail('LOCAL_REVIEW_LINEAGE_INITIAL_ANCHOR_MISMATCH');
   observerId=checked.observerId;firstReceipt=checked.previousReceiptDigest;
   usedKeyIds.add(old.keyId);usedFingerprints.add(checked.oldKeyFingerprint);
  }
  usedPredecessors.add(checked.previousReceiptDigest);usedRotations.add(checked.rotationDigest);
  usedKeyIds.add(newer.keyId);usedFingerprints.add(checked.newKeyFingerprint);
  previous={...checked,newKeyId:newer.keyId};lastReceipt=checked.successorReceiptDigest;
 }
 return {observerId,firstReceiptDigest:firstReceipt,terminalReceiptDigest:lastReceipt,
  terminalKeyFingerprint:previous.newKeyFingerprint,rotationDigests:[...usedRotations],hopCount:envelope.hops.length};
}
/** Canonical export. This creates an artifact, NOT a trusted external anchor. */
export async function exportLocalReviewRotationLineage({hops,expectedRootPin,
 resolveObserverPublicKey,expectedInitialReceiptDigest,expectedInitialKeyFingerprint,
 policy,expectedPolicySha256}={}){
 // Snapshot before any asynchronous key resolution: never verify one mutable
 // lineage and export another after an untrusted callback changes its inputs.
 if(!Array.isArray(hops)||!hops.length||hops.length>MAX_HOPS||
  Reflect.ownKeys(hops).length!==hops.length+1)fail('LOCAL_REVIEW_LINEAGE_MALFORMED');
 for(let i=0;i<hops.length;i++){
  const d=Object.getOwnPropertyDescriptor(hops,i);
  if(!d||!('value'in d)||!d.enumerable||!exact(d.value,HOP_FIELDS))
   fail('LOCAL_REVIEW_LINEAGE_MALFORMED');
 }
 let bytes,envelope;
 try{
  bytes=Buffer.from(JSON.stringify({schema:LOCAL_REVIEW_LINEAGE_SCHEMA,
   rootPin:expectedRootPin,hops,authority:'NONE'}),'utf8');
  if(bytes.length>MAX_BYTES)fail('LOCAL_REVIEW_LINEAGE_OVERSIZED');
  envelope=JSON.parse(bytes.toString('utf8'));
 }catch(e){if(e?.code)throw e;fail('LOCAL_REVIEW_LINEAGE_MALFORMED');}
 const checked=await inspectLineage(envelope,{expectedRootPin,resolveObserverPublicKey,
  expectedInitialReceiptDigest,expectedInitialKeyFingerprint,policy,expectedPolicySha256});
 if(!Buffer.from(JSON.stringify(envelope)).equals(bytes))fail('LOCAL_REVIEW_LINEAGE_MALFORMED');
 return Object.freeze({bytes:Buffer.from(bytes),sha256:hash(bytes),...checked,
  independentlyRetained:false,revocationRegistryAuthenticated:false,authorizesProduction:false,
  shopifyWritesAllowed:false});
}
/** Import refuses any unpinned terminal state and unpinned revocation policy. */
export async function importLocalReviewRotationLineage({bytes,expectedSha256,expectedRootPin,
 expectedInitialReceiptDigest,expectedInitialKeyFingerprint,expectedTerminalReceiptDigest,
 expectedTerminalKeyFingerprint,resolveObserverPublicKey,policy,expectedPolicySha256}={}){
 if(!Buffer.isBuffer(bytes)||bytes.length<2||bytes.length>MAX_BYTES)
  fail('LOCAL_REVIEW_LINEAGE_INVALID_BYTES');
 for(const v of [expectedSha256,expectedTerminalReceiptDigest,expectedTerminalKeyFingerprint])
  pinCheck(v,'LOCAL_REVIEW_LINEAGE_EXTERNAL_ANCHORS_REQUIRED');
 if(!timingSafeEqual(Buffer.from(hash(bytes),'hex'),Buffer.from(expectedSha256,'hex')))
  fail('LOCAL_REVIEW_LINEAGE_DIGEST_MISMATCH');
 let envelope;
 try{envelope=JSON.parse(bytes.toString('utf8'));}catch{fail('LOCAL_REVIEW_LINEAGE_MALFORMED');}
 if(!exact(envelope,LINEAGE_FIELDS)||!Buffer.from(JSON.stringify(envelope)).equals(bytes))
  fail('LOCAL_REVIEW_LINEAGE_MALFORMED');
 const checked=await inspectLineage(envelope,{expectedRootPin,resolveObserverPublicKey,
  expectedInitialReceiptDigest,expectedInitialKeyFingerprint,policy,expectedPolicySha256});
 if(checked.terminalReceiptDigest!==expectedTerminalReceiptDigest||
  checked.terminalKeyFingerprint!==expectedTerminalKeyFingerprint)
  fail('LOCAL_REVIEW_LINEAGE_TERMINAL_ANCHOR_MISMATCH');
 return Object.freeze({schema:LOCAL_REVIEW_LINEAGE_SCHEMA,sha256:expectedSha256,...checked,
  externallySuppliedAnchorsMatched:true,independentAnchorCustodyVerified:false,
  revocationRegistryAuthenticated:false,trustedTime:false,authorizesProduction:false,
  shopifyWritesAllowed:false});
}
