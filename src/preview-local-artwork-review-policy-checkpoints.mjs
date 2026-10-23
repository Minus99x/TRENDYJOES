/** Objective 35AD — read-only, externally retained revocation-policy checkpoint
 * verification boundary. This module cannot establish custody or commit a head.
 * The caller must authenticate and retain the head OUTSIDE the reviewed journal.
 */
import {createHash,createPublicKey,sign as signEd,verify as verifyEd,timingSafeEqual} from 'node:crypto';
import {digestLocalReviewRevocationPolicy} from './preview-local-artwork-review-rotation-lineage.mjs';

export const LOCAL_REVIEW_POLICY_CHECKPOINT_SCHEMA='TJ-LOCAL-REVIEW-POLICY-CHECKPOINT-35AD-1';
export const LOCAL_REVIEW_RETAINED_HEAD_SCHEMA='TJ-LOCAL-REVIEW-RETAINED-HEAD-35AD-1';
export const LOCAL_REVIEW_POLICY_GENESIS_DIGEST='0'.repeat(64);
const HEX=/^[a-f0-9]{64}$/;
const SIG=/^[A-Za-z0-9_-]{86}$/;
const DOMAIN='TRENDYJOES_LOCAL_REVIEW_POLICY_CHECKPOINT_35AD_V1\n';
const BODY=['schema','rootPin','registryId','signerFingerprint','previousCheckpointSha256','policy','policySha256','authority'];
const SIGNED=[...BODY,'signature'];
const HEAD=['schema','rootPin','registryId','signerFingerprint','checkpointSha256','revision'];
const MAX_CHECKPOINT_BYTES=16384;
const MAX_CHAIN=17; // one pinned predecessor plus at most 16 successors
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hash=b=>createHash('sha256').update(b).digest('hex');
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value'in d&&d.enumerable;});
const validHex=x=>typeof x==='string'&&HEX.test(x);
const validKey=(k,type)=>k?.type===type&&k?.asymmetricKeyType==='ed25519';
const fingerprint=k=>hash(k.export({type:'spki',format:'der'}));
const equalHex=(a,b)=>validHex(a)&&validHex(b)&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
const cloneBytes=b=>{
 if(!Buffer.isBuffer(b)||b.length<2||b.length>MAX_CHECKPOINT_BYTES)
  fail('LOCAL_REVIEW_POLICY_INVALID_BYTES');
 return Buffer.from(b);
};
function checkPolicy(policy){
 try{return digestLocalReviewRevocationPolicy(policy);}
 catch{fail('LOCAL_REVIEW_POLICY_INVALID_POLICY');}
}
function validateBody(body,{expectedRootPin,expectedRegistryId,expectedSignerFingerprint}){
 if(!exact(body,BODY)||body.schema!==LOCAL_REVIEW_POLICY_CHECKPOINT_SCHEMA||
  !validHex(body.rootPin)||!validHex(body.registryId)||!validHex(body.signerFingerprint)||
  !validHex(body.previousCheckpointSha256)||!validHex(body.policySha256)||
  body.authority!=='NONE'||!equalHex(body.rootPin,expectedRootPin)||
  !equalHex(body.registryId,expectedRegistryId)||
  !equalHex(body.signerFingerprint,expectedSignerFingerprint)||
  !equalHex(checkPolicy(body.policy),body.policySha256))
  fail('LOCAL_REVIEW_POLICY_INVALID_CHECKPOINT');
}
function verifyBytes(bytes,{expectedSha256,expectedRootPin,expectedRegistryId,
 expectedSignerFingerprint,signerPublicKey}){
 const input=cloneBytes(bytes);
 if(!validHex(expectedSha256)||!equalHex(hash(input),expectedSha256))
  fail('LOCAL_REVIEW_POLICY_CHECKPOINT_DIGEST_MISMATCH');
 if(!validKey(signerPublicKey,'public')||!validHex(expectedSignerFingerprint)||
  !equalHex(fingerprint(signerPublicKey),expectedSignerFingerprint))
  fail('LOCAL_REVIEW_POLICY_UNTRUSTED_SIGNER');
 let envelope;
 try{envelope=JSON.parse(input.toString('utf8'));}
 catch{fail('LOCAL_REVIEW_POLICY_MALFORMED');}
 if(!exact(envelope,SIGNED)||!Buffer.from(JSON.stringify(envelope)).equals(input))
  fail('LOCAL_REVIEW_POLICY_MALFORMED');
 const body=Object.fromEntries(BODY.map(k=>[k,envelope[k]]));
 validateBody(body,{expectedRootPin,expectedRegistryId,expectedSignerFingerprint});
 if(typeof envelope.signature!=='string'||!SIG.test(envelope.signature))
  fail('LOCAL_REVIEW_POLICY_MALFORMED');
 const signature=Buffer.from(envelope.signature,'base64url');
 if(signature.length!==64||signature.toString('base64url')!==envelope.signature)
  fail('LOCAL_REVIEW_POLICY_MALFORMED');
 if(!verifyEd(null,Buffer.from(DOMAIN+JSON.stringify(body)),signerPublicKey,signature))
  fail('LOCAL_REVIEW_POLICY_BAD_SIGNATURE');
 return Object.freeze({sha256:expectedSha256,revision:body.policy.revision,
  previousCheckpointSha256:body.previousCheckpointSha256,policy:body.policy,
  policySha256:body.policySha256,signatureVerified:true});
}
/** Create portable signed bytes. The result is not retained or trusted by itself. */
export function createLocalReviewPolicyCheckpoint({policy,rootPin,registryId,
 previousCheckpointSha256,signingKey}={}){
 if(!validKey(signingKey,'private'))fail('LOCAL_REVIEW_POLICY_INVALID_SIGNING_KEY');
 const signerPublicKey=createPublicKey(signingKey);
 const expectedSignerFingerprint=fingerprint(signerPublicKey);
 const originalDigest=checkPolicy(policy);
 let copied;
 try{copied=JSON.parse(JSON.stringify(policy));}catch{fail('LOCAL_REVIEW_POLICY_INVALID_POLICY');}
 const copiedDigest=checkPolicy(copied);
 if(!equalHex(originalDigest,copiedDigest))fail('LOCAL_REVIEW_POLICY_MUTATED');
 const body={schema:LOCAL_REVIEW_POLICY_CHECKPOINT_SCHEMA,rootPin,registryId,
  signerFingerprint:expectedSignerFingerprint,previousCheckpointSha256,
  policy:copied,policySha256:copiedDigest,authority:'NONE'};
 validateBody(body,{expectedRootPin:rootPin,expectedRegistryId:registryId,expectedSignerFingerprint});
 const signature=signEd(null,Buffer.from(DOMAIN+JSON.stringify(body)),signingKey).toString('base64url');
 const bytes=Buffer.from(JSON.stringify({...body,signature}));
 if(bytes.length>MAX_CHECKPOINT_BYTES)fail('LOCAL_REVIEW_POLICY_INVALID_BYTES');
 const sha256=hash(bytes);
 verifyBytes(bytes,{expectedSha256:sha256,expectedRootPin:rootPin,
  expectedRegistryId:registryId,expectedSignerFingerprint,signerPublicKey});
 return Object.freeze({bytes:Buffer.from(bytes),sha256,revision:copied.revision,
  signerFingerprint:expectedSignerFingerprint,independentlyRetained:false,
  authenticatedRegistry:false,authorizesProduction:false,shopifyWritesAllowed:false});
}
function checkedHead(head,{expectedRootPin,expectedRegistryId,expectedSignerFingerprint}){
 if(!exact(head,HEAD)||head.schema!==LOCAL_REVIEW_RETAINED_HEAD_SCHEMA||
  !validHex(head.rootPin)||!validHex(head.registryId)||!validHex(head.signerFingerprint)||
  !validHex(head.checkpointSha256)||!Number.isSafeInteger(head.revision)||head.revision<1||
  !equalHex(head.rootPin,expectedRootPin)||!equalHex(head.registryId,expectedRegistryId)||
  !equalHex(head.signerFingerprint,expectedSignerFingerprint))
  fail('LOCAL_REVIEW_POLICY_UNTRUSTED_RETAINED_HEAD');
 return JSON.stringify(head);
}
function isSuperset(next,previous){
 const available=new Set(next);
 return previous.every(v=>available.has(v));
}
/** Verify a pinned predecessor and 1..16 strictly monotonic signed successors.
 * readRetainedHead MUST be an independently trusted adapter; this cannot prove it.
 * The second read detects a moving local head, not distributed fork prevention.
 * No compare-and-swap, promotion, persistence or Shopify writes are performed.
 */
export async function verifyLocalReviewPolicyCheckpointAdvancement({checkpointBytes,
 readRetainedHead,signerPublicKey,expectedRootPin,expectedRegistryId,
 expectedSignerFingerprint}={}){
 if(!validHex(expectedRootPin)||!validHex(expectedRegistryId)||
  !validHex(expectedSignerFingerprint)||!validKey(signerPublicKey,'public')||
  !Array.isArray(checkpointBytes)||checkpointBytes.length<2||
  checkpointBytes.length>MAX_CHAIN||Reflect.ownKeys(checkpointBytes).length!==checkpointBytes.length+1||
  typeof readRetainedHead!=='function')fail('LOCAL_REVIEW_POLICY_INVALID_OPTIONS');
 // Clone BEFORE invoking any asynchronous/untrusted adapter.
 const snapshots=[];
 for(let i=0;i<checkpointBytes.length;i++){
  const d=Object.getOwnPropertyDescriptor(checkpointBytes,i);
  if(!d||!('value'in d)||!d.enumerable)fail('LOCAL_REVIEW_POLICY_INVALID_OPTIONS');
  snapshots.push(cloneBytes(d.value));
 }
 const options={expectedRootPin,expectedRegistryId,expectedSignerFingerprint};
 let firstHead,secondHead;
 try{firstHead=structuredClone(await readRetainedHead());}
 catch{fail('LOCAL_REVIEW_POLICY_RETAINED_HEAD_UNAVAILABLE');}
 const headSnapshot=checkedHead(firstHead,options);
 let previous=null;
 for(let i=0;i<snapshots.length;i++){
  const digest=hash(snapshots[i]);
  const checked=verifyBytes(snapshots[i],{expectedSha256:digest,...options,signerPublicKey});
  if(i===0){
   if(!equalHex(digest,firstHead.checkpointSha256)||checked.revision!==firstHead.revision)
    fail('LOCAL_REVIEW_POLICY_RETAINED_HEAD_MISMATCH');
  }else{
   if(!equalHex(checked.previousCheckpointSha256,previous.sha256)||
    checked.revision!==previous.revision+1)
    fail('LOCAL_REVIEW_POLICY_REVISION_OR_LINK_ROLLBACK');
   if(!isSuperset(checked.policy.revokedKeyFingerprints,previous.policy.revokedKeyFingerprints)||
    !isSuperset(checked.policy.revokedRotationDigests,previous.policy.revokedRotationDigests))
    fail('LOCAL_REVIEW_POLICY_REVOCATION_ROLLBACK');
  }
  previous=checked;
 }
 try{secondHead=structuredClone(await readRetainedHead());}
 catch{fail('LOCAL_REVIEW_POLICY_RETAINED_HEAD_UNAVAILABLE');}
 if(checkedHead(secondHead,options)!==headSnapshot)
  fail('LOCAL_REVIEW_POLICY_RETAINED_HEAD_CHANGED');
 return Object.freeze({schema:LOCAL_REVIEW_POLICY_CHECKPOINT_SCHEMA,
  retainedHeadSha256:firstHead.checkpointSha256,retainedRevision:firstHead.revision,
  candidateSha256:previous.sha256,candidateRevision:previous.revision,
  checkedSuccessors:snapshots.length-1,signaturesVerified:true,
  revocationsMonotonic:true,independentCustodyVerified:false,
  candidateExternallyRetained:false,authenticatedRegistry:false,
  authorizesProduction:false,shopifyWritesAllowed:false});
}
