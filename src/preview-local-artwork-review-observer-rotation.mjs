/** Objective 35AB: dual-key offline observer rotation and portable pin envelopes.
 * Every trust anchor is caller supplied and must be retained independently.
 * No key custody, trusted time, hosted witness or mutation authority.
 */
import {createHash,sign as signEd,verify as verifyEd,timingSafeEqual} from 'node:crypto';
import {verifyLocalReviewObserverReceipt} from './preview-local-artwork-review-observer.mjs';

export const LOCAL_REVIEW_ROTATION_SCHEMA='TJ-LOCAL-REVIEW-ROTATION-35AB-1';
export const LOCAL_REVIEW_PIN_SCHEMA='TJ-LOCAL-REVIEW-EXTERNAL-PIN-35AB-1';
const HEX=/^[a-f0-9]{64}$/;
const SIG=/^[A-Za-z0-9_-]{86}$/;
const DOMAIN='TRENDYJOES_LOCAL_REVIEW_ROTATION_35AB_V1\n';
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hash=b=>createHash('sha256').update(b).digest('hex');
const plain=o=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o));
const exact=(o,keys)=>plain(o)&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value'in d&&d.enumerable;});
const FIELDS=['schema','rootPin','observerId','oldKeyId','newKeyId',
 'oldKeyFingerprint','newKeyFingerprint','previousReceiptDigest','successorReceiptDigest','authority'];
const ALL=[...FIELDS,'oldSignature','newSignature','rotationDigest'];
const bytes=body=>Buffer.from(DOMAIN+JSON.stringify(body));
const rotationDigest=(body,oldSignature,newSignature)=>hash('TJ-35AB-ROTATION\n'+JSON.stringify({...body,oldSignature,newSignature}));
const fingerprint=key=>hash(key.export({type:'spki',format:'der'}));
const keyValid=(key,type)=>key?.type===type&&key?.asymmetricKeyType==='ed25519';
const signatureBytes=s=>{
 if(typeof s!=='string'||!SIG.test(s))fail('LOCAL_REVIEW_ROTATION_MALFORMED');
 const b=Buffer.from(s,'base64url');
 if(b.length!==64||b.toString('base64url')!==s)fail('LOCAL_REVIEW_ROTATION_MALFORMED');
 return b;
};
async function checkedReceipts(previousReceipt,successorReceipt,resolveObserverPublicKey,expectedRootPin){
 if(typeof resolveObserverPublicKey!=='function'||typeof expectedRootPin!=='string'||!HEX.test(expectedRootPin))
  fail('LOCAL_REVIEW_ROTATION_INVALID_OPTIONS');
 const a=await verifyLocalReviewObserverReceipt(previousReceipt,{resolveObserverPublicKey,expectedRootPin});
 const b=await verifyLocalReviewObserverReceipt(successorReceipt,{resolveObserverPublicKey,expectedRootPin});
 const old=a.receipt,next=b.receipt;
 if(old.observerId!==next.observerId||old.keyId===next.keyId||next.sequence!==1||
  a.observerKeyFingerprint===b.observerKeyFingerprint||
  next.head.count<old.head.count||
  old.recordDigests.some((d,i)=>next.recordDigests[i]!==d))
  fail('LOCAL_REVIEW_ROTATION_NON_EXTENSION');
 return {old,next,oldFingerprint:a.observerKeyFingerprint,newFingerprint:b.observerKeyFingerprint};
}
async function resolveKeys(resolver,observerId,oldKeyId,newKeyId){
 let oldKey,newKey;
 try{[oldKey,newKey]=await Promise.all([resolver(observerId,oldKeyId),resolver(observerId,newKeyId)]);}
 catch{fail('LOCAL_REVIEW_ROTATION_UNTRUSTED_KEY');}
 if(!keyValid(oldKey,'public')||!keyValid(newKey,'public'))fail('LOCAL_REVIEW_ROTATION_UNTRUSTED_KEY');
 return {oldKey,newKey};
}
export async function verifyLocalReviewObserverKeyRotation(rotation,{previousReceipt,successorReceipt,
 resolveObserverPublicKey,expectedRootPin}={}){
 const {old,next,oldFingerprint,newFingerprint}=await checkedReceipts(previousReceipt,successorReceipt,
  resolveObserverPublicKey,expectedRootPin);
 if(!exact(rotation,ALL))fail('LOCAL_REVIEW_ROTATION_MALFORMED');
 const body=Object.fromEntries(FIELDS.map(k=>[k,rotation[k]]));
 if(body.schema!==LOCAL_REVIEW_ROTATION_SCHEMA||body.rootPin!==expectedRootPin||
  body.observerId!==old.observerId||body.oldKeyId!==old.keyId||body.newKeyId!==next.keyId||
  body.oldKeyFingerprint!==oldFingerprint||body.newKeyFingerprint!==newFingerprint||
  body.previousReceiptDigest!==old.receiptDigest||body.successorReceiptDigest!==next.receiptDigest||
  body.authority!=='NONE'||typeof rotation.rotationDigest!=='string'||!HEX.test(rotation.rotationDigest))
  fail('LOCAL_REVIEW_ROTATION_MALFORMED');
 const oldSig=signatureBytes(rotation.oldSignature),newSig=signatureBytes(rotation.newSignature);
 if(rotation.rotationDigest!==rotationDigest(body,rotation.oldSignature,rotation.newSignature))
  fail('LOCAL_REVIEW_ROTATION_TAMPERED');
 const {oldKey,newKey}=await resolveKeys(resolveObserverPublicKey,old.observerId,old.keyId,next.keyId);
 if(!verifyEd(null,bytes(body),oldKey,oldSig)||!verifyEd(null,bytes(body),newKey,newSig))
  fail('LOCAL_REVIEW_ROTATION_BAD_SIGNATURE');
 return Object.freeze({rotationDigest:rotation.rotationDigest,observerId:old.observerId,
  previousReceiptDigest:old.receiptDigest,successorReceiptDigest:next.receiptDigest,
  oldKeyFingerprint:oldFingerprint,newKeyFingerprint:newFingerprint,
  historyPrefixVerified:true,dualSignatureVerified:true,independentKeyCustodyVerified:false,
  independentlyRetainedPinVerified:false,authorizesProduction:false,shopifyWritesAllowed:false});
}
export async function createLocalReviewObserverKeyRotation({previousReceipt,successorReceipt,
 resolveObserverPublicKey,expectedRootPin,oldSigningKey,newSigningKey}={}){
 if(!keyValid(oldSigningKey,'private')||!keyValid(newSigningKey,'private'))
  fail('LOCAL_REVIEW_ROTATION_INVALID_OPTIONS');
 const {old,next,oldFingerprint,newFingerprint}=await checkedReceipts(previousReceipt,successorReceipt,
  resolveObserverPublicKey,expectedRootPin);
 const body={schema:LOCAL_REVIEW_ROTATION_SCHEMA,rootPin:expectedRootPin,
  observerId:old.observerId,oldKeyId:old.keyId,newKeyId:next.keyId,
  oldKeyFingerprint:oldFingerprint,newKeyFingerprint:newFingerprint,
  previousReceiptDigest:old.receiptDigest,successorReceiptDigest:next.receiptDigest,authority:'NONE'};
 const oldSignature=signEd(null,bytes(body),oldSigningKey).toString('base64url');
 const newSignature=signEd(null,bytes(body),newSigningKey).toString('base64url');
 const rotation=Object.freeze({...body,oldSignature,newSignature,
  rotationDigest:rotationDigest(body,oldSignature,newSignature)});
 await verifyLocalReviewObserverKeyRotation(rotation,{previousReceipt,successorReceipt,
  resolveObserverPublicKey,expectedRootPin});
 return rotation;
}
const PIN_FIELDS=['schema','rootPin','previousReceipt','successorReceipt','rotation'];
/** Export canonical bytes for storage OUTSIDE the journal. Retain SHA256 out of band. */
export async function exportLocalReviewRotationPin({rotation,previousReceipt,successorReceipt,
 resolveObserverPublicKey,expectedRootPin}={}){
 await verifyLocalReviewObserverKeyRotation(rotation,{previousReceipt,successorReceipt,
  resolveObserverPublicKey,expectedRootPin});
 const envelope={schema:LOCAL_REVIEW_PIN_SCHEMA,rootPin:expectedRootPin,
  previousReceipt,successorReceipt,rotation};
 const payload=Buffer.from(JSON.stringify(envelope),'utf8');
 if(payload.length>262144)fail('LOCAL_REVIEW_PIN_OVERSIZED');
 return Object.freeze({bytes:Buffer.from(payload),sha256:hash(payload),
  independentlyRetained:false,authorizesProduction:false,shopifyWritesAllowed:false});
}
/** Import requires an externally supplied digest AND a previously retained receipt digest.
 * A digest supplied by the same untrusted bundle is NOT independent evidence.
 */
export async function importLocalReviewRotationPin({bytes:input,expectedSha256,
 expectedPreviousReceiptDigest,expectedRootPin,resolveObserverPublicKey}={}){
 if(!Buffer.isBuffer(input)||input.length<2||input.length>262144||
  typeof expectedSha256!=='string'||!HEX.test(expectedSha256)||
  typeof expectedPreviousReceiptDigest!=='string'||!HEX.test(expectedPreviousReceiptDigest)||
  typeof expectedRootPin!=='string'||!HEX.test(expectedRootPin))fail('LOCAL_REVIEW_PIN_INVALID_OPTIONS');
 const actual=Buffer.from(hash(input),'hex'),expected=Buffer.from(expectedSha256,'hex');
 if(!timingSafeEqual(actual,expected))fail('LOCAL_REVIEW_PIN_DIGEST_MISMATCH');
 let envelope;
 try{envelope=JSON.parse(input.toString('utf8'));}catch{fail('LOCAL_REVIEW_PIN_MALFORMED');}
 if(!exact(envelope,PIN_FIELDS)||envelope.schema!==LOCAL_REVIEW_PIN_SCHEMA||
  envelope.rootPin!==expectedRootPin||
  !Buffer.from(JSON.stringify(envelope)).equals(input))fail('LOCAL_REVIEW_PIN_MALFORMED');
 if(envelope.previousReceipt?.receiptDigest!==expectedPreviousReceiptDigest)
  fail('LOCAL_REVIEW_PIN_ANCHOR_MISMATCH');
 const checked=await verifyLocalReviewObserverKeyRotation(envelope.rotation,{previousReceipt:envelope.previousReceipt,
  successorReceipt:envelope.successorReceipt,resolveObserverPublicKey,expectedRootPin});
 return Object.freeze({schema:LOCAL_REVIEW_PIN_SCHEMA,sha256:expectedSha256,
  rotationDigest:checked.rotationDigest,previousReceiptDigest:checked.previousReceiptDigest,
  successorReceiptDigest:checked.successorReceiptDigest,historyPrefixVerified:true,
  dualSignatureVerified:true,externallySuppliedDigestMatched:true,
  independentDigestCustodyVerified:false,independentKeyCustodyVerified:false,
  authorizesProduction:false,shopifyWritesAllowed:false});
}
