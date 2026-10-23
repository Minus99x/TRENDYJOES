/** Objective 35AN: offline dual-signed receipt signer cutover.
 * Caller MUST independently authenticate both per-window pins and the rotation
 * digest. This is not external custody, key revocation, or fork consensus.
 */
import {createHash,sign,verify,timingSafeEqual} from 'node:crypto';
import {verifyOfflineRetentionReceiptWindow} from './preview-local-artwork-retention-receipts.mjs';

export const OFFLINE_RETENTION_ROTATION_SCHEMA='TJ-LOCAL-RETENTION-ROTATION-35AN-1';
const DOMAIN=Buffer.from('TJ35AN_RETENTION_KEY_CUTOVER\0');
const HEX=/^[0-9a-f]{64}$/;
const B64=/^[A-Za-z0-9_-]+$/;
const BODY=['schema','streamId','cutoverSequence','priorReceiptSha256','nextReceiptSha256','cutoverAtMs','oldSignerFingerprint','newSignerFingerprint','authority'];
const ENVELOPE=['schema','body','oldSignature','newSignature'];
const EXTERNAL=['oldPins','newPins','expectedRotationSha256'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hash=b=>createHash('sha256').update(b).digest('hex');
const hex=x=>typeof x==='string'&&HEX.test(x);
const equal=(a,b)=>hex(a)&&hex(b)&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
const uint=x=>Number.isSafeInteger(x)&&x>=0;
const time=x=>uint(x)&&x<1e15;
const exact=(x,keys)=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null)&&
 Reflect.ownKeys(x).length===keys.length&&keys.every(k=>{
  const d=Object.getOwnPropertyDescriptor(x,k);return d?.enumerable&&'value'in d;
 });
const fp=k=>{
 if(k?.type!=='public'||k.asymmetricKeyType!=='ed25519')fail('OFFLINE_ROTATION_INVALID_KEY');
 return hash(k.export({type:'spki',format:'der'}));
};
const keyPair=(privateKey,publicKey)=>{
 if(privateKey?.type!=='private'||privateKey.asymmetricKeyType!=='ed25519')
  fail('OFFLINE_ROTATION_INVALID_KEY');
 if(!verify(null,Buffer.from('TJ35AN-key-pair'),publicKey,
  sign(null,Buffer.from('TJ35AN-key-pair'),privateKey)))fail('OFFLINE_ROTATION_KEY_MISMATCH');
};
const safePins=p=>exact(p,['mode','streamId','signerFingerprint','trustedNowMs','expectedHead','expectedAnchor','expectedCheckpoints'])&&
 exact(p.expectedHead,['sequence','receiptSha256'])&&
 (p.expectedAnchor===null||exact(p.expectedAnchor,['sequence','receiptSha256','observedAtMs','retainUntilMs']))&&
 Array.isArray(p.expectedCheckpoints)&&p.expectedCheckpoints.length>0&&p.expectedCheckpoints.length<=128&&
 Reflect.ownKeys(p.expectedCheckpoints).length===p.expectedCheckpoints.length+1&&
 p.expectedCheckpoints.every(x=>exact(x,['checkpoint','observedAtMs','retainUntilMs'])&&
  exact(x.checkpoint,['epoch','provenanceSha256','evidenceSha256','headSha256']));
const bodyValid=p=>exact(p,BODY)&&p.schema===OFFLINE_RETENTION_ROTATION_SCHEMA&&
 hex(p.streamId)&&uint(p.cutoverSequence)&&p.cutoverSequence>0&&
 hex(p.priorReceiptSha256)&&hex(p.nextReceiptSha256)&&
 !equal(p.priorReceiptSha256,p.nextReceiptSha256)&&time(p.cutoverAtMs)&&
 hex(p.oldSignerFingerprint)&&hex(p.newSignerFingerprint)&&
 !equal(p.oldSignerFingerprint,p.newSignerFingerprint)&&p.authority==='NONE';
const canonical=p=>Object.fromEntries(BODY.map(k=>[k,p[k]]));
function sigBytes(s){
 if(typeof s!=='string'||!B64.test(s))fail('OFFLINE_ROTATION_INVALID_ENVELOPE');
 const b=Buffer.from(s,'base64url');
 if(b.length!==64||b.toString('base64url')!==s)fail('OFFLINE_ROTATION_INVALID_ENVELOPE');
 return b;
}
function parse(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<250||bytes.length>1800)
  fail('OFFLINE_ROTATION_INVALID_ENVELOPE');
 let e;try{e=JSON.parse(bytes.toString('utf8'));}catch{fail('OFFLINE_ROTATION_INVALID_ENVELOPE');}
 if(!exact(e,ENVELOPE)||e.schema!==OFFLINE_RETENTION_ROTATION_SCHEMA||
  typeof e.body!=='string'||!B64.test(e.body)||
  !Buffer.from(JSON.stringify(Object.fromEntries(ENVELOPE.map(k=>[k,e[k]])))).equals(bytes))
  fail('OFFLINE_ROTATION_INVALID_ENVELOPE');
 const oldSignature=sigBytes(e.oldSignature),newSignature=sigBytes(e.newSignature);
 const body=Buffer.from(e.body,'base64url');
 if(body.toString('base64url')!==e.body||body.length<150||body.length>1200)
  fail('OFFLINE_ROTATION_INVALID_ENVELOPE');
 let p;try{p=JSON.parse(body.toString('utf8'));}catch{fail('OFFLINE_ROTATION_INVALID_BODY');}
 if(!bodyValid(p)||!Buffer.from(JSON.stringify(canonical(p))).equals(body))
  fail('OFFLINE_ROTATION_INVALID_BODY');
 return {p,body,oldSignature,newSignature};
}
/** Signing belongs to an offline trusted issuer, never a browser. */
export function createOfflineRetentionKeyRotation({streamId,cutoverSequence,priorReceiptSha256,
 nextReceiptSha256,cutoverAtMs,oldSigningKey,oldPublicKey,newSigningKey,newPublicKey}={}){
 const oldSignerFingerprint=fp(oldPublicKey),newSignerFingerprint=fp(newPublicKey);
 const p={schema:OFFLINE_RETENTION_ROTATION_SCHEMA,streamId,cutoverSequence,
  priorReceiptSha256,nextReceiptSha256,cutoverAtMs,oldSignerFingerprint,
  newSignerFingerprint,authority:'NONE'};
 if(!bodyValid(p))fail('OFFLINE_ROTATION_INVALID_BODY');
 keyPair(oldSigningKey,oldPublicKey);keyPair(newSigningKey,newPublicKey);
 const body=Buffer.from(JSON.stringify(canonical(p)));
 const signed=Buffer.concat([DOMAIN,body]);
 const bytes=Buffer.from(JSON.stringify({schema:OFFLINE_RETENTION_ROTATION_SCHEMA,
  body:body.toString('base64url'),oldSignature:sign(null,signed,oldSigningKey).toString('base64url'),
  newSignature:sign(null,signed,newSigningKey).toString('base64url')}));
 return Object.freeze({bytes,sha256:hash(bytes),oldSignerFingerprint,newSignerFingerprint});
}
/** Independently pinned dual-key cutover. Old window ends at predecessor,
 * new append window starts at its successor. Both are verified by 35AM.
 */
export function verifyOfflineRetentionKeyRotation({oldReceiptBytes,newReceiptBytes,
 rotationBytes,externalPins,oldPublicKey,newPublicKey}={}){
 if(!exact(externalPins,EXTERNAL)||!hex(externalPins.expectedRotationSha256)||
  !safePins(externalPins.oldPins)||!safePins(externalPins.newPins)||
  !Array.isArray(oldReceiptBytes)||!Array.isArray(newReceiptBytes)||
  !oldReceiptBytes.length||!newReceiptBytes.length)
  fail('OFFLINE_ROTATION_MISSING_EXTERNAL_PINS');
 const old=externalPins.oldPins, next=externalPins.newPins;
 if(!Buffer.isBuffer(rotationBytes)||!equal(hash(rotationBytes),externalPins.expectedRotationSha256))
  fail('OFFLINE_ROTATION_EXTERNAL_DIGEST_MISMATCH');
 const {p,body,oldSignature,newSignature}=parse(rotationBytes);
 const oldFingerprint=fp(oldPublicKey),newFingerprint=fp(newPublicKey);
 if(equal(oldFingerprint,newFingerprint)||!equal(p.oldSignerFingerprint,oldFingerprint)||
  !equal(p.newSignerFingerprint,newFingerprint)||
  !equal(old.signerFingerprint,oldFingerprint)||!equal(next.signerFingerprint,newFingerprint))
  fail('OFFLINE_ROTATION_SIGNER_SUBSTITUTION');
 const signed=Buffer.concat([DOMAIN,body]);
 if(!verify(null,signed,oldPublicKey,oldSignature)||
  !verify(null,signed,newPublicKey,newSignature))fail('OFFLINE_ROTATION_INVALID_SIGNATURE');
 if(!equal(p.streamId,old.streamId)||!equal(p.streamId,next.streamId)||
  next.mode!=='append'||old.mode==='pruned'||
  !time(old.trustedNowMs)||old.trustedNowMs!==next.trustedNowMs||
  !time(p.cutoverAtMs)||p.cutoverAtMs>old.trustedNowMs||
  !uint(old.expectedHead?.sequence)||p.cutoverSequence!==old.expectedHead.sequence+1||
  !equal(p.priorReceiptSha256,old.expectedHead.receiptSha256)||
  !Buffer.isBuffer(newReceiptBytes[0])||
  !equal(p.nextReceiptSha256,hash(newReceiptBytes[0]))||
  !equal(next.expectedAnchor?.receiptSha256,p.priorReceiptSha256)||
  next.expectedAnchor?.sequence!==old.expectedHead.sequence||
  next.expectedHead?.sequence< p.cutoverSequence)
  fail('OFFLINE_ROTATION_BOUNDARY_MISMATCH');
 // The preceding receipt is authenticated by the old signer, and its time pin
 // is authenticated by the 35AM verifier before any success can be returned.
 const previous=old.expectedCheckpoints?.[old.expectedCheckpoints.length-1];
 if(!previous||!time(previous.observedAtMs)||p.cutoverAtMs<=previous.observedAtMs||
  p.cutoverAtMs!==next.expectedCheckpoints?.[0]?.observedAtMs||
  next.expectedAnchor?.observedAtMs!==previous.observedAtMs||
  next.expectedAnchor?.retainUntilMs!==previous.retainUntilMs)
  fail('OFFLINE_ROTATION_BOUNDARY_MISMATCH');
 const oldResult=verifyOfflineRetentionReceiptWindow({receiptBytes:oldReceiptBytes,
  externalPins:old,signerPublicKey:oldPublicKey});
 const newResult=verifyOfflineRetentionReceiptWindow({receiptBytes:newReceiptBytes,
  externalPins:next,signerPublicKey:newPublicKey});
 if(oldResult.lastSequence+1!==newResult.firstSequence||
  !equal(oldResult.headSha256,p.priorReceiptSha256)||
  !equal(newResult.verifiedReceipts[0].receiptSha256,p.nextReceiptSha256))
  fail('OFFLINE_ROTATION_BOUNDARY_MISMATCH');
 return Object.freeze({schema:OFFLINE_RETENTION_ROTATION_SCHEMA,
  oldVerifiedCount:oldResult.verifiedCount,newVerifiedCount:newResult.verifiedCount,
  cutoverSequence:p.cutoverSequence,rotationSha256:hash(rotationBytes),
  headSha256:newResult.headSha256,oldSignerFingerprint:oldFingerprint,newSignerFingerprint:newFingerprint,
  bothSignaturesVerified:true,independentlyPinnedRotationMatched:true,
  independentlyCustodied:false,completeHistoryVerified:oldResult.completeHistoryVerified,
  trustedClockIndependentlyVerified:false,authorizesProduction:false});
}
