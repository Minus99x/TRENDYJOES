/**
 * Objective 32L — offline read-only, two-party conflict-proof exchange.
 * Public keys, proof pins, session/nonces and replay state MUST be supplied by
 * independent channels. Nothing here is hosted identity or durable replay storage.
 */
import {createHash,sign,verify,KeyObject,createPublicKey} from 'node:crypto';
import {verifyOfflineSplitViewConflictProof} from './offline-portable-split-view-conflict-proof.mjs';

export const OFFLINE_CONFLICT_EXCHANGE_SCHEMA='TJ-OFFLINE-CONFLICT-EXCHANGE-1';
const MAX_RECEIPT_BYTES=4096;
const MAX_LIFETIME_MS=5*60*1000;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hash=(domain,bytes)=>createHash('sha256').update(domain+'\0').update(bytes).digest('hex');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const token=x=>typeof x==='string'&&/^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/.test(x);
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
function exact(o,fields){
 return plain(o)&&Object.keys(o).length===fields.length&&fields.every(k=>{
  const d=Object.getOwnPropertyDescriptor(o,k);
  return d&&Object.hasOwn(d,'value')&&d.enumerable;
 })&&Object.keys(o).every(k=>fields.includes(k));
}
const canonical=x=>Buffer.from(JSON.stringify(x));
const OFFER_FIELDS=['schema','role','sessionId','senderId','receiverId','senderNonce','receiverChallenge','sequence','previousExchangeDigest','proofDigest','proofInventoryDigest','issuedAt','expiresAt'];
const ACK_FIELDS=['schema','role','sessionId','senderId','receiverId','senderNonce','receiverChallenge','sequence','previousExchangeDigest','proofDigest','proofInventoryDigest','issuedAt','expiresAt','offerDigest'];
function bodyCheck(b,role){
 const fields=role==='OFFER'?OFFER_FIELDS:ACK_FIELDS;
 if(!exact(b,fields)||b.schema!==OFFLINE_CONFLICT_EXCHANGE_SCHEMA||b.role!==role||
  ![b.sessionId,b.senderId,b.receiverId,b.senderNonce,b.receiverChallenge].every(token)||
  b.senderId===b.receiverId||!Number.isSafeInteger(b.sequence)||b.sequence<1||
  ![b.previousExchangeDigest,b.proofDigest,b.proofInventoryDigest].every(hex)||
  !Number.isSafeInteger(b.issuedAt)||!Number.isSafeInteger(b.expiresAt)||
  b.issuedAt<0||b.expiresAt<=b.issuedAt||b.expiresAt-b.issuedAt>MAX_LIFETIME_MS||
  (role==='ACK'&&!hex(b.offerDigest)))fail('EXCHANGE32L_BODY_INVALID');
 return b;
}
function receiptCheck(r,role){
 if(!exact(r,['body','signature'])||typeof r.signature!=='string'||
  !/^[A-Za-z0-9_-]{86}$/.test(r.signature))fail('EXCHANGE32L_RECEIPT_INVALID');
 const sig=Buffer.from(r.signature,'base64url');
 if(sig.length!==64||sig.toString('base64url')!==r.signature)fail('EXCHANGE32L_RECEIPT_INVALID');
 bodyCheck(r.body,role);
 return sig;
}
const signingBytes=body=>Buffer.concat([Buffer.from('TJ-32L-ED25519-'+body.role+'\0'),canonical(body)]);
function keyCheck(key,kind){
 if(!(key instanceof KeyObject)||key.type!==kind||key.asymmetricKeyType!=='ed25519')
  fail('EXCHANGE32L_KEY_INVALID');
 return key;
}
function makeReceipt(body,privateKey){
 bodyCheck(body,body.role);
 keyCheck(privateKey,'private');
 const signature=sign(null,signingBytes(body),privateKey).toString('base64url');
 return Object.freeze({body:Object.freeze({...body}),signature});
}
function distinctKeys(senderPublicKey,receiverPublicKey){
 keyCheck(senderPublicKey,'public');keyCheck(receiverPublicKey,'public');
 if(senderPublicKey.export({type:'spki',format:'der'}).equals(receiverPublicKey.export({type:'spki',format:'der'})))
  fail('EXCHANGE32L_INDEPENDENT_KEYS_REQUIRED');
}
function checkSignature(r,role,publicKey){
 const sig=receiptCheck(r,role);
 keyCheck(publicKey,'public');
 if(!verify(null,signingBytes(r.body),publicKey,sig))fail('EXCHANGE32L_SIGNATURE_INVALID');
}
function contextCheck({proofBytes,expectedPin,expectedProofDigest}){
 if(!Buffer.isBuffer(proofBytes)||!hex(expectedProofDigest)||sha(proofBytes)!==expectedProofDigest)
  fail('EXCHANGE32L_PROOF_DIGEST_MISMATCH');
 const result=verifyOfflineSplitViewConflictProof({bytes:proofBytes,expectedPin});
 if(!result.verified||result.inventoryDigest!==expectedPin.inventoryDigest)
  fail('EXCHANGE32L_PROOF_INVALID');
 return result;
}
function expectations({sessionId,senderId,receiverId,senderNonce,receiverChallenge,sequence,previousExchangeDigest}){
 if(![sessionId,senderId,receiverId,senderNonce,receiverChallenge].every(token)||
  senderId===receiverId||!Number.isSafeInteger(sequence)||sequence<1||!hex(previousExchangeDigest))
  fail('EXCHANGE32L_EXPECTATIONS_INVALID');
 return {sessionId,senderId,receiverId,senderNonce,receiverChallenge,sequence,previousExchangeDigest};
}
function expectedBody(b,e,proofDigest,inventoryDigest){
 for(const k of ['sessionId','senderId','receiverId','senderNonce','receiverChallenge','sequence','previousExchangeDigest'])
  if(b[k]!==e[k])fail('EXCHANGE32L_CONTEXT_MISMATCH');
 if(b.proofDigest!==proofDigest||b.proofInventoryDigest!==inventoryDigest)
  fail('EXCHANGE32L_PROOF_BINDING_MISMATCH');
}
function clockCheck(b,nowMs){
 if(!Number.isSafeInteger(nowMs)||nowMs<0)fail('EXCHANGE32L_CLOCK_REQUIRED');
 if(b.issuedAt>nowMs||nowMs>=b.expiresAt)fail('EXCHANGE32L_EXPIRED_OR_FUTURE');
}
export function offlineConflictExchangeReceiptDigest(receipt){
 if(!plain(receipt)||!plain(receipt.body)||!['OFFER','ACK'].includes(receipt.body.role))
  fail('EXCHANGE32L_RECEIPT_INVALID');
 receiptCheck(receipt,receipt.body.role);
 return hash('TJ-32L-RECEIPT',canonical(receipt));
}
/** Create an offer only after full cryptographic proof verification. */
export function createOfflineConflictExchangeOffer({proofBytes,expectedPin,expectedProofDigest,
 senderPrivateKey,issuedAt,expiresAt,...identity}={}){
 const e=expectations(identity);
 contextCheck({proofBytes,expectedPin,expectedProofDigest});
 return makeReceipt({schema:OFFLINE_CONFLICT_EXCHANGE_SCHEMA,role:'OFFER',...e,
  proofDigest:expectedProofDigest,proofInventoryDigest:expectedPin.inventoryDigest,issuedAt,expiresAt},senderPrivateKey);
}
/** Independently verify the offer before countersigning the same evidence. */
export function acceptOfflineConflictExchangeOffer({offer,proofBytes,expectedPin,expectedProofDigest,
 senderPublicKey,receiverPrivateKey,nowMs,issuedAt,expiresAt,...identity}={}){
 const e=expectations(identity);
 distinctKeys(senderPublicKey,createPublicKey(keyCheck(receiverPrivateKey,'private')));
 checkSignature(offer,'OFFER',senderPublicKey);
 const verified=contextCheck({proofBytes,expectedPin,expectedProofDigest});
 expectedBody(offer.body,e,expectedProofDigest,verified.inventoryDigest);
 clockCheck(offer.body,nowMs);
 if(!Number.isSafeInteger(issuedAt)||!Number.isSafeInteger(expiresAt)||
  issuedAt<offer.body.issuedAt||issuedAt>nowMs||issuedAt>=offer.body.expiresAt||
  expiresAt>offer.body.expiresAt)fail('EXCHANGE32L_ACK_WINDOW_INVALID');
 const offerDigest=offlineConflictExchangeReceiptDigest(offer);
 return makeReceipt({schema:OFFLINE_CONFLICT_EXCHANGE_SCHEMA,role:'ACK',...e,
  proofDigest:expectedProofDigest,proofInventoryDigest:verified.inventoryDigest,
  issuedAt,expiresAt,offerDigest},receiverPrivateKey);
}
/**
 * Pure verifier. Caller must independently pin BOTH keys, expected nonces,
 * sequence/previous digest, and durably reject a previously seen exchange digest.
 */
export function verifyOfflineConflictExchange({offer,ack,proofBytes,expectedPin,expectedProofDigest,
 senderPublicKey,receiverPublicKey,nowMs,seenExchangeDigests=[],...identity}={}){
 const e=expectations(identity);
 distinctKeys(senderPublicKey,receiverPublicKey);
 checkSignature(offer,'OFFER',senderPublicKey);
 checkSignature(ack,'ACK',receiverPublicKey);
 const verified=contextCheck({proofBytes,expectedPin,expectedProofDigest});
 expectedBody(offer.body,e,expectedProofDigest,verified.inventoryDigest);
 expectedBody(ack.body,e,expectedProofDigest,verified.inventoryDigest);
 clockCheck(offer.body,nowMs);clockCheck(ack.body,nowMs);
 if(ack.body.issuedAt<offer.body.issuedAt||ack.body.issuedAt>=offer.body.expiresAt||
  ack.body.expiresAt>offer.body.expiresAt)fail('EXCHANGE32L_ACK_WINDOW_INVALID');
 const offerDigest=offlineConflictExchangeReceiptDigest(offer);
 if(ack.body.offerDigest!==offerDigest)fail('EXCHANGE32L_OFFER_BINDING_MISMATCH');
 const ackDigest=offlineConflictExchangeReceiptDigest(ack);
 const exchangeDigest=hash('TJ-32L-EXCHANGE',canonical({offerDigest,ackDigest}));
 if(!Array.isArray(seenExchangeDigests)||seenExchangeDigests.length>4096||
  seenExchangeDigests.some(x=>!hex(x)))fail('EXCHANGE32L_REPLAY_STATE_INVALID');
 if(seenExchangeDigests.includes(exchangeDigest))fail('EXCHANGE32L_REPLAY_DETECTED');
 return Object.freeze({schema:OFFLINE_CONFLICT_EXCHANGE_SCHEMA,verified:true,readOnly:true,
  exchangeDigest,offerDigest,ackDigest,proofDigest:expectedProofDigest,
  proofInventoryDigest:verified.inventoryDigest,sequence:e.sequence,
  independentlyPublished:false,authenticatedHostedIdentity:false,
  externalReplayStatePersisted:false,globalUniquenessVerified:false,
  authorizesCheckout:false,authorizesRemediation:false,productionApproved:false});
}
/** Byte-oriented strict transport codec; refuses noncanonical/duplicate-key JSON. */
export function encodeOfflineConflictExchangeTranscript({offer,ack}={}){
 receiptCheck(offer,'OFFER');receiptCheck(ack,'ACK');
 const bytes=canonical({schema:OFFLINE_CONFLICT_EXCHANGE_SCHEMA,offer,ack});
 if(bytes.length>MAX_RECEIPT_BYTES)fail('EXCHANGE32L_TRANSCRIPT_TOO_LARGE');
 return bytes;
}
export function decodeOfflineConflictExchangeTranscript(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length===0||bytes.length>MAX_RECEIPT_BYTES)
  fail('EXCHANGE32L_TRANSCRIPT_INVALID');
 let payload;try{payload=JSON.parse(bytes.toString('utf8'));}catch{fail('EXCHANGE32L_TRANSCRIPT_INVALID');}
 if(!exact(payload,['schema','offer','ack'])||payload.schema!==OFFLINE_CONFLICT_EXCHANGE_SCHEMA||
  !canonical(payload).equals(bytes))fail('EXCHANGE32L_TRANSCRIPT_INVALID');
 receiptCheck(payload.offer,'OFFER');receiptCheck(payload.ack,'ACK');
 return Object.freeze({offer:payload.offer,ack:payload.ack});
}

/** Domain-separated transcript digest; compare only with separately obtained pins. */
export function offlineConflictExchangeTranscriptDigest(bytes){
 decodeOfflineConflictExchangeTranscript(bytes);
 return hash('TJ-32L-TRANSCRIPT',bytes);
}
/**
 * Reconcile sender/receiver copies with independently pinned transcript digests.
 * Requires BOTH complete views in fixed role order; never infers publication.
 */
export function reconcileOfflineConflictExchangeViews({observations,
 expectedSenderTranscriptDigest,expectedReceiverTranscriptDigest,...verification}={}){
 if(!Array.isArray(observations)||observations.length!==2||
  !hex(expectedSenderTranscriptDigest)||!hex(expectedReceiverTranscriptDigest))
  fail('EXCHANGE32L_TWO_PINNED_VIEWS_REQUIRED');
 const e=expectations(verification);
 const ids=[e.senderId,e.receiverId],pins=[expectedSenderTranscriptDigest,expectedReceiverTranscriptDigest];
 const results=[];
 for(let i=0;i<2;i++){
  const o=observations[i];
  if(!exact(o,['partyId','transcriptBytes'])||o.partyId!==ids[i]||!Buffer.isBuffer(o.transcriptBytes))
   fail('EXCHANGE32L_VIEW_ORDER_OR_OMISSION');
  const digest=offlineConflictExchangeTranscriptDigest(o.transcriptBytes);
  if(digest!==pins[i])fail('EXCHANGE32L_VIEW_PIN_MISMATCH');
  const {offer,ack}=decodeOfflineConflictExchangeTranscript(o.transcriptBytes);
  results.push(verifyOfflineConflictExchange({...verification,offer,ack}));
 }
 if(results[0].exchangeDigest!==results[1].exchangeDigest)fail('EXCHANGE32L_EQUIVOCATION_DETECTED');
 return Object.freeze({verified:true,readOnly:true,viewsReconciled:2,
  exchangeDigest:results[0].exchangeDigest,proofInventoryDigest:results[0].proofInventoryDigest,
  independentlyPublished:false,externalPinPublicationVerified:false,
  externalReplayStatePersisted:false,authorizesCheckout:false,
  authorizesRemediation:false,productionApproved:false});
}
