import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {make,now} from './support/objective32l-fixture.mjs';
import {createOfflineConflictExchangeOffer,acceptOfflineConflictExchangeOffer,
 verifyOfflineConflictExchange,encodeOfflineConflictExchangeTranscript,
 decodeOfflineConflictExchangeTranscript,offlineConflictExchangeReceiptDigest,
 OFFLINE_CONFLICT_EXCHANGE_SCHEMA} from '../src/offline-conflict-proof-exchange.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const sender=generateKeyPairSync('ed25519'),receiver=generateKeyPairSync('ed25519'),other=generateKeyPairSync('ed25519');
const E={sessionId:'session_32l_0001',senderId:'sender_32l_0001',receiverId:'receiver_32l_0001',
 senderNonce:'sender_nonce_32l_0001',receiverChallenge:'receiver_challenge_32l_0001',sequence:4,
 previousExchangeDigest:sha('previous-exchange')};
const err=code=>e=>e?.code===code;
function setup(){
 const proof=make(),proofBytes=proof.bytes,expectedPin=proof.pinCandidate,expectedProofDigest=sha(proofBytes);
 const base={proofBytes,expectedPin,expectedProofDigest,...E};
 const offer=createOfflineConflictExchangeOffer({...base,senderPrivateKey:sender.privateKey,issuedAt:now,expiresAt:now+60000});
 const ack=acceptOfflineConflictExchangeOffer({...base,offer,senderPublicKey:sender.publicKey,
  receiverPrivateKey:receiver.privateKey,nowMs:now+1000,issuedAt:now+1000,expiresAt:now+59000});
 const args={...base,offer,ack,senderPublicKey:sender.publicKey,receiverPublicKey:receiver.publicKey,nowMs:now+2000};
 return {args,proof,base,offer,ack};
}
function tamperReceipt(r,edit){const body={...r.body};edit(body);return {body,signature:r.signature};}
function tamperSig(r){return {...r,signature:(r.signature[0]==='A'?'B':'A')+r.signature.slice(1)};}
const verify=args=>verifyOfflineConflictExchange(args);
const caseTest=(name,fn)=>test('32L '+name,fn);
caseTest('full signed two-party proof exchange verifies the underlying fork',()=>{
 const f=setup(),v=verify(f.args);
 assert.equal(v.schema,OFFLINE_CONFLICT_EXCHANGE_SCHEMA);assert.equal(v.verified,true);
 assert.equal(v.readOnly,true);assert.equal(v.productionApproved,false);
 assert.equal(v.authenticatedHostedIdentity,false);assert.equal(v.externalReplayStatePersisted,false);
 assert.equal(v.proofInventoryDigest,f.proof.pinCandidate.inventoryDigest);
});
caseTest('portable transcript roundtrip remains independently verifiable',()=>{
 const f=setup(),bytes=encodeOfflineConflictExchangeTranscript(f),t=decodeOfflineConflictExchangeTranscript(bytes);
 assert.deepEqual(t.offer,f.offer);assert.deepEqual(t.ack,f.ack);
 assert.equal(verify({...f.args,...t}).verified,true);
 assert.equal(bytes.toString().includes('PRIVATE KEY'),false);
});
caseTest('deterministic receipt and exchange digests',()=>{
 const f=setup(),v=verify(f.args);assert.equal(v.offerDigest,offlineConflictExchangeReceiptDigest(f.offer));
 assert.equal(v.exchangeDigest,verify(f.args).exchangeDigest);
});
caseTest('missing independent pin rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,expectedPin:undefined}));});
caseTest('wrong independent proof digest rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,expectedProofDigest:sha('wrong')}),err('EXCHANGE32L_PROOF_DIGEST_MISMATCH'));});
caseTest('wrong proof inventory pin rejected even when exchange signatures valid',()=>{const f=setup();assert.throws(()=>verify({...f.args,expectedPin:{...f.proof.pinCandidate,inventoryDigest:sha('wrong')}}));});
caseTest('proof bytes substituted after exchange rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,proofBytes:Buffer.from('other')}),err('EXCHANGE32L_PROOF_DIGEST_MISMATCH'));});
caseTest('wrong sender public key rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,senderPublicKey:other.publicKey}),err('EXCHANGE32L_SIGNATURE_INVALID'));});
caseTest('wrong receiver public key rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,receiverPublicKey:other.publicKey}),err('EXCHANGE32L_SIGNATURE_INVALID'));});
caseTest('sender signature mutation rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,offer:tamperSig(f.offer)}),err('EXCHANGE32L_SIGNATURE_INVALID'));});
caseTest('receiver signature mutation rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,ack:tamperSig(f.ack)}),err('EXCHANGE32L_SIGNATURE_INVALID'));});
caseTest('sender identity substitution rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,senderId:'attacker_32l_0001'}),err('EXCHANGE32L_CONTEXT_MISMATCH'));});
caseTest('receiver identity substitution rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,receiverId:'attacker_32l_0001'}),err('EXCHANGE32L_CONTEXT_MISMATCH'));});
caseTest('session substitution rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,sessionId:'other_session_0001'}),err('EXCHANGE32L_CONTEXT_MISMATCH'));});
caseTest('sender nonce substitution rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,senderNonce:'other_nonce_00001'}),err('EXCHANGE32L_CONTEXT_MISMATCH'));});
caseTest('receiver challenge substitution rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,receiverChallenge:'other_challenge_00001'}),err('EXCHANGE32L_CONTEXT_MISMATCH'));});
caseTest('historical sequence rollback rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,sequence:3}),err('EXCHANGE32L_CONTEXT_MISMATCH'));});
caseTest('historical previous exchange rollback rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,previousExchangeDigest:sha('older')}),err('EXCHANGE32L_CONTEXT_MISMATCH'));});
caseTest('previously consumed exchange digest rejected',()=>{const f=setup(),v=verify(f.args);assert.throws(()=>verify({...f.args,seenExchangeDigests:[v.exchangeDigest]}),err('EXCHANGE32L_REPLAY_DETECTED'));});
caseTest('malformed replay state fails closed',()=>{const f=setup();assert.throws(()=>verify({...f.args,seenExchangeDigests:['not-a-digest']}),err('EXCHANGE32L_REPLAY_STATE_INVALID'));});
caseTest('expired offer rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,nowMs:now+61000}),err('EXCHANGE32L_EXPIRED_OR_FUTURE'));});
caseTest('future offer rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,nowMs:now-1}),err('EXCHANGE32L_EXPIRED_OR_FUTURE'));});
caseTest('expired acknowledgement rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,nowMs:now+59000}),err('EXCHANGE32L_EXPIRED_OR_FUTURE'));});
caseTest('invalid clock fails closed',()=>{const f=setup();assert.throws(()=>verify({...f.args,nowMs:NaN}),err('EXCHANGE32L_CLOCK_REQUIRED'));});
caseTest('offer signed field mutation rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,offer:tamperReceipt(f.offer,b=>b.sequence++)}),err('EXCHANGE32L_SIGNATURE_INVALID'));});
caseTest('ack signed offer digest mutation rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,ack:tamperReceipt(f.ack,b=>b.offerDigest=sha('other'))}),err('EXCHANGE32L_SIGNATURE_INVALID'));});
caseTest('ack from a different valid signed offer rejected',()=>{
 const f=setup(),b=f.base;
 const alternate=createOfflineConflictExchangeOffer({...b,senderPrivateKey:sender.privateKey,issuedAt:now+1,expiresAt:now+60000});
 assert.throws(()=>verify({...f.args,offer:alternate}),err('EXCHANGE32L_OFFER_BINDING_MISMATCH'));
});
caseTest('cross-party signing key mismatch during acceptance rejected',()=>{
 const f=setup();assert.throws(()=>acceptOfflineConflictExchangeOffer({...f.base,offer:f.offer,
  senderPublicKey:other.publicKey,receiverPrivateKey:receiver.privateKey,
  nowMs:now+1000,issuedAt:now+1000,expiresAt:now+59000}),err('EXCHANGE32L_SIGNATURE_INVALID'));
});
caseTest('cross-party challenge mismatch during acceptance rejected',()=>{
 const f=setup();assert.throws(()=>acceptOfflineConflictExchangeOffer({...f.base,receiverChallenge:'other_challenge_0001',offer:f.offer,
  senderPublicKey:sender.publicKey,receiverPrivateKey:receiver.privateKey,
  nowMs:now+1000,issuedAt:now+1000,expiresAt:now+59000}),err('EXCHANGE32L_CONTEXT_MISMATCH'));
});
caseTest('non-Ed25519 signer rejected',()=>{const f=setup();assert.throws(()=>createOfflineConflictExchangeOffer({...f.base,
 senderPrivateKey:other.publicKey,issuedAt:now,expiresAt:now+60000}),err('EXCHANGE32L_KEY_INVALID'));});
caseTest('receipt with unexpected production approval field rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,offer:{...f.offer,productionApproved:true}}),err('EXCHANGE32L_RECEIPT_INVALID'));});
caseTest('body with injected production approval field rejected',()=>{const f=setup();assert.throws(()=>verify({...f.args,ack:{...f.ack,body:{...f.ack.body,productionApproved:true}}}),err('EXCHANGE32L_BODY_INVALID'));});
caseTest('transport refuses noncanonical whitespace',()=>{const f=setup(),bytes=encodeOfflineConflictExchangeTranscript(f);
 assert.throws(()=>decodeOfflineConflictExchangeTranscript(Buffer.concat([Buffer.from(' '),bytes])),err('EXCHANGE32L_TRANSCRIPT_INVALID'));
});
caseTest('transport refuses duplicate JSON keys',()=>{const f=setup(),bytes=encodeOfflineConflictExchangeTranscript(f);
 const altered=bytes.toString().replace('"schema":"TJ-OFFLINE-CONFLICT-EXCHANGE-1",','"schema":"TJ-OFFLINE-CONFLICT-EXCHANGE-1","schema":"TJ-OFFLINE-CONFLICT-EXCHANGE-1",');
 assert.throws(()=>decodeOfflineConflictExchangeTranscript(Buffer.from(altered)),err('EXCHANGE32L_TRANSCRIPT_INVALID'));
});
caseTest('transport refuses omitted receipt',()=>{const f=setup();assert.throws(()=>decodeOfflineConflictExchangeTranscript(Buffer.from(JSON.stringify({schema:OFFLINE_CONFLICT_EXCHANGE_SCHEMA,offer:f.offer}))),err('EXCHANGE32L_TRANSCRIPT_INVALID'));});
caseTest('transport refuses extra checkout authorization',()=>{const f=setup();assert.throws(()=>decodeOfflineConflictExchangeTranscript(Buffer.from(JSON.stringify({schema:OFFLINE_CONFLICT_EXCHANGE_SCHEMA,offer:f.offer,ack:f.ack,checkoutApproved:true}))),err('EXCHANGE32L_TRANSCRIPT_INVALID'));});
caseTest('transport refuses excessive bytes',()=>{assert.throws(()=>decodeOfflineConflictExchangeTranscript(Buffer.alloc(4097)),err('EXCHANGE32L_TRANSCRIPT_INVALID'));});
caseTest('transport refuses malformed base64url signature',()=>{const f=setup();assert.throws(()=>encodeOfflineConflictExchangeTranscript({...f,offer:{...f.offer,signature:'AAAA'}}),err('EXCHANGE32L_RECEIPT_INVALID'));});
caseTest('transport refuses accessor body without invoking it',()=>{const f=setup(),b={...f.offer.body};Object.defineProperty(b,'senderId',{get(){throw Error('accessor executed')},enumerable:true});
 assert.throws(()=>encodeOfflineConflictExchangeTranscript({...f,offer:{...f.offer,body:b}}),err('EXCHANGE32L_BODY_INVALID'));
});
caseTest('receipt digest changes on signed acknowledgement',()=>{const f=setup();assert.notEqual(offlineConflictExchangeReceiptDigest(f.offer),offlineConflictExchangeReceiptDigest(f.ack));});

import {offlineConflictExchangeTranscriptDigest,reconcileOfflineConflictExchangeViews} from '../src/offline-conflict-proof-exchange.mjs';
const views=(f,receiverBytes=encodeOfflineConflictExchangeTranscript(f))=>{
 const senderBytes=encodeOfflineConflictExchangeTranscript(f);
 return {observations:[{partyId:E.senderId,transcriptBytes:senderBytes},{partyId:E.receiverId,transcriptBytes:receiverBytes}],
  expectedSenderTranscriptDigest:offlineConflictExchangeTranscriptDigest(senderBytes),
  expectedReceiverTranscriptDigest:offlineConflictExchangeTranscriptDigest(receiverBytes),...f.args};
};
caseTest('two independently pinned copies reconcile the same authenticated exchange',()=>{
 const f=setup(),v=reconcileOfflineConflictExchangeViews(views(f));
 assert.equal(v.verified,true);assert.equal(v.viewsReconciled,2);assert.equal(v.productionApproved,false);
});
caseTest('omitted receiver view rejected',()=>{const f=setup(),a=views(f);a.observations.pop();assert.throws(()=>reconcileOfflineConflictExchangeViews(a),err('EXCHANGE32L_TWO_PINNED_VIEWS_REQUIRED'));});
caseTest('reordered views rejected',()=>{const f=setup(),a=views(f);a.observations.reverse();assert.throws(()=>reconcileOfflineConflictExchangeViews(a),err('EXCHANGE32L_VIEW_ORDER_OR_OMISSION'));});
caseTest('duplicate sender view rejected',()=>{const f=setup(),a=views(f);a.observations[1].partyId=E.senderId;assert.throws(()=>reconcileOfflineConflictExchangeViews(a),err('EXCHANGE32L_VIEW_ORDER_OR_OMISSION'));});
caseTest('missing independently pinned receiver digest rejected',()=>{const f=setup(),a=views(f);delete a.expectedReceiverTranscriptDigest;assert.throws(()=>reconcileOfflineConflictExchangeViews(a),err('EXCHANGE32L_TWO_PINNED_VIEWS_REQUIRED'));});
caseTest('receiver transcript substituted against independent pin rejected',()=>{const f=setup(),a=views(f);a.observations[1].transcriptBytes=Buffer.from('substitution');assert.throws(()=>reconcileOfflineConflictExchangeViews(a));});
caseTest('forged sender pin rejected',()=>{const f=setup(),a=views(f);a.expectedSenderTranscriptDigest=sha('forged');assert.throws(()=>reconcileOfflineConflictExchangeViews(a),err('EXCHANGE32L_VIEW_PIN_MISMATCH'));});
caseTest('two valid signed but different acknowledgements expose equivocation',()=>{
 const f=setup();const alternate=acceptOfflineConflictExchangeOffer({...f.base,offer:f.offer,
  senderPublicKey:sender.publicKey,receiverPrivateKey:receiver.privateKey,
  nowMs:now+1500,issuedAt:now+1500,expiresAt:now+59000});
 const bytes=encodeOfflineConflictExchangeTranscript({offer:f.offer,ack:alternate});
 assert.notEqual(offlineConflictExchangeTranscriptDigest(bytes),offlineConflictExchangeTranscriptDigest(encodeOfflineConflictExchangeTranscript(f)));
 assert.throws(()=>reconcileOfflineConflictExchangeViews(views(f,bytes)),err('EXCHANGE32L_EQUIVOCATION_DETECTED'));
});
caseTest('forged second view cannot become equivocation evidence',()=>{
 const f=setup(),bytes=encodeOfflineConflictExchangeTranscript({offer:f.offer,ack:tamperSig(f.ack)});
 assert.throws(()=>reconcileOfflineConflictExchangeViews(views(f,bytes)),err('EXCHANGE32L_SIGNATURE_INVALID'));
});
caseTest('same signing key for both roles fails independent-key check',()=>{
 const f=setup();assert.throws(()=>verify({...f.args,receiverPublicKey:sender.publicKey}),err('EXCHANGE32L_INDEPENDENT_KEYS_REQUIRED'));
});
caseTest('receiver refuses to countersign with sender key',()=>{
 const f=setup();assert.throws(()=>acceptOfflineConflictExchangeOffer({...f.base,offer:f.offer,
  senderPublicKey:sender.publicKey,receiverPrivateKey:sender.privateKey,
  nowMs:now+1000,issuedAt:now+1000,expiresAt:now+59000}),err('EXCHANGE32L_INDEPENDENT_KEYS_REQUIRED'));
});
caseTest('receiver refuses acknowledgement issued in the future',()=>{
 const f=setup();assert.throws(()=>acceptOfflineConflictExchangeOffer({...f.base,offer:f.offer,
  senderPublicKey:sender.publicKey,receiverPrivateKey:receiver.privateKey,
  nowMs:now+1000,issuedAt:now+2000,expiresAt:now+59000}),err('EXCHANGE32L_ACK_WINDOW_INVALID'));
});
caseTest('receiver refuses acknowledgement expiring beyond offer',()=>{
 const f=setup();assert.throws(()=>acceptOfflineConflictExchangeOffer({...f.base,offer:f.offer,
  senderPublicKey:sender.publicKey,receiverPrivateKey:receiver.privateKey,
  nowMs:now+1000,issuedAt:now+1000,expiresAt:now+70000}),err('EXCHANGE32L_ACK_WINDOW_INVALID'));
});
