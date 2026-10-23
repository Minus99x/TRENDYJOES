import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {mkdtemp,chmod,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createOfflineWitnessAcknowledgement} from '../src/preview-local-artwork-review-witness-acknowledgements.mjs';
import {serializeOfflineWitnessRoster,initializeOfflineWitnessChallengeLedger,
 openOfflineWitnessChallengeLedger,deriveOfflineWitnessChallengeReceiptPin}
 from '../src/preview-local-artwork-review-witness-roster-ledger.mjs';
import {LOCAL_REVIEW_RETAINED_HEAD_SCHEMA} from '../src/preview-local-artwork-review-policy-checkpoints.mjs';
import {OFFLINE_WITNESS_EPOCH_SCHEMA,OFFLINE_WITNESS_ISSUANCE_SCHEMA,
 createOfflineWitnessRosterEpochTransition,verifyOfflineWitnessRosterEpochTransition,
 createOfflineWitnessChallengeTicket,verifyOfflineIssuedWitnessAcknowledgement}
 from '../src/preview-local-artwork-review-witness-epoch.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const fp=k=>sha(k.export({type:'spki',format:'der'}));
const issuer=generateKeyPairSync('ed25519'),wA=generateKeyPairSync('ed25519'),
 wB=generateKeyPairSync('ed25519'),wC=generateKeyPairSync('ed25519'),
 impostor=generateKeyPairSync('ed25519');
const now=1700000000000,cutoverMs=now-500;
const rootPin=sha('35AH-root'),registryId=sha('35AH-registry'),
 policySignerFingerprint=sha('35AH-policy'),audience=sha('35AH-audience');
const witnessA=sha('35AH-a'),witnessB=sha('35AH-b'),witnessC=sha('35AH-c');
const challenge=sha('35AH-challenge'),parentCheckpointSha256=sha('35AH-parent'),
 candidateCheckpointSha256=sha('35AH-candidate');
const witness=(id,key)=>({witnessId:id,publicKeyFingerprint:fp(key),status:'active'});
const base={rootPin,registryId,policySignerFingerprint,audience};
const previousRoster=serializeOfflineWitnessRoster({...base,validFromMs:now-10000,
 validUntilMs:now+1000,witnesses:[witness(witnessA,wA.publicKey),
  witness(witnessC,wC.publicKey)].sort((x,y)=>x.witnessId.localeCompare(y.witnessId))});
const nextRoster=serializeOfflineWitnessRoster({...base,validFromMs:now-1000,
 validUntilMs:now+10000,witnesses:[witness(witnessA,wA.publicKey),
  witness(witnessB,wB.publicKey)].sort((x,y)=>x.witnessId.localeCompare(y.witnessId))});
const transitionInput={...base,previousRosterSha256:previousRoster.sha256,
 nextRosterSha256:nextRoster.sha256,previousEpoch:2,nextEpoch:3,cutoverMs};
const transition=createOfflineWitnessRosterEpochTransition({signingKey:issuer.privateKey,...transitionInput});
const epochPins={transitionBytes:transition.bytes,expectedTransitionSha256:transition.sha256,
 issuerPublicKey:issuer.publicKey,expectedIssuerKeyFingerprint:fp(issuer.publicKey),
 previousRosterBytes:previousRoster.bytes,nextRosterBytes:nextRoster.bytes,
 expectedPreviousRosterSha256:previousRoster.sha256,expectedNextRosterSha256:nextRoster.sha256,
 expectedRootPin:rootPin,expectedRegistryId:registryId,
 expectedPolicySignerFingerprint:policySignerFingerprint,expectedAudience:audience,
 expectedPreviousEpoch:2,expectedNextEpoch:3,trustedNowMs:now};
const ticketInput={rootPin,registryId,audience,rosterSha256:nextRoster.sha256,
 epoch:3,transitionSha256:transition.sha256,witnessId:witnessA,challenge,
 parentCheckpointSha256,parentRevision:4,candidateCheckpointSha256,
 candidateRevision:5,issuedAtMs:now-200,expiresAtMs:now+2000};
const ticket=createOfflineWitnessChallengeTicket({signingKey:issuer.privateKey,...ticketInput});
const head={schema:LOCAL_REVIEW_RETAINED_HEAD_SCHEMA,rootPin,registryId,
 signerFingerprint:policySignerFingerprint,checkpointSha256:parentCheckpointSha256,revision:4};
const ack=(key=wA.privateKey,wid=witnessA,opts={})=>createOfflineWitnessAcknowledgement({
 signingKey:key,witnessId:wid,head,candidateCheckpointSha256,
 challenge,audience,issuedAtMs:now-100,expiresAtMs:now+1000,...opts}).bytes;
const receipt=ack();
const tmp=async()=>{const d=await mkdtemp(join(tmpdir(),'tj35ah-'));await chmod(d,0o700);return d;};
const ledgerFor=async d=>{await initializeOfflineWitnessChallengeLedger({directory:d,namespacePin:nextRoster.sha256});
 return openOfflineWitnessChallengeLedger({directory:d,namespacePin:nextRoster.sha256});};
const args=(ledger,extra={})=>({...epochPins,epochTransitionBytes:transition.bytes,ticketBytes:ticket.bytes,
 expectedTicketSha256:ticket.sha256,witnessId:witnessA,witnessPublicKey:wA.publicKey,
 receiptBytes:receipt,ledger,...extra});
const reject=(p,code)=>assert.rejects(p,{code});
const alter=(bytes,edit)=>{const x=JSON.parse(bytes);edit(x);return Buffer.from(JSON.stringify(x));};
const transitionVerify=extra=>verifyOfflineWitnessRosterEpochTransition({...epochPins,...extra});
const run=async extra=>{const d=await tmp();try{const ledger=await ledgerFor(d);
 return await verifyOfflineIssuedWitnessAcknowledgement(args(ledger,extra));
 }finally{await rm(d,{recursive:true,force:true});}};
const bad=async(extra,code)=>reject(run(extra),code);

test('35AH pinned signed transition validates epoch and non-authorizing result',()=>{
 const r=transitionVerify();assert.equal(r.epoch,3);assert.equal(r.rosterSha256,nextRoster.sha256);
 assert.equal(r.authorizesProduction,false);assert.equal(r.independentCustodyVerified,false);
});
test('35AH issuance ticket is signed, pinned, and binds durable witness acceptance',async()=>{
 const r=await run();assert.equal(r.epoch,3);assert.equal(r.challengeTicketSha256,ticket.sha256);
 assert.equal(r.signatureVerified,true);assert.equal(r.replayTokenConsumed,true);
 assert.equal(r.authorizesProduction,false);assert.equal(r.shopifyWritesAllowed,false);
});
test('35AH schemas are stable and distinct',()=>{
 assert.equal(JSON.parse(transition.bytes).schema,OFFLINE_WITNESS_EPOCH_SCHEMA);
 assert.equal(JSON.parse(ticket.bytes).schema,OFFLINE_WITNESS_ISSUANCE_SCHEMA);
});
for(const [name,field,value,code] of [
 ['transition pin','expectedTransitionSha256',sha('wrong'),'OFFLINE_EPOCH_DIGEST_MISMATCH'],
 ['issuer key pin','expectedIssuerKeyFingerprint',fp(impostor.publicKey),'OFFLINE_EPOCH_MISSING_EXTERNAL_PINS'],
 ['previous roster pin','expectedPreviousRosterSha256',sha('wrong'),'OFFLINE_EPOCH_HEAD_MISMATCH'],
 ['next roster pin','expectedNextRosterSha256',sha('wrong'),'OFFLINE_EPOCH_HEAD_MISMATCH'],
 ['root pin','expectedRootPin',sha('wrong'),'OFFLINE_EPOCH_HEAD_MISMATCH'],
 ['registry pin','expectedRegistryId',sha('wrong'),'OFFLINE_EPOCH_HEAD_MISMATCH'],
 ['audience pin','expectedAudience',sha('wrong'),'OFFLINE_EPOCH_HEAD_MISMATCH'],
 ['policy signer pin','expectedPolicySignerFingerprint',sha('wrong'),'OFFLINE_EPOCH_HEAD_MISMATCH'],
 ['previous epoch','expectedPreviousEpoch',1,'OFFLINE_EPOCH_MISSING_EXTERNAL_PINS'],
 ['next epoch','expectedNextEpoch',4,'OFFLINE_EPOCH_MISSING_EXTERNAL_PINS'],
 ['missing external pin','expectedTransitionSha256',undefined,'OFFLINE_EPOCH_MISSING_EXTERNAL_PINS'],
 ['invalid trusted time','trustedNowMs',NaN,'OFFLINE_EPOCH_MISSING_EXTERNAL_PINS']
])test(`35AH rejects ${name}`,()=>assert.throws(()=>transitionVerify({[field]:value}),{code}));
test('35AH rejects pre-cutover transition',()=>assert.throws(()=>transitionVerify({trustedNowMs:cutoverMs-1}),{code:'OFFLINE_EPOCH_NOT_YET_ACTIVE'}));
test('35AH rejects stale next-roster validity',()=>assert.throws(()=>transitionVerify({trustedNowMs:now+10000}),{code:'OFFLINE_ROSTER_OUTSIDE_VALIDITY'}));
test('35AH rejects malformed transition JSON',()=>assert.throws(()=>transitionVerify({transitionBytes:Buffer.from('{')}),{code:'OFFLINE_EPOCH_MALFORMED_TRANSITION'}));
test('35AH rejects noncanonical transition JSON even if hash repinned',()=>{
 const b=Buffer.from(JSON.stringify(JSON.parse(transition.bytes),null,2));
 assert.throws(()=>transitionVerify({transitionBytes:b,expectedTransitionSha256:sha(b)}),{code:'OFFLINE_EPOCH_MALFORMED_TRANSITION'});
});
test('35AH rejects tampered signed transition even if SHA repinned',()=>{
 const b=alter(transition.bytes,o=>o.cutoverMs--);
 assert.throws(()=>transitionVerify({transitionBytes:b,expectedTransitionSha256:sha(b)}),{code:'OFFLINE_EPOCH_BAD_SIGNATURE'});
});
test('35AH rejects impostor-signed transition despite matching external digest',()=>{
 const forged=createOfflineWitnessRosterEpochTransition({signingKey:impostor.privateKey,...transitionInput});
 assert.throws(()=>transitionVerify({transitionBytes:forged.bytes,expectedTransitionSha256:forged.sha256}),{code:'OFFLINE_EPOCH_SIGNER_SUBSTITUTION'});
});
test('35AH rejects non-incrementing epoch in signed transition',()=>assert.throws(()=>
 createOfflineWitnessRosterEpochTransition({signingKey:issuer.privateKey,...transitionInput,nextEpoch:5}),
 {code:'OFFLINE_EPOCH_INVALID_TRANSITION'}));
test('35AH rejects equal roster hashes in signed transition',()=>assert.throws(()=>
 createOfflineWitnessRosterEpochTransition({signingKey:issuer.privateKey,...transitionInput,nextRosterSha256:previousRoster.sha256}),
 {code:'OFFLINE_EPOCH_INVALID_TRANSITION'}));
test('35AH rejects invalid signer object',()=>assert.throws(()=>
 createOfflineWitnessRosterEpochTransition({signingKey:issuer.publicKey,...transitionInput}),
 {code:'OFFLINE_EPOCH_INVALID_SIGNER'}));
test('35AH rejects late cutover beyond previous roster validity',()=>{
 const changed=createOfflineWitnessRosterEpochTransition({signingKey:issuer.privateKey,...transitionInput,cutoverMs:now+1001});
 assert.throws(()=>transitionVerify({transitionBytes:changed.bytes,expectedTransitionSha256:changed.sha256,trustedNowMs:now+1002}),
 {code:'OFFLINE_ROSTER_OUTSIDE_VALIDITY'});
});
test('35AH rejects cutover before next roster validity',()=>{
 const changed=createOfflineWitnessRosterEpochTransition({signingKey:issuer.privateKey,...transitionInput,cutoverMs:now-5000});
 assert.throws(()=>transitionVerify({transitionBytes:changed.bytes,expectedTransitionSha256:changed.sha256}),
 {code:'OFFLINE_EPOCH_INVALID_CUTOVER'});
});
for(const [name,field,value,code] of [
 ['ticket hash','expectedTicketSha256',sha('wrong'),'OFFLINE_EPOCH_DIGEST_MISMATCH'],
 ['ticket missing pin','expectedTicketSha256',undefined,'OFFLINE_EPOCH_MISSING_EXTERNAL_PINS'],
 ['ticket missing issuer','issuerPublicKey',undefined,'OFFLINE_EPOCH_MISSING_EXTERNAL_PINS'],
 ['old roster','nextRosterBytes',previousRoster.bytes,'OFFLINE_ROSTER_PIN_MISMATCH'],
 ['old epoch','expectedNextEpoch',2,'OFFLINE_EPOCH_MISSING_EXTERNAL_PINS'],
 ['wrong witness','witnessId',witnessB,'OFFLINE_ISSUANCE_PIN_MISMATCH']
])test(`35AH rejects ${name} at issuance`,()=>bad({[field]:value},code));
test('35AH rejects altered ticket with repinned hash',async()=>{
 const b=alter(ticket.bytes,o=>o.challenge=sha('replacement'));
 await bad({ticketBytes:b,expectedTicketSha256:sha(b)},'OFFLINE_EPOCH_BAD_SIGNATURE');
});
test('35AH rejects malformed ticket',()=>bad({ticketBytes:Buffer.from('bad')},'OFFLINE_ISSUANCE_MALFORMED_TICKET'));
test('35AH rejects forged ticket signed by different issuer',async()=>{
 const forged=createOfflineWitnessChallengeTicket({signingKey:impostor.privateKey,...ticketInput});
 await bad({ticketBytes:forged.bytes,expectedTicketSha256:forged.sha256},'OFFLINE_EPOCH_SIGNER_SUBSTITUTION');
});
test('35AH rejects ticket for previous roster',async()=>{
 const old=createOfflineWitnessChallengeTicket({signingKey:issuer.privateKey,...ticketInput,rosterSha256:previousRoster.sha256});
 await bad({ticketBytes:old.bytes,expectedTicketSha256:old.sha256},'OFFLINE_ISSUANCE_PIN_MISMATCH');
});
test('35AH rejects ticket for previous epoch',async()=>{
 const old=createOfflineWitnessChallengeTicket({signingKey:issuer.privateKey,...ticketInput,epoch:2});
 await bad({ticketBytes:old.bytes,expectedTicketSha256:old.sha256},'OFFLINE_ISSUANCE_PIN_MISMATCH');
});
test('35AH rejects ticket bound to different transition',async()=>{
 const old=createOfflineWitnessChallengeTicket({signingKey:issuer.privateKey,...ticketInput,transitionSha256:sha('old-transition')});
 await bad({ticketBytes:old.bytes,expectedTicketSha256:old.sha256},'OFFLINE_ISSUANCE_PIN_MISMATCH');
});
test('35AH rejects challenge ticket issued before cutover',async()=>{
 const early=createOfflineWitnessChallengeTicket({signingKey:issuer.privateKey,...ticketInput,issuedAtMs:cutoverMs-1});
 await bad({ticketBytes:early.bytes,expectedTicketSha256:early.sha256},'OFFLINE_ISSUANCE_PRE_CUTOVER');
});
test('35AH rejects not-yet-valid challenge ticket',async()=>{
 const future=createOfflineWitnessChallengeTicket({signingKey:issuer.privateKey,...ticketInput,issuedAtMs:now+100});
 await bad({ticketBytes:future.bytes,expectedTicketSha256:future.sha256},'OFFLINE_ISSUANCE_NOT_YET_VALID');
});
test('35AH rejects expired challenge ticket',async()=>{
 const expired=createOfflineWitnessChallengeTicket({signingKey:issuer.privateKey,...ticketInput,expiresAtMs:now});
 await bad({ticketBytes:expired.bytes,expectedTicketSha256:expired.sha256},'OFFLINE_ISSUANCE_EXPIRED');
});
test('35AH rejects ticket extending past roster expiry',async()=>{
 const late=createOfflineWitnessChallengeTicket({signingKey:issuer.privateKey,...ticketInput,expiresAtMs:now+10001});
 await bad({ticketBytes:late.bytes,expectedTicketSha256:late.sha256},'OFFLINE_ISSUANCE_OUTLIVES_ROSTER');
});
test('35AH rejects oversized challenge lifetime',()=>assert.throws(()=>
 createOfflineWitnessChallengeTicket({signingKey:issuer.privateKey,...ticketInput,expiresAtMs:now+300001}),
 {code:'OFFLINE_ISSUANCE_INVALID_TICKET'}));
test('35AH rejects stale candidate revision',()=>assert.throws(()=>
 createOfflineWitnessChallengeTicket({signingKey:issuer.privateKey,...ticketInput,candidateRevision:7}),
 {code:'OFFLINE_ISSUANCE_INVALID_TICKET'}));
test('35AH rejects identical parent and candidate digest',()=>assert.throws(()=>
 createOfflineWitnessChallengeTicket({signingKey:issuer.privateKey,...ticketInput,candidateCheckpointSha256:parentCheckpointSha256}),
 {code:'OFFLINE_ISSUANCE_INVALID_TICKET'}));
test('35AH rejects receipt created before challenge issuance',()=>bad({receiptBytes:ack(wA.privateKey,witnessA,{issuedAtMs:now-300})},'OFFLINE_ISSUANCE_RECEIPT_WINDOW_MISMATCH'));
test('35AH rejects receipt extending past challenge expiry',()=>bad({receiptBytes:ack(wA.privateKey,witnessA,{expiresAtMs:now+2500})},'OFFLINE_ISSUANCE_RECEIPT_WINDOW_MISMATCH'));
test('35AH rejects witness signature forgery',()=>bad({receiptBytes:alter(receipt,o=>o.signature=(o.signature[0]==='A'?'B':'A')+o.signature.slice(1))},'OFFLINE_WITNESS_BAD_SIGNATURE'));
test('35AH rejects wrong receipt challenge',()=>bad({receiptBytes:ack(wA.privateKey,witnessA,{challenge:sha('old')})},'OFFLINE_WITNESS_PIN_MISMATCH'));
test('35AH rejects witness from superseded roster',async()=>{
 const cTicket=createOfflineWitnessChallengeTicket({signingKey:issuer.privateKey,...ticketInput,witnessId:witnessC});
 await bad({ticketBytes:cTicket.bytes,expectedTicketSha256:cTicket.sha256,
  witnessId:witnessC,witnessPublicKey:wC.publicKey,receiptBytes:ack(wC.privateKey,witnessC)},
  'OFFLINE_ROSTER_WITNESS_NOT_ACTIVE');
});
test('35AH rejects malformed witness receipt before ledger mutation',()=>bad({receiptBytes:Buffer.from('{')},'OFFLINE_ISSUANCE_INVALID_RECEIPT'));
test('35AH replay fails across ledger reopen',async()=>{
 const d=await tmp();try{const l=await ledgerFor(d);
  await verifyOfflineIssuedWitnessAcknowledgement(args(l));
  const reopened=await openOfflineWitnessChallengeLedger({directory:d,namespacePin:nextRoster.sha256});
  await reject(verifyOfflineIssuedWitnessAcknowledgement(args(reopened)),'OFFLINE_WITNESS_REPLAY');
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AH competing signed challenge acknowledgements consume exactly once',async()=>{
 const d=await tmp();try{const l=await ledgerFor(d);
  const r=await Promise.allSettled(Array.from({length:7},()=>verifyOfflineIssuedWitnessAcknowledgement(args(l))));
  assert.equal(r.filter(x=>x.status==='fulfilled').length,1);
  assert.equal(r.filter(x=>x.status==='rejected'&&x.reason.code==='OFFLINE_WITNESS_REPLAY').length,6);
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AH crash-created partial ledger receipt blocks ticket reuse',async()=>{
 const d=await tmp();try{const l=await ledgerFor(d),body=JSON.parse(receipt);
  const replayToken=sha(Buffer.from(`TRENDYJOES_LOCAL_POLICY_WITNESS_ACK_35AF_V1\nREPLAY\n${sha(receipt)}\n${body.witnessId}\n${body.audience}\n${body.challenge}`));
  const pin=deriveOfflineWitnessChallengeReceiptPin({namespacePin:nextRoster.sha256,
   witnessId:witnessA,challenge,audience,registryId,receiptReplayToken:replayToken});
  await writeFile(join(d,`c-${pin.challengeKey}.json`),'');
  await reject(verifyOfflineIssuedWitnessAcknowledgement(args(l)),'OFFLINE_WITNESS_REPLAY');
 }finally{await rm(d,{recursive:true,force:true});}
});
