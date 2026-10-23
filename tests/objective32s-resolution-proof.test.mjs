import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {mkdtemp,rm,readFile,writeFile,unlink,symlink,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createOfflineConflictExchangeJournal} from '../src/offline-conflict-exchange-journal.mjs';
import {offlineConflictRecoveryReceiptGenesisHead} from '../src/offline-conflict-exchange-recovery-receipts.mjs';
import {offlineConflictExchangeRecoveryReviewerPolicyDigest} from '../src/offline-conflict-exchange-recovery.mjs';
import {OFFLINE_CONFLICT_RECOVERY_POLICY_EPOCH_SCHEMA,offlineConflictRecoveryPolicyEpochGenesisDigest,
 offlineConflictRecoveryPolicyTransitionBytes,offlineConflictRecoveryPolicyTransitionDigest} from '../src/offline-conflict-recovery-policy-epochs.mjs';
import {OFFLINE_CONFLICT_RECOVERY_CUTOVER_SCHEMA,offlineConflictRecoveryCutoverDigest} from '../src/offline-conflict-recovery-policy-cutover.mjs';
import {OFFLINE_CONFLICT_CUTOVER_ADJUDICATION_SCHEMA,offlineConflictCutoverAdjudicationBytes,
 offlineConflictCutoverAdjudicationDigest} from '../src/offline-conflict-recovery-cutover-adjudication.mjs';
import {OFFLINE_CONFLICT_CUTOVER_RESOLUTION_PROOF_SCHEMA,offlineConflictCutoverResolutionProofDigest,
 verifyOfflineConflictCutoverResolutionProof} from '../src/offline-conflict-cutover-resolution-proof.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const gen=sha('objective32s-genesis');const now=1792200000000;
const group=p=>[1,2,3].map(i=>({reviewerId:`${p}_reviewer_${i}`,...generateKeyPairSync('ed25519')}));
const old=group('old32s'),next=group('new32s');
const pub=g=>g.map(x=>({reviewerId:x.reviewerId,publicKey:x.publicKey.export({format:'pem',type:'spki'})}));
const digest=g=>offlineConflictExchangeRecoveryReviewerPolicyDigest(pub(g));
const signatures=(body,g,fn)=>g.slice(0,2).map(k=>({reviewerId:k.reviewerId,signature:sign(null,fn(body),k.privateKey).toString('base64url')}));
const receiptHead=offlineConflictRecoveryReceiptGenesisHead(gen);
const transitionBody={schema:OFFLINE_CONFLICT_RECOVERY_POLICY_EPOCH_SCHEMA,sequence:1,
 previousTransitionDigest:offlineConflictRecoveryPolicyEpochGenesisDigest({genesisExchangeDigest:gen,initialPolicyDigest:digest(old)}),
 genesisExchangeDigest:gen,fromPolicyDigest:digest(old),toPolicyDigest:digest(next),receiptHead,
 issuedAt:now-1000,expiresAt:now+30000,nonce:'epoch_nonce_32s_01'};
const transition={body:transitionBody,outgoingSignatures:signatures(transitionBody,old,offlineConflictRecoveryPolicyTransitionBytes),
 incomingSignatures:signatures(transitionBody,next,offlineConflictRecoveryPolicyTransitionBytes)};
const transitionHead={count:1,headDigest:offlineConflictRecoveryPolicyTransitionDigest({transition})};
const history=()=>({genesisExchangeDigest:gen,reviewerPolicies:[pub(old),pub(next)],transitions:[transition],segments:[[],[]],
 expectedTransitionHead:transitionHead,expectedFinalReceiptHead:receiptHead,expectedFinalPolicyDigest:digest(next),nowMs:now});
const cutoverBody=()=>({schema:OFFLINE_CONFLICT_RECOVERY_CUTOVER_SCHEMA,genesisExchangeDigest:gen,
 previousPolicyDigest:digest(old),activePolicyDigest:digest(next),transitionHead,receiptHead,activatedAt:now});
const cutoverDigest=offlineConflictRecoveryCutoverDigest(cutoverBody());
const marker={...cutoverBody(),cutoverDigest};
const markerBytes=Buffer.from(JSON.stringify(marker));const pendingBytesDigest=sha(markerBytes);
const journalHead={count:0,headDigest:sha('test-journal-head')};
const decisionBody=action=>({schema:OFFLINE_CONFLICT_CUTOVER_ADJUDICATION_SCHEMA,action,genesisExchangeDigest:gen,
 cutoverDigest,pendingBytesDigest,previousPolicyDigest:digest(old),activePolicyDigest:digest(next),
 exchangeJournalHead:journalHead,receiptHead,issuedAt:now-500,expiresAt:now+10000,nonce:'cutover_recovery_nonce_32s'});
const decision=action=>{const b=decisionBody(action);return {body:b,
 outgoingSignatures:signatures(b,old,offlineConflictCutoverAdjudicationBytes),
 incomingSignatures:signatures(b,next,offlineConflictCutoverAdjudicationBytes)};};
const resolution=(action,d)=>{const b={schema:'TJ-OFFLINE-CONFLICT-CUTOVER-RESOLUTION-1',action,genesisExchangeDigest:gen,
 cutoverDigest,pendingBytesDigest,decisionDigest:offlineConflictCutoverAdjudicationDigest(d),resolvedAt:now};
 return {...b,receiptDigest:sha('TJ-32R-RESOLUTION-RECEIPT\0'+JSON.stringify(b))};};
const make=(action='abort')=>{const d=decision(action),r=resolution(action,d);
 const proof={schema:OFFLINE_CONFLICT_CUTOVER_RESOLUTION_PROOF_SCHEMA,history:history(),cutoverMarker:marker,
 pendingMarkerBase64url:markerBytes.toString('base64url'),decision:d,resolutionReceipt:r};
 const pins={proofDigest:offlineConflictCutoverResolutionProofDigest(proof),decisionDigest:offlineConflictCutoverAdjudicationDigest(d),
 resolutionDigest:r.receiptDigest,cutoverDigest,pendingBytesDigest,genesisExchangeDigest:gen,
 transitionHead,receiptHead,finalPolicyDigest:digest(next),exchangeJournalHead:journalHead};
 return {proof,pins};};
const audit=({proof,pins},at=now+86400000)=>verifyOfflineConflictCutoverResolutionProof({proof,pins,nowMs:at});
const repin=f=>{f.pins.proofDigest=offlineConflictCutoverResolutionProofDigest(f.proof);return f;};
const t=(name,fn)=>test('32S '+name,fn);
const rejects=(f,code)=>assert.throws(()=>audit(f),e=>e?.code===code);

t('valid retrospective abort receipt verifies dual quorums and historical transition, but not completion',()=>{
 const v=audit(make());assert.equal(v.signedQuorumsVerified,true);assert.equal(v.localCompletionVerified,false);
 assert.equal(v.externalPublicationVerified,false);assert.equal(v.authorizesProduction,false);
 assert.equal(v.status,'authenticated-attempt-only');});
t('valid retrospective finalize receipt verifies without production authorization',()=>{
 const v=audit(make('finalize'));assert.equal(v.action,'finalize');assert.equal(v.localCompletionVerified,false);});
t('missing external proof pin rejected',()=>{const f=make();delete f.pins.proofDigest;rejects(f,'EXCHANGE32S_EXTERNAL_PINS_REQUIRED');});
t('missing independently pinned receipt head rejected',()=>{const f=make();delete f.pins.receiptHead;rejects(f,'EXCHANGE32S_EXTERNAL_PINS_REQUIRED');});
t('substituted complete bundle rejected by external proof pin',()=>{const f=make();f.proof.resolutionReceipt.resolvedAt++;rejects(f,'EXCHANGE32S_PROOF_PIN_MISMATCH');});
t('forged outgoing signature fails even after attacker re-pins proof and decision',()=>{
 const f=make();f.proof.decision.outgoingSignatures[0].signature='A'.repeat(86);
 f.pins.decisionDigest=offlineConflictCutoverAdjudicationDigest(f.proof.decision);
 f.proof.resolutionReceipt=resolution('abort',f.proof.decision);
 f.pins.resolutionDigest=f.proof.resolutionReceipt.receiptDigest;
 rejects(repin(f),'EXCHANGE32R_SIGNATURE_INVALID');});
t('forged incoming signature fails after complete digest re-computation',()=>{
 const f=make();f.proof.decision.incomingSignatures[1].signature='A'.repeat(86);
 f.pins.decisionDigest=offlineConflictCutoverAdjudicationDigest(f.proof.decision);
 f.proof.resolutionReceipt=resolution('abort',f.proof.decision);f.pins.resolutionDigest=f.proof.resolutionReceipt.receiptDigest;
 rejects(repin(f),'EXCHANGE32R_SIGNATURE_INVALID');});
t('outgoing quorum omission rejected even after re-pinning all affected digests',()=>{
 const f=make();f.proof.decision.outgoingSignatures.pop();f.pins.decisionDigest=offlineConflictCutoverAdjudicationDigest(f.proof.decision);
 f.proof.resolutionReceipt=resolution('abort',f.proof.decision);f.pins.resolutionDigest=f.proof.resolutionReceipt.receiptDigest;
 rejects(repin(f),'EXCHANGE32R_QUORUM_REQUIRED');});
t('incoming quorum omission rejected',()=>{
 const f=make();f.proof.decision.incomingSignatures.pop();f.pins.decisionDigest=offlineConflictCutoverAdjudicationDigest(f.proof.decision);
 f.proof.resolutionReceipt=resolution('abort',f.proof.decision);f.pins.resolutionDigest=f.proof.resolutionReceipt.receiptDigest;
 rejects(repin(f),'EXCHANGE32R_QUORUM_REQUIRED');});
t('omitted historical transition rejected',()=>{const f=make();f.proof.history.transitions=[];rejects(repin(f),'EXCHANGE32P_EXTERNAL_PINS_REQUIRED');});
t('historical transition signature forgery rejected',()=>{
 const f=make();f.proof.history.transitions=structuredClone(f.proof.history.transitions);
 f.proof.history.transitions[0].incomingSignatures[0].signature='A'.repeat(86);
 rejects(repin(f),'EXCHANGE32P_SIGNATURE_INVALID');});
t('history rollback pin rejected',()=>{const f=make();f.proof.history.expectedTransitionHead={count:0,headDigest:sha('old')};
 rejects(repin(f),'EXCHANGE32S_HISTORY_PIN_MISMATCH');});
t('receipt history omitted from anchored proof rejected',()=>{const f=make();f.proof.history.segments=[];
 rejects(repin(f),'EXCHANGE32P_EXTERNAL_PINS_REQUIRED');});
t('wrong independent receipt digest rejected',()=>{const f=make();f.pins.resolutionDigest=sha('substitute');rejects(f,'EXCHANGE32S_RESOLUTION_INVALID');});
t('wrong independent pending digest rejected',()=>{const f=make();f.pins.pendingBytesDigest=sha('substitute');rejects(f,'EXCHANGE32S_PENDING_PIN_MISMATCH');});
t('wrong independent journal head rejected',()=>{const f=make();f.pins.exchangeJournalHead={count:0,headDigest:sha('fork')};rejects(f,'EXCHANGE32S_EVIDENCE_CONFLICT');});
t('mismatched signed action and resolution action rejected',()=>{
 const f=make();f.proof.resolutionReceipt=resolution('finalize',f.proof.decision);
 f.pins.resolutionDigest=f.proof.resolutionReceipt.receiptDigest;
 rejects(repin(f),'EXCHANGE32S_EVIDENCE_CONFLICT');});
t('resolution receipt after signed expiry rejected',()=>{
 const f=make();const b={...f.proof.resolutionReceipt,resolvedAt:now+20000};delete b.receiptDigest;
 f.proof.resolutionReceipt={...b,receiptDigest:sha('TJ-32R-RESOLUTION-RECEIPT\0'+JSON.stringify(b))};
 f.pins.resolutionDigest=f.proof.resolutionReceipt.receiptDigest;
 rejects(repin(f),'EXCHANGE32R_DECISION_EXPIRED');});
t('resolution timestamp in future of audit rejected',()=>{
 const f=make();const b={...f.proof.resolutionReceipt,resolvedAt:now+1};delete b.receiptDigest;
 f.proof.resolutionReceipt={...b,receiptDigest:sha('TJ-32R-RESOLUTION-RECEIPT\0'+JSON.stringify(b))};
 f.pins.resolutionDigest=f.proof.resolutionReceipt.receiptDigest;
 assert.throws(()=>audit(repin(f),now),e=>e?.code==='EXCHANGE32S_RESOLUTION_INVALID');});
t('receipt predating cutover activation rejected despite re-pinned digest',()=>{
 const f=make();const b={...f.proof.resolutionReceipt,resolvedAt:now-1};delete b.receiptDigest;
 f.proof.resolutionReceipt={...b,receiptDigest:sha('TJ-32R-RESOLUTION-RECEIPT\0'+JSON.stringify(b))};
 f.pins.resolutionDigest=f.proof.resolutionReceipt.receiptDigest;
 rejects(repin(f),'EXCHANGE32S_RESOLUTION_INVALID');});
t('replaced independent policy pin rejected',()=>{const f=make();f.pins.finalPolicyDigest=sha('wrong');
 rejects(f,'EXCHANGE32S_HISTORY_PIN_MISMATCH');});
t('extra unexpected receipt claim rejected',()=>{const f=make();f.proof.resolutionReceipt.productionApproved=true;
 rejects(repin(f),'EXCHANGE32S_PROOF_INVALID');});
t('pending bytes omitted rejected',()=>{const f=make();f.proof.pendingMarkerBase64url='';rejects(repin(f),'EXCHANGE32S_PROOF_INVALID');});
t('pending marker swapped and re-pinned but signed cutover disagrees',()=>{
 const f=make();const b={...marker,activatedAt:now+1};
 f.proof.pendingMarkerBase64url=Buffer.from(JSON.stringify(b)).toString('base64url');
 f.pins.pendingBytesDigest=sha(Buffer.from(JSON.stringify(b)));
 rejects(repin(f),'EXCHANGE32S_PENDING_INVALID');});
t('unexpected production authorization field rejected',()=>{const f=make();f.proof.productionApproved=true;
 assert.throws(()=>offlineConflictCutoverResolutionProofDigest(f.proof),e=>e?.code==='EXCHANGE32S_PROOF_INVALID');});
t('canonical proof digest stable across JSON serialization',()=>{const f=make();assert.equal(offlineConflictCutoverResolutionProofDigest(JSON.parse(JSON.stringify(f.proof))),f.pins.proofDigest);});

async function localFixture(stage,fn){
 const root=await mkdtemp(join(tmpdir(),'tj32s-'));
 try{
  const journal=createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen,
   injectFault:s=>{if(s===stage)throw Object.assign(new Error('crash'),{code:'SIMULATED_CRASH'});}});
  await assert.rejects(journal.activateRecoveryPolicyCutover({history:history(),expectedPriorPolicyDigest:digest(old),
   expectedCutoverDigest:cutoverDigest,expectedExchangeJournalHead:journal.genesisHead}),e=>e?.code==='SIMULATED_CRASH');
  const p=await readFile(join(root,'.recovery-policy-cutover.pending'));const pd=sha(p);
  const action=stage==='after-cutover-link-sync'?'finalize':'abort';const d=decision(action);
  // Sign a decision bound to the actual genesis journal head and actual pending bytes.
  const body={...d.body,pendingBytesDigest:pd,exchangeJournalHead:journal.genesisHead};
  const signed={body,outgoingSignatures:signatures(body,old,offlineConflictCutoverAdjudicationBytes),
   incomingSignatures:signatures(body,next,offlineConflictCutoverAdjudicationBytes)};
  const dd=offlineConflictCutoverAdjudicationDigest(signed);
  const rb={schema:'TJ-OFFLINE-CONFLICT-CUTOVER-RESOLUTION-1',action,genesisExchangeDigest:gen,
   cutoverDigest,pendingBytesDigest:pd,decisionDigest:dd,resolvedAt:now};
  const rd=sha('TJ-32R-RESOLUTION-RECEIPT\0'+JSON.stringify(rb));
  const args={decision:signed,history:history(),expectedDecisionDigest:dd,expectedCutoverDigest:cutoverDigest,
   expectedPendingBytesDigest:pd,expectedResolutionDigest:rd,expectedExchangeJournalHead:journal.genesisHead,nowMs:now};
  return await fn({root,args,journal:createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen})});
 }finally{await rm(root,{recursive:true,force:true});}
}
t('local read-only inspection distinguishes receipt synced before unlink as UNCERTAIN',()=>localFixture('after-cutover-pending-sync',async({root,args,journal})=>{
 const crash=createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen,
  injectFault:s=>{if(s==='after-cutover-resolution-receipt-sync')throw Object.assign(new Error('crash'),{code:'SIMULATED_CRASH'});}});
 await assert.rejects(crash.adjudicateInterruptedRecoveryPolicyCutover(args),e=>e?.code==='SIMULATED_CRASH');
 const before=(await readdir(root)).sort();
 const r=await journal.inspectRecoveryPolicyCutoverResolutionEvidence({expectedResolutionDigest:args.expectedResolutionDigest});
 assert.equal(r.status,'uncertain-pending');assert.equal(r.completionProvenLocally,false);
 assert.equal(r.authorizesProduction,false);
 assert.deepEqual((await readdir(root)).sort(),before);
 await assert.rejects(journal.inspectRecoveryPolicyCutoverResolution({expectedResolutionDigest:args.expectedResolutionDigest}),e=>e?.code==='EXCHANGE32R_UNCERTAIN_RESOLUTION');
}));
t('local read-only inspection reports locally completed abort after durable unlink',()=>localFixture('after-cutover-pending-sync',async({root,args,journal})=>{
 await journal.adjudicateInterruptedRecoveryPolicyCutover(args);
 const r=await journal.inspectRecoveryPolicyCutoverResolutionEvidence({expectedResolutionDigest:args.expectedResolutionDigest});
 assert.equal(r.status,'locally-completed');assert.equal(r.completionProvenLocally,true);
 assert.equal(r.independentlyPublished,false);
}));
t('local read-only inspection reports locally completed finalize after durable unlink',()=>localFixture('after-cutover-link-sync',async({args,journal})=>{
 await journal.adjudicateInterruptedRecoveryPolicyCutover(args);
 const r=await journal.inspectRecoveryPolicyCutoverResolutionEvidence({expectedResolutionDigest:args.expectedResolutionDigest});
 assert.equal(r.action,'finalize');assert.equal(r.status,'locally-completed');
}));
t('local uncertain receipt rejects tampered pending bytes without repair',()=>localFixture('after-cutover-pending-sync',async({root,args,journal})=>{
 const crash=createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen,
  injectFault:s=>{if(s==='after-cutover-resolution-receipt-sync')throw Object.assign(new Error('crash'),{code:'SIMULATED_CRASH'});}});
 await assert.rejects(crash.adjudicateInterruptedRecoveryPolicyCutover(args));
 const p=join(root,'.recovery-policy-cutover.pending');const b=JSON.parse(await readFile(p));b.activatedAt++;
 await writeFile(p,JSON.stringify(b));
 await assert.rejects(journal.inspectRecoveryPolicyCutoverResolutionEvidence({expectedResolutionDigest:args.expectedResolutionDigest}),e=>e?.code==='EXCHANGE32S_PENDING_PIN_MISMATCH');
}));
t('local uncertain receipt rejects symlink pending substitution',()=>localFixture('after-cutover-pending-sync',async({root,args,journal})=>{
 const crash=createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen,
  injectFault:s=>{if(s==='after-cutover-resolution-receipt-sync')throw Object.assign(new Error('crash'),{code:'SIMULATED_CRASH'});}});
 await assert.rejects(crash.adjudicateInterruptedRecoveryPolicyCutover(args));
 const p=join(root,'.recovery-policy-cutover.pending');await unlink(p);await symlink('/etc/passwd',p);
 await assert.rejects(journal.inspectRecoveryPolicyCutoverResolutionEvidence({expectedResolutionDigest:args.expectedResolutionDigest}));
}));
t('uncertain abort receipt with forged active marker fails closed',()=>localFixture('after-cutover-pending-sync',async({root,args,journal})=>{
 const crash=createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen,
  injectFault:s=>{if(s==='after-cutover-resolution-receipt-sync')throw Object.assign(new Error('crash'),{code:'SIMULATED_CRASH'});}});
 await assert.rejects(crash.adjudicateInterruptedRecoveryPolicyCutover(args));
 await writeFile(join(root,'.recovery-policy-cutover.json'),JSON.stringify(marker),{mode:0o600});
 await assert.rejects(journal.inspectRecoveryPolicyCutoverResolutionEvidence({expectedResolutionDigest:args.expectedResolutionDigest}),e=>e?.code==='EXCHANGE32S_UNCERTAIN_STATE_CONFLICT');
}));
t('uncertain finalize receipt with removed active marker fails closed',()=>localFixture('after-cutover-link-sync',async({root,args,journal})=>{
 const crash=createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen,
  injectFault:s=>{if(s==='after-cutover-resolution-receipt-sync')throw Object.assign(new Error('crash'),{code:'SIMULATED_CRASH'});}});
 await assert.rejects(crash.adjudicateInterruptedRecoveryPolicyCutover(args));
 await unlink(join(root,'.recovery-policy-cutover.json'));
 await assert.rejects(journal.inspectRecoveryPolicyCutoverResolutionEvidence({expectedResolutionDigest:args.expectedResolutionDigest}),e=>e?.code==='EXCHANGE32S_UNCERTAIN_STATE_CONFLICT');
}));
t('local receipt inspection requires independently pinned digest',()=>localFixture('after-cutover-pending-sync',async({root,args,journal})=>{
 await journal.adjudicateInterruptedRecoveryPolicyCutover(args);
 await assert.rejects(journal.inspectRecoveryPolicyCutoverResolutionEvidence(),e=>e?.code==='EXCHANGE32R_EXTERNAL_PINS_REQUIRED');
}));
