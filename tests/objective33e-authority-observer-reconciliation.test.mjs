import {createOfflineConflictAdjudicationTranscriptInventory,offlineConflictAdjudicationInventoryGenesisHead} from '../src/offline-conflict-adjudication-transcript-inventory.mjs';
import {exportOfflineConflictPendingAdjudicationTranscript,verifyOfflineConflictPendingAdjudicationTranscript,reconcileOfflineConflictPendingAdjudicationTranscripts,offlineConflictPendingAdjudicationTranscriptBodyBytes} from '../src/offline-conflict-pending-adjudication-transcript.mjs';
import test,{before,after} from 'node:test';
import {offlineConflictAuthorityHistoryNextHead,verifyOfflineConflictAuthorityHistory} from '../src/offline-conflict-authority-history.mjs';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,chmod,unlink,symlink,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {OFFLINE_CONFLICT_AUTHORITY_OBSERVER_SCHEMA,offlineConflictAuthorityObserverBodyBytes,offlineConflictAuthorityObserverAttestationDigest,verifyOfflineConflictAuthorityObserverReconciliation} from '../src/offline-conflict-authority-observer-reconciliation.mjs';
import {fixturePack} from './support/objective32w-fixture.mjs';
import {exportOfflineConflictAuthorityEquivocationEnvelope,verifyOfflineConflictAuthorityEquivocationEnvelope} from '../src/offline-conflict-authority-equivocation-envelope.mjs';
import {createOfflineConflictEquivocationAcceptanceRegistry,offlineConflictEquivocationAcceptanceGenesisHead,
 OFFLINE_CONFLICT_EQUIVOCATION_PENDING_DECISION_SCHEMA,offlineConflictEquivocationPendingDecisionBytes,
 offlineConflictEquivocationPendingDecisionDigest,offlineConflictEquivocationPendingReviewerGroupDigest} from '../src/offline-conflict-equivocation-acceptance-registry.mjs';
import {createOfflineConflictManifestJournal,offlineConflictManifestJournalGenesisHead} from '../src/offline-conflict-resolution-manifest-journal.mjs';
import {offlineConflictExchangeRecoveryReviewerPolicyDigest} from '../src/offline-conflict-exchange-recovery.mjs';
import {OFFLINE_CONFLICT_MANIFEST_CLAIM_ADJUDICATION_SCHEMA,offlineConflictManifestClaimDecisionBytes,offlineConflictManifestClaimDecisionDigest} from '../src/offline-conflict-manifest-claim-adjudication.mjs';
import {calculateOfflineConflictManifestClaimContinuity} from '../src/offline-conflict-manifest-claim-continuity.mjs';
import {calculateOfflineConflictManifestMultiClaimInventory,calculateOfflineConflictManifestMultiClaimReconciliation} from '../src/offline-conflict-manifest-multi-claim-inventory.mjs';
import {OFFLINE_CONFLICT_SIGNED_NAMESPACE_SCHEMA,offlineConflictNamespaceAuthorityPolicyDigest,
 offlineConflictSignedNamespaceBodyBytes,offlineConflictSignedNamespaceCommitmentDigest} from '../src/offline-conflict-signed-namespace-roster.mjs';
import {OFFLINE_CONFLICT_AUTHORITY_ROTATION_SCHEMA,offlineConflictAuthorityRotationBodyBytes,
 offlineConflictAuthorityRotationDigest,verifyOfflineConflictAuthorityPolicyRotation} from '../src/offline-conflict-authority-policy-rotation.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const err=code=>e=>e?.code===code;
const now=1792280000000,scope=sha('33c independent namespace scope'),namespaceId='namespace_33c_test_001';
const keys=(prefix,n)=>Array.from({length:n},(_,i)=>({id:`${prefix}_${String(i+1).padStart(2,'0')}`,...generateKeyPairSync('ed25519')}));
const reviewersA=keys('reviewer33c_A',3),reviewersB=keys('reviewer33c_B',3);
const oldKeys=keys('authority33c_old',3),newKeys=keys('authority33c_new',3),observerKeys=keys('observer33c',3);
const finalKeys=keys('authority33d_final',3),fourthKeys=keys('authority33d_fourth',3);
const pub=k=>k.publicKey.export({type:'spki',format:'der'}).toString('base64url');
const reviewerRoster=g=>g.map(k=>({reviewerId:k.id,publicKey:k.publicKey}));
const policy=g=>offlineConflictExchangeRecoveryReviewerPolicyDigest(reviewerRoster(g));
const authorityRoster=g=>g.map(k=>({authorityId:k.id,publicKey:pub(k)}));
const oldDigest=offlineConflictNamespaceAuthorityPolicyDigest(authorityRoster(oldKeys));
const newDigest=offlineConflictNamespaceAuthorityPolicyDigest(authorityRoster(newKeys));
const finalDigest=offlineConflictNamespaceAuthorityPolicyDigest(authorityRoster(finalKeys));
const fourthDigest=offlineConflictNamespaceAuthorityPolicyDigest(authorityRoster(fourthKeys));
const copy=x=>Buffer.isBuffer(x)?Buffer.from(x):Array.isArray(x)?x.map(copy):x&&typeof x==='object'&&Object.getPrototypeOf(x)===Object.prototype?Object.fromEntries(Object.entries(x).map(([k,v])=>[k,copy(v)])):x;
const t=(name,fn)=>test('33E '+name,fn);
let root,oldBody,newBody,transitionBody,oldVerification,newVerification,args;
async function makeClaim(){
 const dir=join(root,'journal');const head=offlineConflictManifestJournalGenesisHead();
 const j=createOfflineConflictManifestJournal({directory:dir,injectFault:stage=>{
  if(stage==='after-pending-sync')throw Error('simulated crash');}});
 await assert.rejects(j.claim({verificationArgs:fixturePack('session_33c_claim_0001',2048,'a'),expectedHead:head}),/simulated crash/);
 const pending=await readFile(join(dir,'.pending.json')),record=JSON.parse(pending);
 const body={schema:OFFLINE_CONFLICT_MANIFEST_CLAIM_ADJUDICATION_SCHEMA,action:'inspect-only',journalHead:head,
  pendingBytesDigest:sha(pending),pendingRecordDigest:record.recordDigest,pendingIndex:head.count+1,
  expectedPendingState:'pending-only',reviewerGroupADigest:policy(reviewersA),reviewerGroupBDigest:policy(reviewersB),
  issuedAt:now-1000,expiresAt:now+10000,nonce:'nonce_33c_signed_001'};
 const signed=g=>g.slice(0,2).map(k=>({reviewerId:k.id,
  signature:sign(null,offlineConflictManifestClaimDecisionBytes(body),k.privateKey).toString('base64url')}));
 const decision={body,groupASignatures:signed(reviewersA),groupBSignatures:signed(reviewersB)};
 const pins={decision,reviewerGroupA:reviewerRoster(reviewersA),reviewerGroupB:reviewerRoster(reviewersB),
  expectedDecisionDigest:offlineConflictManifestClaimDecisionDigest(decision),
  expectedReviewerGroupADigest:policy(reviewersA),expectedReviewerGroupBDigest:policy(reviewersB),
  expectedHead:head,expectedPendingBytesDigest:sha(pending),nowMs:now};
 const inspector=createOfflineConflictManifestJournal({directory:dir});
 const out=await inspector.exportInterruptedClaimTranscriptReadOnly(pins);
 const {nowMs:unused,...entry}=pins;
 const entries=[{...entry,bytes:out.bytes,expectedTranscriptDigest:out.transcriptDigest,
  expectedSnapshotDigest:out.snapshotDigest}];
 return {entries,expectedHead:calculateOfflineConflictManifestClaimContinuity({entries}).head};
}
function namespaceCommitment(body,authorities){
 const bytes=offlineConflictSignedNamespaceBodyBytes(body);
 return {body,authoritySignatures:authorities.slice(0,2).map(k=>({authorityId:k.id,
  signature:sign(null,bytes,k.privateKey).toString('base64url')})),
  observerSignatures:observerKeys.map(k=>({observerId:k.id,
   signature:sign(null,bytes,k.privateKey).toString('base64url')}))};
}
function signedTransition(body=transitionBody,oldSigners=oldKeys.slice(0,2),newSigners=newKeys.slice(0,2)){
 const bytes=offlineConflictAuthorityRotationBodyBytes(body);
 return {body,predecessorSignatures:oldSigners.map(k=>({authorityId:k.id,
  signature:sign(null,bytes,k.privateKey).toString('base64url')})),
  successorSignatures:newSigners.map(k=>({authorityId:k.id,
  signature:sign(null,bytes,k.privateKey).toString('base64url')}))};
}
const mutate=(change)=>({...args,...change});
const changeBody=(change)=>({...transitionBody,...change});
const changeTransition=(change)=>({...args.transition,...change});

let history, thirdVerification,thirdBody,secondBody,fourthVerification,fourthBody,thirdTransitionBody;
const firstGenesis=sha('independently pinned 33D chain genesis');
const next=(prev,digest,body)=>offlineConflictAuthorityHistoryNextHead(prev,digest,body.toEpoch,body.successorCommitmentDigest);
const candidateHead=entries=>entries.reduce((h,e)=>next(h,offlineConflictAuthorityRotationDigest(e.transition.body),e.transition.body),firstGenesis);
const mutateHistory=change=>({...history,...change});
const err33d=code=>e=>e?.code===code;
before(async()=>{
 root=await mkdtemp(join(tmpdir(),'trendy33d-'));
 const claim=await makeClaim();
 const inv=calculateOfflineConflictManifestMultiClaimInventory({journalScopeDigest:scope,claims:[claim]});
 const observations=observerKeys.map(k=>({observerId:k.id,claims:[claim],expectedInventoryDigest:inv.inventoryDigest,expectedClaimCount:1}));
 const reconciliationDigest=calculateOfflineConflictManifestMultiClaimReconciliation({journalScopeDigest:scope,observations}).reconciliationDigest;
 const shared={schema:OFFLINE_CONFLICT_SIGNED_NAMESPACE_SCHEMA,namespaceId,journalScopeDigest:scope,
  issuedAt:now-1000,expiresAt:now+10000,reconciliationDigest,
  observers:observerKeys.map(k=>({observerId:k.id,publicKey:pub(k),inventoryDigest:inv.inventoryDigest,claimCount:1}))};
 oldBody={...shared,epoch:3,nonce:'namespace_nonce_33c_old',authorityPolicyDigest:oldDigest};
 newBody={...shared,epoch:4,nonce:'namespace_nonce_33c_new',authorityPolicyDigest:newDigest};
 thirdBody={...shared,epoch:5,nonce:'namespace_nonce_33d_final',authorityPolicyDigest:finalDigest};
 fourthBody={...shared,epoch:6,nonce:'namespace_nonce_33d_fourth',authorityPolicyDigest:fourthDigest};
 const verification=(body,authorities)=>({commitment:namespaceCommitment(body,authorities),authorities:authorityRoster(authorities),
  observations,expectedAuthorityPolicyDigest:body.authorityPolicyDigest,
  expectedCommitmentDigest:offlineConflictSignedNamespaceCommitmentDigest(body),
  expectedJournalScopeDigest:scope,expectedNamespaceId:namespaceId,expectedEpoch:body.epoch,
  expectedReconciliationDigest:reconciliationDigest,expectedObserverCount:3,nowMs:now});
 oldVerification=verification(oldBody,oldKeys);newVerification=verification(newBody,newKeys);
 thirdVerification=verification(thirdBody,finalKeys);fourthVerification=verification(fourthBody,fourthKeys);
 transitionBody={schema:OFFLINE_CONFLICT_AUTHORITY_ROTATION_SCHEMA,namespaceId,journalScopeDigest:scope,
  fromEpoch:3,toEpoch:4,predecessorAuthorityPolicyDigest:oldDigest,successorAuthorityPolicyDigest:newDigest,
  predecessorCommitmentDigest:oldVerification.expectedCommitmentDigest,
  successorCommitmentDigest:newVerification.expectedCommitmentDigest,
  previousTransitionDigest:sha('externally retained predecessor transition'),
  issuedAt:now-1000,expiresAt:now+10000,nonce:'rotation_nonce_33c_001'};
 secondBody={...transitionBody,fromEpoch:4,toEpoch:5,
  predecessorAuthorityPolicyDigest:newDigest,successorAuthorityPolicyDigest:finalDigest,
  predecessorCommitmentDigest:newVerification.expectedCommitmentDigest,
  successorCommitmentDigest:thirdVerification.expectedCommitmentDigest,
  previousTransitionDigest:offlineConflictAuthorityRotationDigest(transitionBody),
  nonce:'rotation_nonce_33d_002'};
 thirdTransitionBody={...secondBody,fromEpoch:5,toEpoch:6,
  predecessorAuthorityPolicyDigest:finalDigest,successorAuthorityPolicyDigest:fourthDigest,
  predecessorCommitmentDigest:thirdVerification.expectedCommitmentDigest,
  successorCommitmentDigest:fourthVerification.expectedCommitmentDigest,
  previousTransitionDigest:offlineConflictAuthorityRotationDigest(secondBody),
  nonce:'rotation_nonce_33d_003'};
 const entries=[{transition:signedTransition(),predecessor:{verification:oldVerification},successor:{verification:newVerification}},
  {transition:signedTransition(secondBody,newKeys.slice(0,2),finalKeys.slice(0,2)),
   predecessor:{verification:newVerification},successor:{verification:thirdVerification}},
  {transition:signedTransition(thirdTransitionBody,finalKeys.slice(0,2),fourthKeys.slice(0,2)),
   predecessor:{verification:thirdVerification},successor:{verification:fourthVerification}}];
 history={entries,expectedNamespaceId:namespaceId,expectedJournalScopeDigest:scope,expectedFirstEpoch:3,
  expectedPreviousTransitionDigest:transitionBody.previousTransitionDigest,
  expectedInitialAuthorityPolicyDigest:oldDigest,
  expectedInitialCommitmentDigest:oldVerification.expectedCommitmentDigest,
  expectedGenesisHead:firstGenesis,expectedFinalAuthorityPolicyDigest:fourthDigest,
  expectedFinalCommitmentDigest:fourthVerification.expectedCommitmentDigest,
  expectedChainHead:candidateHead(entries),nowMs:now};
});
after(async()=>{if(root)await rm(root,{recursive:true,force:true});});
const attesters=keys('observer33e_attest',2);
function forkHistory(){
 const entries=copy(history.entries),body={...thirdTransitionBody,nonce:'rotation_nonce_33e_signed_fork'};
 entries[2].transition=signedTransition(body,finalKeys.slice(0,2),fourthKeys.slice(0,2));
 return {...history,entries,expectedChainHead:candidateHead(entries)};
}
function prefixHistory(){
 const entries=copy(history.entries.slice(0,2));
 return {...history,entries,expectedFinalAuthorityPolicyDigest:finalDigest,
  expectedFinalCommitmentDigest:thirdVerification.expectedCommitmentDigest,
  expectedChainHead:candidateHead(entries)};
}
function viewFor(k,h,nonce=`nonce_33e_${k.id}`){
 const body={schema:OFFLINE_CONFLICT_AUTHORITY_OBSERVER_SCHEMA,observerId:k.id,
  namespaceId:h.expectedNamespaceId,journalScopeDigest:h.expectedJournalScopeDigest,
  firstEpoch:h.expectedFirstEpoch,previousTransitionDigest:h.expectedPreviousTransitionDigest,
  initialAuthorityPolicyDigest:h.expectedInitialAuthorityPolicyDigest,
  initialCommitmentDigest:h.expectedInitialCommitmentDigest,genesisHead:h.expectedGenesisHead,
  finalAuthorityPolicyDigest:h.expectedFinalAuthorityPolicyDigest,
  finalCommitmentDigest:h.expectedFinalCommitmentDigest,chainHead:h.expectedChainHead,
  transitionCount:h.entries.length,observedAt:now-500,expiresAt:now+9000,nonce};
 const attestation={body,signature:sign(null,offlineConflictAuthorityObserverBodyBytes(body),k.privateKey).toString('base64url')};
 return {observerId:k.id,history:h,attestation};
}
function pair(h1=history,h2=history){
 const views=[viewFor(attesters[0],h1),viewFor(attesters[1],h2)];
 const observerPins=views.map((v,i)=>({observerId:v.observerId,publicKey:pub(attesters[i]),
  expectedAttestationDigest:offlineConflictAuthorityObserverAttestationDigest(v.attestation)}));
 return {views,observerPins,expectedNamespaceId:namespaceId,
  expectedJournalScopeDigest:scope,expectedFirstEpoch:3,
  expectedPreviousTransitionDigest:history.expectedPreviousTransitionDigest,
  expectedInitialAuthorityPolicyDigest:history.expectedInitialAuthorityPolicyDigest,
  expectedInitialCommitmentDigest:history.expectedInitialCommitmentDigest,
  expectedGenesisHead:firstGenesis,nowMs:now};
}
const verify=arg=>verifyOfflineConflictAuthorityObserverReconciliation(arg);
const failCode=code=>e=>e?.code===code;
const modify=(arg,change)=>({...arg,...change});
const changedViews=(arg,change,index=1)=>{const views=arg.views.slice();views[index]=change;return {...arg,views};};
const reSign=(view,k=attesters[1])=>{
 const body=view.attestation.body;
 return {...view,attestation:{body,signature:sign(null,offlineConflictAuthorityObserverBodyBytes(body),k.privateKey).toString('base64url')}};
};
t('two independently signed and pinned matching histories agree',()=>{
 const r=verify(pair());assert.equal(r.status,'consistent');assert.equal(r.sharedTransitions,3);
 assert.equal(r.evidence,null);assert.equal(r.verified,true);
 for(const f of ['independentlyPublished','globallyComplete','globalForkPrevention','authorizesRepair','authorizesProduction','authorizesCheckout'])assert.equal(r[f],false);
});
t('valid independently pinned extension is not falsely called equivocation',()=>{
 const r=verify(pair(prefixHistory(),history));assert.equal(r.status,'extension');
 assert.equal(r.sharedTransitions,2);assert.equal(r.evidence,null);
});
t('signed conflicting terminal authority transitions yield self-contained signed evidence',()=>{
 const r=verify(pair(history,forkHistory()));assert.equal(r.status,'equivocation');
 assert.equal(r.sharedTransitions,2);assert.equal(r.evidence.forkIndex,2);
 assert.equal(r.evidence.fromEpoch,5);
 assert.notEqual(r.evidence.leftTransitionDigest,r.evidence.rightTransitionDigest);
 const a=JSON.parse(r.evidence.leftSignedTransitionJson),b=JSON.parse(r.evidence.rightSignedTransitionJson);
 assert.equal(a.body.previousTransitionDigest,b.body.previousTransitionDigest);
 assert.equal(a.predecessorSignatures.length,2);assert.equal(b.successorSignatures.length,2);
 assert.equal(JSON.parse(r.evidence.leftObserverAttestationJson).body.chainHead,r.chainHeads[0]);
 assert.equal(JSON.parse(r.evidence.rightObserverAttestationJson).body.chainHead,r.chainHeads[1]);
});
t('signed fork is still evidence-only, not canonical selection',()=>{
 const r=verify(pair(history,forkHistory()));assert.equal(r.readOnly,true);
 assert.equal(r.authorizesRepair,false);assert.equal(r.globalForkPrevention,false);
 assert.equal(Object.isFrozen(r.evidence),true);
});
t('observer attestation digest determinism',()=>{
 const a=pair();assert.equal(offlineConflictAuthorityObserverAttestationDigest(a.views[0].attestation),a.observerPins[0].expectedAttestationDigest);
});
for(const key of ['expectedNamespaceId','expectedJournalScopeDigest','expectedFirstEpoch',
 'expectedPreviousTransitionDigest','expectedInitialAuthorityPolicyDigest',
 'expectedInitialCommitmentDigest','expectedGenesisHead','nowMs']){
 t('missing independent anchor '+key+' fails closed',()=>{
  const a=pair();assert.throws(()=>verify(modify(a,{[key]:undefined})),failCode('EXCHANGE33E_EXTERNAL_PINS_REQUIRED'));
 });
}
t('missing observer attestation pin fails closed',()=>{
 const a=pair();a.observerPins[1].expectedAttestationDigest=undefined;
 assert.throws(()=>verify(a),failCode('EXCHANGE33E_OBSERVER_SET_INVALID'));
});
t('externally pinned digest rejects signed re-pinning even with legitimate observer key',()=>{
 const a=pair(),v=copy(a.views[1]);v.attestation.body.nonce='nonce_33e_repinned_2';
 const altered=reSign(v);assert.throws(()=>verify(changedViews(a,altered)),failCode('EXCHANGE33E_ATTESTATION_PIN_MISMATCH'));
});
t('externally pinned digest rejects replacing a fork view with signed honest view',()=>{
 const a=pair(history,forkHistory()),replacement=viewFor(attesters[1],history,'nonce_33e_replacement');
 assert.throws(()=>verify(changedViews(a,replacement)),failCode('EXCHANGE33E_ATTESTATION_PIN_MISMATCH'));
});
t('tampered signed observer attestation rejected',()=>{
 const a=pair();a.views[1].attestation.signature=a.views[0].attestation.signature;
 assert.throws(()=>verify(a),failCode('EXCHANGE33E_ATTESTATION_PIN_MISMATCH'));
});
t('forged signature rejected even when digest pin updated',()=>{
 const a=pair(),v=a.views[1];v.attestation.signature=sign(null,offlineConflictAuthorityObserverBodyBytes(v.attestation.body),attesters[0].privateKey).toString('base64url');
 a.observerPins[1].expectedAttestationDigest=offlineConflictAuthorityObserverAttestationDigest(v.attestation);
 assert.throws(()=>verify(a),failCode('EXCHANGE33E_SIGNATURE_INVALID'));
});
t('history substituted under authentic attestation rejected',()=>{
 const a=pair(history,forkHistory());a.views[1].history=history;
 assert.throws(()=>verify(a),failCode('EXCHANGE33E_HISTORY_BINDING_MISMATCH'));
});
t('omitted signed transition rejected against pinned history head',()=>{
 const a=pair();a.views[1].history={...history,entries:history.entries.slice(0,2)};
 assert.throws(()=>verify(a),failCode('EXCHANGE33E_HISTORY_BINDING_MISMATCH'));
});
t('omission with independently re-signed short view is detected as extension not equality',()=>{
 const a=pair(prefixHistory(),history);
 assert.equal(verify(a).status,'extension');
});
t('forged authority signature in observer history rejected recursively',()=>{
 const a=pair(),h=copy(history);
 h.entries[1].transition.predecessorSignatures[0].signature=sign(null,offlineConflictAuthorityRotationBodyBytes(secondBody),oldKeys[0].privateKey).toString('base64url');
 a.views[1].history=h;
 assert.throws(()=>verify(a),e=>e?.code==='EXCHANGE33C_PREDECESSOR_SIGNATURE_INVALID');
});
t('history namespace substitution rejected',()=>{
 const a=pair();a.views[1].history={...history,expectedNamespaceId:'wrong_namespace_33e'};
 assert.throws(()=>verify(a),failCode('EXCHANGE33E_HISTORY_BINDING_MISMATCH'));
});
t('observer namespace substitution rejected before signature verification',()=>{
 const a=pair(),v=copy(a.views[1]);v.attestation.body.namespaceId='wrong_namespace_33e';
 const altered=reSign(v);a.observerPins[1].expectedAttestationDigest=offlineConflictAuthorityObserverAttestationDigest(altered.attestation);
 assert.throws(()=>verify(changedViews(a,altered)),failCode('EXCHANGE33E_VIEW_SCOPE_OR_EXPIRY'));
});
t('expired observer attestation rejected even with valid signature and digest',()=>{
 const a=pair();a.nowMs=now+10000;
 assert.throws(()=>verify(a),failCode('EXCHANGE33E_VIEW_SCOPE_OR_EXPIRY'));
});
t('future dated observer attestation rejected',()=>{
 const a=pair();a.nowMs=now-1000;
 assert.throws(()=>verify(a),failCode('EXCHANGE33E_VIEW_SCOPE_OR_EXPIRY'));
});
t('reversed observer roster rejected',()=>{
 const a=pair();a.observerPins.reverse();a.views.reverse();
 assert.throws(()=>verify(a),failCode('EXCHANGE33E_OBSERVER_SET_INVALID'));
});
t('duplicate observer identity rejected',()=>{
 const a=pair();a.observerPins[1].observerId=a.observerPins[0].observerId;
 assert.throws(()=>verify(a),failCode('EXCHANGE33E_OBSERVER_SET_INVALID'));
});
t('duplicate observer signing key rejected',()=>{
 const a=pair();a.observerPins[1].publicKey=a.observerPins[0].publicKey;
 assert.throws(()=>verify(a),failCode('EXCHANGE33E_DUPLICATE_OBSERVER_KEY'));
});
t('non-Ed25519 public key rejected',()=>{
 const a=pair();a.observerPins[1].publicKey='ZmFrZQ';
 assert.throws(()=>verify(a),failCode('EXCHANGE33E_OBSERVER_KEY_INVALID'));
});
t('sparse observer set rejected',()=>{
 const a=pair();delete a.views[0];
 assert.throws(()=>verify(a),failCode('EXCHANGE33E_OBSERVER_SET_INVALID'));
});
t('unexpected attestation fields rejected',()=>{
 const a=pair();a.views[1].attestation.body.authorizesRepair=true;
 assert.throws(()=>verify(a),failCode('EXCHANGE33E_BODY_INVALID'));
});
t('malicious observer body accessor rejected without execution',()=>{
 const a=pair();Object.defineProperty(a.views[1].attestation.body,'nonce',{enumerable:true,get(){throw Error('MALICIOUS_GETTER_EXECUTED');}});
 assert.throws(()=>verify(a),failCode('EXCHANGE33E_BODY_INVALID'));
});
t('unsigned evidence cannot be silently upgraded to a production assertion',()=>{
 const a=pair();a.views[0].attestation.authorizesProduction=true;
 assert.throws(()=>verify(a),failCode('EXCHANGE33E_OBSERVER_SET_INVALID'));
});
t('malformed signature encoding rejected',()=>{
 const a=pair();a.views[0].attestation.signature='bad';
 assert.throws(()=>verify(a),failCode('EXCHANGE33E_ATTESTATION_INVALID'));
});
t('oversized observer history rejected',()=>{
 const a=pair();a.views[1].history={...history,entries:Array(9).fill(history.entries[0])};
 assert.throws(()=>verify(a),failCode('EXCHANGE33E_HISTORY_BINDING_MISMATCH'));
});
t('signed fork at middle link detected against identical authenticated predecessor',()=>{
 const entries=copy(history.entries.slice(0,2));
 const b={...secondBody,nonce:'rotation_nonce_33e_middle_fork'};
 entries[1].transition=signedTransition(b,newKeys.slice(0,2),finalKeys.slice(0,2));
 const fork={...history,entries,expectedFinalAuthorityPolicyDigest:finalDigest,
  expectedFinalCommitmentDigest:thirdVerification.expectedCommitmentDigest,
  expectedChainHead:candidateHead(entries)};
 const r=verify(pair(prefixHistory(),fork));
 assert.equal(r.status,'equivocation');assert.equal(r.evidence.forkIndex,1);
 assert.equal(r.evidence.fromEpoch,4);
});
t('signed evidence is an immutable textual snapshot after caller mutates input',()=>{
 const a=pair(copy(history),forkHistory()),r=verify(a),snapshot=r.evidence.rightSignedTransitionJson;
 a.views[1].history.entries[2].transition.body.nonce='after_the_fact_mutation';
 assert.equal(r.evidence.rightSignedTransitionJson,snapshot);
});
t('observer body expires beyond one-hour bound rejected',()=>{
 const a=pair(),v=copy(a.views[1]);v.attestation.body.expiresAt=now+7200000;
 assert.throws(()=>offlineConflictAuthorityObserverBodyBytes(v.attestation.body),failCode('EXCHANGE33E_BODY_INVALID'));
});

// Objective 33F integration regression: use the same REAL 33E signed, nested
// interrupted-claim history fixtures rather than invented empty attestations.
const f=tname=>`33F ${tname}`;
const previousEnvelopeDigest=sha('33f independently retained previous envelope');
const envOptions=(change={})=>({reconciliationArgs:pair(history,forkHistory()),
 nonce:'nonce_33f_evidence_0001',issuedAt:now-1000,expiresAt:now+10000,
 previousEnvelopeDigest,...change});
const create33f=(change={})=>exportOfflineConflictAuthorityEquivocationEnvelope(envOptions(change));
const pins33f=(out,change={})=>{
 const doc=JSON.parse(out.bytes.toString('utf8'));
 return {bytes:out.bytes,expectedDigest:out.digest,expectedNonce:doc.meta.nonce,
  expectedPreviousEnvelopeDigest:doc.meta.previousEnvelopeDigest,
  expectedNamespaceId:doc.meta.namespaceId,
  expectedJournalScopeDigest:doc.meta.journalScopeDigest,
  expectedObserverIds:doc.meta.observerIds,expectedAttestationDigests:doc.meta.attestationDigests,
  expectedChainHeads:doc.meta.chainHeads,seenEnvelopeDigests:[],nowMs:now,...change};
};
const digest33f=bytes=>sha(Buffer.concat([Buffer.from('TJ-33F-EQUIVOCATION-ENVELOPE\0'),bytes]));
const canonical33f=x=>Array.isArray(x)?x.map(canonical33f):x&&typeof x==='object'?
 Object.fromEntries(Object.keys(x).sort().map(k=>[k,canonical33f(x[k])])):x;
const edit33f=(out,mutate,canonical=false)=>{
 const doc=JSON.parse(out.bytes.toString('utf8'));mutate(doc);
 const bytes=Buffer.from(JSON.stringify(canonical?canonical33f(doc):doc),'utf8');
 return pins33f(out,{bytes,expectedDigest:digest33f(bytes)});
};
const rejects33f=(f,code)=>assert.throws(f,e=>e?.code===code);
const rejectsAny33f=(f)=>assert.throws(f,e=>e?.code?.startsWith('EXCHANGE33'));

test(f('fully signed equivocation exports portable bytes and re-verifies independently'),()=>{
 const out=create33f(),r=verifyOfflineConflictAuthorityEquivocationEnvelope(pins33f(out));
 assert.equal(r.verified,true);assert.equal(r.status,'equivocation');assert.equal(r.forkIndex,2);
 assert.equal(r.digest,out.digest);assert.equal(r.readOnly,true);assert.ok(out.length>1000);
});
test(f('envelope canonical digest deterministic across equivalent snapshots'),()=>{
 const a=create33f(),b=create33f();assert.equal(a.digest,b.digest);assert.deepEqual(a.bytes,b.bytes);
});
test(f('export refuses consistent histories'),()=>rejects33f(()=>create33f({reconciliationArgs:pair()}),'EXCHANGE33F_FORK_REQUIRED'));
test(f('export refuses a mere prefix extension'),()=>rejects33f(()=>create33f({reconciliationArgs:pair(prefixHistory(),history)}),'EXCHANGE33F_FORK_REQUIRED'));
test(f('export refuses forged observer signatures'),()=>{
 const a=pair(history,forkHistory());a.views[1].attestation.signature='A'.repeat(86);
 rejectsAny33f(()=>create33f({reconciliationArgs:a}));
});
test(f('export refuses absent previous independently pinned envelope digest'),()=>rejects33f(()=>create33f({previousEnvelopeDigest:undefined}),'EXCHANGE33F_DOCUMENT_INVALID'));
test(f('export refuses expired metadata window'),()=>rejects33f(()=>create33f({expiresAt:now-1000}),'EXCHANGE33F_DOCUMENT_INVALID'));
test(f('export refuses oversized expiry window'),()=>rejects33f(()=>create33f({expiresAt:now+7200000}),'EXCHANGE33F_DOCUMENT_INVALID'));
test(f('export refuses a getter without running it'),()=>{
 const a=pair(history,forkHistory());Object.defineProperty(a,'nowMs',{enumerable:true,get(){throw Error('GETTER_RAN');}});
 assert.throws(()=>create33f({reconciliationArgs:a}),e=>e?.message!=='GETTER_RAN');
});
test(f('digest tampering fails before parsing'),()=>{
 const out=create33f(),bytes=Buffer.from(out.bytes);bytes[20]^=1;
 rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(pins33f(out,{bytes})),'EXCHANGE33F_ENVELOPE_DIGEST_MISMATCH');
});
test(f('replay in externally supplied history rejected'),()=>{
 const out=create33f();rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(pins33f(out,{seenEnvelopeDigests:[out.digest]})),'EXCHANGE33F_REPLAY_DETECTED');
});
test(f('wrong independently retained nonce rejected'),()=>{
 const out=create33f();rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(pins33f(out,{expectedNonce:'nonce_33f_wrong_0002'})),'EXCHANGE33F_EXTERNAL_PIN_MISMATCH');
});
test(f('wrong predecessor envelope digest rejected'),()=>{
 const out=create33f();rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(pins33f(out,{expectedPreviousEnvelopeDigest:sha('wrong previous')})),'EXCHANGE33F_EXTERNAL_PIN_MISMATCH');
});
test(f('wrong namespace pin rejected'),()=>{
 const out=create33f();rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(pins33f(out,{expectedNamespaceId:'wrong_namespace_33f'})),'EXCHANGE33F_EXTERNAL_PIN_MISMATCH');
});
test(f('wrong journal scope pin rejected'),()=>{
 const out=create33f();rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(pins33f(out,{expectedJournalScopeDigest:sha('wrong scope')})),'EXCHANGE33F_EXTERNAL_PIN_MISMATCH');
});
test(f('observer omission in external pin list rejected'),()=>{
 const out=create33f();rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(pins33f(out,{expectedObserverIds:['only_one']})),'EXCHANGE33F_EXTERNAL_PINS_REQUIRED');
});
test(f('observer attestation digest substitution rejected'),()=>{
 const out=create33f(),p=pins33f(out);p.expectedAttestationDigests[0]=sha('other attestation');
 rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(p),'EXCHANGE33F_EXTERNAL_PIN_MISMATCH');
});
test(f('observer chain-head substitution rejected'),()=>{
 const out=create33f(),p=pins33f(out);p.expectedChainHeads[1]=sha('wrong head');
 rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(p),'EXCHANGE33F_EXTERNAL_PIN_MISMATCH');
});
test(f('future envelope cannot be verified'),()=>{
 const out=create33f();rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(pins33f(out,{nowMs:now-2000})),'EXCHANGE33F_EXPIRED_OR_FUTURE');
});
test(f('expired envelope cannot be verified'),()=>{
 const out=create33f();rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(pins33f(out,{nowMs:now+10001})),'EXCHANGE33F_EXPIRED_OR_FUTURE');
});
test(f('no replay ledger supplied fails closed'),()=>{
 const out=create33f();rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(pins33f(out,{seenEnvelopeDigests:undefined})),'EXCHANGE33F_EXTERNAL_PINS_REQUIRED');
});
test(f('duplicate JSON keys rejected even with attacker re-pinned digest'),()=>{
 const out=create33f();const bytes=Buffer.from(out.bytes.toString('utf8').replace('"nonce":"nonce_33f_evidence_0001"','"nonce":"nonce_33f_evidence_0001","nonce":"nonce_33f_evidence_0001"'));
 assert.notDeepEqual(bytes,out.bytes);
 rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(pins33f(out,{bytes,expectedDigest:digest33f(bytes)})),'EXCHANGE33F_NONCANONICAL_JSON');
});
test(f('noncanonical whitespace rejected even with attacker re-pinned digest'),()=>{
 const out=create33f(),bytes=Buffer.concat([Buffer.from(' '),out.bytes]);
 rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(pins33f(out,{bytes,expectedDigest:digest33f(bytes)})),'EXCHANGE33F_NONCANONICAL_JSON');
});
test(f('malformed UTF-8 rejected even with attacker re-pinned digest'),()=>{
 const out=create33f(),bytes=Buffer.from(out.bytes);bytes[0]=0xff;
 rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(pins33f(out,{bytes,expectedDigest:digest33f(bytes)})),'EXCHANGE33F_UTF8_INVALID');
});
test(f('truncated evidence rejected even with attacker re-pinned digest'),()=>{
 const out=create33f(),bytes=out.bytes.subarray(0,out.bytes.length-2);
 rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(pins33f(out,{bytes,expectedDigest:digest33f(bytes)})),'EXCHANGE33F_JSON_INVALID');
});
test(f('signed fork evidence omission rejected with re-pinned digest'),()=>{
 const out=create33f(),p=edit33f(out,d=>{delete d.forkEvidence.rightSignedTransitionJson;});
 rejectsAny33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(p));
});
test(f('signed fork evidence substitution rejected with re-pinned digest'),()=>{
 const out=create33f(),p=edit33f(out,d=>{d.forkEvidence.rightSignedTransitionJson=d.forkEvidence.leftSignedTransitionJson;});
 rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(p),'EXCHANGE33F_FORK_BINDING_MISMATCH');
});
test(f('signed transition altered in full history rejected despite re-pinning'),()=>{
 const out=create33f(),p=edit33f(out,d=>{d.reconciliationArgs.views[1].history.entries[2].transition.body.nonce='tampered_33f_transition';});
 rejectsAny33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(p));
});
test(f('observer attestation altered in full history rejected despite re-pinning'),()=>{
 const out=create33f(),p=edit33f(out,d=>{d.reconciliationArgs.views[1].attestation.body.nonce='tampered_33f_observer';});
 rejectsAny33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(p));
});
test(f('re-pinned signed history omission rejected'),()=>{
 const out=create33f(),p=edit33f(out,d=>{d.reconciliationArgs.views[1].history.entries.pop();});
 rejectsAny33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(p));
});
test(f('fork-index substitution rejected with re-pinned digest'),()=>{
 const out=create33f(),p=edit33f(out,d=>{d.meta.forkIndex=1;});
 rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(p),'EXCHANGE33F_FORK_BINDING_MISMATCH');
});
test(f('production authority injection rejected'),()=>{
 const out=create33f(),p=edit33f(out,d=>{d.authorizesProduction=true;});
 rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(p),'EXCHANGE33F_DOCUMENT_INVALID');
});
test(f('unknown typed evidence wrapper rejected'),()=>{
 const out=create33f(),p=edit33f(out,d=>{d.reconciliationArgs.views[0].history.entries[0].predecessor.verification.observations={$type:'unknown',value:'x'};});
 rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(p),'EXCHANGE33F_TYPED_VALUE_INVALID');
});
test(f('private key typed evidence wrapper rejected'),()=>{
 const out=create33f(),p=edit33f(out,d=>{d.reconciliationArgs.views[0].history.entries[0].predecessor.verification.observations={$type:'ed25519-private-key',value:'x'};});
 rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(p),'EXCHANGE33F_TYPED_VALUE_INVALID');
});
test(f('oversized envelope rejected without allocating parser state'),()=>{
 const out=create33f(),bytes=Buffer.alloc(2*1024*1024+1);
 rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(pins33f(out,{bytes})),'EXCHANGE33F_ENVELOPE_SIZE_INVALID');
});
test(f('unsafe sparse external replay ledger rejected'),()=>{
 const out=create33f(),seen=Array(2);seen[0]=sha('first');
 rejects33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(pins33f(out,{seenEnvelopeDigests:seen})),'EXCHANGE33F_EXTERNAL_PINS_REQUIRED');
});
test(f('reordered signed observer body rejected despite re-pinned envelope digest'),()=>{
 const out=create33f(),p=edit33f(out,d=>{d.reconciliationArgs.views[1].attestation.body=canonical33f(d.reconciliationArgs.views[1].attestation.body);});
 rejectsAny33f(()=>verifyOfflineConflictAuthorityEquivocationEnvelope(p));
});
test(f('read-only result cannot imply global publication or settlement'),()=>{
 const out=create33f(),r=verifyOfflineConflictAuthorityEquivocationEnvelope(pins33f(out));
 for(const key of ['independentlyPublished','globallyComplete','persistentReplayProtection','authorizesRepair','authorizesProduction','authorizesCheckout'])assert.equal(r[key],false);
 assert.equal(Object.isFrozen(r),true);
});


// Objective 33G: actual disk-backed replay/continuity acceptance of fully signed
// 33F fork evidence. Fixtures use the real signed 33E nested histories above.
const g=name=>`33G ${name}`;
const genesis33g=()=>offlineConflictEquivocationAcceptanceGenesisHead(namespaceId,scope);
const registry33g=async(options={})=>{
 const directory=await mkdtemp(join(root,'registry33g-'));
 return {directory,registry:createOfflineConflictEquivocationAcceptanceRegistry({directory,namespaceId,
  journalScopeDigest:scope,...options}),head:genesis33g()};
};
const first33g=()=>create33f({nonce:'nonce_33g_first_0001',previousEnvelopeDigest:genesis33g().headDigest});
const next33g=prior=>create33f({nonce:'nonce_33g_second_0002',previousEnvelopeDigest:prior.digest});
const claim33g=(out,head)=>({verificationArgs:pins33f(out),expectedHead:head});
const reject33g=(promise,code)=>assert.rejects(promise,e=>e?.code===code);
const worker33g=async(payload)=>{
 const file=join(root,'worker33g_'+Math.random().toString(36).slice(2)+'.json');
 const verificationArgs={...payload.verificationArgs,bytes:payload.verificationArgs.bytes.toString('base64')};
 await writeFile(file,JSON.stringify({...payload,verificationArgs}),{mode:0o600});
 const script=new URL('./support/objective33g-worker.mjs',import.meta.url).pathname;
 return await new Promise((ok,no)=>{
  const child=spawn(process.execPath,[script,file],{stdio:['ignore','ignore','pipe']});
  let stderr='';child.stderr.on('data',d=>stderr+=d);
  child.on('error',no);child.on('close',(code,signal)=>ok({code,signal,stderr}));
 });
};
test(g('genesis is scoped, deterministic and never claims external anchoring'),()=>{
 assert.deepEqual(genesis33g(),genesis33g());
 assert.notEqual(genesis33g().headDigest,offlineConflictEquivocationAcceptanceGenesisHead('other_namespace_33g',scope).headDigest);
 assert.notEqual(genesis33g().headDigest,offlineConflictEquivocationAcceptanceGenesisHead(namespaceId,sha('other scope')).headDigest);
});
test(g('accepts signed evidence, persists exact pinned monotonic head across restart'),async()=>{
 const {directory,registry,head}=await registry33g(),out=first33g();
 assert.equal((await registry.inspect({expectedHead:head})).count,0);
 const accepted=await registry.accept(claim33g(out,head));
 assert.equal(accepted.count,1);assert.equal(accepted.lastEnvelopeDigest,out.digest);
 assert.equal(accepted.authorizesRepair,false);assert.equal(accepted.authorizesCheckout,false);
 assert.equal(accepted.independentlyAnchored,false);assert.equal(accepted.trustedTimestamp,false);
 const restarted=createOfflineConflictEquivocationAcceptanceRegistry({directory,namespaceId,journalScopeDigest:scope});
 assert.equal((await restarted.inspect({expectedHead:{count:1,headDigest:accepted.headDigest}})).count,1);
 assert.equal((await readdir(directory)).filter(x=>x.endsWith('.json')).length,1);
});
test(g('two consecutive distinct signed forks preserve exact predecessor continuity'),async()=>{
 const {registry,head}=await registry33g(),first=first33g(),second=next33g(first);
 const a=await registry.accept(claim33g(first,head));
 const b=await registry.accept(claim33g(second,{count:a.count,headDigest:a.headDigest}));
 assert.equal(b.count,2);assert.equal(b.lastEnvelopeDigest,second.digest);
});
test(g('same envelope digest is rejected by durable replay history after restart'),async()=>{
 const {directory,registry,head}=await registry33g(),out=first33g();
 const a=await registry.accept(claim33g(out,head));
 const restarted=createOfflineConflictEquivocationAcceptanceRegistry({directory,namespaceId,journalScopeDigest:scope});
 await reject33g(restarted.accept(claim33g(out,{count:a.count,headDigest:a.headDigest})),'EXCHANGE33G_REPLAY');
});
test(g('reused nonce with new valid signed envelope digest is rejected'),async()=>{
 const {registry,head}=await registry33g(),first=first33g();
 const a=await registry.accept(claim33g(first,head));
 const sameNonce=create33f({nonce:'nonce_33g_first_0001',previousEnvelopeDigest:first.digest});
 await reject33g(registry.accept(claim33g(sameNonce,{count:a.count,headDigest:a.headDigest})),'EXCHANGE33G_REPLAY');
});
test(g('stale external head rejects new valid envelope'),async()=>{
 const {registry,head}=await registry33g(),first=first33g();
 await registry.accept(claim33g(first,head));
 await reject33g(registry.accept(claim33g(next33g(first),head)),'EXCHANGE33G_STALE_OR_ROLLED_BACK_HEAD');
});
test(g('wrong predecessor rejects even with newly signed independently re-pinned envelope'),async()=>{
 const {registry,head}=await registry33g();
 const bad=create33f({nonce:'nonce_33g_wrong_previous',previousEnvelopeDigest:sha('unrelated predecessor')});
 await reject33g(registry.accept(claim33g(bad,head)),'EXCHANGE33G_PREDECESSOR_MISMATCH');
});
test(g('wrong namespace and scope are rejected before writing'),async()=>{
 const {registry,head}=await registry33g(),out=first33g();
 await reject33g(registry.accept({expectedHead:head,verificationArgs:pins33f(out,{expectedNamespaceId:'other_namespace_33g'})}),'EXCHANGE33G_SCOPE_MISMATCH');
 await reject33g(registry.accept({expectedHead:head,verificationArgs:pins33f(out,{expectedJournalScopeDigest:sha('other')})}),'EXCHANGE33G_SCOPE_MISMATCH');
});
test(g('forged evidence bytes cannot enter acceptance registry'),async()=>{
 const {registry,head}=await registry33g(),out=first33g();
 const bytes=Buffer.from(out.bytes);bytes[50]^=1;
 await reject33g(registry.accept({expectedHead:head,verificationArgs:pins33f(out,{bytes})}),'EXCHANGE33F_ENVELOPE_DIGEST_MISMATCH');
});
test(g('missing independent head pin is rejected'),async()=>{
 const {registry}=await registry33g();
 await reject33g(registry.accept({verificationArgs:pins33f(first33g())}),'EXCHANGE33G_REQUEST_INVALID');
});
test(g('record tampering fails closed against the original head'),async()=>{
 const {registry,directory,head}=await registry33g(),out=first33g();
 const a=await registry.accept(claim33g(out,head)),p=join(directory,'0001.json');
 const e=JSON.parse(await readFile(p,'utf8'));e.nonce='nonce_33g_tampered';
 await writeFile(p,JSON.stringify(e));
 await reject33g(registry.inspect({expectedHead:{count:1,headDigest:a.headDigest}}),'EXCHANGE33G_HISTORY_INVALID');
});
test(g('missing historical record cannot pass independently pinned head'),async()=>{
 const {registry,directory,head}=await registry33g(),out=first33g();
 const a=await registry.accept(claim33g(out,head));await unlink(join(directory,'0001.json'));
 await reject33g(registry.inspect({expectedHead:{count:1,headDigest:a.headDigest}}),'EXCHANGE33G_STALE_OR_ROLLED_BACK_HEAD');
});
test(g('orphan record filename fails closed'),async()=>{
 const {registry,directory,head}=await registry33g();
 await registry.inspect({expectedHead:head});await writeFile(join(directory,'9999.json'),'{}',{mode:0o600});
 await reject33g(registry.inspect({expectedHead:head}),'EXCHANGE33G_HISTORY_INVALID');
});
test(g('symlinked record fails closed'),async()=>{
 const {registry,directory,head}=await registry33g();
 await registry.inspect({expectedHead:head});await symlink('/etc/passwd',join(directory,'0001.json'));
 await reject33g(registry.inspect({expectedHead:head}),'EXCHANGE33G_RECORD_UNSAFE');
});
test(g('world-readable record fails closed'),async()=>{
 const {registry,directory,head}=await registry33g(),out=first33g();
 const a=await registry.accept(claim33g(out,head));await chmod(join(directory,'0001.json'),0o644);
 await reject33g(registry.inspect({expectedHead:{count:1,headDigest:a.headDigest}}),'EXCHANGE33G_RECORD_UNSAFE');
});
test(g('real competing Node processes admit exactly one signed envelope'),async()=>{
 const {directory,head}=await registry33g(),out=first33g(),request={directory,namespaceId,
  journalScopeDigest:scope,...claim33g(out,head)};
 const results=await Promise.all([worker33g(request),worker33g(request)]);
 assert.deepEqual(results.map(x=>x.code).sort((a,b)=>a-b),[0,11]);
 assert.match(results.find(x=>x.code===11).stderr,/EXCHANGE33G_(STALE_OR_ROLLED_BACK_HEAD|REPLAY)/);
 const r=createOfflineConflictEquivocationAcceptanceRegistry({directory,namespaceId,journalScopeDigest:scope});
 const record=JSON.parse(await readFile(join(directory,'0001.json'),'utf8'));
 assert.equal((await r.inspect({expectedHead:{count:1,headDigest:record.recordDigest}})).count,1);
});
test(g('actual child-process crash after durable pending sync blocks all new writes'),async()=>{
 const {directory,registry,head}=await registry33g(),out=first33g();
 const result=await worker33g({directory,namespaceId,journalScopeDigest:scope,...claim33g(out,head),crashAt:'after-pending-sync'});
 assert.equal(result.signal,'SIGKILL');
 await reject33g(registry.inspect({expectedHead:head}),'EXCHANGE33G_UNCERTAIN_COMMIT');
 await reject33g(registry.accept(claim33g(out,head)),'EXCHANGE33G_UNCERTAIN_COMMIT');
});
test(g('actual child-process crash after hardlink sync remains uncertain and blocked'),async()=>{
 const {directory,registry,head}=await registry33g(),out=first33g();
 const result=await worker33g({directory,namespaceId,journalScopeDigest:scope,...claim33g(out,head),crashAt:'after-link-sync'});
 assert.equal(result.signal,'SIGKILL');
 assert.ok((await readdir(directory)).includes('0001.json'));
 await reject33g(registry.inspect({expectedHead:head}),'EXCHANGE33G_UNCERTAIN_COMMIT');
});
test(g('actual child-process crash after committed directory sync is independently inspectable'),async()=>{
 const {directory,registry,head}=await registry33g(),out=first33g();
 const result=await worker33g({directory,namespaceId,journalScopeDigest:scope,...claim33g(out,head),crashAt:'after-commit-sync'});
 assert.equal(result.signal,'SIGKILL');
 const record=JSON.parse(await readFile(join(directory,'0001.json'),'utf8'));
 const accepted=await registry.inspect({expectedHead:{count:1,headDigest:record.recordDigest}});
 assert.equal(accepted.lastEnvelopeDigest,out.digest);
 await reject33g(registry.accept(claim33g(out,{count:1,headDigest:record.recordDigest})),'EXCHANGE33G_REPLAY');
});
test(g('simulated crash in same process leaves uncertain marker rather than retrying'),async()=>{
 const {directory,head}=await registry33g(),out=first33g();
 const crash=createOfflineConflictEquivocationAcceptanceRegistry({directory,namespaceId,journalScopeDigest:scope,
  injectFault:stage=>{if(stage==='after-pending-sync')throw Error('33G simulated disk interruption');}});
 await assert.rejects(crash.accept(claim33g(out,head)),/33G simulated disk interruption/);
 await reject33g(crash.inspect({expectedHead:head}),'EXCHANGE33G_UNCERTAIN_COMMIT');
});
test(g('unsafe lock pathname swap is rejected before acceptance'),async()=>{
 const {registry,directory,head}=await registry33g();
 await registry.inspect({expectedHead:head});await unlink(join(directory,'.acceptance-lock'));
 await symlink('/etc/passwd',join(directory,'.acceptance-lock'));
 await reject33g(registry.accept(claim33g(first33g(),head)),'ELOOP');
});

test(g('distinct concurrent signed envelopes cannot fork the same externally pinned predecessor'),async()=>{
 const {directory,head}=await registry33g(),a=first33g(),b=create33f({
  nonce:'nonce_33g_parallel_0002',previousEnvelopeDigest:head.headDigest});
 const req=out=>({directory,namespaceId,journalScopeDigest:scope,...claim33g(out,head)});
 const results=await Promise.all([worker33g(req(a)),worker33g(req(b))]);
 assert.deepEqual(results.map(x=>x.code).sort((x,y)=>x-y),[0,11]);
 assert.match(results.find(x=>x.code===11).stderr,/EXCHANGE33G_STALE_OR_ROLLED_BACK_HEAD/);
 const record=JSON.parse(await readFile(join(directory,'0001.json'),'utf8'));
 assert.ok([a.digest,b.digest].includes(record.envelopeDigest));
});
test(g('hardlinked historical record fails closed'),async()=>{
 const {registry,directory,head}=await registry33g(),out=first33g();
 const a=await registry.accept(claim33g(out,head));
 const {link}=await import('node:fs/promises');await link(join(directory,'0001.json'),join(root,'hardlink33g_'+Date.now()));
 await reject33g(registry.inspect({expectedHead:{count:1,headDigest:a.headDigest}}),'EXCHANGE33G_RECORD_UNSAFE');
});
test(g('world-readable registry directory fails closed'),async()=>{
 const {registry,directory,head}=await registry33g();
 await chmod(directory,0o755);
 await reject33g(registry.accept(claim33g(first33g(),head)),'EXCHANGE33G_DIRECTORY_UNSAFE');
});
test(g('forged nested signed history rejected even when envelope digest is attacker re-pinned'),async()=>{
 const {registry,head}=await registry33g(),out=first33g();
 const tampered=edit33f(out,d=>{d.reconciliationArgs.views[1].attestation.body.nonce='nonce_33g_forged';});
 await assert.rejects(registry.accept({expectedHead:head,verificationArgs:tampered}),e=>e?.code?.startsWith('EXCHANGE33'));
});


// Objective 33H: independent dual-reviewer-group read-only adjudication of
// interrupted 33G evidence acceptance. These use real signed 33F envelopes.
const h=name=>`33H ${name}`;
const reviewerGroup33h=g=>g.map(k=>({reviewerId:k.id,publicKey:pub(k)}));
const groupA33h=reviewerGroup33h(reviewersA),groupB33h=reviewerGroup33h(reviewersB);
const groupADigest33h=offlineConflictEquivocationPendingReviewerGroupDigest(groupA33h);
const groupBDigest33h=offlineConflictEquivocationPendingReviewerGroupDigest(groupB33h);
const prepare33h=async(stage='after-pending-sync')=>{
 const {directory,registry,head}=await registry33g();
 const out=first33g();
 const result=await worker33g({directory,namespaceId,journalScopeDigest:scope,
  ...claim33g(out,head),crashAt:stage});
 assert.equal(result.signal,'SIGKILL');
 const bytes=await readFile(join(directory,'.pending.json'));
 const pending=JSON.parse(bytes);
 return {directory,registry,head,out,bytes,pending,stage};
};
const decision33h=(fx,change={},options={})=>{
 const body={schema:OFFLINE_CONFLICT_EQUIVOCATION_PENDING_DECISION_SCHEMA,action:'inspect-only',
  namespaceId,journalScopeDigest:scope,expectedPreHead:fx.head,
  pendingBytesDigest:sha(fx.bytes),pendingRecordDigest:fx.pending.recordDigest,
  pendingIndex:fx.head.count+1,
  expectedPendingState:fx.stage==='after-link-sync'?'pending-linked':'pending-only',
  reviewerGroupADigest:groupADigest33h,reviewerGroupBDigest:groupBDigest33h,
  issuedAt:now-1000,expiresAt:now+10000,nonce:'nonce_33h_adjudicate_0001',...change};
 const bytes=offlineConflictEquivocationPendingDecisionBytes(body);
 const signed=g=>g.slice(0,2).map(k=>({reviewerId:k.id,
  signature:sign(null,bytes,k.privateKey).toString('base64url')}));
 const decision={body,groupASignatures:signed(reviewersA),groupBSignatures:signed(reviewersB)};
 return {decision,reviewerGroupA:groupA33h,reviewerGroupB:groupB33h,
  expectedReviewerGroupADigest:groupADigest33h,expectedReviewerGroupBDigest:groupBDigest33h,
  expectedDecisionDigest:offlineConflictEquivocationPendingDecisionDigest(decision),
  expectedPendingBytesDigest:sha(fx.bytes),expectedPreHead:fx.head,nowMs:now,...options};
};
const reject33h=(promise,code)=>assert.rejects(promise,e=>e?.code===code);
test(h('independently signed two-group decision classifies SIGKILL pending-only without repair'),async()=>{
 const fx=await prepare33h();const beforeNames=await readdir(fx.directory);
 const r=await fx.registry.adjudicatePendingReadOnly(decision33h(fx));
 assert.equal(r.status,'pending-only');assert.equal(r.verified,true);
 for(const k of ['authorizesRepair','authorizesRecovery','authorizesCheckout','authorizesProduction',
  'globallyComplete','independentlyWitnessed','trustedTimestamp','mutatedAcceptanceRecords'])assert.equal(r[k],false);
 assert.deepEqual(await readdir(fx.directory),beforeNames);
 assert.deepEqual(await readFile(join(fx.directory,'.pending.json')),fx.bytes);
 await reject33g(fx.registry.inspect({expectedHead:fx.head}),'EXCHANGE33G_UNCERTAIN_COMMIT');
});
test(h('real SIGKILL after hardlink sync classifies pending-linked without cleanup'),async()=>{
 const fx=await prepare33h('after-link-sync');const beforeNames=await readdir(fx.directory);
 const r=await fx.registry.adjudicatePendingReadOnly(decision33h(fx));
 assert.equal(r.status,'pending-linked');assert.equal(r.observedHead.count,1);
 assert.deepEqual(await readdir(fx.directory),beforeNames);
 await reject33g(fx.registry.inspect({expectedHead:fx.head}),'EXCHANGE33G_UNCERTAIN_COMMIT');
});
test(h('decision with incorrect pending state fails closed'),async()=>{
 const fx=await prepare33h();const p=decision33h(fx,{expectedPendingState:'pending-linked'});
 await reject33h(fx.registry.adjudicatePendingReadOnly(p),'EXCHANGE33H_STATE_MISMATCH');
});
test(h('pending bytes alteration fails even when signed decision remains valid'),async()=>{
 const fx=await prepare33h();const p=decision33h(fx);
 const b=Buffer.from(fx.bytes);b[40]^=1;await writeFile(join(fx.directory,'.pending.json'),b);
 await reject33h(fx.registry.adjudicatePendingReadOnly(p),'EXCHANGE33H_PENDING_TAMPERED');
});
test(h('substituted pending record digest signed with new external pins fails'),async()=>{
 const fx=await prepare33h();const p=decision33h(fx,{pendingRecordDigest:sha('wrong')});
 await reject33h(fx.registry.adjudicatePendingReadOnly(p),'EXCHANGE33H_PENDING_TAMPERED');
});
test(h('expired independently signed decision rejected'),async()=>{
 const fx=await prepare33h();const p=decision33h(fx,{issuedAt:now-20000,expiresAt:now-1000});
 await reject33h(fx.registry.adjudicatePendingReadOnly(p),'EXCHANGE33H_DECISION_EXPIRED');
});
test(h('not-yet-issued independently signed decision rejected'),async()=>{
 const fx=await prepare33h();const p=decision33h(fx,{issuedAt:now+1000,expiresAt:now+10000});
 await reject33h(fx.registry.adjudicatePendingReadOnly(p),'EXCHANGE33H_DECISION_EXPIRED');
});
test(h('forged signature fails even with attacker-repinned signed-decision digest'),async()=>{
 const fx=await prepare33h();const p=decision33h(fx);
 p.decision.groupASignatures[0].signature=sign(null,Buffer.from('forgery'),reviewersA[0].privateKey).toString('base64url');
 p.expectedDecisionDigest=offlineConflictEquivocationPendingDecisionDigest(p.decision);
 await reject33h(fx.registry.adjudicatePendingReadOnly(p),'EXCHANGE33H_SIGNATURES_INVALID');
});
test(h('insufficient independent reviewer quorum rejected'),async()=>{
 const fx=await prepare33h();const p=decision33h(fx);p.decision.groupBSignatures.pop();
 p.expectedDecisionDigest=offlineConflictEquivocationPendingDecisionDigest(p.decision);
 await reject33h(fx.registry.adjudicatePendingReadOnly(p),'EXCHANGE33H_SIGNATURES_INVALID');
});
test(h('duplicate reviewer signature cannot create majority'),async()=>{
 const fx=await prepare33h();const p=decision33h(fx);
 p.decision.groupASignatures[1]={...p.decision.groupASignatures[0]};
 p.expectedDecisionDigest=offlineConflictEquivocationPendingDecisionDigest(p.decision);
 await reject33h(fx.registry.adjudicatePendingReadOnly(p),'EXCHANGE33H_SIGNATURES_INVALID');
});
test(h('external group pin substitution rejected'),async()=>{
 const fx=await prepare33h();const p=decision33h(fx,{},{expectedReviewerGroupADigest:sha('attacker policy')});
 await reject33h(fx.registry.adjudicatePendingReadOnly(p),'EXCHANGE33H_EXTERNAL_PINS_MISMATCH');
});
test(h('external pending bytes pin substitution rejected'),async()=>{
 const fx=await prepare33h();const p=decision33h(fx,{},{expectedPendingBytesDigest:sha('attacker bytes')});
 await reject33h(fx.registry.adjudicatePendingReadOnly(p),'EXCHANGE33H_EXTERNAL_PINS_MISMATCH');
});
test(h('stale independently pinned pre-head rejected'),async()=>{
 const fx=await prepare33h();const p=decision33h(fx,{},{expectedPreHead:{count:0,headDigest:sha('stale')}});
 await reject33h(fx.registry.adjudicatePendingReadOnly(p),'EXCHANGE33H_EXTERNAL_PINS_MISMATCH');
});
test(h('namespace substitution rejected even when separately signed'),async()=>{
 const fx=await prepare33h();const p=decision33h(fx,{namespaceId:'namespace_attacker_33h'});
 await reject33h(fx.registry.adjudicatePendingReadOnly(p),'EXCHANGE33H_SCOPE_MISMATCH');
});
test(h('missing pending file is never recreated'),async()=>{
 const fx=await prepare33h();const p=decision33h(fx);await unlink(join(fx.directory,'.pending.json'));
 await reject33h(fx.registry.adjudicatePendingReadOnly(p),'EXCHANGE33H_PENDING_MISSING');
 assert.equal((await readdir(fx.directory)).includes('.pending.json'),false);
});
test(h('symlinked pending is rejected'),async()=>{
 const fx=await prepare33h();const p=decision33h(fx);
 await unlink(join(fx.directory,'.pending.json'));await symlink('/etc/passwd',join(fx.directory,'.pending.json'));
 await reject33h(fx.registry.adjudicatePendingReadOnly(p),'EXCHANGE33G_RECORD_UNSAFE');
});
test(h('copied rather than hardlinked record rejected as non-atomic link'),async()=>{
 const fx=await prepare33h('after-link-sync');const p=decision33h(fx);
 await unlink(join(fx.directory,'0001.json'));await writeFile(join(fx.directory,'0001.json'),fx.bytes,{mode:0o600});
 await reject33h(fx.registry.adjudicatePendingReadOnly(p),'EXCHANGE33H_LINK_MISMATCH');
});
test(h('linked record content tamper rejected even when independent decision pinned'),async()=>{
 const fx=await prepare33h('after-link-sync');const p=decision33h(fx);
 const b=Buffer.from(fx.bytes);b[100]^=1;await writeFile(join(fx.directory,'0001.json'),b);
 await reject33h(fx.registry.adjudicatePendingReadOnly(p),'EXCHANGE33H_PENDING_TAMPERED');
});
test(h('unexpected orphan record fails closed'),async()=>{
 const fx=await prepare33h();const p=decision33h(fx);
 await writeFile(join(fx.directory,'9999.json'),'{}',{mode:0o600});
 await reject33h(fx.registry.adjudicatePendingReadOnly(p),'EXCHANGE33G_HISTORY_INVALID');
});
test(h('world-readable pending file fails closed'),async()=>{
 const fx=await prepare33h();const p=decision33h(fx);
 await chmod(join(fx.directory,'.pending.json'),0o644);
 await reject33h(fx.registry.adjudicatePendingReadOnly(p),'EXCHANGE33G_RECORD_UNSAFE');
});
test(h('no pending adjudication on completed acceptance and no new lock creation'),async()=>{
 const {directory,registry,head}=await registry33g();const out=first33g();
 await registry.accept(claim33g(out,head));
 const fake={head,stage:'after-pending-sync',bytes:Buffer.from('{}'),pending:{recordDigest:sha('fake')}};
 const p=decision33h(fake);
 await reject33h(registry.adjudicatePendingReadOnly(p),'EXCHANGE33H_PENDING_MISSING');
 assert.equal((await readdir(directory)).includes('.pending.json'),false);
});

// Objective 33I: portable observer-signed read-only adjudication evidence.
const i=name=>`33I ${name}`;
const observers33i=keys('observer33i',3);
const fixture33i=async(stage='after-pending-sync')=>{
 const fx=await prepare33h(stage),p=decision33h(fx),r=await fx.registry.adjudicatePendingReadOnly(p);
 const make=(observer=observers33i[0],changes={})=>{
  const out=exportOfflineConflictPendingAdjudicationTranscript({adjudication:r,decision:p.decision,
   reviewerGroupA:p.reviewerGroupA,reviewerGroupB:p.reviewerGroupB,
   observerId:observer.id,observerPublicKey:pub(observer),observerPrivateKey:observer.privateKey,
   observedAt:now,expiresAt:now+30000,nonce:`nonce_33i_${observer.id}`,...changes});
  return {bytes:out.bytes,expectedTranscriptDigest:out.digest,nowMs:now+1000,
   expectedNamespaceId:namespaceId,expectedJournalScopeDigest:scope,
   expectedDecisionDigest:p.expectedDecisionDigest,
   expectedReviewerGroupADigest:p.expectedReviewerGroupADigest,
   expectedReviewerGroupBDigest:p.expectedReviewerGroupBDigest,
   expectedPendingBytesDigest:p.expectedPendingBytesDigest,
   expectedPreHead:fx.head,expectedObservedHead:r.observedHead,
   expectedObserverId:observer.id,expectedObserverPublicKey:pub(observer)};
 };
 return {fx,p,r,make};
};
const mutate33i=(a,fn)=>{const t=JSON.parse(a.bytes);fn(t);return Buffer.from(JSON.stringify(t));};
const rejects33i=(fn,code)=>assert.throws(fn,e=>e?.code===code);
test(i('signed pending-only transcript roundtrips with external pins'),async()=>{
 const f=await fixture33i(),a=f.make();const r=verifyOfflineConflictPendingAdjudicationTranscript(a);
 assert.equal(r.verified,true);assert.equal(r.status,'pending-only');assert.equal(r.observerAssertionOnly,true);
 assert.equal(r.authorizesRepair,false);assert.equal(r.independentlyWitnessed,false);
});
test(i('signed pending-linked transcript roundtrips after SIGKILL'),async()=>{
 const f=await fixture33i('after-link-sync'),a=f.make();
 assert.equal(verifyOfflineConflictPendingAdjudicationTranscript(a).status,'pending-linked');
});
test(i('two independent observers reconcile same signed snapshot'),async()=>{
 const f=await fixture33i(),r=reconcileOfflineConflictPendingAdjudicationTranscripts({
  left:f.make(observers33i[0]),right:f.make(observers33i[1])});
 assert.equal(r.status,'consistent');assert.equal(r.authorizesProduction,false);
});
test(i('signed transcript never changes pending files'),async()=>{
 const f=await fixture33i(),before=await readFile(join(f.fx.directory,'.pending.json'));
 verifyOfflineConflictPendingAdjudicationTranscript(f.make());
 assert.deepEqual(await readFile(join(f.fx.directory,'.pending.json')),before);
 await reject33g(f.fx.registry.inspect({expectedHead:f.fx.head}),'EXCHANGE33G_UNCERTAIN_COMMIT');
});
test(i('independent transcript digest substitution rejected'),async()=>{
 const f=await fixture33i(),a=f.make();
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,expectedTranscriptDigest:sha('attacker')}),'EXCHANGE33I_TRANSCRIPT_DIGEST_MISMATCH');
});
test(i('replayed digest rejected using caller-maintained history'),async()=>{
 const f=await fixture33i(),a=f.make();
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,seenDigests:[a.expectedTranscriptDigest]}),'EXCHANGE33I_REPLAY');
});
test(i('replayed nonce rejected using caller-maintained history'),async()=>{
 const f=await fixture33i(),a=f.make();
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,seenNonces:[`nonce_33i_${observers33i[0].id}`]}),'EXCHANGE33I_REPLAY');
});
test(i('expired transcript rejected'),async()=>{
 const f=await fixture33i(),a=f.make();
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,nowMs:now+30001}),'EXCHANGE33I_TRANSCRIPT_EXPIRED');
});
test(i('future transcript rejected'),async()=>{
 const f=await fixture33i(),a=f.make();
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,nowMs:now-1}),'EXCHANGE33I_TRANSCRIPT_EXPIRED');
});
test(i('observer signature forgery rejected even when repinned'),async()=>{
 const f=await fixture33i(),a=f.make();const bytes=mutate33i(a,t=>{t.observerSignature=sign(null,Buffer.from('forgery'),observers33i[0].privateKey).toString('base64url');});
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,bytes,expectedTranscriptDigest:sha33i(bytes)}),'EXCHANGE33I_OBSERVER_SIGNATURE_INVALID');
});
const sha33i=bytes=>createHash('sha256').update('TJ-33I-TRANSCRIPT\0').update(bytes).digest('hex');
test(i('observer key substitution rejected'),async()=>{
 const f=await fixture33i(),a=f.make();
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,expectedObserverPublicKey:pub(observers33i[1])}),'EXCHANGE33I_EXTERNAL_PINS_MISMATCH');
});
test(i('observer identity substitution rejected'),async()=>{
 const f=await fixture33i(),a=f.make();
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,expectedObserverId:observers33i[1].id}),'EXCHANGE33I_EXTERNAL_PINS_MISMATCH');
});
test(i('decision digest substitution rejected'),async()=>{
 const f=await fixture33i(),a=f.make();
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,expectedDecisionDigest:sha('fake')}),'EXCHANGE33I_EXTERNAL_PINS_MISMATCH');
});
test(i('reviewer group pin substitution rejected'),async()=>{
 const f=await fixture33i(),a=f.make();
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,expectedReviewerGroupBDigest:sha('fake')}),'EXCHANGE33I_EXTERNAL_PINS_MISMATCH');
});
test(i('predecessor rollback pin rejected'),async()=>{
 const f=await fixture33i(),a=f.make();
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,expectedPreHead:{count:0,headDigest:sha('old')}}),'EXCHANGE33I_EXTERNAL_PINS_MISMATCH');
});
test(i('divergent observed head pin rejected'),async()=>{
 const f=await fixture33i(),a=f.make();
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,expectedObservedHead:{count:0,headDigest:sha('fork')}}),'EXCHANGE33I_EXTERNAL_PINS_MISMATCH');
});
test(i('truncated JSON rejected'),async()=>{
 const f=await fixture33i(),a=f.make();
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,bytes:a.bytes.subarray(0,a.bytes.length-1)}),'EXCHANGE33I_BYTES_INVALID');
});
test(i('malformed UTF8 rejected'),async()=>{
 const f=await fixture33i(),a=f.make(),bytes=Buffer.from(a.bytes);bytes[2]=0xff;
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,bytes}),'EXCHANGE33I_BYTES_INVALID');
});
test(i('duplicate JSON key rejected'),async()=>{
 const f=await fixture33i(),a=f.make();
 const bytes=Buffer.from(a.bytes.toString().replace('"body":{','"body":{},"body":{'));
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,bytes}),'EXCHANGE33I_NONCANONICAL');
});
test(i('omitted signed decision rejected'),async()=>{
 const f=await fixture33i(),a=f.make(),bytes=mutate33i(a,t=>{delete t.decision;});
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,bytes}),'EXCHANGE33I_NONCANONICAL');
});
test(i('omitted reviewer authorization rejected'),async()=>{
 const f=await fixture33i(),a=f.make(),bytes=mutate33i(a,t=>{t.decision.groupASignatures.pop();});
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,bytes,expectedTranscriptDigest:sha33i(bytes)}),'EXCHANGE33H_EXTERNAL_PINS_MISMATCH');
});
test(i('tampered signed decision rejected with attacker transcript repin'),async()=>{
 const f=await fixture33i(),a=f.make(),bytes=mutate33i(a,t=>{t.decision.groupBSignatures[0].signature=sign(null,Buffer.from('wrong'),reviewersB[0].privateKey).toString('base64url');});
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,bytes,expectedTranscriptDigest:sha33i(bytes)}),'EXCHANGE33H_EXTERNAL_PINS_MISMATCH');
});
test(i('body claims inconsistent pending-only head rejected'),async()=>{
 const f=await fixture33i(),a=f.make(),bytes=mutate33i(a,t=>{t.body.observedHead={count:1,headDigest:t.body.pendingRecordDigest};});
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,bytes}),'EXCHANGE33I_SNAPSHOT_INCONSISTENT');
});
test(i('body claims inconsistent pending-linked head rejected'),async()=>{
 const f=await fixture33i('after-link-sync'),a=f.make(),bytes=mutate33i(a,t=>{t.body.observedHead={count:1,headDigest:sha('fork')};});
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,bytes}),'EXCHANGE33I_SNAPSHOT_INCONSISTENT');
});
test(i('same observer cannot impersonate independent witness'),async()=>{
 const f=await fixture33i(),a=f.make();
 rejects33i(()=>reconcileOfflineConflictPendingAdjudicationTranscripts({left:a,right:a}),'EXCHANGE33I_OBSERVERS_NOT_INDEPENDENT');
});
test(i('cross-observer omission of decision scope fails closed'),async()=>{
 const f=await fixture33i(),a=f.make(observers33i[0]),b=f.make(observers33i[1]);
 rejects33i(()=>reconcileOfflineConflictPendingAdjudicationTranscripts({left:a,right:{...b,expectedDecisionDigest:sha('missing')}}),'EXCHANGE33I_EXTERNAL_PINS_MISMATCH');
});
test(i('cross-observer conflicting snapshot fails closed with valid signatures'),async()=>{
 const f=await fixture33i(),a=f.make(observers33i[0]),b=f.make(observers33i[1]);
 // The second observer is independently signed, but an attacker with that key
 // substitutes a locally asserted linked snapshot inconsistent with the decision.
 const bytes=mutate33i(b,t=>{t.body.pendingState='pending-linked';t.body.observedHead={count:1,headDigest:t.body.pendingRecordDigest};
  t.observerSignature=sign(null,offlineConflictPendingAdjudicationTranscriptBodyBytes(t.body),observers33i[1].privateKey).toString('base64url');});
 rejects33i(()=>reconcileOfflineConflictPendingAdjudicationTranscripts({left:a,right:{...b,bytes,expectedTranscriptDigest:sha33i(bytes),expectedObservedHead:{count:1,headDigest:f.r.pendingRecordDigest}}}),'EXCHANGE33I_DECISION_MISMATCH');
});
test(i('export refuses unverified adjudication'),async()=>{
 const f=await fixture33i(),bad={...f.r,verified:false};
 rejects33i(()=>exportOfflineConflictPendingAdjudicationTranscript({adjudication:bad,decision:f.p.decision,
  reviewerGroupA:f.p.reviewerGroupA,reviewerGroupB:f.p.reviewerGroupB,
  observerId:observers33i[0].id,observerPublicKey:pub(observers33i[0]),observerPrivateKey:observers33i[0].privateKey,
  observedAt:now,expiresAt:now+30000,nonce:'nonce_33i_export_invalid'}),'EXCHANGE33I_UNVERIFIED_ADJUDICATION');
});
test(i('export refuses wrong signing key'),async()=>{
 const f=await fixture33i();
 rejects33i(()=>f.make(observers33i[0],{observerPrivateKey:observers33i[1].privateKey}),'EXCHANGE33I_OBSERVER_KEY_INVALID');
});
test(i('cross-scope observer pin mismatch rejected'),async()=>{
 const f=await fixture33i(),a=f.make();
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,expectedJournalScopeDigest:sha('different')}),'EXCHANGE33I_EXTERNAL_PINS_MISMATCH');
});

test(i('distinct observer IDs cannot reuse the same signing key'),async()=>{
 const f=await fixture33i(),a=f.make(observers33i[0]);
 const b=f.make(observers33i[0],{observerId:observers33i[1].id,nonce:'nonce_33i_same_key_2'});
 rejects33i(()=>reconcileOfflineConflictPendingAdjudicationTranscripts({left:a,right:{...b,expectedObserverId:observers33i[1].id}}),'EXCHANGE33I_OBSERVERS_NOT_INDEPENDENT');
});
test(i('extra transcript field fails closed'),async()=>{
 const f=await fixture33i(),a=f.make(),bytes=mutate33i(a,t=>{t.unauthorizedProduction=true;});
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,bytes}),'EXCHANGE33I_NONCANONICAL');
});
test(i('reordered signed body fails canonical serialization'),async()=>{
 const f=await fixture33i(),a=f.make(),bytes=mutate33i(a,t=>{
  t.body={observerId:t.body.observerId,...Object.fromEntries(Object.entries(t.body).filter(([k])=>k!=='observerId'))};
 });
 rejects33i(()=>verifyOfflineConflictPendingAdjudicationTranscript({...a,bytes}),'EXCHANGE33I_BODY_INVALID');
});

// Objective 33J: persistent two-observer transcript admission. The underlying
// 33I fixtures are real signed, SIGKILL-created 33G pending evidence.
const j=name=>`33J ${name}`;
const reject33j=(promise,code)=>assert.rejects(promise,e=>e?.code===code);
async function fixture33j(){
 const f=await fixture33i();
 const dir=await mkdtemp(join(root,'33j-'));
 const directory=join(dir,'inventory');
 const genesis=offlineConflictAdjudicationInventoryGenesisHead(namespaceId,scope);
 const registry=createOfflineConflictAdjudicationTranscriptInventory({directory,namespaceId,journalScopeDigest:scope});
 return {f,dir,directory,genesis,registry,left:f.make(observers33i[0]),right:f.make(observers33i[1])};
}
test(j('genesis is namespace- and scope-bound, without production authority'),async()=>{
 const x=await fixture33j(),v=await x.registry.inspect({expectedHead:x.genesis});
 assert.equal(v.count,0);assert.equal(v.headDigest,x.genesis.headDigest);
 assert.equal(v.authorizesProduction,false);assert.equal(v.independentlyPublished,false);
 assert.notEqual(x.genesis.headDigest,offlineConflictAdjudicationInventoryGenesisHead('namespace_other_0001',scope).headDigest);
});
test(j('two genuine independent signed observers admit durably and survive reopening'),async()=>{
 const x=await fixture33j();const out=await x.registry.accept({left:x.left,right:x.right,expectedHead:x.genesis});
 assert.equal(out.count,1);assert.equal(out.authorizesRepair,false);
 const reopened=createOfflineConflictAdjudicationTranscriptInventory({directory:x.directory,namespaceId,journalScopeDigest:scope});
 assert.equal((await reopened.inspect({expectedHead:{count:out.count,headDigest:out.headDigest}})).headDigest,out.headDigest);
 assert.deepEqual((await readdir(x.directory)).sort(),['0001.json']);
});
test(j('durable replay rejects duplicate transcript after process-independent reopen'),async()=>{
 const x=await fixture33j(),out=await x.registry.accept({left:x.left,right:x.right,expectedHead:x.genesis});
 const reopened=createOfflineConflictAdjudicationTranscriptInventory({directory:x.directory,namespaceId,journalScopeDigest:scope});
 await reject33j(reopened.accept({left:x.left,right:x.right,expectedHead:{count:out.count,headDigest:out.headDigest}}),'EXCHANGE33J_REPLAY');
 assert.deepEqual(await readdir(x.directory),['0001.json']);
});
test(j('stale independently retained head rejects second acceptance'),async()=>{
 const x=await fixture33j();await x.registry.accept({left:x.left,right:x.right,expectedHead:x.genesis});
 await reject33j(x.registry.accept({left:x.f.make(observers33i[0],{nonce:'nonce_33j_fresh_left'}),
  right:x.f.make(observers33i[1],{nonce:'nonce_33j_fresh_right'}),expectedHead:x.genesis}),'EXCHANGE33J_STALE_OR_ROLLED_BACK_HEAD');
});
test(j('two different signed transcript pairs append with chained head and no nonce reuse'),async()=>{
 const x=await fixture33j(),a=await x.registry.accept({left:x.left,right:x.right,expectedHead:x.genesis});
 const b=await x.registry.accept({left:x.f.make(observers33i[0],{nonce:'nonce_33j_fresh_left'}),
  right:x.f.make(observers33i[1],{nonce:'nonce_33j_fresh_right'}),expectedHead:{count:a.count,headDigest:a.headDigest}});
 assert.equal(b.count,2);assert.notEqual(b.headDigest,a.headDigest);
});
test(j('historical rollback by removing a record is detected against independent pin'),async()=>{
 const x=await fixture33j(),a=await x.registry.accept({left:x.left,right:x.right,expectedHead:x.genesis});
 await unlink(join(x.directory,'0001.json'));
 await reject33j(x.registry.inspect({expectedHead:{count:a.count,headDigest:a.headDigest}}),'EXCHANGE33J_STALE_OR_ROLLED_BACK_HEAD');
});
test(j('historical record byte tampering rejects even if attacker supplies its new head'),async()=>{
 const x=await fixture33j(),a=await x.registry.accept({left:x.left,right:x.right,expectedHead:x.genesis});
 const p=join(x.directory,'0001.json'),r=JSON.parse(await readFile(p));
 r.pair[0].bytes=r.pair[0].bytes.slice(0,-1)+'A';await writeFile(p,JSON.stringify(r),{mode:0o600});
 await reject33j(x.registry.inspect({expectedHead:{count:a.count,headDigest:a.headDigest}}),'EXCHANGE33J_HISTORY_INVALID');
});
test(j('omitted historical slot fails closed'),async()=>{
 const x=await fixture33j(),a=await x.registry.accept({left:x.left,right:x.right,expectedHead:x.genesis});
 const p=join(x.directory,'0001.json');await (await import('node:fs/promises')).rename(p,join(x.directory,'0002.json'));
 await reject33j(x.registry.inspect({expectedHead:{count:a.count,headDigest:a.headDigest}}),'EXCHANGE33J_HISTORY_INVALID');
});
test(j('forged observer signature rejected with no accepted record'),async()=>{
 const x=await fixture33j(),left={...x.left,bytes:mutate33i(x.left,t=>{t.observerSignature='A'.repeat(86);})};
 const altered={...left,expectedTranscriptDigest:sha33i(left.bytes)};
 await reject33j(x.registry.accept({left:altered,right:x.right,expectedHead:x.genesis}),'EXCHANGE33I_OBSERVER_SIGNATURE_INVALID');
 assert.deepEqual(await readdir(x.directory),[]);
});
test(j('omitted reviewer approval rejected with no accepted record'),async()=>{
 const x=await fixture33j(),left={...x.left,bytes:mutate33i(x.left,t=>{t.decision.groupASignatures=[];})};
 await reject33j(x.registry.accept({left:{...left,expectedTranscriptDigest:sha33i(left.bytes)},right:x.right,expectedHead:x.genesis}),'EXCHANGE33H_EXTERNAL_PINS_MISMATCH');
 assert.deepEqual(await readdir(x.directory),[]);
});
test(j('same observer cannot impersonate independent corroboration'),async()=>{
 const x=await fixture33j();await reject33j(x.registry.accept({left:x.left,right:x.left,expectedHead:x.genesis}),'EXCHANGE33I_OBSERVERS_NOT_INDEPENDENT');
});
test(j('foreign namespace is rejected even when supplied signatures are valid'),async()=>{
 const x=await fixture33j(),foreign=createOfflineConflictAdjudicationTranscriptInventory({directory:x.directory,
  namespaceId:'namespace_other_0001',journalScopeDigest:scope});
 await reject33j(foreign.accept({left:x.left,right:x.right,expectedHead:foreign.genesisHead}),'EXCHANGE33J_SCOPE_MISMATCH');
});
test(j('pending-only interrupted append blocks further admissions without repair'),async()=>{
 const x=await fixture33j(),r=createOfflineConflictAdjudicationTranscriptInventory({directory:x.directory,
  namespaceId,journalScopeDigest:scope,injectFault:stage=>{if(stage==='after-pending-sync')throw Error('crash');}});
 await assert.rejects(r.accept({left:x.left,right:x.right,expectedHead:x.genesis}),/crash/);
 await reject33j(x.registry.inspect({expectedHead:x.genesis}),'EXCHANGE33J_UNCERTAIN_COMMIT');
 assert((await readdir(x.directory)).includes('.pending.json'));
});
test(j('pending-linked interrupted append blocks further admissions without repair'),async()=>{
 const x=await fixture33j(),r=createOfflineConflictAdjudicationTranscriptInventory({directory:x.directory,
  namespaceId,journalScopeDigest:scope,injectFault:stage=>{if(stage==='after-link-sync')throw Error('crash');}});
 await assert.rejects(r.accept({left:x.left,right:x.right,expectedHead:x.genesis}),/crash/);
 await reject33j(x.registry.inspect({expectedHead:x.genesis}),'EXCHANGE33J_UNCERTAIN_COMMIT');
 assert((await readdir(x.directory)).includes('0001.json'));
});
test(j('unknown orphan file fails closed before any signed admission'),async()=>{
 const x=await fixture33j();await x.registry.inspect({expectedHead:x.genesis});
 await writeFile(join(x.directory,'orphan.json'),'{}',{mode:0o600});
 await reject33j(x.registry.accept({left:x.left,right:x.right,expectedHead:x.genesis}),'EXCHANGE33J_HISTORY_INVALID');
});
test(j('unsafe symlink record fails closed'),async()=>{
 const x=await fixture33j(),a=await x.registry.accept({left:x.left,right:x.right,expectedHead:x.genesis});
 const p=join(x.directory,'0001.json'),backup=join(x.dir,'backup');
 await (await import('node:fs/promises')).rename(p,backup);await symlink(backup,p);
 await reject33j(x.registry.inspect({expectedHead:{count:a.count,headDigest:a.headDigest}}),'EXCHANGE33J_RECORD_UNSAFE');
});
test(j('stale lock from a terminated process fails closed, not auto-reaped'),async()=>{
 const x=await fixture33j();await x.registry.inspect({expectedHead:x.genesis});
 await (await import('node:fs/promises')).mkdir(join(x.directory,'.inventory-lock'),{mode:0o700});
 await reject33j(x.registry.accept({left:x.left,right:x.right,expectedHead:x.genesis}),'EXCHANGE33J_LOCKED');
});

const worker33j=async(x,stage='none')=>{
 const path=join(x.dir,`worker-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
 const serial=a=>({...a,bytes:a.bytes.toString('base64url')});
 await writeFile(path,JSON.stringify({directory:x.directory,namespaceId,journalScopeDigest:scope,
  left:serial(x.left),right:serial(x.right),expectedHead:x.genesis}),{mode:0o600});
 return new Promise((resolve,reject)=>{
  const child=spawn(process.execPath,[new URL('./support/objective33j-worker.mjs',import.meta.url).pathname,path,stage],
   {stdio:['ignore','pipe','pipe']});let stdout='',stderr='';
  child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);
  child.on('error',reject);child.on('close',(code,signal)=>resolve({code,signal,stdout,stderr}));
 });
};
test(j('actual SIGKILL after durable pending fsync blocks all future admissions'),async()=>{
 const x=await fixture33j(),r=await worker33j(x,'after-pending-sync');
 assert.equal(r.signal,'SIGKILL');
 await reject33j(x.registry.inspect({expectedHead:x.genesis}),'EXCHANGE33J_LOCKED');
 assert((await readdir(x.directory)).includes('.pending.json'));
});
test(j('actual SIGKILL after hardlink fsync blocks uncertain linked history'),async()=>{
 const x=await fixture33j(),r=await worker33j(x,'after-link-sync');
 assert.equal(r.signal,'SIGKILL');
 await reject33j(x.registry.inspect({expectedHead:x.genesis}),'EXCHANGE33J_LOCKED');
 assert((await readdir(x.directory)).includes('0001.json'));
 assert((await readdir(x.directory)).includes('.pending.json'));
});
test(j('competing real Node processes cannot both accept same pinned transcript pair'),async()=>{
 const x=await fixture33j();const results=await Promise.all([worker33j(x),worker33j(x)]);
 const ok=results.filter(r=>r.code===0).map(r=>JSON.parse(r.stdout));
 const failures=results.filter(r=>r.code!==0).map(r=>JSON.parse(r.stdout));
 assert.equal(ok.length,1);assert.equal(failures.length,1);
 assert(['EXCHANGE33J_LOCKED','EXCHANGE33J_STALE_OR_ROLLED_BACK_HEAD'].includes(failures[0].code));
 const result=await x.registry.inspect({expectedHead:{count:ok[0].count,headDigest:ok[0].headDigest}});
 assert.equal(result.count,1);assert.deepEqual(await readdir(x.directory),['0001.json']);
});
test(j('SIGKILL after committed fsync retains committed record but refuses unreviewed lock removal'),async()=>{
 const x=await fixture33j(),r=await worker33j(x,'after-commit-sync');
 assert.equal(r.signal,'SIGKILL');
 assert((await readdir(x.directory)).includes('0001.json'));
 assert(!(await readdir(x.directory)).includes('.pending.json'));
 await reject33j(x.registry.inspect({expectedHead:x.genesis}),'EXCHANGE33J_LOCKED');
});
test(j('cross-observer contradictory signed snapshots fail without disk mutation'),async()=>{
 const x=await fixture33j(),other=await fixture33i('after-link-sync');
 const right=other.make(observers33i[1]);
 await reject33j(x.registry.accept({left:x.left,right,expectedHead:x.genesis}),'EXCHANGE33I_CROSS_SCOPE_OR_OMISSION');
 assert.deepEqual(await readdir(x.directory),[]);
});
test(j('noncanonical caller arguments with accessor properties fail before admission'),async()=>{
 const x=await fixture33j(),left={...x.left};
 Object.defineProperty(left,'expectedObserverId',{enumerable:true,get(){throw Error('getter should not execute');}});
 await reject33j(x.registry.accept({left,right:x.right,expectedHead:x.genesis}),'EXCHANGE33J_ARGUMENTS_INVALID');
});
