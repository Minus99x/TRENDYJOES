import test,{before,after} from 'node:test';
import {offlineConflictAuthorityHistoryNextHead,verifyOfflineConflictAuthorityHistory} from '../src/offline-conflict-authority-history.mjs';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {fixturePack} from './support/objective32w-fixture.mjs';
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
const t=(name,fn)=>test('33D '+name,fn);
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
t('three fully authenticated consecutive transitions verify against independent terminal head',()=>{
 const r=verifyOfflineConflictAuthorityHistory(history);
 assert.equal(r.verified,true);assert.equal(r.finalEpoch,6);assert.equal(r.transitionCount,3);
 assert.equal(r.chainHead,history.expectedChainHead);
 for(const k of ['independentlyPublished','globalForkPrevention','trustedTimestamp','authorizesRepair','authorizesProduction','authorizesCheckout'])assert.equal(r[k],false);
});
t('deterministic domain-separated head and complete history',()=>{
 assert.equal(candidateHead(history.entries),history.expectedChainHead);
 assert.equal(verifyOfflineConflictAuthorityHistory(copy(history)).chainHead,history.expectedChainHead);
});
for(const k of ['expectedNamespaceId','expectedJournalScopeDigest','expectedFirstEpoch',
 'expectedPreviousTransitionDigest','expectedInitialAuthorityPolicyDigest',
 'expectedInitialCommitmentDigest','expectedGenesisHead','expectedFinalAuthorityPolicyDigest',
 'expectedFinalCommitmentDigest','expectedChainHead','nowMs']){
 t('missing external pin '+k+' rejected',()=>assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({[k]:undefined})),err33d('EXCHANGE33D_EXTERNAL_PINS_REQUIRED')));
}
for(const [k,value] of [['expectedNamespaceId','other_namespace_33d'],['expectedJournalScopeDigest',sha('other scope')],
 ['expectedFirstEpoch',4],['expectedPreviousTransitionDigest',sha('rollback genesis')],
 ['expectedInitialAuthorityPolicyDigest',sha('forged old policy')],
 ['expectedInitialCommitmentDigest',sha('forged old commitment')]]){
 t('forged initial anchor '+k+' rejected',()=>assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({[k]:value})),e=>!!e?.code));
}
for(const [k,value] of [['expectedGenesisHead',sha('other genesis')],
 ['expectedFinalAuthorityPolicyDigest',sha('other final policy')],
 ['expectedFinalCommitmentDigest',sha('other final commitment')],
 ['expectedChainHead',sha('other chain head')]]){
 t('terminal anchor mismatch '+k+' rejected',()=>assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({[k]:value})),err33d('EXCHANGE33D_TERMINAL_PIN_MISMATCH')));
}
t('missing intermediate transition rejected',()=>assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({entries:[history.entries[0],history.entries[2]]})),err33d('EXCHANGE33D_LINK_MISMATCH')));
t('truncated history rejected against independently pinned terminal head',()=>assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({entries:history.entries.slice(0,2)})),err33d('EXCHANGE33D_TERMINAL_PIN_MISMATCH')));
t('reverse transition order rejected',()=>assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({entries:copy(history.entries).reverse()})),err33d('EXCHANGE33D_LINK_MISMATCH')));
t('duplicate transition rejected',()=>assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({entries:[history.entries[0],history.entries[0]]})),err33d('EXCHANGE33D_LINK_MISMATCH')));
t('sparse transition array rejected',()=>{const a=copy(history.entries);delete a[0];assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({entries:a})),err33d('EXCHANGE33D_ENTRIES_INVALID'));});
t('oversized transition history rejected',()=>assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({entries:Array(9).fill(history.entries[0])})),err33d('EXCHANGE33D_ENTRIES_INVALID')));
t('unrecognized entry property rejected',()=>{const a=copy(history.entries);a[0].authorizesRepair=true;assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({entries:a})),err33d('EXCHANGE33D_ENTRY_INVALID'));});
t('malicious body accessor rejected without executing getter',()=>{
 const a=copy(history.entries);Object.defineProperty(a[0].transition.body,'nonce',{enumerable:true,get(){throw Error('GETTER_EXECUTED');}});
 assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({entries:a})),err33d('EXCHANGE33C_BODY_INVALID'));
});
t('forged successor signature in second transition rejected',()=>{
 const a=copy(history.entries);a[1].transition.successorSignatures[0].signature=sign(null,
  offlineConflictAuthorityRotationBodyBytes(secondBody),oldKeys[0].privateKey).toString('base64url');
 assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({entries:a})),err33d('EXCHANGE33C_SUCCESSOR_SIGNATURE_INVALID'));
});
t('forged predecessor signature in first transition rejected',()=>{
 const a=copy(history.entries);a[0].transition.predecessorSignatures[0].signature=sign(null,
  offlineConflictAuthorityRotationBodyBytes(transitionBody),finalKeys[0].privateKey).toString('base64url');
 assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({entries:a})),err33d('EXCHANGE33C_PREDECESSOR_SIGNATURE_INVALID'));
});
t('signed but forked middle transition breaks next link',()=>{
 const a=copy(history.entries);const b={...secondBody,nonce:'rotation_nonce_33d_fork'};
 a[1].transition=signedTransition(b,newKeys.slice(0,2),finalKeys.slice(0,2));
 assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({entries:a})),err33d('EXCHANGE33D_LINK_MISMATCH'));
});
t('signed but forked terminal transition rejected by independent head',()=>{
 const a=copy(history.entries);const b={...thirdTransitionBody,nonce:'rotation_nonce_33d_fork_final'};
 a[2].transition=signedTransition(b,finalKeys.slice(0,2),fourthKeys.slice(0,2));
 assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({entries:a})),err33d('EXCHANGE33D_TERMINAL_PIN_MISMATCH'));
});
t('intermediate commitment rollback rejected',()=>{
 const a=copy(history.entries);a[1].transition.body.predecessorCommitmentDigest=oldVerification.expectedCommitmentDigest;
 assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({entries:a})),err33d('EXCHANGE33D_LINK_MISMATCH'));
});
t('skipped epoch rejected',()=>{
 const a=copy(history.entries);a[1].transition.body.toEpoch=6;
 assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({entries:a})),err33d('EXCHANGE33C_BODY_INVALID'));
});
t('cross-scope substitution rejected',()=>{
 const a=copy(history.entries);a[1].transition.body.journalScopeDigest=sha('other scope');
 assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({entries:a})),err33d('EXCHANGE33C_EXTERNAL_PIN_MISMATCH'));
});
t('stale signed authority commitment rejected',()=>{
 const a=copy(history.entries);a[1].successor.verification.commitment.body.nonce='changed_nonce_33d';
 assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({entries:a})),e=>!!e?.code?.startsWith('EXCHANGE33B_'));
});
t('expired transition rejected',()=>assert.throws(()=>verifyOfflineConflictAuthorityHistory(mutateHistory({nowMs:now+20000})),err33d('EXCHANGE33C_TRANSITION_EXPIRED')));
t('external head builder rejects invalid parameters',()=>{
 assert.throws(()=>offlineConflictAuthorityHistoryNextHead('bad',sha('digest'),4,sha('commitment')),err33d('EXCHANGE33D_HEAD_INPUT_INVALID'));
});
