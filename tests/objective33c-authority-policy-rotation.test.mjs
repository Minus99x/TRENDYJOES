import test,{before,after} from 'node:test';
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
const pub=k=>k.publicKey.export({type:'spki',format:'der'}).toString('base64url');
const reviewerRoster=g=>g.map(k=>({reviewerId:k.id,publicKey:k.publicKey}));
const policy=g=>offlineConflictExchangeRecoveryReviewerPolicyDigest(reviewerRoster(g));
const authorityRoster=g=>g.map(k=>({authorityId:k.id,publicKey:pub(k)}));
const oldDigest=offlineConflictNamespaceAuthorityPolicyDigest(authorityRoster(oldKeys));
const newDigest=offlineConflictNamespaceAuthorityPolicyDigest(authorityRoster(newKeys));
const copy=x=>structuredClone(x);
const t=(name,fn)=>test('33C '+name,fn);
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
before(async()=>{
 root=await mkdtemp(join(tmpdir(),'trendy33c-'));
 const claim=await makeClaim();
 const inv=calculateOfflineConflictManifestMultiClaimInventory({journalScopeDigest:scope,claims:[claim]});
 const observations=observerKeys.map(k=>({observerId:k.id,claims:[claim],expectedInventoryDigest:inv.inventoryDigest,expectedClaimCount:1}));
 const reconciliationDigest=calculateOfflineConflictManifestMultiClaimReconciliation({journalScopeDigest:scope,observations}).reconciliationDigest;
 const shared={schema:OFFLINE_CONFLICT_SIGNED_NAMESPACE_SCHEMA,namespaceId,journalScopeDigest:scope,
  issuedAt:now-1000,expiresAt:now+10000,reconciliationDigest,
  observers:observerKeys.map(k=>({observerId:k.id,publicKey:pub(k),inventoryDigest:inv.inventoryDigest,claimCount:1}))};
 oldBody={...shared,epoch:3,nonce:'namespace_nonce_33c_old',authorityPolicyDigest:oldDigest};
 newBody={...shared,epoch:4,nonce:'namespace_nonce_33c_new',authorityPolicyDigest:newDigest};
 const verification=(body,authorities)=>({commitment:namespaceCommitment(body,authorities),authorities:authorityRoster(authorities),
  observations,expectedAuthorityPolicyDigest:body.authorityPolicyDigest,
  expectedCommitmentDigest:offlineConflictSignedNamespaceCommitmentDigest(body),
  expectedJournalScopeDigest:scope,expectedNamespaceId:namespaceId,expectedEpoch:body.epoch,
  expectedReconciliationDigest:reconciliationDigest,expectedObserverCount:3,nowMs:now});
 oldVerification=verification(oldBody,oldKeys);newVerification=verification(newBody,newKeys);
 transitionBody={schema:OFFLINE_CONFLICT_AUTHORITY_ROTATION_SCHEMA,namespaceId,journalScopeDigest:scope,
  fromEpoch:3,toEpoch:4,predecessorAuthorityPolicyDigest:oldDigest,successorAuthorityPolicyDigest:newDigest,
  predecessorCommitmentDigest:oldVerification.expectedCommitmentDigest,
  successorCommitmentDigest:newVerification.expectedCommitmentDigest,
  previousTransitionDigest:sha('externally retained predecessor transition'),
  issuedAt:now-1000,expiresAt:now+10000,nonce:'rotation_nonce_33c_001'};
 args={transition:signedTransition(),predecessor:{verification:oldVerification},successor:{verification:newVerification},
  expectedNamespaceId:namespaceId,expectedJournalScopeDigest:scope,expectedFromEpoch:3,
  expectedPredecessorAuthorityPolicyDigest:oldDigest,expectedSuccessorAuthorityPolicyDigest:newDigest,
  expectedPredecessorCommitmentDigest:oldVerification.expectedCommitmentDigest,
  expectedSuccessorCommitmentDigest:newVerification.expectedCommitmentDigest,
  expectedPreviousTransitionDigest:transitionBody.previousTransitionDigest,
  expectedTransitionDigest:offlineConflictAuthorityRotationDigest(transitionBody),nowMs:now};
});
after(async()=>{if(root)await rm(root,{recursive:true,force:true});});
t('valid old/new majority authorization recursively authenticates both namespace histories',()=>{
 const r=verifyOfflineConflictAuthorityPolicyRotation(args);
 assert.equal(r.verified,true);assert.equal(r.toEpoch,4);assert.equal(r.fromEpoch,3);
 assert.equal(r.predecessorSigners,2);assert.equal(r.successorSigners,2);
 assert.equal(r.independentlyPublished,false);assert.equal(r.globalForkPrevention,false);
 assert.equal(r.authorizesRepair,false);assert.equal(r.authorizesCheckout,false);
});
t('canonical bytes and transition digest stable',()=>{
 assert.deepEqual(offlineConflictAuthorityRotationBodyBytes(transitionBody),offlineConflictAuthorityRotationBodyBytes(copy(transitionBody)));
 assert.equal(offlineConflictAuthorityRotationDigest(transitionBody),args.expectedTransitionDigest);
});
for(const field of ['expectedNamespaceId','expectedJournalScopeDigest','expectedFromEpoch',
 'expectedPredecessorAuthorityPolicyDigest','expectedSuccessorAuthorityPolicyDigest',
 'expectedPredecessorCommitmentDigest','expectedSuccessorCommitmentDigest',
 'expectedPreviousTransitionDigest','expectedTransitionDigest','nowMs']){
 t(`missing independent ${field} fails closed`,()=>assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({[field]:undefined})),err('EXCHANGE33C_EXTERNAL_PINS_REQUIRED')));
}
for(const [field,value] of [['expectedNamespaceId','wrong_namespace_33c'],['expectedJournalScopeDigest',sha('wrong scope')],
 ['expectedFromEpoch',2],['expectedPredecessorAuthorityPolicyDigest',sha('wrong old policy')],
 ['expectedSuccessorAuthorityPolicyDigest',sha('wrong new policy')],
 ['expectedPredecessorCommitmentDigest',sha('wrong old commitment')],
 ['expectedSuccessorCommitmentDigest',sha('wrong new commitment')],
 ['expectedPreviousTransitionDigest',sha('rollback')],['expectedTransitionDigest',sha('fork')]]){
 t(`external ${field} mismatch rejects fork/substitution`,()=>assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({[field]:value})),err('EXCHANGE33C_EXTERNAL_PIN_MISMATCH')));
}
t('expired rotation rejected',()=>assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({nowMs:now+20000})),err('EXCHANGE33C_TRANSITION_EXPIRED')));
t('not yet issued rotation rejected',()=>assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({nowMs:now-2000})),err('EXCHANGE33C_TRANSITION_EXPIRED')));
t('predecessor majority required',()=>assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({transition:signedTransition(transitionBody,oldKeys.slice(0,1))})),err('EXCHANGE33C_PREDECESSOR_QUORUM_REQUIRED')));
t('successor majority required',()=>assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({transition:signedTransition(transitionBody,oldKeys.slice(0,2),newKeys.slice(0,1))})),err('EXCHANGE33C_SUCCESSOR_QUORUM_REQUIRED')));
t('forged predecessor signature rejected',()=>{
 const x=copy(args.transition);x.predecessorSignatures[0].signature=sign(null,offlineConflictAuthorityRotationBodyBytes(transitionBody),newKeys[0].privateKey).toString('base64url');
 assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({transition:x})),err('EXCHANGE33C_PREDECESSOR_SIGNATURE_INVALID'));
});
t('forged successor signature rejected',()=>{
 const x=copy(args.transition);x.successorSignatures[0].signature=sign(null,offlineConflictAuthorityRotationBodyBytes(transitionBody),oldKeys[0].privateKey).toString('base64url');
 assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({transition:x})),err('EXCHANGE33C_SUCCESSOR_SIGNATURE_INVALID'));
});
t('reordered predecessor signatures rejected',()=>{
 const x=copy(args.transition);x.predecessorSignatures.reverse();
 assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({transition:x})),err('EXCHANGE33C_PREDECESSOR_SIGNATURE_INVALID'));
});
t('duplicated successor signature rejected',()=>{
 const x=copy(args.transition);x.successorSignatures[1]=x.successorSignatures[0];
 assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({transition:x})),err('EXCHANGE33C_SUCCESSOR_SIGNATURE_INVALID'));
});
t('same-epoch rotation rejected before verification',()=>assert.throws(()=>offlineConflictAuthorityRotationBodyBytes(changeBody({toEpoch:3})),err('EXCHANGE33C_BODY_INVALID')));
t('skipped epoch rejected before verification',()=>assert.throws(()=>offlineConflictAuthorityRotationBodyBytes(changeBody({toEpoch:5})),err('EXCHANGE33C_BODY_INVALID')));
t('same policy cannot masquerade as rotation',()=>assert.throws(()=>offlineConflictAuthorityRotationBodyBytes(changeBody({successorAuthorityPolicyDigest:oldDigest})),err('EXCHANGE33C_BODY_INVALID')));
t('same commitment cannot masquerade as rotation',()=>assert.throws(()=>offlineConflictAuthorityRotationBodyBytes(changeBody({successorCommitmentDigest:oldVerification.expectedCommitmentDigest})),err('EXCHANGE33C_BODY_INVALID')));
t('overlong validity rejected',()=>assert.throws(()=>offlineConflictAuthorityRotationBodyBytes(changeBody({expiresAt:now+3600001})),err('EXCHANGE33C_BODY_INVALID')));
t('negative epoch rejected',()=>assert.throws(()=>offlineConflictAuthorityRotationBodyBytes(changeBody({fromEpoch:-1})),err('EXCHANGE33C_BODY_INVALID')));
t('unexpected body property rejected',()=>assert.throws(()=>offlineConflictAuthorityRotationBodyBytes({...transitionBody,authorizesRepair:true}),err('EXCHANGE33C_BODY_INVALID')));
t('sparse transition signatures rejected',()=>{
 const x=copy(args.transition);delete x.predecessorSignatures[0];
 assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({transition:x})),err('EXCHANGE33C_PREDECESSOR_QUORUM_REQUIRED'));
});
t('malicious accessor on signed body rejected',()=>{
 const x=copy(transitionBody);Object.defineProperty(x,'nonce',{get(){throw Error('accessed');},enumerable:true});
 assert.throws(()=>offlineConflictAuthorityRotationBodyBytes(x),err('EXCHANGE33C_BODY_INVALID'));
});
t('signed body nonce substitution rejected against independent digest',()=>{
 const x=signedTransition(changeBody({nonce:'tampered_nonce_33c'}));
 assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({transition:x})),err('EXCHANGE33C_EXTERNAL_PIN_MISMATCH'));
});
t('historical policy mismatch in old commitment rejected',()=>{
 const x=copy(oldVerification);x.expectedAuthorityPolicyDigest=newDigest;
 assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({predecessor:{verification:x}})),err('EXCHANGE33C_COMMITMENT_BINDING_MISMATCH'));
});
t('successor epoch substitution rejected',()=>{
 const x=copy(newVerification);x.expectedEpoch=5;
 assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({successor:{verification:x}})),err('EXCHANGE33C_COMMITMENT_BINDING_MISMATCH'));
});
t('successor observer signature forgery rejected by downstream 33B verifier',()=>{
 const x=copy(newVerification);x.commitment.observerSignatures[0].signature=sign(null,offlineConflictSignedNamespaceBodyBytes(newBody),oldKeys[0].privateKey).toString('base64url');
 assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({successor:{verification:x}})),err('EXCHANGE33B_OBSERVER_SIGNATURE_INVALID'));
});
t('successor inventory omission rejected by downstream 33B verifier',()=>{
 const x=copy(newVerification);x.observations.pop();
 assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({successor:{verification:x}})),err('EXCHANGE33B_OBSERVATION_SET_MISMATCH'));
});
t('predecessor expired commitment rejected despite valid transition signatures',()=>{
 const x=copy(oldVerification);x.commitment.body.expiresAt=now-1;
 assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({predecessor:{verification:x}})),err('EXCHANGE33B_EXTERNAL_PIN_MISMATCH'));
});
t('successor roster substitution rejected',()=>{
 const x=copy(newVerification);x.authorities[0].publicKey=pub(oldKeys[0]);
 assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({successor:{verification:x}})),err('EXCHANGE33B_AUTHORITY_POLICY_PIN_MISMATCH'));
});
t('predecessor and successor clocks must match external caller time',()=>{
 const x=copy(oldVerification);x.nowMs=now+1;
 assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({predecessor:{verification:x}})),err('EXCHANGE33C_COMMITMENT_BINDING_MISMATCH'));
});
t('invalid signature bytes rejected',()=>{
 const x=copy(args.transition);x.successorSignatures[0].signature='A'.repeat(86);
 assert.throws(()=>verifyOfflineConflictAuthorityPolicyRotation(mutate({transition:x})),err('EXCHANGE33C_SUCCESSOR_SIGNATURE_INVALID'));
});
