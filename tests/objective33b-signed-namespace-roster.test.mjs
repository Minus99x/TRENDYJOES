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
 offlineConflictSignedNamespaceBodyBytes,offlineConflictSignedNamespaceCommitmentDigest,
 verifyOfflineConflictSignedNamespaceRoster,inspectOfflineConflictSignedNamespaceMembership} from '../src/offline-conflict-signed-namespace-roster.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const err=code=>e=>e?.code===code;
const now=1792280000000,scope=sha('33b independently pinned namespace scope');
const namespaceId='namespace_33b_test_001';
const keys=(prefix,count)=>Array.from({length:count},(_,i)=>({id:`${prefix}_${String(i+1).padStart(2,'0')}`,...generateKeyPairSync('ed25519')}));
const a=keys('reviewer33b_A',3),b=keys('reviewer33b_B',3),authority=keys('authority33b',3),observers=keys('observer33b',3);
const pub=k=>k.publicKey.export({type:'spki',format:'der'}).toString('base64url');
const reviewers=g=>g.map(k=>({reviewerId:k.id,publicKey:k.publicKey}));
const policy=g=>offlineConflictExchangeRecoveryReviewerPolicyDigest(reviewers(g));
const authorityRoster=authority.map(k=>({authorityId:k.id,publicKey:pub(k)}));
const authorityDigest=offlineConflictNamespaceAuthorityPolicyDigest(authorityRoster);
const t=(name,fn)=>test('33B '+name,fn);
let root,claim,observations,body,commitment,args;
async function makeClaim(){
 const dir=join(root,'journal');const head=offlineConflictManifestJournalGenesisHead();
 const j=createOfflineConflictManifestJournal({directory:dir,injectFault:stage=>{
  if(stage==='after-pending-sync')throw Error('simulated crash');}});
 await assert.rejects(j.claim({verificationArgs:fixturePack('session_33b_claim_0001',2048,'a'),expectedHead:head}),/simulated crash/);
 const pending=await readFile(join(dir,'.pending.json')),record=JSON.parse(pending);
 const body={schema:OFFLINE_CONFLICT_MANIFEST_CLAIM_ADJUDICATION_SCHEMA,action:'inspect-only',journalHead:head,
  pendingBytesDigest:sha(pending),pendingRecordDigest:record.recordDigest,pendingIndex:head.count+1,
  expectedPendingState:'pending-only',reviewerGroupADigest:policy(a),reviewerGroupBDigest:policy(b),
  issuedAt:now-1000,expiresAt:now+10000,nonce:'nonce_33b_signed_001'};
 const signed=g=>g.slice(0,2).map(k=>({reviewerId:k.id,
  signature:sign(null,offlineConflictManifestClaimDecisionBytes(body),k.privateKey).toString('base64url')}));
 const decision={body,groupASignatures:signed(a),groupBSignatures:signed(b)};
 const pins={decision,reviewerGroupA:reviewers(a),reviewerGroupB:reviewers(b),
  expectedDecisionDigest:offlineConflictManifestClaimDecisionDigest(decision),
  expectedReviewerGroupADigest:policy(a),expectedReviewerGroupBDigest:policy(b),
  expectedHead:head,expectedPendingBytesDigest:sha(pending),nowMs:now};
 const inspector=createOfflineConflictManifestJournal({directory:dir});
 const out=await inspector.exportInterruptedClaimTranscriptReadOnly(pins);
 const {nowMs:unused,...entry}=pins;
 const entries=[{...entry,bytes:out.bytes,expectedTranscriptDigest:out.transcriptDigest,
  expectedSnapshotDigest:out.snapshotDigest}];
 return {entries,expectedHead:calculateOfflineConflictManifestClaimContinuity({entries}).head};
}
function signedCommitment(bdy=body,signers=authority.slice(0,2),members=observers){
 const bytes=offlineConflictSignedNamespaceBodyBytes(bdy);
 return {body:bdy,
  authoritySignatures:signers.map(k=>({authorityId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')})),
  observerSignatures:members.map(k=>({observerId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}))};
}
const copy=x=>structuredClone(x);
const replace=(changes)=>({...args,...changes});
const bdyChange=change=>({...body,...change});
before(async()=>{
 root=await mkdtemp(join(tmpdir(),'trendy33b-'));
 claim=await makeClaim();
 const inv=calculateOfflineConflictManifestMultiClaimInventory({journalScopeDigest:scope,claims:[claim]});
 observations=observers.map(k=>({observerId:k.id,claims:[claim],expectedInventoryDigest:inv.inventoryDigest,expectedClaimCount:1}));
 const reconciliationDigest=calculateOfflineConflictManifestMultiClaimReconciliation({journalScopeDigest:scope,observations}).reconciliationDigest;
 body={schema:OFFLINE_CONFLICT_SIGNED_NAMESPACE_SCHEMA,namespaceId,journalScopeDigest:scope,
  epoch:3,issuedAt:now-1000,expiresAt:now+10000,nonce:'namespace_nonce_33b_001',
  authorityPolicyDigest:authorityDigest,reconciliationDigest,
  observers:observers.map(k=>({observerId:k.id,publicKey:pub(k),inventoryDigest:inv.inventoryDigest,claimCount:1}))};
 commitment=signedCommitment();
 args={commitment,authorities:authorityRoster,observations,
  expectedAuthorityPolicyDigest:authorityDigest,expectedCommitmentDigest:offlineConflictSignedNamespaceCommitmentDigest(body),
  expectedJournalScopeDigest:scope,expectedNamespaceId:namespaceId,expectedEpoch:3,
  expectedReconciliationDigest:reconciliationDigest,expectedObserverCount:3,nowMs:now};
});
after(async()=>{if(root)await rm(root,{recursive:true,force:true});});
t('valid dual-signature layer authenticates complete three-observer inventory',()=>{
 const r=verifyOfflineConflictSignedNamespaceRoster(args);
 assert.equal(r.verified,true);assert.equal(r.observerCount,3);assert.equal(r.authoritySigners,2);
 assert.equal(r.authorizesRepair,false);assert.equal(r.authorizesCheckout,false);
 assert.equal(r.independentlyPublished,false);
});
t('complete signed roster proves scoped membership',()=>{
 const r=inspectOfflineConflictSignedNamespaceMembership({...args,targetObserverId:observers[0].id});
 assert.equal(r.member,true);assert.equal(r.globallyComplete,false);
});
t('complete signed roster proves scoped nonmembership only',()=>{
 const r=inspectOfflineConflictSignedNamespaceMembership({...args,targetObserverId:'outsider33b_00001'});
 assert.equal(r.member,false);assert.equal(r.proofKind,'complete-signed-local-roster');
});
t('canonical signing bytes and digest deterministic',()=>{
 assert.deepEqual(offlineConflictSignedNamespaceBodyBytes(body),offlineConflictSignedNamespaceBodyBytes(copy(body)));
 assert.equal(offlineConflictSignedNamespaceCommitmentDigest(body),args.expectedCommitmentDigest);
});
t('authority policy pin deterministic',()=>assert.equal(offlineConflictNamespaceAuthorityPolicyDigest(authorityRoster),authorityDigest));
t('no authority pin fails closed',()=>assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({expectedAuthorityPolicyDigest:undefined})),err('EXCHANGE33B_EXTERNAL_PINS_REQUIRED')));
t('no commitment pin fails closed',()=>assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({expectedCommitmentDigest:undefined})),err('EXCHANGE33B_EXTERNAL_PINS_REQUIRED')));
t('no namespace pin fails closed',()=>assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({expectedNamespaceId:undefined})),err('EXCHANGE33B_EXTERNAL_PINS_REQUIRED')));
t('no reconciliation pin fails closed',()=>assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({expectedReconciliationDigest:undefined})),err('EXCHANGE33B_EXTERNAL_PINS_REQUIRED')));
t('no scope pin fails closed',()=>assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({expectedJournalScopeDigest:undefined})),err('EXCHANGE33B_EXTERNAL_PINS_REQUIRED')));
t('wrong external namespace rejected',()=>assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({expectedNamespaceId:'other_namespace_33b'})),err('EXCHANGE33B_EXTERNAL_PIN_MISMATCH')));
t('wrong external epoch rejected',()=>assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({expectedEpoch:4})),err('EXCHANGE33B_EXTERNAL_PIN_MISMATCH')));
t('wrong external scope rejected',()=>assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({expectedJournalScopeDigest:sha('different')})),err('EXCHANGE33B_EXTERNAL_PIN_MISMATCH')));
t('wrong external commitment pin rejected',()=>assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({expectedCommitmentDigest:sha('different')})),err('EXCHANGE33B_EXTERNAL_PIN_MISMATCH')));
t('wrong external authority policy pin rejected',()=>assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({expectedAuthorityPolicyDigest:sha('different')})),err('EXCHANGE33B_EXTERNAL_PIN_MISMATCH')));
t('expired signed commitment rejected',()=>assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({nowMs:now+20000})),err('EXCHANGE33B_COMMITMENT_EXPIRED')));
t('not-yet-issued commitment rejected',()=>assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({nowMs:now-2000})),err('EXCHANGE33B_COMMITMENT_EXPIRED')));
t('one authority signer is insufficient',()=>assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({commitment:signedCommitment(body,authority.slice(0,1))})),err('EXCHANGE33B_AUTHORITY_QUORUM_REQUIRED')));
t('forged authority signature rejected',()=>{
 const c=copy(commitment);c.authoritySignatures[0].signature=sign(null,offlineConflictSignedNamespaceBodyBytes(body),observers[0].privateKey).toString('base64url');
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({commitment:c})),err('EXCHANGE33B_AUTHORITY_SIGNATURE_INVALID'));
});
t('missing observer signature rejected',()=>{
 const c=copy(commitment);c.observerSignatures.pop();
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({commitment:c})),err('EXCHANGE33B_OBSERVER_QUORUM_REQUIRED'));
});
t('forged observer signature rejected',()=>{
 const c=copy(commitment);c.observerSignatures[0].signature=sign(null,offlineConflictSignedNamespaceBodyBytes(body),authority[0].privateKey).toString('base64url');
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({commitment:c})),err('EXCHANGE33B_OBSERVER_SIGNATURE_INVALID'));
});
t('duplicate observer signature rejected',()=>{
 const c=copy(commitment);c.observerSignatures[1]=c.observerSignatures[0];
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({commitment:c})),err('EXCHANGE33B_OBSERVER_SIGNATURE_INVALID'));
});
t('reordered authority signatures rejected',()=>{
 const c=copy(commitment);c.authoritySignatures.reverse();
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({commitment:c})),err('EXCHANGE33B_AUTHORITY_SIGNATURE_INVALID'));
});
t('signed body scope substitution cannot reuse signatures or external pins',()=>{
 const c=signedCommitment(bdyChange({journalScopeDigest:sha('other scope')}));
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({commitment:c})),err('EXCHANGE33B_EXTERNAL_PIN_MISMATCH'));
});
t('signed namespace substitution rejected',()=>{
 const c=signedCommitment(bdyChange({namespaceId:'namespace_other_33b'}));
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({commitment:c})),err('EXCHANGE33B_EXTERNAL_PIN_MISMATCH'));
});
t('signed epoch replay rejected against newer external pin',()=>{
 const c=signedCommitment(bdyChange({epoch:2}));
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({commitment:c})),err('EXCHANGE33B_EXTERNAL_PIN_MISMATCH'));
});
t('signed reconciliation substitution rejected',()=>{
 const c=signedCommitment(bdyChange({reconciliationDigest:sha('different')}));
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({commitment:c})),err('EXCHANGE33B_EXTERNAL_PIN_MISMATCH'));
});
t('body tampering after signing rejected',()=>{
 const c=copy(commitment);c.body.nonce='tampered_nonce_33b_01';
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({commitment:c})),err('EXCHANGE33B_EXTERNAL_PIN_MISMATCH'));
});
t('omitting one observation rejected even with intact signed roster',()=>assert.throws(()=>
 verifyOfflineConflictSignedNamespaceRoster(replace({observations:observations.slice(0,2)})),err('EXCHANGE33B_OBSERVATION_SET_MISMATCH')));
t('adding uncommitted observer observation rejected',()=>assert.throws(()=>
 verifyOfflineConflictSignedNamespaceRoster(replace({observations:[...observations,{
  observerId:'uncommitted33b',claims:[claim],expectedInventoryDigest:body.observers[0].inventoryDigest,expectedClaimCount:1}]})),err('EXCHANGE33B_OBSERVATION_SET_MISMATCH')));
t('observer inventory digest substitution rejected',()=>{
 const obs=copy(observations);obs[0].expectedInventoryDigest=sha('substitute');
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({observations:obs})),err('EXCHANGE33B_OBSERVATION_SET_MISMATCH'));
});
t('observer claim count substitution rejected',()=>{
 const obs=copy(observations);obs[0].expectedClaimCount=2;
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({observations:obs})),err('EXCHANGE33B_OBSERVATION_SET_MISMATCH'));
});
t('duplicate observer observation rejected',()=>{
 const obs=copy(observations);obs[1]=obs[0];
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({observations:obs})),err('EXCHANGE33B_OBSERVATION_SET_MISMATCH'));
});
t('changed transcript bytes rejected through downstream signature verification',()=>{
 const obs=copy(observations);obs[0].claims[0].entries[0].bytes[20]^=1;
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({observations:obs})),e=>!!e?.code);
});
t('missing one claim under unchanged signed inventory rejected',()=>{
 const obs=copy(observations);obs[0].claims=[];
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({observations:obs})),e=>!!e?.code);
});
t('reordered signed roster rejected',()=>{
 const c=copy(commitment);c.body.observers.reverse();
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({commitment:c})),err('EXCHANGE33B_ROSTER_INVALID'));
});
t('duplicate observer public key rejected',()=>{
 const c=copy(commitment);c.body.observers[1].publicKey=c.body.observers[0].publicKey;
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({commitment:c})),err('EXCHANGE33B_DUPLICATE_KEY'));
});
t('authority key reused by observer rejected',()=>{
 const c=copy(commitment);c.body.observers[0].publicKey=pub(authority[0]);
 const signed=signedCommitment(c.body);
 const pins=replace({commitment:signed,expectedCommitmentDigest:offlineConflictSignedNamespaceCommitmentDigest(c.body)});
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(pins),err('EXCHANGE33B_AUTHORITY_OBSERVER_KEY_OVERLAP'));
});
t('duplicate authority key rejected',()=>{
 const roster=copy(authorityRoster);roster[1].publicKey=roster[0].publicKey;
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({authorities:roster})),err('EXCHANGE33B_DUPLICATE_KEY'));
});
t('unknown authority signer rejected',()=>{
 const c=copy(commitment);c.authoritySignatures[0].authorityId='unknown_authority_33b';
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({commitment:c})),err('EXCHANGE33B_AUTHORITY_SIGNATURE_INVALID'));
});
t('malformed Ed25519 public key rejected',()=>{
 const c=copy(commitment);c.body.observers[0].publicKey='invalid-key';
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({commitment:c})),err('EXCHANGE33B_PUBLIC_KEY_INVALID'));
});
t('extra unexpected body property rejected',()=>{
 const c=copy(commitment);c.body.productionReady=true;
 assert.throws(()=>verifyOfflineConflictSignedNamespaceRoster(replace({commitment:c})),err('EXCHANGE33B_BODY_INVALID'));
});
t('malicious accessor on observer rejected before signing',()=>{
 const c=copy(body);Object.defineProperty(c.observers[0],'publicKey',{get(){throw Error('accessor invoked');},enumerable:true});
 assert.throws(()=>offlineConflictSignedNamespaceBodyBytes(c),err('EXCHANGE33B_ROSTER_INVALID'));
});
t('sparse observer roster rejected',()=>{
 const c=copy(body);delete c.observers[1];
 assert.throws(()=>offlineConflictSignedNamespaceBodyBytes(c),err('EXCHANGE33B_BODY_INVALID'));
});
t('unsigned arbitrary membership lookup cannot bypass verification',()=>{
 const c=copy(commitment);c.authoritySignatures=[];
 assert.throws(()=>inspectOfflineConflictSignedNamespaceMembership({...args,commitment:c,targetObserverId:observers[0].id}),err('EXCHANGE33B_AUTHORITY_QUORUM_REQUIRED'));
});
t('invalid membership identifier rejected',()=>assert.throws(()=>
 inspectOfflineConflictSignedNamespaceMembership({...args,targetObserverId:'bad'}),err('EXCHANGE33B_MEMBER_ID_INVALID')));
