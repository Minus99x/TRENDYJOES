import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,link} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {fixturePack} from './support/objective32w-fixture.mjs';
import {createOfflineConflictManifestJournal,offlineConflictManifestJournalGenesisHead} from '../src/offline-conflict-resolution-manifest-journal.mjs';
import {offlineConflictExchangeRecoveryReviewerPolicyDigest} from '../src/offline-conflict-exchange-recovery.mjs';
import {OFFLINE_CONFLICT_MANIFEST_CLAIM_ADJUDICATION_SCHEMA,offlineConflictManifestClaimDecisionBytes,offlineConflictManifestClaimDecisionDigest} from '../src/offline-conflict-manifest-claim-adjudication.mjs';
import {calculateOfflineConflictManifestClaimContinuity as calculate,verifyOfflineConflictManifestClaimContinuity as verify,OFFLINE_CONFLICT_MANIFEST_CLAIM_CONTINUITY_MAX_ENTRIES} from '../src/offline-conflict-manifest-claim-continuity.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const err=code=>e=>e?.code===code;
const now=1792280000000;
const a=[1,2,3].map(i=>({reviewerId:`alpha32z_reviewer_${i}`,...generateKeyPairSync('ed25519')}));
const b=[1,2,3].map(i=>({reviewerId:`bravo32z_reviewer_${i}`,...generateKeyPairSync('ed25519')}));
const pub=g=>g.map(({reviewerId,publicKey})=>({reviewerId,publicKey}));
const policy=g=>offlineConflictExchangeRecoveryReviewerPolicyDigest(pub(g));
const signed=(body,g)=>g.slice(0,2).map(k=>({reviewerId:k.reviewerId,signature:sign(null,offlineConflictManifestClaimDecisionBytes(body),k.privateKey).toString('base64url')}));
const t=(name,fn)=>test('32Z '+name,fn);
async function scenario(fn){
 const root=await mkdtemp(join(tmpdir(),'trendy32z-')),directory=join(root,'journal');
 try{
  const head=offlineConflictManifestJournalGenesisHead();
  const j=createOfflineConflictManifestJournal({directory,injectFault:stage=>{if(stage==='after-pending-sync')throw Error('simulated crash');}});
  await assert.rejects(j.claim({verificationArgs:fixturePack('session_32z_pending_001',2048,'a'),expectedHead:head}),/simulated crash/);
  const pending=await readFile(join(directory,'.pending.json')),record=JSON.parse(pending);
  const inspector=createOfflineConflictManifestJournal({directory});
  async function entry(n,state='pending-only',observedAt=now+n){
   const body={schema:OFFLINE_CONFLICT_MANIFEST_CLAIM_ADJUDICATION_SCHEMA,action:'inspect-only',journalHead:head,
    pendingBytesDigest:sha(pending),pendingRecordDigest:record.recordDigest,pendingIndex:head.count+1,
    expectedPendingState:state,reviewerGroupADigest:policy(a),reviewerGroupBDigest:policy(b),
    issuedAt:now-1000,expiresAt:now+10000,nonce:`transcript32z_nonce_${String(n).padStart(4,'0')}`};
   const decision={body,groupASignatures:signed(body,a),groupBSignatures:signed(body,b)};
   const args={decision,reviewerGroupA:pub(a),reviewerGroupB:pub(b),
    expectedDecisionDigest:offlineConflictManifestClaimDecisionDigest(decision),
    expectedReviewerGroupADigest:policy(a),expectedReviewerGroupBDigest:policy(b),
    expectedHead:head,expectedPendingBytesDigest:sha(pending),nowMs:observedAt};
   const out=await inspector.exportInterruptedClaimTranscriptReadOnly(args);
   const {nowMs:ignored,...verificationArgs}=args;
   return {...verificationArgs,bytes:out.bytes,expectedTranscriptDigest:out.transcriptDigest,expectedSnapshotDigest:out.snapshotDigest};
  }
  const first=await entry(1),second=await entry(2);
  const latePending=await entry(4,'pending-only',now+4);
  const reused=await entry(1,'pending-only',now+5);
  await link(join(directory,'.pending.json'),join(directory,'0001.json'));
  const third=await entry(3,'linked-pending');
  await fn({entries:[first,second,third],latePending,reused,entry,head,directory,root});
 }finally{await rm(root,{recursive:true,force:true});}
}
const pins=entries=>({entries,expectedHead:calculate({entries}).head});
t('three signed inspections preserve pending to linked progression',()=>scenario(async({entries})=>{
 const r=verify(pins(entries));assert.equal(r.verified,true);assert.equal(r.head.count,3);
 assert.equal(r.lastObservedState,'linked-pending');assert.equal(r.authorizesRepair,false);
 assert.equal(r.authorizesProduction,false);assert.equal(r.independentlyWitnessed,false);
}));
t('single signed inspection supports initial checkpoint',()=>scenario(async({entries})=>assert.equal(verify(pins(entries.slice(0,1))).head.count,1)));
t('two pending inspections can be pinned without claiming linked completion',()=>scenario(async({entries})=>{
 const r=verify(pins(entries.slice(0,2)));assert.equal(r.lastObservedState,'pending-only');
}));
t('prior independently pinned checkpoint validates exact prefix',()=>scenario(async({entries})=>{
 const previous=calculate({entries:entries.slice(0,2)}).head;
 assert.equal(verify({...pins(entries),expectedPreviousHead:previous}).previousCheckpointVerified,true);
}));
t('missing final independent pin fails closed',()=>scenario(async({entries})=>assert.throws(()=>verify({entries}),err('EXCHANGE32Z_EXTERNAL_CHECKPOINT_REQUIRED'))));
t('malformed final independent pin fails closed',()=>scenario(async({entries})=>assert.throws(()=>verify({entries,expectedHead:{count:3,headDigest:'abc'}}),err('EXCHANGE32Z_EXTERNAL_CHECKPOINT_REQUIRED'))));
t('wrong final head rejects a fork',()=>scenario(async({entries})=>assert.throws(()=>verify({...pins(entries),expectedHead:{count:3,headDigest:sha('fork')}}),err('EXCHANGE32Z_CHECKPOINT_MISMATCH'))));
t('omitting middle transcript is detected against retained full head',()=>scenario(async({entries})=>{
 const expectedHead=calculate({entries}).head;
 assert.throws(()=>verify({entries:[entries[0],entries[2]],expectedHead}),err('EXCHANGE32Z_CHECKPOINT_MISMATCH'));
}));
t('omitting final transcript is detected against retained count',()=>scenario(async({entries})=>{
 const expectedHead=calculate({entries}).head;
 assert.throws(()=>verify({entries:entries.slice(0,2),expectedHead}),err('EXCHANGE32Z_CHECKPOINT_MISMATCH'));
}));
t('prefix rollback fails when pinned to full history',()=>scenario(async({entries})=>{
 const expectedHead=calculate({entries}).head;
 assert.throws(()=>verify({entries:entries.slice(0,1),expectedHead}),err('EXCHANGE32Z_CHECKPOINT_MISMATCH'));
}));
t('reordered observations fail monotonicity',()=>scenario(async({entries})=>{
 assert.throws(()=>calculate({entries:[entries[1],entries[0],entries[2]]}),err('EXCHANGE32Z_TIME_ORDER'));
}));
t('linked then later-stamped pending is a state rollback',()=>scenario(async({entries,latePending})=>{
 assert.throws(()=>calculate({entries:[entries[2],latePending]}),err('EXCHANGE32Z_STATE_ROLLBACK'));
}));
t('repeated transcript rejected',()=>scenario(async({entries})=>{
 assert.throws(()=>calculate({entries:[entries[0],entries[0]]}),err('EXCHANGE32Z_TIME_ORDER'));
}));
t('same signed decision reused for a fresh timestamp rejected',()=>scenario(async({entries,reused})=>{
 // The same signed inspection decision may produce another 32Y transcript at a later time.
 assert.throws(()=>calculate({entries:[entries[0],reused]}),err('EXCHANGE32Z_REPLAY'));
}));
t('equal caller-supplied observation timestamps fail closed',()=>scenario(async({entries,entry})=>{
 const equal=await entry(4,'linked-pending',now+3);
 assert.throws(()=>calculate({entries:[...entries,equal]}),err('EXCHANGE32Z_TIME_ORDER'));
}));
t('fresh signed alternate branch cannot satisfy old external head',()=>scenario(async({entries,entry})=>{
 const expectedHead=calculate({entries}).head;
 const fork=await entry(4,'linked-pending',now+4);
 assert.throws(()=>verify({entries:[entries[0],entries[1],fork],expectedHead}),err('EXCHANGE32Z_CHECKPOINT_MISMATCH'));
}));
t('wrong prefix pin fails despite valid final history',()=>scenario(async({entries})=>{
 assert.throws(()=>verify({...pins(entries),expectedPreviousHead:{count:2,headDigest:sha('fork')}}),err('EXCHANGE32Z_PREFIX_MISMATCH'));
}));
t('prefix count must be smaller than final count',()=>scenario(async({entries})=>{
 assert.throws(()=>verify({...pins(entries),expectedPreviousHead:calculate({entries}).head}),err('EXCHANGE32Z_EXTERNAL_CHECKPOINT_REQUIRED'));
}));
t('external snapshot pin substitution rejected',()=>scenario(async({entries})=>{
 const changed={...entries[1],expectedSnapshotDigest:sha('fake')};
 assert.throws(()=>calculate({entries:[entries[0],changed]}),err('EXCHANGE32Y_SNAPSHOT_PIN_MISMATCH'));
}));
t('external transcript pin substitution rejected',()=>scenario(async({entries})=>{
 const changed={...entries[1],expectedTranscriptDigest:sha('fake')};
 assert.throws(()=>calculate({entries:[entries[0],changed]}),err('EXCHANGE32Y_TRANSCRIPT_PIN_MISMATCH'));
}));
t('missing per-entry external pin rejected',()=>scenario(async({entries})=>{
 const changed={...entries[1],expectedPendingBytesDigest:undefined};
 assert.throws(()=>calculate({entries:[entries[0],changed]}),err('EXCHANGE32Y_EXTERNAL_PINS_REQUIRED'));
}));
t('forged decision signature cannot be smuggled through chain',()=>scenario(async({entries})=>{
 const decision=structuredClone(entries[1].decision);
 const sig=decision.groupASignatures[0].signature;
 decision.groupASignatures[0].signature=(sig[0]==='A'?'B':'A')+sig.slice(1);
 assert.throws(()=>calculate({entries:[entries[0],{...entries[1],decision}]}));
}));
t('cross-claim prior head substitution fails independent per-entry pin',()=>scenario(async({entries})=>{
 const changed={...entries[1],expectedHead:{count:0,headDigest:sha('wrong')}};
 assert.throws(()=>calculate({entries:[entries[0],changed]}),err('EXCHANGE32Y_SNAPSHOT_PIN_MISMATCH'));
}));
t('changing signed decision to unrelated claim is rejected',()=>scenario(async({entries})=>{
 const changed={...entries[1],decision:entries[2].decision};
 assert.throws(()=>calculate({entries:[entries[0],changed]}));
}));
t('truncated transcript rejected before chaining',()=>scenario(async({entries})=>{
 const changed={...entries[1],bytes:entries[1].bytes.subarray(0,-1)};
 assert.throws(()=>calculate({entries:[entries[0],changed]}),err('EXCHANGE32Y_TRANSCRIPT_PIN_MISMATCH'));
}));
t('extra per-entry fields rejected',()=>scenario(async({entries})=>{
 const changed={...entries[0],authorizesRepair:true};
 assert.throws(()=>calculate({entries:[changed]}),err('EXCHANGE32Z_ENTRY_INVALID'));
}));
t('holes in entry list rejected',()=>scenario(async({entries})=>{
 const list=[entries[0],,entries[2]];
 assert.throws(()=>calculate({entries:list}),err('EXCHANGE32Z_ENTRIES_INVALID'));
}));
t('empty history rejected',()=>assert.throws(()=>calculate({entries:[]}),err('EXCHANGE32Z_ENTRIES_INVALID')));
t('oversized history rejected without verification',()=>scenario(async({entries})=>{
 const list=Array(OFFLINE_CONFLICT_MANIFEST_CLAIM_CONTINUITY_MAX_ENTRIES+1).fill(entries[0]);
 assert.throws(()=>calculate({entries:list}),err('EXCHANGE32Z_ENTRIES_INVALID'));
}));
t('bad checkpoint count rejected',()=>scenario(async({entries})=>{
 assert.throws(()=>verify({...pins(entries),expectedHead:{count:65,headDigest:sha('x')}}),err('EXCHANGE32Z_EXTERNAL_CHECKPOINT_REQUIRED'));
}));
t('non-array history rejected',()=>assert.throws(()=>calculate({entries:{}}),err('EXCHANGE32Z_ENTRIES_INVALID')));
t('read-only result cannot claim checkout authorization',()=>scenario(async({entries})=>{
 const r=verify(pins(entries));assert.equal(r.authorizesCheckout,false);assert.equal(r.requiresIndependentResolution,true);
}));
t('independently signed different pending claim cannot join this chain',()=>scenario(async({entries,root,head})=>{
 const directory=join(root,'other-claim');
 const journal=createOfflineConflictManifestJournal({directory,injectFault:s=>{if(s==='after-pending-sync')throw Error('simulated crash');}});
 await assert.rejects(journal.claim({verificationArgs:fixturePack('session_32z_other_0002',2048,'b'),expectedHead:head}),/simulated crash/);
 const pending=await readFile(join(directory,'.pending.json')),record=JSON.parse(pending);
 const body={schema:OFFLINE_CONFLICT_MANIFEST_CLAIM_ADJUDICATION_SCHEMA,action:'inspect-only',journalHead:head,
  pendingBytesDigest:sha(pending),pendingRecordDigest:record.recordDigest,pendingIndex:head.count+1,
  expectedPendingState:'pending-only',reviewerGroupADigest:policy(a),reviewerGroupBDigest:policy(b),
  issuedAt:now-1000,expiresAt:now+10000,nonce:'transcript32z_other_0002'};
 const decision={body,groupASignatures:signed(body,a),groupBSignatures:signed(body,b)};
 const args={decision,reviewerGroupA:pub(a),reviewerGroupB:pub(b),
  expectedDecisionDigest:offlineConflictManifestClaimDecisionDigest(decision),
  expectedReviewerGroupADigest:policy(a),expectedReviewerGroupBDigest:policy(b),
  expectedHead:head,expectedPendingBytesDigest:sha(pending),nowMs:now+5};
 const out=await createOfflineConflictManifestJournal({directory}).exportInterruptedClaimTranscriptReadOnly(args);
 const {nowMs:ignored,...pinned}=args;
 const different={...pinned,bytes:out.bytes,expectedTranscriptDigest:out.transcriptDigest,
  expectedSnapshotDigest:out.snapshotDigest};
 assert.throws(()=>calculate({entries:[entries[0],different]}),err('EXCHANGE32Z_CLAIM_FORK'));
}));
