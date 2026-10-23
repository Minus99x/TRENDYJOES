import test from 'node:test';
import {mkdtempSync,writeFileSync,readFileSync,truncateSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA} from '../src/offline-pinned-orphan-classifier.mjs';
import {OFFLINE_ORPHAN_SUPERVISOR_DECISION_SCHEMA,offlineOrphanSupervisorPolicyDigest,
 offlineOrphanReportIssueDigest,offlineOrphanSupervisorDecisionSigningBytes,encodeOfflineOrphanReplaySnapshot} from '../src/offline-orphan-supervisor-decision.mjs';
import {OFFLINE_SUPERVISOR_REPLAY_COMMIT_SCHEMA} from '../src/offline-supervisor-replay-commit.mjs';
import {OFFLINE_REPLAY_HEAD_CHECKPOINT_SCHEMA,offlineReplayHeadAuditorPolicyDigest,offlineReplayHeadAuditHistoryDigest,
 offlineReplayHeadCheckpointSigningBytes,offlineReplayHeadCheckpointDigest} from '../src/offline-supervisor-replay-checkpoint.mjs';
import {OFFLINE_PORTABLE_REPLAY_AUDIT_SCHEMA,OFFLINE_PORTABLE_REPLAY_WITNESS_SCHEMA,
 encodeOfflinePortableReplayAuditBundle,offlinePortableReplayAuditBundleDigest,offlinePortableReplayWitnessSigningBytes,
 offlinePortableReplayWitnessReceiptDigest,offlinePortableReplayWitnessPolicyDigest,verifyOfflinePortableReplayAuditBundle} from '../src/offline-portable-replay-audit-bundle.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const ZERO='0'.repeat(64),registryId='orphan_registry_32f',now=1800000000000;
const keys=prefix=>[0,1,2].map(i=>({id:`${prefix}_32f_${i}`,...generateKeyPairSync('ed25519')}));
const reviewersK=keys('reviewer'),auditorsK=keys('auditor'),witnessesK=keys('witness');
const pub=keys=>keys.map(({id,publicKey})=>({id,publicKey}));
const reviewers=pub(reviewersK),auditors=pub(auditorsK),witnesses=pub(witnessesK);
const reviewerPin=offlineOrphanSupervisorPolicyDigest({reviewers,quorum:2});
const auditorPin=offlineReplayHeadAuditorPolicyDigest({auditors,quorum:2});
const witnessPin=offlinePortableReplayWitnessPolicyDigest({witnesses,quorum:2});
const err=code=>e=>e?.code===code;
function report(){
 const evidence=[{directoryIndex:0,name:'orphan-32f.tjexport',nameDigest:sha('orphan-32f.tjexport'),classification:'UNTRACKED_ARCHIVE_UNVERIFIED',digest:sha('bytes'),bytes:10}];
 const body={schema:OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA,registryId,manifestDigest:sha('manifest'),head:{count:1,headDigest:sha('head')},epoch:0,transitionDigest:ZERO,recordsDigest:sha('records'),evidence,
  status:'SUPERVISORY_REVIEW_REQUIRED',issueCount:1,supervisoryDisposition:'EXTERNAL_DECISION_REQUIRED_FOR_ANY_REMEDIATION',
  readOnly:true,productionApproved:false,mayDelete:false,mayRepair:false,mayManufacture:false,mayAcknowledge:false};
 return {...body,reportDigest:sha(Buffer.from(`${OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA}\0${JSON.stringify(body)}`))};
}
const pins=r=>({reportDigest:r.reportDigest,manifestDigest:r.manifestDigest,head:r.head,epoch:r.epoch,transitionDigest:r.transitionDigest,recordsDigest:r.recordsDigest});
function decision(r,head,n){
 const body={schema:OFFLINE_ORPHAN_SUPERVISOR_DECISION_SCHEMA,registryId,reportDigest:r.reportDigest,manifestDigest:r.manifestDigest,
  head:r.head,epoch:r.epoch,transitionDigest:r.transitionDigest,recordsDigest:r.recordsDigest,issueDigest:offlineOrphanReportIssueDigest(r),
  issueCount:1,disposition:'REJECT_EVIDENCE',decisionId:`decision_32f_${String(n).padStart(4,'0')}`,nonce:`nonce_32f_${String(n).padStart(4,'0')}`,
  issuedAt:now-1000,expiresAt:now+60000,replayDigest:head,reviewerPolicyDigest:reviewerPin};
 const bytes=offlineOrphanSupervisorDecisionSigningBytes(body);
 return {body,signatures:reviewersK.slice(0,2).map(k=>({reviewerId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}))};
}
function checkpoint(body){const bytes=offlineReplayHeadCheckpointSigningBytes(body);
 return {body,signatures:auditorsK.slice(0,2).map(k=>({auditorId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}))};}
function witnessReceipt(body,signers=witnessesK.slice(0,2)){
 const bytes=offlinePortableReplayWitnessSigningBytes(body);
 return {body,signatures:signers.map(k=>({witnessId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}))};
}
function fixture(count=2){
 const genesisBytes=encodeOfflineOrphanReplaySnapshot({registryId,consumed:[]}),expectedGenesisDigest=sha(genesisBytes);
 let head=expectedGenesisDigest;const r=report(),items=[];
 for(let n=1;n<=count;n++){
  const d=decision(r,head,n),prev=head;
  const state=encodeOfflineOrphanReplaySnapshot({registryId,consumed:Array.from({length:n},(_,i)=>({decisionId:`decision_32f_${String(i+1).padStart(4,'0')}`,nonce:`nonce_32f_${String(i+1).padStart(4,'0')}`}))});
  head=sha(state);
  const record={schema:OFFLINE_SUPERVISOR_REPLAY_COMMIT_SCHEMA,registryId,previousDigest:prev,nextDigest:head,
   decisionId:d.body.decisionId,nonce:d.body.nonce,decisionDigest:sha(offlineOrphanSupervisorDecisionSigningBytes(d.body))};
  items.push({record,report:r,expectedPins:pins(r),decision:d,reviewers,quorum:2,expectedReviewerPolicyDigest:reviewerPin,observedAtMs:now});
 }
 const expectedPreviousCheckpointDigest=sha('previous-checkpoint');
 const body={schema:OFFLINE_REPLAY_HEAD_CHECKPOINT_SCHEMA,registryId,genesisDigest:expectedGenesisDigest,headDigest:head,
  commitCount:items.length,historyDigest:offlineReplayHeadAuditHistoryDigest(items),previousCheckpointDigest:expectedPreviousCheckpointDigest,
  sequence:7,issuedAt:now+5000,auditorPolicyDigest:auditorPin};
 const c=checkpoint(body),expectedCheckpointDigest=offlineReplayHeadCheckpointDigest(c);
 const source={registryId,genesisBytes,expectedGenesisDigest,items,checkpoint:c,auditors,auditorQuorum:2,
  expectedAuditorPolicyDigest:auditorPin,expectedCheckpointDigest,expectedPreviousCheckpointDigest,expectedSequence:7};
 const bundleBytes=encodeOfflinePortableReplayAuditBundle(source),expectedBundleDigest=offlinePortableReplayAuditBundleDigest(bundleBytes);
 const receiptBody={schema:OFFLINE_PORTABLE_REPLAY_WITNESS_SCHEMA,registryId,bundleDigest:expectedBundleDigest,
  checkpointDigest:expectedCheckpointDigest,historyDigest:c.body.historyDigest,genesisDigest:expectedGenesisDigest,commitCount:items.length,
  previousWitnessReceiptDigest:sha('previous-witness'),sequence:19,issuedAt:now+7000,witnessPolicyDigest:witnessPin};
 const receipt=witnessReceipt(receiptBody),expectedWitnessReceiptDigest=offlinePortableReplayWitnessReceiptDigest(receipt);
 const args={bundleBytes,expectedBundleDigest,witnessReceipt:receipt,witnesses,witnessQuorum:2,
  expectedWitnessPolicyDigest:witnessPin,expectedWitnessReceiptDigest,
  expectedPreviousWitnessReceiptDigest:receiptBody.previousWitnessReceiptDigest,expectedWitnessSequence:19,
  expectedGenesisDigest,expectedCheckpointDigest,expectedPreviousCheckpointDigest,expectedSequence:7,expectedAuditorPolicyDigest:auditorPin};
 return {args,source,bundleBytes,receipt,receiptBody};
}
const editBundle=(f,edit)=>{
 const b=JSON.parse(f.bundleBytes.toString('utf8'));edit(b);const bundleBytes=Buffer.from(JSON.stringify(b));
 return {...f.args,bundleBytes,expectedBundleDigest:offlinePortableReplayAuditBundleDigest(bundleBytes)};
};
const editReceipt=(f,edit)=>{
 const body={...f.receiptBody};edit(body);
 const receipt=witnessReceipt(body);
 return {...f.args,witnessReceipt:receipt,expectedWitnessReceiptDigest:offlinePortableReplayWitnessReceiptDigest(receipt)};
};
import {OFFLINE_PORTABLE_REPLAY_WITNESS_TRANSITION_SCHEMA,
 offlinePortableReplayWitnessTransitionSigningBytes,offlinePortableReplayWitnessTransitionDigest,
 offlinePortableReplayWitnessHistoryDigest,verifyOfflinePortableReplayWitnessHistory} from '../src/offline-portable-replay-witness-history.mjs';
const nextWitnessK=keys('nextwitness');
const nextWitnesses=pub(nextWitnessK);
const nextPin=offlinePortableReplayWitnessPolicyDigest({witnesses:nextWitnesses,quorum:2});
function historyFixture(rotated=true){
 const f=fixture(2),first=f.args;
 const mk=(prev,sequence,issuedAt,policyDigest,signers)=>{
  const body={...f.receiptBody,previousWitnessReceiptDigest:prev,sequence,issuedAt,witnessPolicyDigest:policyDigest};
  const witnessReceipt2=witnessReceipt(body,signers);
  return {...first,witnessReceipt:witnessReceipt2,expectedWitnessReceiptDigest:offlinePortableReplayWitnessReceiptDigest(witnessReceipt2),
   expectedPreviousWitnessReceiptDigest:prev,expectedWitnessSequence:sequence,expectedWitnessPolicyDigest:policyDigest};
 };
 const second=mk(first.expectedWitnessReceiptDigest,20,now+8000,witnessPin,witnessesK.slice(0,2));
 const third=mk(second.expectedWitnessReceiptDigest,21,now+10000,rotated?nextPin:witnessPin,
  rotated?nextWitnessK.slice(0,2):witnessesK.slice(0,2));
 const policies=[{witnesses,quorum:2,expectedPolicyDigest:witnessPin,transition:null,expectedTransitionDigest:null}];
 let transitionDigest=null;
 if(rotated){
  const body={schema:OFFLINE_PORTABLE_REPLAY_WITNESS_TRANSITION_SCHEMA,registryId,atSequence:21,
   previousReceiptDigest:second.expectedWitnessReceiptDigest,oldPolicyDigest:witnessPin,newPolicyDigest:nextPin,issuedAt:now+9000};
  const bytes=offlinePortableReplayWitnessTransitionSigningBytes(body);
  const signatures=signers=>signers.slice(0,2).map(k=>({witnessId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}));
  const transition={body,outgoingSignatures:signatures(witnessesK),incomingSignatures:signatures(nextWitnessK)};
  transitionDigest=offlinePortableReplayWitnessTransitionDigest(transition);
  policies.push({witnesses:nextWitnesses,quorum:2,expectedPolicyDigest:nextPin,transition,expectedTransitionDigest:transitionDigest});
 }
 const entries=[{policyIndex:0,verificationArgs:first},{policyIndex:0,verificationArgs:second},
  {policyIndex:rotated?1:0,verificationArgs:third}];
 const records=entries.map((e,i)=>({sequence:19+i,receiptDigest:e.verificationArgs.expectedWitnessReceiptDigest,
  policyDigest:i===2&&rotated?nextPin:witnessPin,transitionDigest:i===2?transitionDigest:null}));
 const args={registryId,entries,policies,expectedInitialPreviousReceiptDigest:first.expectedPreviousWitnessReceiptDigest,
  expectedStartSequence:19,expectedEndSequence:21,expectedHeadReceiptDigest:third.expectedWitnessReceiptDigest,
  expectedHistoryDigest:offlinePortableReplayWitnessHistoryDigest({registryId,initialPreviousReceiptDigest:first.expectedPreviousWitnessReceiptDigest,records}),
  expectedGenesisDigest:first.expectedGenesisDigest};
 return {args,f,records};
}
const mutate=(f,fn)=>{// preserve KeyObjects and Buffers; copy only containers
 const args={...f.args,entries:f.args.entries.map(e=>({...e,verificationArgs:{...e.verificationArgs}})),
  policies:f.args.policies.map(p=>({...p,transition:p.transition?{...p.transition,body:{...p.transition.body},outgoingSignatures:p.transition.outgoingSignatures.map(x=>({...x})),incomingSignatures:p.transition.incomingSignatures.map(x=>({...x}))}:null}))};
 fn(args);return args;
};
import {OFFLINE_WITNESS_HISTORY_CHECKPOINT_SCHEMA,OFFLINE_WITNESS_HISTORY_ANCHOR_SCHEMA,
 offlineWitnessHistoryCheckpointSigningBytes,encodeOfflineWitnessHistoryCheckpoint,
 decodeOfflineWitnessHistoryCheckpoint,offlineWitnessHistoryCheckpointDigest,
 offlineWitnessHistoryCheckpointAuditorPolicyDigest,offlineWitnessHistoryAnchorCandidate,
 verifyOfflineWitnessHistoryCheckpoint} from '../src/offline-portable-witness-history-checkpoint.mjs';
const checkpointAuditorsK=keys('checkpointauditor');
const checkpointAuditors=pub(checkpointAuditorsK);
const checkpointPolicyPin=offlineWitnessHistoryCheckpointAuditorPolicyDigest({auditors:checkpointAuditors,quorum:2});
function signCheckpoint(body,signers=checkpointAuditorsK.slice(0,2)){
 const bytes=offlineWitnessHistoryCheckpointSigningBytes(body);
 return {body,signatures:signers.map(k=>({auditorId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}))};
}
function candidate(){
 const f=historyFixture(),a=f.args;
 const anchor={schema:OFFLINE_WITNESS_HISTORY_ANCHOR_SCHEMA,registryId,genesisDigest:a.expectedGenesisDigest,
  sequence:18,headReceiptDigest:a.expectedInitialPreviousReceiptDigest,checkpointDigest:sha('prior-independent-checkpoint'),
  issuedAt:now+1000,auditorPolicyDigest:checkpointPolicyPin};
 const body={schema:OFFLINE_WITNESS_HISTORY_CHECKPOINT_SCHEMA,registryId,genesisDigest:a.expectedGenesisDigest,
  startSequence:a.expectedStartSequence,endSequence:a.expectedEndSequence,previousReceiptDigest:a.expectedInitialPreviousReceiptDigest,
  headReceiptDigest:a.expectedHeadReceiptDigest,historyDigest:a.expectedHistoryDigest,
  previousCheckpointDigest:anchor.checkpointDigest,issuedAt:now+12000,auditorPolicyDigest:checkpointPolicyPin};
 const checkpoint=signCheckpoint(body),checkpointBytes=encodeOfflineWitnessHistoryCheckpoint(checkpoint);
 return {f,anchor,checkpoint,checkpointBytes,args:{checkpointBytes,historyArgs:a,auditors:checkpointAuditors,
  auditorQuorum:2,expectedAuditorPolicyDigest:checkpointPolicyPin,anchor}};
}
import {OFFLINE_WITNESS_CHECKPOINT_AUDITOR_TRANSITION_SCHEMA,
 offlineWitnessCheckpointAuditorTransitionSigningBytes,offlineWitnessCheckpointAuditorTransitionDigest,
 verifyOfflineWitnessCheckpointAncestry} from '../src/offline-witness-checkpoint-ancestry.mjs';
const nextCheckpointAuditorsK=keys('next_checkpoint_auditor');
const nextCheckpointAuditors=pub(nextCheckpointAuditorsK);
const nextCheckpointPin=offlineWitnessHistoryCheckpointAuditorPolicyDigest({auditors:nextCheckpointAuditors,quorum:2});
const bad=code=>e=>e?.code===code;
function ancestry(rotated=true){
 const f=historyFixture(false),h=f.args;
 const makeHistory=(start,end)=>{
  const entries=h.entries.slice(start-19,end-18);
  const records=f.records.slice(start-19,end-18);
  const prev=start===19?h.expectedInitialPreviousReceiptDigest:h.entries[start-20].verificationArgs.expectedWitnessReceiptDigest;
  return {...h,entries,expectedInitialPreviousReceiptDigest:prev,expectedStartSequence:start,expectedEndSequence:end,
   expectedHeadReceiptDigest:entries.at(-1).verificationArgs.expectedWitnessReceiptDigest,
   expectedHistoryDigest:offlinePortableReplayWitnessHistoryDigest({registryId,initialPreviousReceiptDigest:prev,records})};
 };
 const firstHistory=makeHistory(19,20),secondHistory=makeHistory(21,21);
 const initialAnchor={schema:OFFLINE_WITNESS_HISTORY_ANCHOR_SCHEMA,registryId,genesisDigest:h.expectedGenesisDigest,
  sequence:18,headReceiptDigest:h.expectedInitialPreviousReceiptDigest,checkpointDigest:sha('root-independent-anchor'),
  issuedAt:now+1000,auditorPolicyDigest:checkpointPolicyPin};
 const firstBody={schema:OFFLINE_WITNESS_HISTORY_CHECKPOINT_SCHEMA,registryId,genesisDigest:h.expectedGenesisDigest,
  startSequence:19,endSequence:20,previousReceiptDigest:firstHistory.expectedInitialPreviousReceiptDigest,
  headReceiptDigest:firstHistory.expectedHeadReceiptDigest,historyDigest:firstHistory.expectedHistoryDigest,
  previousCheckpointDigest:initialAnchor.checkpointDigest,issuedAt:now+12000,auditorPolicyDigest:checkpointPolicyPin};
 const firstBytes=encodeOfflineWitnessHistoryCheckpoint(signCheckpoint(firstBody));
 const firstAnchor=offlineWitnessHistoryAnchorCandidate(firstBytes);
 const secondBody={...firstBody,startSequence:21,endSequence:21,
  previousReceiptDigest:secondHistory.expectedInitialPreviousReceiptDigest,
  headReceiptDigest:secondHistory.expectedHeadReceiptDigest,historyDigest:secondHistory.expectedHistoryDigest,
  previousCheckpointDigest:firstAnchor.checkpointDigest,issuedAt:now+14000,
  auditorPolicyDigest:rotated?nextCheckpointPin:checkpointPolicyPin};
 const secondBytes=encodeOfflineWitnessHistoryCheckpoint(signCheckpoint(secondBody,
  rotated?nextCheckpointAuditorsK.slice(0,2):checkpointAuditorsK.slice(0,2)));
 const terminalAnchor=offlineWitnessHistoryAnchorCandidate(secondBytes);
 const entries=[{checkpointBytes:firstBytes,historyArgs:firstHistory,auditors:checkpointAuditors,
  auditorQuorum:2,expectedAuditorPolicyDigest:checkpointPolicyPin,transition:null,expectedTransitionDigest:null},
 {checkpointBytes:secondBytes,historyArgs:secondHistory,auditors:rotated?nextCheckpointAuditors:checkpointAuditors,
  auditorQuorum:2,expectedAuditorPolicyDigest:rotated?nextCheckpointPin:checkpointPolicyPin,
  transition:null,expectedTransitionDigest:null}];
 if(rotated){
  const body={schema:OFFLINE_WITNESS_CHECKPOINT_AUDITOR_TRANSITION_SCHEMA,registryId,genesisDigest:h.expectedGenesisDigest,
   atStartSequence:21,previousCheckpointDigest:firstAnchor.checkpointDigest,
   previousReceiptDigest:firstAnchor.headReceiptDigest,oldPolicyDigest:checkpointPolicyPin,
   newPolicyDigest:nextCheckpointPin,issuedAt:now+13000};
  const bytes=offlineWitnessCheckpointAuditorTransitionSigningBytes(body);
  const signatures=signers=>signers.slice(0,2).map(k=>({auditorId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}));
  const transition={body,outgoingSignatures:signatures(checkpointAuditorsK),incomingSignatures:signatures(nextCheckpointAuditorsK)};
  entries[1].transition=transition;entries[1].expectedTransitionDigest=offlineWitnessCheckpointAuditorTransitionDigest(transition);
 }
 return {initialAnchor,terminalAnchor,entries};
}
const clone=a=>({...a,initialAnchor:{...a.initialAnchor},terminalAnchor:{...a.terminalAnchor},
 entries:a.entries.map(e=>({...e,transition:e.transition?{...e.transition,body:{...e.transition.body},
  outgoingSignatures:e.transition.outgoingSignatures.map(s=>({...s})),incomingSignatures:e.transition.incomingSignatures.map(s=>({...s}))}:null}))});

import {encodeOfflineSplitViewConflictProof,verifyOfflineSplitViewConflictProof,
 OFFLINE_SPLIT_VIEW_CONFLICT_PROOF_SCHEMA} from '../src/offline-portable-split-view-conflict-proof.mjs';
function conflictFixture(){
 const a=ancestry(false),b=clone(a),index=1;
 const original=decodeOfflineWitnessHistoryCheckpoint(b.entries[index].checkpointBytes);
 b.entries[index].checkpointBytes=encodeOfflineWitnessHistoryCheckpoint(signCheckpoint({...original.body,issuedAt:original.body.issuedAt+1},checkpointAuditorsK.slice(1)));
 b.terminalAnchor=offlineWitnessHistoryAnchorCandidate(b.entries[index].checkpointBytes);
 return {initialAnchor:a.initialAnchor,observations:[{terminalAnchor:a.terminalAnchor,entries:a.entries},{terminalAnchor:b.terminalAnchor,entries:b.entries}]};
}
const make=()=>encodeOfflineSplitViewConflictProof(conflictFixture());
const check=(bundle,pin=bundle.pinCandidate)=>verifyOfflineSplitViewConflictProof({bytes:bundle.bytes,expectedPin:pin});
const bad32k=code=>e=>e?.code===code;
const jsonMutate=(bundle,mutator)=>{
 const obj=JSON.parse(bundle.bytes.toString());mutator(obj);
 return Buffer.from(JSON.stringify(obj));
};
test('32K roundtrip verifies a fully authenticated signed fork from portable bytes',()=>{
 const b=make(),v=check(b);
 assert.equal(v.schema,OFFLINE_SPLIT_VIEW_CONFLICT_PROOF_SCHEMA);
 assert.equal(v.verified,true);assert.equal(v.status,'AUTHENTICATED_SPLIT_VIEW_DETECTED');
 assert.equal(v.conflict.sharedAuditors.length,1);
 assert.equal(v.inventoryDigest,b.pinCandidate.inventoryDigest);
 assert.equal(v.independentlyPublished,false);assert.equal(v.authorizesCheckout,false);
});
test('32K portable bytes contain no private signing keys',()=>{
 const b=make();const raw=b.bytes.toString();
 assert.equal(raw.includes('PRIVATE KEY'),false);
 assert.equal(raw.includes('privateKey'),false);
 assert.equal(raw.includes('ed25519-spki'),true);
 assert.equal(raw.includes('"$tjType":"bytes"'),true);
});
test('32K deterministic canonical encoding produces identical pins',()=>{
 const f=conflictFixture();const a=encodeOfflineSplitViewConflictProof(f),b=encodeOfflineSplitViewConflictProof(f);
 assert.ok(a.bytes.equals(b.bytes));assert.deepEqual(a.pinCandidate,b.pinCandidate);
});
test('32K rejects missing independent caller pin',()=>assert.throws(()=>verifyOfflineSplitViewConflictProof({bytes:make().bytes}),bad32k('CONFLICT32K_EXTERNAL_PIN_REQUIRED')));
test('32K rejects extra approval field in external pin',()=>{
 const b=make();assert.throws(()=>check(b,{...b.pinCandidate,productionApproved:true}),bad32k('CONFLICT32K_EXTERNAL_PIN_REQUIRED'));
});
test('32K rejects forged external inventory digest',()=>{
 const b=make();assert.throws(()=>check(b,{...b.pinCandidate,inventoryDigest:sha('fake')}),bad32k('CONFLICT32K_INVENTORY_PIN_MISMATCH'));
});
test('32K rejects swapped caller left/right pins',()=>{
 const b=make();assert.throws(()=>check(b,{...b.pinCandidate,leftDigest:b.pinCandidate.rightDigest,rightDigest:b.pinCandidate.leftDigest}),bad32k('CONFLICT32K_INVENTORY_PIN_MISMATCH'));
});
test('32K rejects omitted branch even with recomputed JSON',()=>{
 const b=make();const bytes=jsonMutate(b,o=>o.branches.pop());
 assert.throws(()=>verifyOfflineSplitViewConflictProof({bytes,expectedPin:b.pinCandidate}),bad32k('CONFLICT32K_BUNDLE_SCHEMA_INVALID'));
});
test('32K rejects omitted checkpoint even with canonical JSON',()=>{
 const b=make();const bytes=jsonMutate(b,o=>o.branches[1].entries.pop());
 assert.throws(()=>verifyOfflineSplitViewConflictProof({bytes,expectedPin:b.pinCandidate}),bad32k('CONFLICT32K_INVENTORY_PIN_MISMATCH'));
});
test('32K rejects substituted checkpoint evidence against pinned inventory',()=>{
 const b=make();const bytes=jsonMutate(b,o=>o.branches[1].entries[1].checkpointBytes.value='AAAA');
 assert.throws(()=>verifyOfflineSplitViewConflictProof({bytes,expectedPin:b.pinCandidate}),bad32k('CONFLICT32K_INVENTORY_PIN_MISMATCH'));
});
test('32K rejects altered cryptographic conflict claim against pinned inventory',()=>{
 const b=make();const bytes=jsonMutate(b,o=>o.conflict.status='IDENTICAL_AUTHENTICATED_PATH');
 assert.throws(()=>verifyOfflineSplitViewConflictProof({bytes,expectedPin:b.pinCandidate}),bad32k('CONFLICT32K_INVENTORY_PIN_MISMATCH'));
});
test('32K rejects branch reordering without independently matching pin',()=>{
 const b=make();const bytes=jsonMutate(b,o=>o.branches.reverse());
 assert.throws(()=>verifyOfflineSplitViewConflictProof({bytes,expectedPin:b.pinCandidate}),bad32k('CONFLICT32K_INVENTORY_PIN_MISMATCH'));
});
test('32K rejects malformed JSON and noncanonical whitespace',()=>{
 const b=make();assert.throws(()=>verifyOfflineSplitViewConflictProof({bytes:Buffer.from('{'),expectedPin:b.pinCandidate}),bad32k('CONFLICT32K_BUNDLE_ENCODING_INVALID'));
 assert.throws(()=>verifyOfflineSplitViewConflictProof({bytes:Buffer.from(' '+b.bytes),expectedPin:b.pinCandidate}),bad32k('CONFLICT32K_NONCANONICAL_BUNDLE'));
});
test('32K rejects duplicate JSON keys through canonical re-encoding',()=>{
 const b=make();const raw=b.bytes.toString().replace('"schema":"TJ-OFFLINE-SPLIT-VIEW-CONFLICT-PROOF-1",','"schema":"TJ-OFFLINE-SPLIT-VIEW-CONFLICT-PROOF-1","schema":"TJ-OFFLINE-SPLIT-VIEW-CONFLICT-PROOF-1",');
 assert.throws(()=>verifyOfflineSplitViewConflictProof({bytes:Buffer.from(raw),expectedPin:b.pinCandidate}),bad32k('CONFLICT32K_NONCANONICAL_BUNDLE'));
});
test('32K rejects excessive evidence bytes',()=>{
 const b=make();assert.throws(()=>verifyOfflineSplitViewConflictProof({bytes:Buffer.alloc(3*1024*1024+1),expectedPin:b.pinCandidate}),bad32k('CONFLICT32K_BUNDLE_ENCODING_INVALID'));
});
test('32K rejects non-fork authenticated prefix history',()=>{
 const a=ancestry(false),o={terminalAnchor:a.terminalAnchor,entries:a.entries};
 assert.throws(()=>encodeOfflineSplitViewConflictProof({initialAnchor:a.initialAnchor,observations:[o,o]}),bad32k('CONFLICT32K_SPLIT_VIEW_REQUIRED'));
});
test('32K rejects forged checkpoint signature before constructing bundle',()=>{
 const f=conflictFixture(),b=f.observations[1];const c=decodeOfflineWitnessHistoryCheckpoint(b.entries[1].checkpointBytes);
 c.signatures[0].signature=sign(null,offlineWitnessHistoryCheckpointSigningBytes(c.body),reviewersK[0].privateKey).toString('base64url');
 b.entries[1].checkpointBytes=encodeOfflineWitnessHistoryCheckpoint(c);
 b.terminalAnchor=offlineWitnessHistoryAnchorCandidate(b.entries[1].checkpointBytes);
 assert.throws(()=>encodeOfflineSplitViewConflictProof(f),bad32k('WITNESS32H_SIGNATURE_INVALID'));
});
test('32K rejects missing receipt evidence before constructing bundle',()=>{
 const f=conflictFixture();f.observations[1].entries[1].historyArgs.entries=[];
 assert.throws(()=>encodeOfflineSplitViewConflictProof(f),bad32k('HISTORY32G_EXTERNAL_PINS_REQUIRED'));
});
test('32K rejects getter-bearing branch objects without invoking getters',()=>{
 const f=conflictFixture();Object.defineProperty(f.observations[0],'terminalAnchor',{get(){throw Error('getter executed');},enumerable:true});
 assert.throws(()=>encodeOfflineSplitViewConflictProof(f),bad32k('SPLIT32J_OBSERVATION_INVALID'));
});
test('32K rejects accessor in deeply nested evidence before encoding',()=>{
 const f=conflictFixture();Object.defineProperty(f.observations[0].entries[0].historyArgs,'expectedHeadReceiptDigest',{get(){throw Error('getter executed');},enumerable:true});
 assert.throws(()=>encodeOfflineSplitViewConflictProof(f));
});
test('32K rejects non-Ed25519 public keys before encoding',()=>{
 const f=conflictFixture();f.observations[0].entries[0].auditors=f.observations[0].entries[0].auditors.map((a,i)=>i===0?{...a,publicKey:generateKeyPairSync('rsa',{modulusLength:2048}).publicKey}:a);
 assert.throws(()=>encodeOfflineSplitViewConflictProof(f));
});
test('32K rejects caller supplied production claim in proof root',()=>{
 const f=conflictFixture();f.initialAnchor={...f.initialAnchor,productionApproved:true};
 assert.throws(()=>encodeOfflineSplitViewConflictProof(f));
});
test('32K rejects extra production-authorization fields in bundle',()=>{
 const b=make(),bytes=jsonMutate(b,o=>o.productionApproved=true);
 assert.throws(()=>verifyOfflineSplitViewConflictProof({bytes,expectedPin:b.pinCandidate}),bad32k('CONFLICT32K_BUNDLE_SCHEMA_INVALID'));
});
const h=(domain,data)=>createHash('sha256').update(domain+'\0').update(data).digest('hex');
function repin(bytes){
 const o=JSON.parse(bytes.toString());
 const m={rootDigest:h('TJ-32K-ROOT',Buffer.from(JSON.stringify(o.root))),
  leftDigest:h('TJ-32K-BRANCH',Buffer.from(JSON.stringify(o.branches[0]))),
  rightDigest:h('TJ-32K-BRANCH',Buffer.from(JSON.stringify(o.branches[1]))),
  conflictDigest:h('TJ-32K-CONFLICT',Buffer.from(JSON.stringify(o.conflict)))};
 o.inventory={...m,inventoryDigest:h('TJ-32K-INVENTORY',Buffer.from(JSON.stringify(m)))};
 return {bytes:Buffer.from(JSON.stringify(o)),expectedPin:{schema:'TJ-OFFLINE-SPLIT-VIEW-CONFLICT-PIN-1',...o.inventory}};
}
test('32K even fully repinned forged signature fails underlying cryptographic verification',()=>{
 const b=make(),o=JSON.parse(b.bytes.toString());
 // Swap one signature while leaving the original historical checkpoint body and its inventory otherwise intact.
 const cp=o.branches[1].entries[1].checkpointBytes;
 const decoded=JSON.parse(Buffer.from(cp.value,'base64url').toString());
 decoded.signatures[0].signature=sign(null,Buffer.from('forged'),reviewersK[0].privateKey).toString('base64url');
 cp.value=Buffer.from(JSON.stringify(decoded)).toString('base64url');
 const re=repin(Buffer.from(JSON.stringify(o)));
 assert.throws(()=>verifyOfflineSplitViewConflictProof(re),bad32k('WITNESS32H_SIGNATURE_INVALID'));
});
test('32K even fully repinned omission fails underlying continuity verification',()=>{
 const b=make(),o=JSON.parse(b.bytes.toString());
 o.branches[1].entries.shift();const re=repin(Buffer.from(JSON.stringify(o)));
 assert.throws(()=>verifyOfflineSplitViewConflictProof(re),bad32k('ANCESTRY32I_WINDOW_CONTINUITY_INVALID'));
});
test('32K even fully repinned conflict-claim substitution fails authenticated comparison',()=>{
 const b=make(),o=JSON.parse(b.bytes.toString());
 o.conflict.conflict.leftCheckpointDigest=sha('pretend-branch');
 const re=repin(Buffer.from(JSON.stringify(o)));
 assert.throws(()=>verifyOfflineSplitViewConflictProof(re),bad32k('CONFLICT32K_CONFLICT_CLAIM_MISMATCH'));
});
test('32K even fully repinned malformed public-key tag fails closed',()=>{
 const b=make(),o=JSON.parse(b.bytes.toString());
 o.branches[0].entries[0].auditors[0].publicKey={$tjType:'ed25519-spki',value:'AAAA'};
 const re=repin(Buffer.from(JSON.stringify(o)));
 assert.throws(()=>verifyOfflineSplitViewConflictProof(re),bad32k('CONFLICT32K_EVIDENCE_TYPE_INVALID'));
});
test('32K even fully repinned prototype pollution key fails closed',()=>{
 const b=make(),o=JSON.parse(b.bytes.toString());
 o.branches[0].entries[0].historyArgs['__proto__']='polluted'; // setter does not create own key; define explicitly
 Object.defineProperty(o.branches[0].entries[0].historyArgs,'__proto__',{value:'polluted',enumerable:true,configurable:true});
 const re=repin(Buffer.from(JSON.stringify(o)));
 assert.throws(()=>verifyOfflineSplitViewConflictProof(re),bad32k('CONFLICT32K_EVIDENCE_TYPE_INVALID'));
 assert.equal({}.polluted,undefined);
});
test('32K even fully repinned receipt pin substitution fails underlying history validation',()=>{
 const b=make(),o=JSON.parse(b.bytes.toString());
 o.branches[0].entries[0].historyArgs.expectedHeadReceiptDigest=sha('substituted');
 const re=repin(Buffer.from(JSON.stringify(o)));
 assert.throws(()=>verifyOfflineSplitViewConflictProof(re));
});
test('32K rejects cyclic evidence objects before serialization',()=>{
 const f=conflictFixture();f.observations[0].entries[0].historyArgs.circular=f.observations[0].entries[0].historyArgs;
 assert.throws(()=>encodeOfflineSplitViewConflictProof(f));
});
test('32K even fully repinned production flag in evidence fails upstream schema checks',()=>{
 const b=make(),o=JSON.parse(b.bytes.toString());
 o.branches[0].entries[0].productionApproved=true;
 const re=repin(Buffer.from(JSON.stringify(o)));
 assert.throws(()=>verifyOfflineSplitViewConflictProof(re),bad32k('ANCESTRY32I_ENTRY_INVALID'));
});
