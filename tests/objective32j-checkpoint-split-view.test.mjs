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

import {verifyOfflineWitnessCheckpointSplitView,OFFLINE_WITNESS_SPLIT_VIEW_SCHEMA} from '../src/offline-witness-checkpoint-split-view.mjs';
const observation=a=>({terminalAnchor:a.terminalAnchor,entries:a.entries});
const compare=(a,b)=>verifyOfflineWitnessCheckpointSplitView({initialAnchor:a.initialAnchor,observations:[observation(a),observation(b)]});
function split(rotated=false,signers){
 const a=ancestry(rotated),b=clone(a),index=b.entries.length-1;
 const old=decodeOfflineWitnessHistoryCheckpoint(b.entries[index].checkpointBytes);
 const newBody={...old.body,issuedAt:old.body.issuedAt+1};
 const chosen=signers||(rotated?nextCheckpointAuditorsK.slice(1):checkpointAuditorsK.slice(1));
 b.entries[index].checkpointBytes=encodeOfflineWitnessHistoryCheckpoint(signCheckpoint(newBody,chosen));
 b.terminalAnchor=offlineWitnessHistoryAnchorCandidate(b.entries[index].checkpointBytes);
 return [a,b];
}
function splitAtRoot(){
 const a=ancestry(false),b=clone(a);
 const first=decodeOfflineWitnessHistoryCheckpoint(b.entries[0].checkpointBytes);
 b.entries[0].checkpointBytes=encodeOfflineWitnessHistoryCheckpoint(signCheckpoint({...first.body,issuedAt:first.body.issuedAt+1},checkpointAuditorsK.slice(1)));
 const newFirst=offlineWitnessHistoryAnchorCandidate(b.entries[0].checkpointBytes);
 const second=decodeOfflineWitnessHistoryCheckpoint(b.entries[1].checkpointBytes);
 b.entries[1].checkpointBytes=encodeOfflineWitnessHistoryCheckpoint(signCheckpoint({...second.body,previousCheckpointDigest:newFirst.checkpointDigest},checkpointAuditorsK.slice(1)));
 b.terminalAnchor=offlineWitnessHistoryAnchorCandidate(b.entries[1].checkpointBytes);
 return [a,b];
}
const splitBad=(name,change,code)=>test(name,()=>{
 const [a,b]=split();change(a,b);
 assert.throws(()=>compare(a,b),bad(code));
});

test('32J detects two authenticated conflicting siblings and overlapping Ed25519 signer',()=>{
 const [a,b]=split(),r=compare(a,b);
 assert.equal(r.schema,OFFLINE_WITNESS_SPLIT_VIEW_SCHEMA);
 assert.equal(r.status,'AUTHENTICATED_SPLIT_VIEW_DETECTED');
 assert.equal(r.forkDetected,true);assert.equal(r.sharedCheckpointCount,1);
 assert.equal(r.competingSuccessorsVerified,true);assert.equal(r.intersectionGuaranteed,true);
 assert.equal(r.conflict.minimumQuorumIntersection,1);
 assert.deepEqual(r.conflict.sharedAuditors.map(x=>x.auditorId),[checkpointAuditorsK[1].id]);
 assert.equal(r.conflict.kind,'CONFLICTING_CHECKPOINT_SIGNATURES');
 assert.notEqual(r.conflict.leftCheckpointDigest,r.conflict.rightCheckpointDigest);
 assert.equal(r.independentlyPublished,false);assert.equal(r.globalUniquenessVerified,false);
 assert.equal(r.authorizesCheckout,false);assert.equal(r.authorizesRemediation,false);assert.equal(r.productionApproved,false);
});
test('32J accepts identical independently supplied local observations without asserting independence',()=>{
 const a=ancestry(false),b=clone(a),r=compare(a,b);
 assert.equal(r.status,'IDENTICAL_AUTHENTICATED_PATH');assert.equal(r.forkDetected,false);
 assert.equal(r.sharedCheckpointCount,2);assert.equal(r.independentlyPublished,false);
});
test('32J classifies an authenticated shorter prefix as consistent extension',()=>{
 const a=ancestry(false),b=clone(a);
 b.entries=b.entries.slice(0,1);b.terminalAnchor=offlineWitnessHistoryAnchorCandidate(b.entries[0].checkpointBytes);
 const r=compare(a,b);assert.equal(r.status,'AUTHENTICATED_PREFIX_EXTENSION');
 assert.equal(r.sharedCheckpointCount,1);assert.equal(r.forkDetected,false);
});
test('32J prefix extension classification is symmetric',()=>{
 const a=ancestry(false),b=clone(a);
 b.entries=b.entries.slice(0,1);b.terminalAnchor=offlineWitnessHistoryAnchorCandidate(b.entries[0].checkpointBytes);
 const r=compare(b,a);assert.equal(r.status,'AUTHENTICATED_PREFIX_EXTENSION');
});
test('32J detects conflicting first successor of pinned root',()=>{
 const r=compare(...splitAtRoot());assert.equal(r.forkDetected,true);
 assert.equal(r.sharedCheckpointCount,0);assert.equal(r.conflict.atStartSequence,19);
 assert.equal(r.conflict.kind,'CONFLICTING_CHECKPOINT_SIGNATURES');
});
test('32J detects fork after a valid dual-majority auditor rotation',()=>{
 const r=compare(...split(true));assert.equal(r.forkDetected,true);
 assert.equal(r.intersectionGuaranteed,true);assert.equal(r.conflict.leftPolicyDigest,nextCheckpointPin);
 assert.equal(r.conflict.kind,'CONFLICTING_CHECKPOINT_SIGNATURES');
});
test('32J detects competing successor policies but does not claim same-policy signer intersection',()=>{
 const a=ancestry(true),b=ancestry(false),r=compare(a,b);
 assert.equal(r.forkDetected,true);assert.equal(r.intersectionGuaranteed,false);
 assert.equal(r.conflict.kind,'CONFLICTING_AUTHENTICATED_SUCCESSORS');
 assert.equal(r.conflict.minimumQuorumIntersection,0);
});
test('32J fork comparison is symmetric with stable digest evidence',()=>{
 const [a,b]=split(),forward=compare(a,b),reverse=compare(b,a);
 assert.equal(forward.forkDetected,reverse.forkDetected);
 assert.equal(forward.conflict.leftCheckpointDigest,reverse.conflict.rightCheckpointDigest);
 assert.equal(forward.conflict.rightCheckpointDigest,reverse.conflict.leftCheckpointDigest);
});
test('32J does not mutate caller-owned checkpoint bytes or pinned anchors',()=>{
 const [a,b]=split(),snap=a.entries.map(e=>Buffer.from(e.checkpointBytes)),terminal={...a.terminalAnchor};
 compare(a,b);assert.deepEqual(a.entries.map(e=>e.checkpointBytes),snap);assert.deepEqual(a.terminalAnchor,terminal);
});
test('32J freezes the report and its nested signer evidence',()=>{
 const r=compare(...split());assert.equal(Object.isFrozen(r),true);
 assert.equal(Object.isFrozen(r.conflict),true);assert.equal(Object.isFrozen(r.sharedSignerEvidence),true);
 assert.equal(Object.isFrozen(r.conflict.sharedAuditors[0]),true);
});
test('32J fails closed for missing inputs',()=>{
 assert.throws(()=>verifyOfflineWitnessCheckpointSplitView(),bad('SPLIT32J_INPUT_INVALID'));
 assert.throws(()=>verifyOfflineWitnessCheckpointSplitView({}),bad('SPLIT32J_INPUT_INVALID'));
});
test('32J rejects forged top-level production flags',()=>{
 const [a,b]=split();assert.throws(()=>verifyOfflineWitnessCheckpointSplitView({initialAnchor:a.initialAnchor,
 observations:[observation(a),observation(b)],productionApproved:true}),bad('SPLIT32J_INPUT_INVALID'));
});
test('32J requires exactly two independently supplied observations',()=>{
 const a=ancestry(false);
 for(const arr of [[],[observation(a)],[observation(a),observation(a),observation(a)]])
  assert.throws(()=>verifyOfflineWitnessCheckpointSplitView({initialAnchor:a.initialAnchor,observations:arr}),bad('SPLIT32J_TWO_OBSERVATIONS_REQUIRED'));
});
test('32J rejects sparse observation arrays without executing getters',()=>{
 const a=ancestry(false),arr=[observation(a),observation(a)];delete arr[0];
 assert.throws(()=>verifyOfflineWitnessCheckpointSplitView({initialAnchor:a.initialAnchor,observations:arr}),bad('SPLIT32J_TWO_OBSERVATIONS_REQUIRED'));
});
test('32J rejects accessor-bearing observation arrays before reading getter',()=>{
 const a=ancestry(false),arr=[observation(a),observation(a)];
 Object.defineProperty(arr,'1',{get(){throw Error('getter executed');},enumerable:true});
 assert.throws(()=>verifyOfflineWitnessCheckpointSplitView({initialAnchor:a.initialAnchor,observations:arr}),bad('SPLIT32J_TWO_OBSERVATIONS_REQUIRED'));
});
test('32J rejects accessor-bearing observation objects before reading getter',()=>{
 const a=ancestry(false),o=observation(a);
 Object.defineProperty(o,'terminalAnchor',{get(){throw Error('getter executed');},enumerable:true});
 assert.throws(()=>verifyOfflineWitnessCheckpointSplitView({initialAnchor:a.initialAnchor,observations:[o,observation(a)]}),bad('SPLIT32J_OBSERVATION_INVALID'));
});
test('32J rejects injected observation approval field',()=>{
 const a=ancestry(false),o={...observation(a),authorizesCheckout:true};
 assert.throws(()=>verifyOfflineWitnessCheckpointSplitView({initialAnchor:a.initialAnchor,observations:[o,observation(a)]}),bad('SPLIT32J_OBSERVATION_INVALID'));
});
splitBad('32J rejects forged terminal pin on one branch',(a,b)=>b.terminalAnchor={...b.terminalAnchor,checkpointDigest:sha('forged')}, 'ANCESTRY32I_TERMINAL_PIN_MISMATCH');
splitBad('32J rejects missing terminal pin on one branch',(a,b)=>delete b.terminalAnchor, 'ANCESTRY32I_EXTERNAL_ANCHORS_REQUIRED');
splitBad('32J rejects omitted intermediate checkpoint on one branch',(a,b)=>b.entries.shift(), 'ANCESTRY32I_WINDOW_CONTINUITY_INVALID');
splitBad('32J rejects missing witness receipt history evidence',(a,b)=>b.entries[1].historyArgs={...b.entries[1].historyArgs,entries:[]},'HISTORY32G_EXTERNAL_PINS_REQUIRED');
splitBad('32J rejects forged checkpoint signature even if terminal repinned',(a,b)=>{
 const c=decodeOfflineWitnessHistoryCheckpoint(b.entries[1].checkpointBytes);
 c.signatures[0].signature=sign(null,offlineWitnessHistoryCheckpointSigningBytes(c.body),reviewersK[0].privateKey).toString('base64url');
 b.entries[1].checkpointBytes=encodeOfflineWitnessHistoryCheckpoint(c);
 b.terminalAnchor=offlineWitnessHistoryAnchorCandidate(b.entries[1].checkpointBytes);
},'WITNESS32H_SIGNATURE_INVALID');
splitBad('32J rejects swapped receipt predecessor',(a,b)=>{
 const c=decodeOfflineWitnessHistoryCheckpoint(b.entries[1].checkpointBytes);
 b.entries[1].checkpointBytes=encodeOfflineWitnessHistoryCheckpoint(signCheckpoint({...c.body,previousReceiptDigest:sha('forged')}));
 b.terminalAnchor=offlineWitnessHistoryAnchorCandidate(b.entries[1].checkpointBytes);
},'ANCESTRY32I_WINDOW_CONTINUITY_INVALID');
splitBad('32J rejects missing signed policy transition',(a,b)=>{
 const rot=ancestry(true);b.entries[1]=rot.entries[1];b.terminalAnchor=rot.terminalAnchor;
 b.entries[1]={...b.entries[1],transition:null,expectedTransitionDigest:null};
},'ANCESTRY32I_TRANSITION_PIN_REQUIRED');
splitBad('32J rejects mismatched genesis root pin',(a,b)=>a.initialAnchor.genesisDigest=sha('forged'), 'ANCESTRY32I_TERMINAL_IDENTITY_OR_ROLLBACK');
splitBad('32J rejects stale signed terminal checkpoint',(a,b)=>{
 b.terminalAnchor={...b.terminalAnchor,sequence:18};
},'ANCESTRY32I_TERMINAL_IDENTITY_OR_ROLLBACK');

const alternateCheckpointAuditorsK=keys('alternate_checkpoint_auditor');
const alternateCheckpointAuditors=pub(alternateCheckpointAuditorsK);
const alternateCheckpointPin=offlineWitnessHistoryCheckpointAuditorPolicyDigest({auditors:alternateCheckpointAuditors,quorum:2});
function dualRotationFork(){
 const a=ancestry(true),b=clone(a),second=decodeOfflineWitnessHistoryCheckpoint(b.entries[1].checkpointBytes);
 const newBody={...second.body,auditorPolicyDigest:alternateCheckpointPin};
 b.entries[1].checkpointBytes=encodeOfflineWitnessHistoryCheckpoint(signCheckpoint(newBody,alternateCheckpointAuditorsK.slice(1)));
 b.entries[1].auditors=alternateCheckpointAuditors;
 b.entries[1].expectedAuditorPolicyDigest=alternateCheckpointPin;
 const t=b.entries[1].transition;
 t.body.newPolicyDigest=alternateCheckpointPin;
 const bytes=offlineWitnessCheckpointAuditorTransitionSigningBytes(t.body);
 t.outgoingSignatures=checkpointAuditorsK.slice(1).map(k=>({auditorId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}));
 t.incomingSignatures=alternateCheckpointAuditorsK.slice(1).map(k=>({auditorId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}));
 b.entries[1].expectedTransitionDigest=offlineWitnessCheckpointAuditorTransitionDigest(t);
 b.terminalAnchor=offlineWitnessHistoryAnchorCandidate(b.entries[1].checkpointBytes);
 return [a,b];
}
test('32J detects independently pinned conflicting dual-majority policy rotations',()=>{
 const r=compare(...dualRotationFork());
 assert.equal(r.forkDetected,true);assert.equal(r.intersectionGuaranteed,true);
 assert.equal(r.conflict.kind,'CONFLICTING_AUDITOR_TRANSITION_SIGNATURES');
 assert.equal(r.conflict.minimumQuorumIntersection,1);
 assert.deepEqual(r.conflict.sharedTransitionAuditorIds,[checkpointAuditorsK[1].id]);
 assert.equal(r.conflict.leftPolicyDigest,nextCheckpointPin);
 assert.equal(r.conflict.rightPolicyDigest,alternateCheckpointPin);
});
test('32J rejects forged outgoing signature on a conflicting policy rotation',()=>{
 const [a,b]=dualRotationFork();b.entries[1].transition.outgoingSignatures[0].signature=sign(null,
  offlineWitnessCheckpointAuditorTransitionSigningBytes(b.entries[1].transition.body),reviewersK[0].privateKey).toString('base64url');
 b.entries[1].expectedTransitionDigest=offlineWitnessCheckpointAuditorTransitionDigest(b.entries[1].transition);
 assert.throws(()=>compare(a,b),bad('ANCESTRY32I_TRANSITION_SIGNATURE_INVALID'));
});
test('32J rejects missing incoming majority on competing policy rotation',()=>{
 const [a,b]=dualRotationFork();b.entries[1].transition.incomingSignatures.pop();
 b.entries[1].expectedTransitionDigest=offlineWitnessCheckpointAuditorTransitionDigest(b.entries[1].transition);
 assert.throws(()=>compare(a,b),bad('ANCESTRY32I_TRANSITION_QUORUM_INVALID'));
});
