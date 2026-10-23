import {mkdtempSync,writeFileSync,readFileSync,truncateSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA} from '../../src/offline-pinned-orphan-classifier.mjs';
import {OFFLINE_ORPHAN_SUPERVISOR_DECISION_SCHEMA,offlineOrphanSupervisorPolicyDigest,
 offlineOrphanReportIssueDigest,offlineOrphanSupervisorDecisionSigningBytes,encodeOfflineOrphanReplaySnapshot} from '../../src/offline-orphan-supervisor-decision.mjs';
import {OFFLINE_SUPERVISOR_REPLAY_COMMIT_SCHEMA} from '../../src/offline-supervisor-replay-commit.mjs';
import {OFFLINE_REPLAY_HEAD_CHECKPOINT_SCHEMA,offlineReplayHeadAuditorPolicyDigest,offlineReplayHeadAuditHistoryDigest,
 offlineReplayHeadCheckpointSigningBytes,offlineReplayHeadCheckpointDigest} from '../../src/offline-supervisor-replay-checkpoint.mjs';
import {OFFLINE_PORTABLE_REPLAY_AUDIT_SCHEMA,OFFLINE_PORTABLE_REPLAY_WITNESS_SCHEMA,
 encodeOfflinePortableReplayAuditBundle,offlinePortableReplayAuditBundleDigest,offlinePortableReplayWitnessSigningBytes,
 offlinePortableReplayWitnessReceiptDigest,offlinePortableReplayWitnessPolicyDigest,verifyOfflinePortableReplayAuditBundle} from '../../src/offline-portable-replay-audit-bundle.mjs';
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
 offlinePortableReplayWitnessHistoryDigest,verifyOfflinePortableReplayWitnessHistory} from '../../src/offline-portable-replay-witness-history.mjs';
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
 verifyOfflineWitnessHistoryCheckpoint} from '../../src/offline-portable-witness-history-checkpoint.mjs';
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
 verifyOfflineWitnessCheckpointAncestry} from '../../src/offline-witness-checkpoint-ancestry.mjs';
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
 OFFLINE_SPLIT_VIEW_CONFLICT_PROOF_SCHEMA} from '../../src/offline-portable-split-view-conflict-proof.mjs';
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

export {make,conflictFixture,now};
