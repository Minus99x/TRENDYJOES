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
const testMutation=(name,mut,code)=>test(name,()=>{
 const a=clone(ancestry());mut(a);assert.throws(()=>verifyOfflineWitnessCheckpointAncestry(a),bad(code));
});
test('32I verifies complete 32G evidence in two consecutive signed checkpoint windows with auditor dual-majority rotation',()=>{
 const r=verifyOfflineWitnessCheckpointAncestry(ancestry());assert.equal(r.verified,true);
 assert.equal(r.windowCount,2);assert.equal(r.rotationCount,1);assert.equal(r.firstSequence,19);assert.equal(r.lastSequence,21);
 assert.equal(r.suppliedTerminalPinMatched,true);assert.equal(r.independentlyPublished,false);
 assert.equal(r.authorizesCheckout,false);assert.equal(r.productionApproved,false);
});
test('32I verifies two consecutive checkpoints without auditor rotation',()=>{
 const r=verifyOfflineWitnessCheckpointAncestry(ancestry(false));assert.equal(r.rotationCount,0);assert.equal(r.windowCount,2);
});
testMutation('32I requires independently supplied initial anchor',a=>delete a.initialAnchor,'ANCESTRY32I_EXTERNAL_ANCHORS_REQUIRED');
testMutation('32I requires independently supplied terminal anchor',a=>delete a.terminalAnchor,'ANCESTRY32I_EXTERNAL_ANCHORS_REQUIRED');
testMutation('32I detects independently pinned terminal fork',a=>a.terminalAnchor.checkpointDigest=sha('fork'),'ANCESTRY32I_TERMINAL_PIN_MISMATCH');
testMutation('32I detects terminal sequence rollback',a=>a.terminalAnchor.sequence=18,'ANCESTRY32I_TERMINAL_IDENTITY_OR_ROLLBACK');
testMutation('32I detects terminal head substitution',a=>a.terminalAnchor.headReceiptDigest=sha('fork'),'ANCESTRY32I_TERMINAL_PIN_MISMATCH');
testMutation('32I detects terminal policy substitution',a=>a.terminalAnchor.auditorPolicyDigest=checkpointPolicyPin,'ANCESTRY32I_TERMINAL_PIN_MISMATCH');
testMutation('32I detects terminal timestamp substitution',a=>a.terminalAnchor.issuedAt+=1,'ANCESTRY32I_TERMINAL_PIN_MISMATCH');
testMutation('32I rejects omitted intermediate signed checkpoint',a=>a.entries.shift(),'ANCESTRY32I_WINDOW_CONTINUITY_INVALID');
testMutation('32I rejects omitted final signed checkpoint',a=>a.entries.pop(),'ANCESTRY32I_TERMINAL_PIN_MISMATCH');
testMutation('32I rejects reordered checkpoints',a=>a.entries.reverse(),'ANCESTRY32I_WINDOW_CONTINUITY_INVALID');
testMutation('32I rejects replayed checkpoint as second window',a=>a.entries[1]={...a.entries[0]},'ANCESTRY32I_WINDOW_CONTINUITY_INVALID');
testMutation('32I rejects missing auditor rotation authorization',a=>a.entries[1].transition=null,'ANCESTRY32I_TRANSITION_PIN_REQUIRED');
testMutation('32I rejects missing independent transition digest pin',a=>a.entries[1].expectedTransitionDigest=null,'ANCESTRY32I_TRANSITION_PIN_REQUIRED');
testMutation('32I rejects forged transition digest pin',a=>a.entries[1].expectedTransitionDigest=sha('other'),'ANCESTRY32I_TRANSITION_PIN_REQUIRED');
testMutation('32I rejects tampered transition predecessor checkpoint',a=>a.entries[1].transition.body.previousCheckpointDigest=sha('other'),'ANCESTRY32I_TRANSITION_PIN_REQUIRED');
testMutation('32I rejects validly signed transition for wrong previous receipt',a=>{
 const t=a.entries[1].transition;t.body.previousReceiptDigest=sha('other');
 const bytes=offlineWitnessCheckpointAuditorTransitionSigningBytes(t.body);
 t.outgoingSignatures=checkpointAuditorsK.slice(0,2).map(k=>({auditorId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}));
 t.incomingSignatures=nextCheckpointAuditorsK.slice(0,2).map(k=>({auditorId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}));
 a.entries[1].expectedTransitionDigest=offlineWitnessCheckpointAuditorTransitionDigest(t);
},'ANCESTRY32I_TRANSITION_BINDING_INVALID');
testMutation('32I rejects minority outgoing quorum',a=>{
 const t=a.entries[1].transition;t.outgoingSignatures.pop();
 a.entries[1].expectedTransitionDigest=offlineWitnessCheckpointAuditorTransitionDigest(t);
},'ANCESTRY32I_TRANSITION_QUORUM_INVALID');
testMutation('32I rejects minority incoming quorum',a=>{
 const t=a.entries[1].transition;t.incomingSignatures.pop();
 a.entries[1].expectedTransitionDigest=offlineWitnessCheckpointAuditorTransitionDigest(t);
},'ANCESTRY32I_TRANSITION_QUORUM_INVALID');
testMutation('32I rejects forged outgoing signature',a=>{
 const t=a.entries[1].transition;t.outgoingSignatures[0].signature=sign(null,offlineWitnessCheckpointAuditorTransitionSigningBytes(t.body),nextCheckpointAuditorsK[0].privateKey).toString('base64url');
 a.entries[1].expectedTransitionDigest=offlineWitnessCheckpointAuditorTransitionDigest(t);
},'ANCESTRY32I_TRANSITION_SIGNATURE_INVALID');
testMutation('32I rejects forged incoming signature',a=>{
 const t=a.entries[1].transition;t.incomingSignatures[0].signature=sign(null,offlineWitnessCheckpointAuditorTransitionSigningBytes(t.body),checkpointAuditorsK[0].privateKey).toString('base64url');
 a.entries[1].expectedTransitionDigest=offlineWitnessCheckpointAuditorTransitionDigest(t);
},'ANCESTRY32I_TRANSITION_SIGNATURE_INVALID');
testMutation('32I rejects duplicate transition signer',a=>{
 const t=a.entries[1].transition;t.incomingSignatures[1]={...t.incomingSignatures[0]};
},'ANCESTRY32I_TRANSITION_SIGNATURES_INVALID');
testMutation('32I rejects auditor policy digest mismatch',a=>a.entries[1].expectedAuditorPolicyDigest=sha('wrong'),'ANCESTRY32I_AUDITOR_POLICY_PIN_MISMATCH');
testMutation('32I rejects altered auditor public key',a=>a.entries[1].auditors=[{...a.entries[1].auditors[0],publicKey:checkpointAuditorsK[0].publicKey},...a.entries[1].auditors.slice(1)],'ANCESTRY32I_AUDITOR_POLICY_PIN_MISMATCH');
testMutation('32I rejects forged checkpoint signatures despite valid transition',a=>{
 const c=decodeOfflineWitnessHistoryCheckpoint(a.entries[1].checkpointBytes);
 c.signatures[0].signature=sign(null,offlineWitnessHistoryCheckpointSigningBytes(c.body),checkpointAuditorsK[0].privateKey).toString('base64url');
 a.entries[1].checkpointBytes=encodeOfflineWitnessHistoryCheckpoint(c);
},'WITNESS32H_SIGNATURE_INVALID');
testMutation('32I rejects forged underlying witness evidence',a=>a.entries[1].historyArgs={...a.entries[1].historyArgs,
 entries:a.entries[1].historyArgs.entries.map(e=>({...e,verificationArgs:{...e.verificationArgs,bundleBytes:Buffer.from('{}')}}))},'PORTABLE32F_EXTERNAL_BUNDLE_PIN_REQUIRED');
testMutation('32I rejects missing witness history receipt',a=>a.entries[0].historyArgs={...a.entries[0].historyArgs,entries:a.entries[0].historyArgs.entries.slice(1)},'HISTORY32G_EXTERNAL_PINS_REQUIRED');
testMutation('32I rejects unpinned local re-sign of checkpoint',a=>{
 const c=decodeOfflineWitnessHistoryCheckpoint(a.entries[1].checkpointBytes),b={...c.body,issuedAt:c.body.issuedAt+1};
 const signed=signCheckpoint(b,nextCheckpointAuditorsK.slice(0,2));
 a.entries[1].checkpointBytes=encodeOfflineWitnessHistoryCheckpoint(signed);
},'ANCESTRY32I_TERMINAL_PIN_MISMATCH');
test('32I refuses unexpected transition without policy change',()=>{
 const a=ancestry(false);a.entries[1].transition=ancestry().entries[1].transition;
 a.entries[1].expectedTransitionDigest=offlineWitnessCheckpointAuditorTransitionDigest(a.entries[1].transition);
 assert.throws(()=>verifyOfflineWitnessCheckpointAncestry(a),bad('ANCESTRY32I_UNEXPECTED_TRANSITION'));
});
test('32I rejects sparse entries without invoking accessors',()=>{
 const a=ancestry();delete a.entries[0];assert.throws(()=>verifyOfflineWitnessCheckpointAncestry(a),bad('ANCESTRY32I_ENTRIES_INVALID'));
});
test('32I rejects accessor-bearing transition signer arrays',()=>{
 const a=ancestry(),s=a.entries[1].transition.incomingSignatures;
 Object.defineProperty(s,'0',{get(){throw new Error('untrusted getter');},enumerable:true});
 assert.throws(()=>verifyOfflineWitnessCheckpointAncestry(a),bad('ANCESTRY32I_TRANSITION_SIGNATURES_INVALID'));
});
test('32I refuses self-declared production flags in transition',()=>{
 const a=ancestry();a.entries[1].transition.body.productionApproved=true;
 assert.throws(()=>verifyOfflineWitnessCheckpointAncestry(a),bad('ANCESTRY32I_TRANSITION_BODY_INVALID'));
});
testMutation('32I rejects signed auditor rotation with overlapping old/new keys',a=>{
 const old=a.entries[0].auditors,oldK=checkpointAuditorsK;
 const mixedK=[oldK[0],nextCheckpointAuditorsK[1],nextCheckpointAuditorsK[2]];
 const mixed=pub(mixedK),mixedPin=offlineWitnessHistoryCheckpointAuditorPolicyDigest({auditors:mixed,quorum:2});
 const c=decodeOfflineWitnessHistoryCheckpoint(a.entries[1].checkpointBytes);
 const body={...c.body,auditorPolicyDigest:mixedPin};
 const bytes=offlineWitnessHistoryCheckpointSigningBytes(body);
 const signers=mixedK.slice().sort((x,y)=>x.id.localeCompare(y.id)).slice(0,2);
 a.entries[1].checkpointBytes=encodeOfflineWitnessHistoryCheckpoint({body,signatures:signers.map(k=>({auditorId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}))});
 a.entries[1].auditors=mixed;a.entries[1].expectedAuditorPolicyDigest=mixedPin;
 const t=a.entries[1].transition;t.body.newPolicyDigest=mixedPin;
 const tb=offlineWitnessCheckpointAuditorTransitionSigningBytes(t.body);
 t.outgoingSignatures=oldK.slice(0,2).map(k=>({auditorId:k.id,signature:sign(null,tb,k.privateKey).toString('base64url')}));
 t.incomingSignatures=signers.map(k=>({auditorId:k.id,signature:sign(null,tb,k.privateKey).toString('base64url')}));
 a.entries[1].expectedTransitionDigest=offlineWitnessCheckpointAuditorTransitionDigest(t);
 a.terminalAnchor=offlineWitnessHistoryAnchorCandidate(a.entries[1].checkpointBytes);
},'ANCESTRY32I_ROTATION_KEY_REUSE');
testMutation('32I rejects future-dated transition relative to signed successor checkpoint',a=>{
 const t=a.entries[1].transition;t.body.issuedAt=now+15000;
 const bytes=offlineWitnessCheckpointAuditorTransitionSigningBytes(t.body);
 t.outgoingSignatures=checkpointAuditorsK.slice(0,2).map(k=>({auditorId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}));
 t.incomingSignatures=nextCheckpointAuditorsK.slice(0,2).map(k=>({auditorId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}));
 a.entries[1].expectedTransitionDigest=offlineWitnessCheckpointAuditorTransitionDigest(t);
},'ANCESTRY32I_TRANSITION_BINDING_INVALID');
testMutation('32I rejects substituted root identity',a=>a.initialAnchor.registryId='forged_registry_32i','ANCESTRY32I_TERMINAL_IDENTITY_OR_ROLLBACK');
testMutation('32I rejects extra arbitrary field on signed transition',a=>a.entries[1].transition.auditApproved=true,'ANCESTRY32I_TRANSITION_INVALID');
