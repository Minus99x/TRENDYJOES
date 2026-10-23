import test from 'node:test';
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
test('32G three linked signed receipts verify through old/new witness policy quorums',()=>{
 const r=verifyOfflinePortableReplayWitnessHistory(historyFixture().args);
 assert.equal(r.verified,true);assert.equal(r.entryCount,3);assert.equal(r.policyEpochs,2);
 assert.equal(r.fullGenesisHistoryVerified,false);assert.equal(r.independentlyPublished,false);
 assert.equal(r.authorizesCheckout,false);assert.equal(r.authorizesRemediation,false);
});
test('32G same-policy three-receipt history remains supported',()=>{
 assert.equal(verifyOfflinePortableReplayWitnessHistory(historyFixture(false).args).policyEpochs,1);
});
test('32G refuses missing independently supplied head',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory({...f.args,expectedHeadReceiptDigest:undefined}),err('HISTORY32G_EXTERNAL_PINS_REQUIRED'));
});
test('32G rejects wrong final head even if local history digest unchanged',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory({...f.args,expectedHeadReceiptDigest:sha('fork')}),err('HISTORY32G_HEAD_PIN_MISMATCH'));
});
test('32G rejects wrong externally pinned history digest',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory({...f.args,expectedHistoryDigest:sha('fork')}),err('HISTORY32G_HISTORY_PIN_MISMATCH'));
});
test('32G refuses omitted final receipt with pinned expected count',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>a.entries.pop())),err('HISTORY32G_EXTERNAL_PINS_REQUIRED'));
});
test('32G refuses omitted middle receipt despite recomputed local array',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>{a.entries.splice(1,1);a.expectedEndSequence=20;})),err('HISTORY32G_CHAIN_INVALID'));
});
test('32G refuses reordered receipt history',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>a.entries.reverse())),err('HISTORY32G_CHAIN_INVALID'));
});
test('32G refuses duplicate receipt substituted into next position',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>a.entries[1]=a.entries[0])),err('HISTORY32G_CHAIN_INVALID'));
});
test('32G rejects missing predecessor anchor',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory({...f.args,expectedInitialPreviousReceiptDigest:sha('fake')}),err('HISTORY32G_CHAIN_INVALID'));
});
test('32G rejects sequence gap and rollback',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>a.entries[1].verificationArgs.expectedWitnessSequence=21)),err('HISTORY32G_CHAIN_INVALID'));
});
test('32G rejects swapped registry',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory({...f.args,registryId:'wrong_registry_32g'}),err('HISTORY32G_CHAIN_INVALID'));
});
test('32G rejects swapped independent genesis pin',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory({...f.args,expectedGenesisDigest:sha('other-genesis')}),err('HISTORY32G_CHAIN_INVALID'));
});
test('32G rejects missing witness transition on epoch change',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>a.policies[1].transition=null)),err('HISTORY32G_TRANSITION_PIN_MISMATCH'));
});
test('32G rejects altered transition external pin',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>a.policies[1].expectedTransitionDigest=sha('fork'))),err('HISTORY32G_TRANSITION_PIN_MISMATCH'));
});
test('32G rejects policy transition previous receipt substitution',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>{a.policies[1].transition.body.previousReceiptDigest=sha('fake');a.policies[1].expectedTransitionDigest=offlinePortableReplayWitnessTransitionDigest(a.policies[1].transition);})),err('HISTORY32G_TRANSITION_BINDING_INVALID'));
});
test('32G rejects policy transition at wrong sequence',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>{a.policies[1].transition.body.atSequence=20;a.policies[1].expectedTransitionDigest=offlinePortableReplayWitnessTransitionDigest(a.policies[1].transition);})),err('HISTORY32G_TRANSITION_BINDING_INVALID'));
});
test('32G rejects transition after first incoming receipt timestamp',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>{a.policies[1].transition.body.issuedAt=now+11000;a.policies[1].expectedTransitionDigest=offlinePortableReplayWitnessTransitionDigest(a.policies[1].transition);})),err('HISTORY32G_TRANSITION_BINDING_INVALID'));
});
test('32G rejects transition before last outgoing receipt timestamp',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>{a.policies[1].transition.body.issuedAt=now+7500;a.policies[1].expectedTransitionDigest=offlinePortableReplayWitnessTransitionDigest(a.policies[1].transition);})),err('HISTORY32G_TRANSITION_BINDING_INVALID'));
});
test('32G rejects forged outgoing transition quorum signature',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>{a.policies[1].transition.outgoingSignatures[0].signature=sign(null,offlinePortableReplayWitnessTransitionSigningBytes(a.policies[1].transition.body),nextWitnessK[0].privateKey).toString('base64url');a.policies[1].expectedTransitionDigest=offlinePortableReplayWitnessTransitionDigest(a.policies[1].transition);})),err('HISTORY32G_TRANSITION_SIGNATURE_INVALID'));
});
test('32G rejects forged incoming key-possession signature',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>{a.policies[1].transition.incomingSignatures[0].signature=sign(null,offlinePortableReplayWitnessTransitionSigningBytes(a.policies[1].transition.body),witnessesK[0].privateKey).toString('base64url');a.policies[1].expectedTransitionDigest=offlinePortableReplayWitnessTransitionDigest(a.policies[1].transition);})),err('HISTORY32G_TRANSITION_SIGNATURE_INVALID'));
});
test('32G rejects minority outgoing transition quorum',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>{a.policies[1].transition.outgoingSignatures.pop();a.policies[1].expectedTransitionDigest=offlinePortableReplayWitnessTransitionDigest(a.policies[1].transition);})),err('HISTORY32G_TRANSITION_QUORUM_INVALID'));
});
test('32G rejects duplicate incoming transition signer',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>{a.policies[1].transition.incomingSignatures[1]={...a.policies[1].transition.incomingSignatures[0]};a.policies[1].expectedTransitionDigest=offlinePortableReplayWitnessTransitionDigest(a.policies[1].transition);})),err('HISTORY32G_TRANSITION_SIGNATURE_INVALID'));
});
test('32G rejects swapped incoming witness policy key',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>a.policies[1].witnesses=[{...a.policies[1].witnesses[0],publicKey:witnessesK[0].publicKey},...a.policies[1].witnesses.slice(1)])),err('HISTORY32G_POLICY_PIN_MISMATCH'));
});
test('32G rejects shared outgoing/incoming witness keys',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>{
  const mixed=[witnesses[0],nextWitnesses[1],nextWitnesses[2]];
  a.policies[1].witnesses=mixed;a.policies[1].expectedPolicyDigest=offlinePortableReplayWitnessPolicyDigest({witnesses:mixed,quorum:2});
  a.policies[1].transition.body.newPolicyDigest=a.policies[1].expectedPolicyDigest;
  a.policies[1].expectedTransitionDigest=offlinePortableReplayWitnessTransitionDigest(a.policies[1].transition);
 })),err('HISTORY32G_ROTATION_KEY_REUSE'));
});
test('32G rejects policy epoch skip',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>a.entries[1].policyIndex=1)),err('HISTORY32G_TRANSITION_BINDING_INVALID'));
});
test('32G rejects unused extra epoch',()=>{
 const f=historyFixture(false);assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>a.policies.push({...a.policies[0]}))),err('HISTORY32G_UNUSED_POLICY_INVALID'));
});
test('32G rejects mismatched witness policy binding for receipt',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>a.entries[2].verificationArgs.expectedWitnessPolicyDigest=witnessPin)),err('HISTORY32G_POLICY_BINDING_INVALID'));
});
test('32G rejects forged witness signature in middle receipt',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>{
  const old=a.entries[1].verificationArgs.witnessReceipt;
  a.entries[1].verificationArgs.witnessReceipt={...old,signatures:old.signatures.map(x=>({...x}))};
  a.entries[1].verificationArgs.witnessReceipt.signatures[0].signature=sign(null,offlinePortableReplayWitnessSigningBytes(old.body),nextWitnessK[0].privateKey).toString('base64url');
  a.entries[1].verificationArgs.expectedWitnessReceiptDigest=offlinePortableReplayWitnessReceiptDigest(a.entries[1].verificationArgs.witnessReceipt);
 })),err('PORTABLE32F_WITNESS_SIGNATURE_INVALID'));
});
test('32G refuses mutation of historical audit bundle',()=>{
 const f=historyFixture();assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>a.entries[1].verificationArgs.bundleBytes=Buffer.from('{}'))),err('PORTABLE32F_EXTERNAL_BUNDLE_PIN_REQUIRED'));
});
test('32G rejects unpinned policy migration and extra transition fields',()=>{
 const f=historyFixture();assert.throws(()=>offlinePortableReplayWitnessTransitionSigningBytes({...f.args.policies[1].transition.body,authorizeProduction:true}),err('HISTORY32G_TRANSITION_BODY_INVALID'));
});
test('32G rejects malformed history digest records',()=>{
 assert.throws(()=>offlinePortableReplayWitnessHistoryDigest({registryId,initialPreviousReceiptDigest:ZERO,records:[{sequence:1,receiptDigest:ZERO,policyDigest:ZERO,transitionDigest:null,extra:true}]}),err('HISTORY32G_DIGEST_INPUT_INVALID'));
});
test('32G bounded windows cannot claim independently published genesis history',()=>{
 const f=historyFixture(),r=verifyOfflinePortableReplayWitnessHistory(f.args);
 assert.equal(r.startSequence,19);assert.equal(r.fullGenesisHistoryVerified,false);assert.equal(r.externalPinPublicationVerified,false);
 assert.equal(r.trustedTimestampVerified,false);assert.equal(r.productionApproved,false);
});
test('32G rejects correctly signed but backwards receipt observation time',()=>{
 const f=historyFixture(false);
 assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>{
  const v=a.entries[1].verificationArgs,body={...v.witnessReceipt.body,issuedAt:now+6000};
  v.witnessReceipt=witnessReceipt(body);v.expectedWitnessReceiptDigest=offlinePortableReplayWitnessReceiptDigest(v.witnessReceipt);
 })),err('HISTORY32G_ROLLBACK_OR_TIME_INVALID'));
});
test('32G rejects a re-signed fork in the middle even with valid quorum',()=>{
 const f=historyFixture(false);
 assert.throws(()=>verifyOfflinePortableReplayWitnessHistory(mutate(f,a=>{
  const v=a.entries[1].verificationArgs,body={...v.witnessReceipt.body,issuedAt:now+9000};
  v.witnessReceipt=witnessReceipt(body);v.expectedWitnessReceiptDigest=offlinePortableReplayWitnessReceiptDigest(v.witnessReceipt);
 })),err('HISTORY32G_CHAIN_INVALID'));
});
