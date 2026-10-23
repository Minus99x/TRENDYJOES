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
const fails=code=>e=>e?.code===code;
const resign=(f,mut)=>{
 const body={...f.checkpoint.body};mut(body);
 const checkpoint=signCheckpoint(body),checkpointBytes=encodeOfflineWitnessHistoryCheckpoint(checkpoint);
 return {...f.args,checkpointBytes};
};
test('32H signed portable successor checkpoint verifies complete 32G witness evidence',()=>{
 const f=candidate(),r=verifyOfflineWitnessHistoryCheckpoint(f.args);
 assert.equal(r.verified,true);assert.equal(r.extendsSuppliedAnchor,true);assert.equal(r.anchoredMatch,false);
 assert.equal(r.independentlyPublished,false);assert.equal(r.authorizesCheckout,false);
});
test('32H independently supplied exact checkpoint pin verifies same-sequence anchor',()=>{
 const f=candidate(),anchor=offlineWitnessHistoryAnchorCandidate(f.checkpointBytes);
 const r=verifyOfflineWitnessHistoryCheckpoint({...f.args,anchor,expectedCandidateCheckpointDigest:anchor.checkpointDigest});
 assert.equal(r.anchoredMatch,true);assert.equal(r.candidateDigestPinned,true);
});
test('32H portable checkpoint canonical encode/decode/digest round-trip',()=>{
 const f=candidate(),parsed=decodeOfflineWitnessHistoryCheckpoint(f.checkpointBytes);
 assert.deepEqual(encodeOfflineWitnessHistoryCheckpoint(parsed),f.checkpointBytes);
 assert.equal(offlineWitnessHistoryCheckpointDigest(parsed),offlineWitnessHistoryCheckpointDigest(f.checkpointBytes));
});
test('32H rejects whitespace/noncanonical serialized checkpoint',()=>{
 const f=candidate();assert.throws(()=>decodeOfflineWitnessHistoryCheckpoint(Buffer.concat([f.checkpointBytes,Buffer.from(' ')])),fails('WITNESS32H_NONCANONICAL_ENCODING'));
});
test('32H rejects duplicate JSON property even when parse keeps the last',()=>{
 const f=candidate(),s=f.checkpointBytes.toString('utf8').replace('"schema":','"schema":"DUPLICATE", "schema":');
 assert.throws(()=>decodeOfflineWitnessHistoryCheckpoint(Buffer.from(s)),fails('WITNESS32H_NONCANONICAL_ENCODING'));
});
test('32H rejects invalid UTF8/JSON bytes',()=>{
 assert.throws(()=>decodeOfflineWitnessHistoryCheckpoint(Buffer.from('{bad')),fails('WITNESS32H_ENCODING_INVALID'));
});
test('32H rejects forged auditor signature',()=>{
 const f=candidate(),c=JSON.parse(f.checkpointBytes.toString());
 c.signatures[0].signature=sign(null,offlineWitnessHistoryCheckpointSigningBytes(c.body),witnessesK[0].privateKey).toString('base64url');
 assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint({...f.args,checkpointBytes:encodeOfflineWitnessHistoryCheckpoint(c)}),fails('WITNESS32H_SIGNATURE_INVALID'));
});
test('32H rejects minority auditor quorum',()=>{
 const f=candidate(),c=JSON.parse(f.checkpointBytes.toString());c.signatures.pop();
 assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint({...f.args,checkpointBytes:encodeOfflineWitnessHistoryCheckpoint(c)}),fails('WITNESS32H_QUORUM_INVALID'));
});
test('32H rejects duplicate auditor signer',()=>{
 const f=candidate(),c=JSON.parse(f.checkpointBytes.toString());c.signatures[1]={...c.signatures[0]};
 assert.throws(()=>encodeOfflineWitnessHistoryCheckpoint(c),fails('WITNESS32H_SIGNATURES_INVALID'));
});
test('32H rejects reordered auditor signatures',()=>{
 const f=candidate(),c=JSON.parse(f.checkpointBytes.toString());c.signatures.reverse();
 assert.throws(()=>encodeOfflineWitnessHistoryCheckpoint(c),fails('WITNESS32H_SIGNATURES_INVALID'));
});
test('32H rejects substituted auditor policy keys despite valid signatures',()=>{
 const f=candidate(),altered=[{...checkpointAuditors[0],publicKey:witnessesK[0].publicKey},...checkpointAuditors.slice(1)];
 assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint({...f.args,auditors:altered}),fails('WITNESS32H_AUDITOR_POLICY_PIN_MISMATCH'));
});
test('32H rejects reused auditor key under multiple IDs',()=>{
 const f=candidate(),altered=[checkpointAuditors[0],{...checkpointAuditors[1],publicKey:checkpointAuditors[0].publicKey},checkpointAuditors[2]];
 assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint({...f.args,auditors:altered}),fails('WITNESS32H_AUDITOR_POLICY_INVALID'));
});
test('32H rejects missing independent anchor',()=>{
 const f=candidate();assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint({...f.args,anchor:undefined}),fails('WITNESS32H_EXTERNAL_ANCHOR_REQUIRED'));
});
test('32H rejects forged external anchor registry',()=>{
 const f=candidate();assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint({...f.args,anchor:{...f.anchor,registryId:'forged_registry_32h'}}),fails('WITNESS32H_ANCHOR_IDENTITY_MISMATCH'));
});
test('32H rejects anchor genesis substitution',()=>{
 const f=candidate();assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint({...f.args,anchor:{...f.anchor,genesisDigest:sha('wrong-genesis')}}),fails('WITNESS32H_ANCHOR_IDENTITY_MISMATCH'));
});
test('32H rejects stale signed checkpoint behind external anchor',()=>{
 const f=candidate();assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint({...f.args,anchor:{...f.anchor,sequence:22}}),fails('WITNESS32H_STALE_CHECKPOINT'));
});
test('32H rejects same-sequence independently pinned fork even with valid signatures',()=>{
 const f=candidate();assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint({...f.args,anchor:{...f.anchor,sequence:21,headReceiptDigest:sha('fork'),checkpointDigest:sha('other-checkpoint')}}),fails('WITNESS32H_ANCHORED_FORK'));
});
test('32H rejects alternate correctly signed same-sequence candidate',()=>{
 const f=candidate(),anchor=offlineWitnessHistoryAnchorCandidate(f.checkpointBytes);
 const args=resign(f,b=>b.issuedAt++);
 assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint({...args,anchor}),fails('WITNESS32H_ANCHORED_FORK'));
});
test('32H rejects gap from external anchor',()=>{
 const f=candidate();assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint({...f.args,anchor:{...f.anchor,sequence:17}}),fails('WITNESS32H_ANCHOR_CONTINUITY_INVALID'));
});
test('32H rejects wrong predecessor checkpoint pin',()=>{
 const f=candidate(),args=resign(f,b=>b.previousCheckpointDigest=sha('fake'));
 assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint(args),fails('WITNESS32H_ANCHOR_CONTINUITY_INVALID'));
});
test('32H rejects wrong previous witness receipt pin',()=>{
 const f=candidate(),args=resign(f,b=>b.previousReceiptDigest=sha('fake'));
 assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint(args),fails('WITNESS32H_HISTORY_BINDING_INVALID'));
});
test('32H rejects backwards signed checkpoint time versus anchor',()=>{
 const f=candidate(),args=resign(f,b=>b.issuedAt=now);
 assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint(args),fails('WITNESS32H_TIMESTAMP_ROLLBACK'));
});
test('32H rejects altered candidate external digest pin',()=>{
 const f=candidate();assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint({...f.args,expectedCandidateCheckpointDigest:sha('fork')}),fails('WITNESS32H_CANDIDATE_PIN_MISMATCH'));
});
test('32H rejects forged historical witness evidence despite authentic checkpoint',()=>{
 const f=candidate(),args=mutate(f.f,a=>a.entries[1].verificationArgs.bundleBytes=Buffer.from('{}'));
 assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint({...f.args,historyArgs:args}),fails('PORTABLE32F_EXTERNAL_BUNDLE_PIN_REQUIRED'));
});
test('32H rejects omitted historical receipt',()=>{
 const f=candidate(),args=mutate(f.f,a=>a.entries.pop());
 assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint({...f.args,historyArgs:args}),fails('HISTORY32G_EXTERNAL_PINS_REQUIRED'));
});
test('32H rejects recomputed history digest without signed checkpoint binding',()=>{
 const f=candidate(),args=mutate(f.f,a=>a.expectedHistoryDigest=sha('new-local-history'));
 assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint({...f.args,historyArgs:args}),fails('WITNESS32H_HISTORY_BINDING_INVALID'));
});
test('32H refuses production/independent-publication assertions',()=>{
 const f=candidate(),r=verifyOfflineWitnessHistoryCheckpoint(f.args);
 for(const key of ['independentlyPublished','externalPinPublicationVerified','trustedTimestampVerified','fullGenesisHistoryVerified','authorizesRemediation','authorizesCheckout','productionApproved'])assert.equal(r[key],false);
});

test('32H rejects accessor-bearing and sparse signature arrays before encoding',()=>{
 const f=candidate(),c=JSON.parse(f.checkpointBytes.toString());
 Object.defineProperty(c.signatures,'0',{get(){throw new Error('untrusted getter');},enumerable:true});
 assert.throws(()=>encodeOfflineWitnessHistoryCheckpoint(c),fails('WITNESS32H_SIGNATURES_INVALID'));
 const d=JSON.parse(f.checkpointBytes.toString());delete d.signatures[0];
 assert.throws(()=>encodeOfflineWitnessHistoryCheckpoint(d),fails('WITNESS32H_SIGNATURES_INVALID'));
});
test('32H rejects unexpected checkpoint and body fields',()=>{
 const f=candidate(),c=JSON.parse(f.checkpointBytes.toString());c.productionApproved=true;
 assert.throws(()=>encodeOfflineWitnessHistoryCheckpoint(c),fails('WITNESS32H_CHECKPOINT_INVALID'));
 const d=JSON.parse(f.checkpointBytes.toString());d.body.authorizesCheckout=true;
 assert.throws(()=>encodeOfflineWitnessHistoryCheckpoint(d),fails('WITNESS32H_BODY_INVALID'));
});
test('32H detects interrupted/truncated portable checkpoint file without writing or recovery',()=>{
 const f=candidate(),dir=mkdtempSync(join(tmpdir(),'tj-32h-readonly-'));
 try{
  const file=join(dir,'checkpoint.json');writeFileSync(file,f.checkpointBytes,{mode:0o600});
  const intact=readFileSync(file);assert.equal(verifyOfflineWitnessHistoryCheckpoint({...f.args,checkpointBytes:intact}).verified,true);
  truncateSync(file,Math.floor(f.checkpointBytes.length/2));
  assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint({...f.args,checkpointBytes:readFileSync(file)}),fails('WITNESS32H_ENCODING_INVALID'));
  assert.equal(readFileSync(file).length,Math.floor(f.checkpointBytes.length/2));
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test('32H detects locally substituted valid but stale checkpoint against retained anchor',()=>{
 const f=candidate(),dir=mkdtempSync(join(tmpdir(),'tj-32h-swap-'));
 try{
  const file=join(dir,'checkpoint.json'),anchored=offlineWitnessHistoryAnchorCandidate(f.checkpointBytes);
  writeFileSync(file,f.checkpointBytes,{mode:0o600});
  assert.equal(verifyOfflineWitnessHistoryCheckpoint({...f.args,anchor:anchored,checkpointBytes:readFileSync(file)}).verified,true);
  const alternate=resign(f,b=>b.issuedAt+=5);
  writeFileSync(file,alternate.checkpointBytes);
  assert.throws(()=>verifyOfflineWitnessHistoryCheckpoint({...f.args,anchor:anchored,checkpointBytes:readFileSync(file)}),fails('WITNESS32H_ANCHORED_FORK'));
 }finally{rmSync(dir,{recursive:true,force:true});}
});
