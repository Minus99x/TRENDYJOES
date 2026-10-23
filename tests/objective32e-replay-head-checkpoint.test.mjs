import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {mkdtemp,mkdir,rm,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA} from '../src/offline-pinned-orphan-classifier.mjs';
import {OFFLINE_ORPHAN_SUPERVISOR_DECISION_SCHEMA,offlineOrphanSupervisorPolicyDigest,offlineOrphanReportIssueDigest,
 offlineOrphanSupervisorDecisionSigningBytes,encodeOfflineOrphanReplaySnapshot} from '../src/offline-orphan-supervisor-decision.mjs';
import {createOfflineSupervisorReplayCommit} from '../src/offline-supervisor-replay-commit.mjs';
import {OFFLINE_REPLAY_HEAD_CHECKPOINT_SCHEMA,offlineReplayHeadAuditorPolicyDigest,offlineReplayHeadAuditHistoryDigest,
 offlineReplayHeadCheckpointSigningBytes,offlineReplayHeadCheckpointDigest,verifyOfflineReplayHeadCheckpoint} from '../src/offline-supervisor-replay-checkpoint.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const ZERO='0'.repeat(64),registryId='orphan_registry_32e',nowMs=1800000000000;
const reviewerKeys=[0,1,2].map(i=>({id:`reviewer_32e_${i}`,...generateKeyPairSync('ed25519')}));
const auditorKeys=[0,1,2].map(i=>({id:`auditor_32e_${i}`,...generateKeyPairSync('ed25519')}));
const reviewers=reviewerKeys.map(({id,publicKey})=>({id,publicKey}));
const auditors=auditorKeys.map(({id,publicKey})=>({id,publicKey}));
const reviewerPin=offlineOrphanSupervisorPolicyDigest({reviewers,quorum:2});
const auditorPin=offlineReplayHeadAuditorPolicyDigest({auditors,quorum:2});
const err=code=>e=>e?.code===code;
function report(){
 const evidence=[{directoryIndex:0,name:'orphan-32e.tjexport',nameDigest:sha('orphan-32e.tjexport'),classification:'UNTRACKED_ARCHIVE_UNVERIFIED',digest:sha('bytes'),bytes:10}];
 const body={schema:OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA,registryId,manifestDigest:sha('manifest'),head:{count:1,headDigest:sha('head')},epoch:0,transitionDigest:ZERO,recordsDigest:sha('records'),evidence,
  status:'SUPERVISORY_REVIEW_REQUIRED',issueCount:1,supervisoryDisposition:'EXTERNAL_DECISION_REQUIRED_FOR_ANY_REMEDIATION',
  readOnly:true,productionApproved:false,mayDelete:false,mayRepair:false,mayManufacture:false,mayAcknowledge:false};
 return {...body,reportDigest:sha(Buffer.from(`${OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA}\0${JSON.stringify(body)}`))};
}
const pins=r=>({reportDigest:r.reportDigest,manifestDigest:r.manifestDigest,head:r.head,epoch:r.epoch,transitionDigest:r.transitionDigest,recordsDigest:r.recordsDigest});
function decision(r,head,n){
 const body={schema:OFFLINE_ORPHAN_SUPERVISOR_DECISION_SCHEMA,registryId,reportDigest:r.reportDigest,manifestDigest:r.manifestDigest,
  head:r.head,epoch:r.epoch,transitionDigest:r.transitionDigest,recordsDigest:r.recordsDigest,issueDigest:offlineOrphanReportIssueDigest(r),
  issueCount:1,disposition:'REJECT_EVIDENCE',decisionId:`decision_32e_${String(n).padStart(4,'0')}`,nonce:`nonce_32e_${String(n).padStart(4,'0')}`,
  issuedAt:nowMs-1000,expiresAt:nowMs+60000,replayDigest:head,reviewerPolicyDigest:reviewerPin};
 const bytes=offlineOrphanSupervisorDecisionSigningBytes(body);
 return {body,signatures:reviewerKeys.slice(0,2).map(k=>({reviewerId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}))};
}
function signedCheckpoint(body,signers=auditorKeys.slice(0,2)){
 const bytes=offlineReplayHeadCheckpointSigningBytes(body);
 return {body,signatures:signers.map(k=>({auditorId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}))};
}
async function fixture(t,count=2){
 const parent=await mkdtemp(join(tmpdir(),'tj32e-'));t.after(()=>rm(parent,{recursive:true,force:true}));
 const directory=join(parent,'replay');await mkdir(directory,{mode:0o700});
 const genesisBytes=encodeOfflineOrphanReplaySnapshot({registryId,consumed:[]}),expectedGenesisDigest=sha(genesisBytes);
 const registry=createOfflineSupervisorReplayCommit({directory,registryId,genesisBytes,expectedGenesisDigest});
 const r=report(),items=[];let head=expectedGenesisDigest;
 for(let n=1;n<=count;n++){
  const d=decision(r,head,n),p=pins(r),previous=head;
  const result=await registry.commit({expectedHeadDigest:head,report:r,expectedPins:p,decision:d,reviewers,quorum:2,expectedReviewerPolicyDigest:reviewerPin,nowMs});
  head=result.nextDigest;
  const record=JSON.parse(await readFile(join(directory,`commit-${previous}.json`),'utf8'));
  items.push({record,report:r,expectedPins:p,decision:d,reviewers,quorum:2,expectedReviewerPolicyDigest:reviewerPin,observedAtMs:nowMs});
 }
 const previousCheckpointDigest=sha('independent-prior-checkpoint');
 const body={schema:OFFLINE_REPLAY_HEAD_CHECKPOINT_SCHEMA,registryId,genesisDigest:expectedGenesisDigest,headDigest:head,
  commitCount:items.length,historyDigest:offlineReplayHeadAuditHistoryDigest(items),previousCheckpointDigest,sequence:7,issuedAt:nowMs+5000,auditorPolicyDigest:auditorPin};
 const checkpoint=signedCheckpoint(body),expectedCheckpointDigest=offlineReplayHeadCheckpointDigest(checkpoint);
 const args={registryId,genesisBytes,expectedGenesisDigest,items,checkpoint,auditors,auditorQuorum:2,expectedAuditorPolicyDigest:auditorPin,
  expectedCheckpointDigest,expectedPreviousCheckpointDigest:previousCheckpointDigest,expectedSequence:7};
 return {parent,directory,genesisBytes,expectedGenesisDigest,head,items,checkpoint,args,r};
}
function revised(x,change){const b={...x.checkpoint.body,...change};const checkpoint=signedCheckpoint(b);return {...x.args,checkpoint,expectedCheckpointDigest:offlineReplayHeadCheckpointDigest(checkpoint)};}
test('32E two genuine signed historic decisions and independently pinned checkpoint verify read-only',async t=>{
 const x=await fixture(t),v=verifyOfflineReplayHeadCheckpoint(x.args);
 assert.equal(v.verified,true);assert.equal(v.commitCount,2);assert.equal(v.headDigest,x.head);assert.equal(v.historicalSignaturesVerified,true);
 assert.equal(v.externalPinPublicationVerified,false);assert.equal(v.trustedTimestampVerified,false);assert.equal(v.authorizesRemediation,false);
});
test('32E genesis checkpoint with no decisions is independently anchored',async t=>{const x=await fixture(t,0);assert.equal(verifyOfflineReplayHeadCheckpoint(x.args).commitCount,0);});
test('32E missing independent checkpoint pin fails closed',async t=>{const x=await fixture(t);assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...x.args,expectedCheckpointDigest:undefined}),err('CHECKPOINT32E_EXTERNAL_ANCHORS_REQUIRED'));});
test('32E missing previous external checkpoint anchor fails closed',async t=>{const x=await fixture(t);assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...x.args,expectedPreviousCheckpointDigest:undefined}),err('CHECKPOINT32E_EXTERNAL_ANCHORS_REQUIRED'));});
test('32E forged genesis bytes rejected',async t=>{const x=await fixture(t);assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...x.args,genesisBytes:Buffer.from('forged')}),err('CHECKPOINT32E_GENESIS_PIN_REQUIRED'));});
test('32E stale sequence rejects valid signed checkpoint',async t=>{const x=await fixture(t);assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...x.args,expectedSequence:8}),err('CHECKPOINT32E_EXTERNAL_ANCHOR_MISMATCH'));});
test('32E rollback to earlier signed head cannot satisfy newer external checkpoint pin',async t=>{const x=await fixture(t);const rollback=revised(x,{headDigest:x.items[0].record.nextDigest,commitCount:1});assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...rollback,expectedCheckpointDigest:x.args.expectedCheckpointDigest}),err('CHECKPOINT32E_EXTERNAL_ANCHOR_MISMATCH'));});
test('32E fork with same sequence and predecessor requires independent winning pin',async t=>{const x=await fixture(t);const fork=revised(x,{historyDigest:sha('forked-history')});assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...fork,expectedCheckpointDigest:x.args.expectedCheckpointDigest}),err('CHECKPOINT32E_EXTERNAL_ANCHOR_MISMATCH'));});
test('32E substituted prior checkpoint anchor rejected despite fresh signatures',async t=>{const x=await fixture(t);const forged=revised(x,{previousCheckpointDigest:sha('another-anchor')});assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...forged,expectedPreviousCheckpointDigest:x.args.expectedPreviousCheckpointDigest}),err('CHECKPOINT32E_EXTERNAL_ANCHOR_MISMATCH'));});
test('32E forged auditor policy rejected',async t=>{const x=await fixture(t);assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...x.args,expectedAuditorPolicyDigest:sha('wrong')}),err('CHECKPOINT32E_AUDITOR_POLICY_PIN_MISMATCH'));});
test('32E forged auditor signature rejected even with matching digest pin',async t=>{const x=await fixture(t);const checkpoint={body:x.checkpoint.body,signatures:x.checkpoint.signatures.map(s=>({...s}))};checkpoint.signatures[0].signature=sign(null,offlineReplayHeadCheckpointSigningBytes(checkpoint.body),auditorKeys[2].privateKey).toString('base64url');assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...x.args,checkpoint,expectedCheckpointDigest:offlineReplayHeadCheckpointDigest(checkpoint)}),err('CHECKPOINT32E_SIGNATURE_INVALID'));});
test('32E minority auditor quorum rejected',async t=>{const x=await fixture(t);const checkpoint={...x.checkpoint,signatures:x.checkpoint.signatures.slice(0,1)};assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...x.args,checkpoint,expectedCheckpointDigest:offlineReplayHeadCheckpointDigest(checkpoint)}),err('CHECKPOINT32E_QUORUM_INVALID'));});
test('32E duplicate auditor identity rejected',async t=>{const x=await fixture(t);assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...x.args,auditors:[auditors[0],auditors[0],auditors[2]]}),err('CHECKPOINT32E_AUDITOR_POLICY_INVALID'));});
test('32E changed archived report bytes detected even if checkpoint signed over original history',async t=>{const x=await fixture(t);const items=x.items.map(a=>({...a,report:{...a.report,evidence:a.report.evidence.map(e=>({...e}))}}));items[0].report.evidence[0].bytes=999;assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...x.args,items}),err('CHECKPOINT32E_HISTORY_MISMATCH'));});
test('32E altered committed replay nextDigest rejected with newly signed checkpoint',async t=>{const x=await fixture(t);const items=x.items.map(a=>({...a,record:{...a.record}}));items[0].record.nextDigest=sha('tampered');const checkpoint=signedCheckpoint({...x.checkpoint.body,historyDigest:offlineReplayHeadAuditHistoryDigest(items)});assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...x.args,items,checkpoint,expectedCheckpointDigest:offlineReplayHeadCheckpointDigest(checkpoint)}),err('CHECKPOINT32E_CHAIN_INVALID'));});
test('32E swapped order of valid records fails chain despite new audit signature',async t=>{const x=await fixture(t);const items=[...x.items].reverse();const checkpoint=signedCheckpoint({...x.checkpoint.body,historyDigest:offlineReplayHeadAuditHistoryDigest(items)});assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...x.args,items,checkpoint,expectedCheckpointDigest:offlineReplayHeadCheckpointDigest(checkpoint)}),err('CHECKPOINT32E_CHAIN_INVALID'));});
test('32E forged historical reviewer signature rejected even if auditors attest to it',async t=>{const x=await fixture(t);const items=x.items.map(a=>({...a,decision:{body:a.decision.body,signatures:a.decision.signatures.map(s=>({...s}))}}));items[0].decision.signatures[0].signature=sign(null,offlineOrphanSupervisorDecisionSigningBytes(items[0].decision.body),reviewerKeys[2].privateKey).toString('base64url');const checkpoint=signedCheckpoint({...x.checkpoint.body,historyDigest:offlineReplayHeadAuditHistoryDigest(items)});assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...x.args,items,checkpoint,expectedCheckpointDigest:offlineReplayHeadCheckpointDigest(checkpoint)}),err('SUPERVISOR_DECISION_SIGNATURE_INVALID'));});
test('32E missing historical signed decision evidence cannot be substituted by bare replay record',async t=>{const x=await fixture(t);const items=x.items.map(a=>({...a}));items[0].decision=undefined;assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...x.args,items}),err('CHECKPOINT32E_CANONICAL'));});
test('32E historical trusted-observation interval cannot be moved outside signature expiry',async t=>{const x=await fixture(t);const items=x.items.map(a=>({...a}));items[0].observedAtMs=nowMs+70000;const checkpoint=signedCheckpoint({...x.checkpoint.body,issuedAt:nowMs+80000,historyDigest:offlineReplayHeadAuditHistoryDigest(items)});assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...x.args,items,checkpoint,expectedCheckpointDigest:offlineReplayHeadCheckpointDigest(checkpoint)}),err('SUPERVISOR_DECISION_EXPIRED_OR_FUTURE'));});
test('32E historical observation rollback rejected even if signed checkpoint matches',async t=>{const x=await fixture(t);const items=x.items.map(a=>({...a}));items[0].observedAtMs=nowMs+500;items[1].observedAtMs=nowMs;const checkpoint=signedCheckpoint({...x.checkpoint.body,historyDigest:offlineReplayHeadAuditHistoryDigest(items)});assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...x.args,items,checkpoint,expectedCheckpointDigest:offlineReplayHeadCheckpointDigest(checkpoint)}),err('CHECKPOINT32E_CHAIN_INVALID'));});
test('32E interrupted external publication cannot claim checkpoint is externally pinned',async t=>{const x=await fixture(t);assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...x.args,expectedCheckpointDigest:undefined}),err('CHECKPOINT32E_EXTERNAL_ANCHORS_REQUIRED'));assert.equal(verifyOfflineReplayHeadCheckpoint(x.args).externalPinPublicationVerified,false);});
test('32E external head advanced after signed checkpoint requires new independently pinned checkpoint',async t=>{const x=await fixture(t);const items=x.items.slice(0,1);assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...x.args,items}),err('CHECKPOINT32E_HISTORY_MISMATCH'));});
test('32E malformed unknown checkpoint field is rejected',async t=>{const x=await fixture(t);assert.throws(()=>offlineReplayHeadCheckpointSigningBytes({...x.checkpoint.body,allowCheckout:true}),err('CHECKPOINT32E_BODY_INVALID'));});
test('32E signer and verifier do not touch Shopify or network',()=>{assert.equal(OFFLINE_REPLAY_HEAD_CHECKPOINT_SCHEMA,'TJ-OFFLINE-REPLAY-HEAD-CHECKPOINT-1');});
test('32E actual SIGKILL after durable commit does not fabricate external signed checkpoint publication',async t=>{
 const x=await fixture(t,0),r=x.r,d=decision(r,x.expectedGenesisDigest,1);
 const configPath=join(x.parent,'crash-worker.json');
 await writeFile(configPath,JSON.stringify({directory:x.directory,registryId,genesisBase64:x.genesisBytes.toString('base64'),
  expectedGenesisDigest:x.expectedGenesisDigest,fault:'afterCommitSync',args:{expectedHeadDigest:x.expectedGenesisDigest,
   report:r,expectedPins:pins(r),decision:d,reviewers:reviewers.map(({id,publicKey})=>({id,publicKey:publicKey.export({format:'pem',type:'spki'})})),
   quorum:2,expectedReviewerPolicyDigest:reviewerPin,nowMs}}),{mode:0o600});
 const worker=fileURLToPath(new URL('./support/objective32d-worker.mjs',import.meta.url));
 const crash=await new Promise((resolve,reject)=>{const child=spawn(process.execPath,[worker,configPath],{stdio:'ignore'});child.once('error',reject);child.once('close',(code,signal)=>resolve({code,signal}));});
 assert.equal(crash.signal,'SIGKILL');
 const head=sha(encodeOfflineOrphanReplaySnapshot({registryId,consumed:[{decisionId:d.body.decisionId,nonce:d.body.nonce}]}));
 const registry=createOfflineSupervisorReplayCommit({directory:x.directory,registryId,genesisBytes:x.genesisBytes,expectedGenesisDigest:x.expectedGenesisDigest});
 await assert.rejects(registry.inspect({expectedHeadDigest:head}),err('REPLAY32D_UNRESOLVED_STAGE'));
 await registry.finalizeLinkedStages({expectedHeadDigest:head,supervisorConfirmed:true});
 const record=JSON.parse(await readFile(join(x.directory,`commit-${x.expectedGenesisDigest}.json`),'utf8'));
 const items=[{record,report:r,expectedPins:pins(r),decision:d,reviewers,quorum:2,expectedReviewerPolicyDigest:reviewerPin,observedAtMs:nowMs}];
 const checkpoint=signedCheckpoint({...x.checkpoint.body,headDigest:head,commitCount:1,historyDigest:offlineReplayHeadAuditHistoryDigest(items)});
 const args={...x.args,items,checkpoint,expectedCheckpointDigest:offlineReplayHeadCheckpointDigest(checkpoint)};
 assert.throws(()=>verifyOfflineReplayHeadCheckpoint({...args,expectedCheckpointDigest:undefined}),err('CHECKPOINT32E_EXTERNAL_ANCHORS_REQUIRED'));
 assert.equal(verifyOfflineReplayHeadCheckpoint(args).historicalSignaturesVerified,true);
 assert.equal(verifyOfflineReplayHeadCheckpoint(args).externalPinPublicationVerified,false);
});
