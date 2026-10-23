import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {mkdtemp,mkdir,rm,writeFile,readFile,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {OFFLINE_ACQUISITION_EXPORT_SCHEMA} from '../src/offline-acquisition-evidence-export.mjs';
import {OFFLINE_ACQUISITION_SESSION_SCHEMA} from '../src/offline-acquisition-session-journal.mjs';
import {OFFLINE_ACQUISITION_MANIFEST_SCHEMA} from '../src/offline-forensic-acquisition-provenance.mjs';
import {createOfflineExportReceiptRegistry,OFFLINE_EXPORT_RECEIPT_SCHEMA,offlineExportReceiptPolicyDigest,offlineExportReceiptSigningBytes} from '../src/offline-acquisition-export-receipt-registry.mjs';
import {encodeOfflinePinnedArchiveInventory} from '../src/offline-pinned-multi-archive-inventory.mjs';
import {classifyOfflinePinnedArchiveOrphans} from '../src/offline-pinned-orphan-classifier.mjs';
import {OFFLINE_ORPHAN_SUPERVISOR_DECISION_SCHEMA,offlineOrphanSupervisorPolicyDigest,offlineOrphanReportIssueDigest,
 offlineOrphanSupervisorDecisionSigningBytes,encodeOfflineOrphanReplaySnapshot,verifyOfflineOrphanSupervisorDecision} from '../src/offline-orphan-supervisor-decision.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex'),ROOT='0'.repeat(64),registryId='integration_registry_32c',nowMs=1800000000000;
const signers=[0,1,2].map(i=>({id:`export_signer_32c_${i}`,...generateKeyPairSync('ed25519')}));
const witnesses=signers.map(k=>({id:k.id,publicKey:k.publicKey}));
const reviewers=[0,1,2].map(i=>({id:`reviewer_integrated_32c_${i}`,...generateKeyPairSync('ed25519')}));
const policyDigest=offlineExportReceiptPolicyDigest({witnesses,quorum:2});
function archive(acquisitionId){
 const pre={phase:'PRE',acquisitionId},post={phase:'POST',acquisitionId};
 const manifest={schema:OFFLINE_ACQUISITION_MANIFEST_SCHEMA,acquisitionId,envelope:{transportDigest:'a'.repeat(64)},receiptHistory:[pre,post]};
 let previous=ROOT;const events=[];
 for(const [index,action,payload] of [[1,'BEGIN',{acquisitionId}],[2,'PRE',pre],[3,'POST',manifest]]){
  const body={schema:OFFLINE_ACQUISITION_SESSION_SCHEMA,index,previousDigest:previous,action,payload};
  const event={...body,digest:sha(Buffer.from(`${OFFLINE_ACQUISITION_SESSION_SCHEMA}\0${JSON.stringify(body)}`))};previous=event.digest;events.push(event);
 }
 const files=new Map([['manifest.json',manifest],['session/0001.json',events[0]],['session/0002.json',events[1]],['session/0003.json',events[2]],['evidence/branch_01.json',{source:'test-only'}]]);
 const entries=[],payload=[];let offset=0;
 for(const [path,value] of [...files].sort((a,b)=>a[0].localeCompare(b[0]))){
  const bytes=Buffer.from(JSON.stringify(value));entries.push({path,offset,size:bytes.length,sha256:sha(bytes)});payload.push(bytes);offset+=bytes.length;
 }
 const body=Buffer.concat(payload),header=Buffer.from(JSON.stringify({schema:OFFLINE_ACQUISITION_EXPORT_SCHEMA,acquisitionId,files:entries,payloadBytes:body.length,payloadDigest:sha(body)}));
 const length=Buffer.alloc(4);length.writeUInt32BE(header.length);
 return Buffer.concat([Buffer.from(`${OFFLINE_ACQUISITION_EXPORT_SCHEMA}\n`),length,header,body]);
}
async function fixture(t){
 const parent=await mkdtemp(join(tmpdir(),'tj32c-integration-'));await chmod(parent,0o700);t.after(()=>rm(parent,{recursive:true,force:true}));
 const registryDirectory=join(parent,'registry'),archiveDirectories=[join(parent,'archiveA'),join(parent,'archiveB')];
 await mkdir(registryDirectory,{mode:0o700});for(const d of archiveDirectories)await mkdir(d,{mode:0o700});
 const registry=createOfflineExportReceiptRegistry({directory:registryDirectory,registryId,witnesses,quorum:2});
 const acquisitionId='acquisition_integrated_32c',archiveBytes=archive(acquisitionId);
 const body={schema:OFFLINE_EXPORT_RECEIPT_SCHEMA,registryId,sequence:1,previousDigest:ROOT,exportId:'export_integrated_32c',acquisitionId,
  archiveDigest:sha(archiveBytes),archiveBytes:archiveBytes.length,issuedAt:nowMs-1000,expiresAt:nowMs+60000,nonce:'nonce_integrated_32c',policyDigest};
 const signing=offlineExportReceiptSigningBytes(body);
 const receipt={body,signatures:signers.slice(0,2).map(k=>({witnessId:k.id,signature:sign(null,signing,k.privateKey).toString('base64url')}))};
 const next=await registry.append({receipt,archiveBytes,expectedHead:{count:0,headDigest:ROOT},nowMs});
 await writeFile(join(archiveDirectories[0],`${sha(archiveBytes)}.tjexport`),archiveBytes,{mode:0o600});
 await writeFile(join(archiveDirectories[1],'unknown.tjexport'),'unverified archive',{mode:0o600});
 const manifestBytes=encodeOfflinePinnedArchiveInventory({registryId,expectedHead:next.head,expectedEpoch:0,expectedTransitionDigest:ROOT,
  archives:[{sequence:1,directoryIndex:0,acquisitionId,archiveDigest:sha(archiveBytes),archiveBytes:archiveBytes.length}]});
 const classify=()=>classifyOfflinePinnedArchiveOrphans({registry,registryDirectory,archiveDirectories,registryId,manifestBytes,
  expectedManifestDigest:sha(manifestBytes),expectedHead:next.head,expectedEpoch:0,expectedTransitionDigest:ROOT,nowMs});
 const report=await classify();
 const expectedPins={reportDigest:report.reportDigest,manifestDigest:report.manifestDigest,head:report.head,epoch:report.epoch,transitionDigest:report.transitionDigest,recordsDigest:report.recordsDigest};
 const replayBytes=encodeOfflineOrphanReplaySnapshot({registryId,consumed:[]}),expectedReplayDigest=sha(replayBytes);
 const reviewerPolicyDigest=offlineOrphanSupervisorPolicyDigest({reviewers:reviewers.map(x=>({id:x.id,publicKey:x.publicKey})),quorum:2});
 const decisionBody={schema:OFFLINE_ORPHAN_SUPERVISOR_DECISION_SCHEMA,registryId,reportDigest:report.reportDigest,manifestDigest:report.manifestDigest,
  head:report.head,epoch:report.epoch,transitionDigest:report.transitionDigest,recordsDigest:report.recordsDigest,
  issueDigest:offlineOrphanReportIssueDigest(report),issueCount:report.issueCount,disposition:'REJECT_EVIDENCE',
  decisionId:'integrated_decision_32c',nonce:'integrated_decision_nonce_32c',issuedAt:nowMs-1000,expiresAt:nowMs+60000,
  replayDigest:expectedReplayDigest,reviewerPolicyDigest};
 const bytes=offlineOrphanSupervisorDecisionSigningBytes(decisionBody);
 const decision={body:decisionBody,signatures:reviewers.slice(0,2).map(k=>({reviewerId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}))};
 const args={report,expectedPins,decision,reviewers:reviewers.map(k=>({id:k.id,publicKey:k.publicKey})),quorum:2,expectedReviewerPolicyDigest:reviewerPolicyDigest,replayBytes,expectedReplayDigest,nowMs};
 return {parent,archiveDirectories,report,classify,args,run:changes=>verifyOfflineOrphanSupervisorDecision({...args,...changes})};
}
test('32C genuine 32B signed archive/orphan classifier evidence verifies under separate supervisor quorum',async t=>{
 const x=await fixture(t),r=x.run();assert.equal(x.report.issueCount,1);assert.equal(x.report.evidence.length,2);
 assert.equal(r.signatureVerified,true);assert.equal(r.disposition,'REJECT_EVIDENCE');assert.equal(r.authorizesRemediation,false);
 assert.equal(r.requiresIndependentAtomicReplayCommit,true);
});
test('32C genuine 32B report and archives remain byte-identical after decision verification',async t=>{
 const x=await fixture(t),before=await readFile(join(x.archiveDirectories[1],'unknown.tjexport')),digest=x.report.reportDigest;
 x.run();assert.ok(before.equals(await readFile(join(x.archiveDirectories[1],'unknown.tjexport'))));
 assert.equal((await x.classify()).reportDigest,digest);
});
test('32C fresh 32B classifier result with new orphan cannot be approved under previous signed review',async t=>{
 const x=await fixture(t);await writeFile(join(x.archiveDirectories[1],'new_orphan.tjexport'),'new orphan',{mode:0o600});
 const fresh=await x.classify();assert.notEqual(fresh.reportDigest,x.report.reportDigest);
 assert.throws(()=>x.run({report:fresh}),e=>e?.code==='SUPERVISOR_REPORT_PIN_MISMATCH');
});
test('32C previously signed review cannot bind a different independently pinned classifier head',async t=>{
 const x=await fixture(t),pins={...x.args.expectedPins,head:{count:1,headDigest:sha('different')}};
 assert.throws(()=>x.run({expectedPins:pins}),e=>e?.code==='SUPERVISOR_REPORT_PIN_MISMATCH');
});
