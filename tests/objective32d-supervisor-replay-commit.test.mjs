import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {mkdtemp,mkdir,rm,writeFile,readFile,readdir,chmod,symlink,unlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA} from '../src/offline-pinned-orphan-classifier.mjs';
import {OFFLINE_ORPHAN_SUPERVISOR_DECISION_SCHEMA,offlineOrphanSupervisorPolicyDigest,offlineOrphanReportIssueDigest,
 offlineOrphanSupervisorDecisionSigningBytes,encodeOfflineOrphanReplaySnapshot} from '../src/offline-orphan-supervisor-decision.mjs';
import {createOfflineSupervisorReplayCommit,OFFLINE_SUPERVISOR_REPLAY_COMMIT_SCHEMA} from '../src/offline-supervisor-replay-commit.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const registryId='orphan_registry_32d',nowMs=1800000000000,ROOT='0'.repeat(64);
const keys=[0,1,2].map(i=>({id:`reviewer_32d_${i}`,...generateKeyPairSync('ed25519')}));
const reviewers=keys.map(x=>({id:x.id,publicKey:x.publicKey}));
const policyDigest=offlineOrphanSupervisorPolicyDigest({reviewers,quorum:2});
const error=(code)=>e=>e?.code===code;
function report(){
 const evidence=[{directoryIndex:0,name:'untracked.tjexport',nameDigest:sha('untracked.tjexport'),classification:'UNTRACKED_ARCHIVE_UNVERIFIED',digest:sha('bytes'),bytes:10}];
 const body={schema:OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA,registryId,manifestDigest:sha('manifest'),head:{count:1,headDigest:sha('head')},epoch:0,transitionDigest:ROOT,
  recordsDigest:sha('records'),evidence,status:'SUPERVISORY_REVIEW_REQUIRED',issueCount:1,supervisoryDisposition:'EXTERNAL_DECISION_REQUIRED_FOR_ANY_REMEDIATION',
  readOnly:true,productionApproved:false,mayDelete:false,mayRepair:false,mayManufacture:false,mayAcknowledge:false};
 return {...body,reportDigest:sha(Buffer.from(`${OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA}\0${JSON.stringify(body)}`))};
}
const pinned=r=>({reportDigest:r.reportDigest,manifestDigest:r.manifestDigest,head:r.head,epoch:r.epoch,transitionDigest:r.transitionDigest,recordsDigest:r.recordsDigest});
function signedDecision(r,digest,decisionId='decision_32d_0001',nonce='nonce_32d_0001'){
 const body={schema:OFFLINE_ORPHAN_SUPERVISOR_DECISION_SCHEMA,registryId,reportDigest:r.reportDigest,manifestDigest:r.manifestDigest,
  head:r.head,epoch:r.epoch,transitionDigest:r.transitionDigest,recordsDigest:r.recordsDigest,issueDigest:offlineOrphanReportIssueDigest(r),
  issueCount:1,disposition:'REJECT_EVIDENCE',decisionId,nonce,issuedAt:nowMs-1000,expiresAt:nowMs+60000,
  replayDigest:digest,reviewerPolicyDigest:policyDigest};
 const bytes=offlineOrphanSupervisorDecisionSigningBytes(body);
 return {body,signatures:keys.slice(0,2).map(k=>({reviewerId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}))};
}
async function fixture(t){
 const parent=await mkdtemp(join(tmpdir(),'tj32d-'));t.after(()=>rm(parent,{recursive:true,force:true}));
 const directory=join(parent,'replay');await mkdir(directory,{mode:0o700});
 const genesisBytes=encodeOfflineOrphanReplaySnapshot({registryId,consumed:[]}),expectedGenesisDigest=sha(genesisBytes);
 const r=report(),decision=signedDecision(r,expectedGenesisDigest);
 const args={expectedHeadDigest:expectedGenesisDigest,report:r,expectedPins:pinned(r),decision,reviewers,quorum:2,
  expectedReviewerPolicyDigest:policyDigest,nowMs};
 const make=(options={})=>createOfflineSupervisorReplayCommit({directory,registryId,genesisBytes,expectedGenesisDigest,...options});
 const workerConfig=(fault)=>({directory,registryId,genesisBase64:genesisBytes.toString('base64'),expectedGenesisDigest,fault,
  args:{...args,reviewers:reviewers.map(x=>({id:x.id,publicKey:x.publicKey.export({format:'pem',type:'spki'})}))}});
 return {parent,directory,genesisBytes,expectedGenesisDigest,r,decision,args,make,workerConfig};
}
async function runWorker(x,fault){
 const config=join(x.parent,`worker-${Date.now()}-${Math.random()}.json`);await writeFile(config,JSON.stringify(x.workerConfig(fault)),{mode:0o600});
 const path=fileURLToPath(new URL('./support/objective32d-worker.mjs',import.meta.url));
 return await new Promise((ok,no)=>{const p=spawn(process.execPath,[path,config],{stdio:['ignore','pipe','pipe']});let stdout='',stderr='';
  p.stdout.on('data',b=>stdout+=b);p.stderr.on('data',b=>stderr+=b);p.once('error',no);
  p.once('close',(code,signal)=>ok({code,signal,stdout,stderr}));});
}
function expectedNext(x){const c=[{decisionId:x.decision.body.decisionId,nonce:x.decision.body.nonce}];return sha(encodeOfflineOrphanReplaySnapshot({registryId,consumed:c}));}
test('32D pinned genesis is independently required',async t=>{const x=await fixture(t);assert.throws(()=>createOfflineSupervisorReplayCommit({directory:x.directory,registryId,genesisBytes:x.genesisBytes,expectedGenesisDigest:sha('fake')}),error('REPLAY32D_GENESIS_PIN_MISMATCH'));});
test('32D initial pinned empty state is read-only',async t=>{const x=await fixture(t),r=await x.make().inspect({expectedHeadDigest:x.expectedGenesisDigest});assert.equal(r.count,0);assert.equal(r.productionApproved,false);});
test('32D missing current independently pinned head rejects inspection',async t=>{const x=await fixture(t);await assert.rejects(x.make().inspect({}),error('REPLAY32D_EXTERNAL_HEAD_REQUIRED'));});
test('32D genuine signed decision commits a durable successor without authorization',async t=>{const x=await fixture(t),r=await x.make().commit(x.args);assert.equal(r.committed,true);assert.equal(r.nextDigest,expectedNext(x));assert.equal(r.externalPinUpdateRequired,true);assert.equal(r.authorizesRemediation,false);assert.equal(r.productionApproved,false);assert.equal((await x.make().inspect({expectedHeadDigest:r.nextDigest})).count,1);});
test('32D exact replay cannot be committed twice under stale head',async t=>{const x=await fixture(t);await x.make().commit(x.args);await assert.rejects(x.make().commit(x.args),error('REPLAY32D_EXTERNAL_HEAD_MISMATCH'));});
test('32D same decision ID under new nonce cannot replay',async t=>{const x=await fixture(t),r=await x.make().commit(x.args);const decision=signedDecision(x.r,r.nextDigest,x.decision.body.decisionId,'nonce_32d_other');await assert.rejects(x.make().commit({...x.args,expectedHeadDigest:r.nextDigest,decision}),error('SUPERVISOR_DECISION_REPLAY'));});
test('32D same nonce under new decision ID cannot replay',async t=>{const x=await fixture(t),r=await x.make().commit(x.args);const decision=signedDecision(x.r,r.nextDigest,'decision_32d_other',x.decision.body.nonce);await assert.rejects(x.make().commit({...x.args,expectedHeadDigest:r.nextDigest,decision}),error('SUPERVISOR_DECISION_REPLAY'));});
test('32D two independently signed decisions chain across process reopen',async t=>{const x=await fixture(t),first=await x.make().commit(x.args);const decision=signedDecision(x.r,first.nextDigest,'decision_32d_0002','nonce_32d_0002');const second=await x.make().commit({...x.args,expectedHeadDigest:first.nextDigest,decision});assert.equal((await x.make().inspect({expectedHeadDigest:second.nextDigest})).count,2);});
test('32D tampered report rejected without creating commit',async t=>{const x=await fixture(t);const r=structuredClone(x.r);r.evidence[0].bytes=99;await assert.rejects(x.make().commit({...x.args,report:r}),error('SUPERVISOR_REPORT_PIN_MISMATCH'));assert.deepEqual(await readdir(x.directory),[]);});
test('32D forged reviewer policy pin rejected',async t=>{const x=await fixture(t);await assert.rejects(x.make().commit({...x.args,expectedReviewerPolicyDigest:sha('wrong')}),error('SUPERVISOR_EXTERNAL_REVIEWER_POLICY_PIN_REQUIRED'));});
test('32D forged decision signature rejected',async t=>{const x=await fixture(t);const decision=structuredClone(x.decision);decision.signatures[0].signature=sign(null,offlineOrphanSupervisorDecisionSigningBytes(decision.body),keys[2].privateKey).toString('base64url');await assert.rejects(x.make().commit({...x.args,decision}),error('SUPERVISOR_DECISION_SIGNATURE_INVALID'));});
test('32D expired decision rejected before persistence',async t=>{const x=await fixture(t);await assert.rejects(x.make().commit({...x.args,nowMs:nowMs+70000}),error('SUPERVISOR_DECISION_EXPIRED_OR_FUTURE'));});
test('32D missing trusted time rejected',async t=>{const x=await fixture(t);await assert.rejects(x.make().commit({...x.args,nowMs:undefined}),error('SUPERVISOR_TRUSTED_TIME_REQUIRED'));});
test('32D missing external report pin rejected',async t=>{const x=await fixture(t);await assert.rejects(x.make().commit({...x.args,expectedPins:undefined}),error('SUPERVISOR_EXTERNAL_PINS_REQUIRED'));});
test('32D no remediation disposition can be signed',async t=>{const x=await fixture(t),decision=structuredClone(x.decision);decision.body.disposition='DELETE_ORPHANS';await assert.rejects(x.make().commit({...x.args,decision}),error('SUPERVISOR_DECISION_INVALID'));});
test('32D external pin rollback rejected after successful commit',async t=>{const x=await fixture(t),r=await x.make().commit(x.args);await assert.rejects(x.make().inspect({expectedHeadDigest:x.expectedGenesisDigest}),error('REPLAY32D_EXTERNAL_HEAD_MISMATCH'));assert.equal((await x.make().inspect({expectedHeadDigest:r.nextDigest})).count,1);});
test('32D altered persisted record rejected against pinned head',async t=>{const x=await fixture(t),r=await x.make().commit(x.args),path=join(x.directory,`commit-${x.expectedGenesisDigest}.json`);const obj=JSON.parse(await readFile(path));obj.decisionId='substituted_32d';await writeFile(path,JSON.stringify(obj));await assert.rejects(x.make().inspect({expectedHeadDigest:r.nextDigest}),error('REPLAY32D_CHAIN_INVALID'));});
test('32D symlinked persisted commit rejected',async t=>{const x=await fixture(t),r=await x.make().commit(x.args),path=join(x.directory,`commit-${x.expectedGenesisDigest}.json`);await unlink(path);await symlink('/etc/passwd',path);await assert.rejects(x.make().inspect({expectedHeadDigest:r.nextDigest}),error('REPLAY32D_FILE_UNSAFE'));});
test('32D unsafe directory mode rejected',async t=>{const x=await fixture(t);await chmod(x.directory,0o755);await assert.rejects(x.make().inspect({expectedHeadDigest:x.expectedGenesisDigest}),error('REPLAY32D_DIRECTORY_UNSAFE'));});
test('32D unexpected untracked file fails closed',async t=>{const x=await fixture(t);await writeFile(join(x.directory,'unknown.json'),'{}',{mode:0o600});await assert.rejects(x.make().inspect({expectedHeadDigest:x.expectedGenesisDigest}),error('REPLAY32D_UNEXPECTED_FILE'));});
test('32D orphan commit outside anchored chain fails closed',async t=>{const x=await fixture(t);await writeFile(join(x.directory,`commit-${sha('rogue')}.json`),'{}',{mode:0o600});await assert.rejects(x.make().inspect({expectedHeadDigest:x.expectedGenesisDigest}),error('REPLAY32D_ORPHAN_COMMIT'));});
test('32D two independent Node processes cannot both consume same head',async t=>{const x=await fixture(t),results=await Promise.all([runWorker(x),runWorker(x)]);const wins=results.filter(r=>r.code===0);assert.equal(wins.length,1,JSON.stringify(results));const next=expectedNext(x);assert.equal((await x.make().inspect({expectedHeadDigest:next})).count,1);});
test('32D actual SIGKILL after durable staging leaves unresolved evidence and no committed replay',async t=>{const x=await fixture(t),r=await runWorker(x,'afterStage');assert.equal(r.signal,'SIGKILL');await assert.rejects(x.make().inspect({expectedHeadDigest:x.expectedGenesisDigest}),error('REPLAY32D_UNRESOLVED_STAGE'));assert.equal((await readdir(x.directory)).filter(n=>n.startsWith('commit-')).length,0);});
test('32D actual SIGKILL after hardlink requires independently pinned supervisory finalization',async t=>{const x=await fixture(t),r=await runWorker(x,'afterLink');assert.equal(r.signal,'SIGKILL');const next=expectedNext(x);await assert.rejects(x.make().inspect({expectedHeadDigest:next}),error('REPLAY32D_UNRESOLVED_STAGE'));await assert.rejects(x.make().finalizeLinkedStages({expectedHeadDigest:next}),error('REPLAY32D_SUPERVISOR_REQUIRED'));const f=await x.make().finalizeLinkedStages({expectedHeadDigest:next,supervisorConfirmed:true});assert.equal(f.finalized,1);assert.equal((await x.make().inspect({expectedHeadDigest:next})).count,1);});
test('32D actual SIGKILL after commit sync leaves independently verifiable committed replay',async t=>{const x=await fixture(t),r=await runWorker(x,'afterCommitSync');assert.equal(r.signal,'SIGKILL');const next=expectedNext(x);await assert.rejects(x.make().inspect({expectedHeadDigest:next}),error('REPLAY32D_UNRESOLVED_STAGE'));await x.make().finalizeLinkedStages({expectedHeadDigest:next,supervisorConfirmed:true});assert.equal((await x.make().inspect({expectedHeadDigest:next})).count,1);});
test('32D supervisor cannot finalize unlinked pre-commit stage',async t=>{const x=await fixture(t);await runWorker(x,'afterStage');await assert.rejects(x.make().finalizeLinkedStages({expectedHeadDigest:x.expectedGenesisDigest,supervisorConfirmed:true}),error('REPLAY32D_UNRESOLVED_STAGE'));});
test('32D schema is stable and does not confer manufacturing authority',()=>{assert.equal(OFFLINE_SUPERVISOR_REPLAY_COMMIT_SCHEMA,'TJ-OFFLINE-SUPERVISOR-REPLAY-COMMIT-1');});
