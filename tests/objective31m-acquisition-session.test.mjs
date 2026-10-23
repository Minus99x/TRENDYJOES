import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {mkdtemp,rm,readFile,writeFile,symlink,link,chmod,unlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createOfflineAcquisitionSessionJournal} from '../src/offline-acquisition-session-journal.mjs';
import {createOfflineForensicPortableReviewBundle} from '../src/offline-forensic-portable-review.mjs';
import {OFFLINE_ACQUISITION_RECEIPT_SCHEMA,offlineAcquisitionReceiptSigningBytes,createOfflineAcquisitionReceipt,verifyOfflineAcquisitionRetentionHistory,createOfflineForensicAcquisitionManifest,verifyOfflineForensicAcquisitionManifest} from '../src/offline-forensic-acquisition-provenance.mjs';
const ROOT='0'.repeat(64),zero={count:0,headDigest:ROOT},heads={forensic:zero,publication:zero,outbox:zero};
const registryId='synthetic-acquisition-31l',anchorType='registry';
const key=()=>generateKeyPairSync('ed25519');
const sha=x=>createHash('sha256').update(x).digest('hex');
const err=(fn,code)=>assert.throws(fn,e=>e?.code===code);
const rejects=(fn,code)=>assert.rejects(fn,e=>e?.code===code);
const sessionZero={count:0,headDigest:ROOT};
const sessionPin=x=>({count:x.count,headDigest:x.headDigest});
async function session(t,extra={}){const directory=await mkdtemp(join(tmpdir(),'tj31m-session-'));t.after(()=>rm(directory,{recursive:true,force:true}));return {directory,j:createOfflineAcquisitionSessionJournal({directory,...extra})};}
const opts=f=>({manifest:f.manifest(),independentPins:heads,forensicTrust:f.forensicTrust,retentionTrust:f.retentionTrust,independentRetentionHead:f.pin(f.history)});
const beginOpts=()=>({acquisitionId:'acquisition-31l-primary',independentPins:heads,priorRetentionHead:sessionZero,expectedSessionHead:sessionZero});
function fixture(){
 const keys=[key(),key(),key()],reviewKeys=[key(),key()],witnessKeys=[key(),key(),key()];
 const retentionTrust={registryId,anchorType,retentionWitnesses:keys.map((k,i)=>({id:`retention-witness-31l-${i}`,publicKey:k.publicKey})),retentionQuorum:2};
 const reviewers=reviewKeys.map((k,i)=>({id:`forensic-reviewer-31l-${i}`,publicKey:k.publicKey,readLatest:async()=>null}));
 const policy={reviewers,quorum:2};
 const forensicTrust={registryId,anchorType,witnesses:witnessKeys.map((k,i)=>({id:`forensic-witness-31l-${i}`,publicKey:k.publicKey})),witnessQuorum:2,reviewerPolicies:[policy],reviewerEpochs:[{startIndex:1,...policy}]};
 const envelope=createOfflineForensicPortableReviewBundle({registryId,anchorType,forensicEvents:[],publications:[],transitionCertificates:[],outboxEvents:[],declaredHeads:heads});
 const signing=(body)=>keys.slice(0,2).map((k,i)=>({witnessId:retentionTrust.retentionWitnesses[i].id,signature:sign(null,offlineAcquisitionReceiptSigningBytes(body),k.privateKey).toString('base64url')}));
 const add=(history,phase,acquisitionId='acquisition-31l-primary',h=heads,bundleDigest=envelope.transportDigest)=>{
  const body={schema:OFFLINE_ACQUISITION_RECEIPT_SCHEMA,registryId,anchorType,index:history.length+1,previousDigest:history.at(-1)?.digest??ROOT,acquisitionId,phase,heads:structuredClone(h),bundleDigest:phase==='PRE'?ROOT:bundleDigest,observedAt:1700000000000+history.length*1000};
  history.push(createOfflineAcquisitionReceipt({body,signatures:signing(body)}));return history.at(-1);
 };
 const history=[];add(history,'PRE');add(history,'POST');
 const pin=hist=>({count:hist.length,headDigest:hist.at(-1)?.digest??ROOT});
 const manifest=()=>createOfflineForensicAcquisitionManifest({acquisitionId:'acquisition-31l-primary',envelope,receiptHistory:history});
 const verify=(m=manifest(),h=history,rt=retentionTrust,fp=heads)=>verifyOfflineForensicAcquisitionManifest({manifest:m,independentPins:fp,forensicTrust,retentionTrust:rt,independentRetentionHead:pin(h)});
 const verifyHistory=(h=history,rt=retentionTrust,p=pin(h))=>verifyOfflineAcquisitionRetentionHistory({history:h,trust:rt,expectedHead:p});
 return {keys,history,retentionTrust,forensicTrust,envelope,add,pin,manifest,verify,verifyHistory,signing};
}

test('31M durable BEGIN, PRE, POST survives restart with independently pinned read-only classification',async t=>{
 const f=fixture(),{directory,j}=await session(t),b=await j.begin(beginOpts());
 assert.equal(b.status,'BEGIN_REVIEW_REQUIRED');assert.equal((await createOfflineAcquisitionSessionJournal({directory}).inspect({expectedSessionHead:sessionPin(b)})).status,'BEGIN_REVIEW_REQUIRED');
 const r=await j.record({...opts(f),expectedSessionHead:{count:b.count,headDigest:b.headDigest}});
 assert.equal(r.status,'COMPLETE_DIAGNOSTIC_ONLY');
 const v=await createOfflineAcquisitionSessionJournal({directory}).verify({...opts(f),expectedSessionHead:{count:r.count,headDigest:r.headDigest}});
 assert.equal(v.classification,'EMPTY_VERIFIED_NO_AUTHORITY');assert.equal(v.mayRetry,false);assert.equal(v.mayAcknowledge,false);assert.equal(v.mayDeletePending,false);assert.equal(v.productionApproved,false);
});
test('31M inspect requires external journal pin even when history is valid',async t=>{const {j}=await session(t);await rejects(()=>j.inspect(),'ACQUISITION_SESSION_EXTERNAL_PIN_REQUIRED');});
test('31M BEGIN does not authorize recording without verified signed POST and independent pins',async t=>{
 const f=fixture(),{j}=await session(t),b=await j.begin(beginOpts());
 const m=f.manifest();m.receiptHistory[1].signatures[0].signature='A'.repeat(86);
 await rejects(()=>j.record({...opts(f),manifest:m,expectedSessionHead:sessionPin(b)}),'ACQUISITION_RECEIPT_SIGNATURE_INVALID');
 assert.equal((await j.inspect({expectedSessionHead:sessionPin(b)})).status,'BEGIN_REVIEW_REQUIRED');
});
test('31M independent pin substitution fails before durable PRE',async t=>{
 const f=fixture(),{j}=await session(t),b=await j.begin(beginOpts());
 await rejects(()=>j.record({...opts(f),independentRetentionHead:{count:2,headDigest:'a'.repeat(64)},expectedSessionHead:sessionPin(b)}),'ACQUISITION_RETENTION_PIN_INVALID');
 assert.equal((await j.inspect({expectedSessionHead:sessionPin(b)})).status,'BEGIN_REVIEW_REQUIRED');
});
test('31M mismatched acquisition identity rejects without appending PRE',async t=>{
 const f=fixture(),{j}=await session(t),b=await j.begin(beginOpts());
 await rejects(()=>j.record({...opts(f),manifest:{...f.manifest(),acquisitionId:'other-acquisition-31m'},expectedSessionHead:sessionPin(b)}),'ACQUISITION_SESSION_BINDING_INVALID');
});
test('31M cannot begin twice or reuse single-use directory',async t=>{
 const {j}=await session(t),b=await j.begin(beginOpts());
 await rejects(()=>j.begin(beginOpts()),'ACQUISITION_SESSION_STALE_PIN');
 await rejects(()=>j.begin({...beginOpts(),expectedSessionHead:sessionPin(b)}),'ACQUISITION_SESSION_SINGLE_USE');
});
test('31M stale compare-and-swap pin blocks recording',async t=>{
 const f=fixture(),{j}=await session(t);await j.begin(beginOpts());
 await rejects(()=>j.record({...opts(f),expectedSessionHead:sessionZero}),'ACQUISITION_SESSION_STALE_PIN');
});
test('31M concurrent BEGIN attempts serialize under OS flock',async t=>{
 const {j}=await session(t);const results=await Promise.allSettled([j.begin(beginOpts()),j.begin(beginOpts())]);
 assert.equal(results.filter(x=>x.status==='fulfilled').length,1);assert.equal(results.filter(x=>x.status==='rejected').length,1);
});
test('31M forged external journal pin detects complete valid-prefix rollback',async t=>{
 const f=fixture(),{j}=await session(t),b=await j.begin(beginOpts());const r=await j.record({...opts(f),expectedSessionHead:sessionPin(b)});
 await rejects(()=>j.inspect({expectedSessionHead:sessionPin(b)}),'ACQUISITION_SESSION_PIN_MISMATCH');
 assert.equal((await j.inspect({expectedSessionHead:sessionPin(r)})).count,3);
});
test('31M tampered committed PRE record is detected by hash chain',async t=>{
 const f=fixture(),{directory,j}=await session(t),b=await j.begin(beginOpts());const r=await j.record({...opts(f),expectedSessionHead:sessionPin(b)});
 const p=join(directory,'0002.json'),e=JSON.parse(await readFile(p,'utf8'));e.payload.acquisitionId='tampered-acquisition-31m';await writeFile(p,JSON.stringify(e));
 await rejects(()=>j.inspect({expectedSessionHead:sessionPin(r)}),'ACQUISITION_SESSION_HISTORY_INVALID');
});
test('31M symlink event substitution fails closed',async t=>{
 const {directory,j}=await session(t),b=await j.begin(beginOpts());const p=join(directory,'0001.json');await unlink(p);await symlink('/etc/passwd',p);
 await rejects(()=>j.inspect({expectedSessionHead:sessionPin(b)}),'ACQUISITION_SESSION_FILE_UNSAFE');
});
test('31M hardlink event substitution fails closed',async t=>{
 const {directory,j}=await session(t),b=await j.begin(beginOpts());const p=join(directory,'0001.json'),backup=join(directory,'hardlink-copy');await link(p,backup);
 await rejects(()=>j.inspect({expectedSessionHead:sessionPin(b)}),'ACQUISITION_SESSION_HISTORY_INVALID');
});
test('31M writable-by-group directory is rejected',async t=>{
 const {directory,j}=await session(t);await chmod(directory,0o770);await rejects(()=>j.begin(beginOpts()),'ACQUISITION_SESSION_DIRECTORY_UNSAFE');
});
test('31M injected crash after durable BEGIN pending fsync leaves unrecoverable pending marker',async t=>{
 const {directory}=await session(t);const modulePath=fileURLToPath(new URL('../src/offline-acquisition-session-journal.mjs',import.meta.url));
 const code=`import {createOfflineAcquisitionSessionJournal} from ${JSON.stringify(modulePath)};const j=createOfflineAcquisitionSessionJournal({directory:process.argv[1],injectFault:phase=>{if(phase==='after-begin-pending-sync')process.exit(83);}});await j.begin(JSON.parse(process.argv[2]));`;
 const p=spawnSync(process.execPath,['--input-type=module','-e',code,directory,JSON.stringify(beginOpts())],{timeout:10000,encoding:'utf8'});
 assert.equal(p.status,83,p.stderr);const j=createOfflineAcquisitionSessionJournal({directory});
 await rejects(()=>j.inspect({expectedSessionHead:sessionZero}),'ACQUISITION_SESSION_UNCERTAIN_COMMIT');
 await rejects(()=>j.begin(beginOpts()),'ACQUISITION_SESSION_UNCERTAIN_COMMIT');
});
test('31M injected crash after durable BEGIN commit yields review-required state',async t=>{
 const {directory}=await session(t);const modulePath=fileURLToPath(new URL('../src/offline-acquisition-session-journal.mjs',import.meta.url));
 const code=`import {createOfflineAcquisitionSessionJournal} from ${JSON.stringify(modulePath)};const j=createOfflineAcquisitionSessionJournal({directory:process.argv[1],injectFault:phase=>{if(phase==='after-begin-commit-sync')process.exit(84);}});await j.begin(JSON.parse(process.argv[2]));`;
 const p=spawnSync(process.execPath,['--input-type=module','-e',code,directory,JSON.stringify(beginOpts())],{timeout:10000,encoding:'utf8'});
 assert.equal(p.status,84,p.stderr);const j=createOfflineAcquisitionSessionJournal({directory});
 const raw=JSON.parse(await readFile(join(directory,'0001.json'),'utf8'));const pin={count:1,headDigest:raw.digest};
 assert.equal((await j.inspect({expectedSessionHead:pin})).status,'BEGIN_REVIEW_REQUIRED');
 await rejects(()=>j.verify({...opts(fixture()),expectedSessionHead:pin}),'ACQUISITION_SESSION_REVIEW_REQUIRED');
});

function childRecord({directory,fixtureData,sessionHead,phase}){
 const modulePath=fileURLToPath(new URL('../src/offline-acquisition-session-journal.mjs',import.meta.url));
 const keyToPem=w=>({id:w.id,publicKey:{__pem:w.publicKey.export({type:'spki',format:'pem'})}});
 const policyToPem=p=>({...p,reviewers:p.reviewers.map(keyToPem)});
 const d=opts(fixtureData);
 d.retentionTrust={...d.retentionTrust,retentionWitnesses:d.retentionTrust.retentionWitnesses.map(keyToPem)};
 d.forensicTrust={...d.forensicTrust,witnesses:d.forensicTrust.witnesses.map(keyToPem),reviewerPolicies:d.forensicTrust.reviewerPolicies.map(policyToPem),reviewerEpochs:d.forensicTrust.reviewerEpochs.map(policyToPem)};
 const json=JSON.stringify({data:d,expectedSessionHead:sessionHead});
 const code=`import {createPublicKey} from 'node:crypto';import {createOfflineAcquisitionSessionJournal} from ${JSON.stringify(modulePath)};const x=JSON.parse(process.argv[2],(k,v)=>v?.__pem?createPublicKey(v.__pem):v);for(const p of [...x.data.forensicTrust.reviewerPolicies,...x.data.forensicTrust.reviewerEpochs])p.reviewers=p.reviewers.map(w=>({...w,readLatest:async()=>null}));const j=createOfflineAcquisitionSessionJournal({directory:process.argv[1],injectFault:stage=>{if(stage===process.argv[3])process.exit(85);}});await j.record({...x.data,expectedSessionHead:x.expectedSessionHead});`;
 return spawnSync(process.execPath,['--input-type=module','-e',code,directory,json,phase],{encoding:'utf8',timeout:15000});
}
test('31M actual child-process crash after durable PRE commit blocks automatic POST and retry',async t=>{
 const f=fixture(),{directory,j}=await session(t),b=await j.begin(beginOpts());
 const p=childRecord({directory,fixtureData:f,sessionHead:sessionPin(b),phase:'after-pre-commit-sync'});
 assert.equal(p.status,85,p.stderr);
 const raw=JSON.parse(await readFile(join(directory,'0002.json'),'utf8'));
 const pin={count:2,headDigest:raw.digest};
 assert.equal((await j.inspect({expectedSessionHead:pin})).status,'PRE_REVIEW_REQUIRED');
 await rejects(()=>j.record({...opts(f),expectedSessionHead:pin}),'ACQUISITION_SESSION_REVIEW_REQUIRED');
 await rejects(()=>j.verify({...opts(f),expectedSessionHead:pin}),'ACQUISITION_SESSION_REVIEW_REQUIRED');
});
test('31M actual child-process crash after POST durable commit permits only pinned diagnostic verification',async t=>{
 const f=fixture(),{directory,j}=await session(t),b=await j.begin(beginOpts());
 const p=childRecord({directory,fixtureData:f,sessionHead:sessionPin(b),phase:'after-post-commit-sync'});
 assert.equal(p.status,85,p.stderr);
 const raw=JSON.parse(await readFile(join(directory,'0003.json'),'utf8'));
 const pin={count:3,headDigest:raw.digest};
 const v=await j.verify({...opts(f),expectedSessionHead:pin});
 assert.equal(v.status,'COMPLETE_DIAGNOSTIC_ONLY');assert.equal(v.mayRetry,false);assert.equal(v.productionApproved,false);
 await rejects(()=>j.record({...opts(f),expectedSessionHead:pin}),'ACQUISITION_SESSION_REVIEW_REQUIRED');
});
test('31M actual child-process crash after POST pending fsync remains fail-closed',async t=>{
 const f=fixture(),{directory,j}=await session(t),b=await j.begin(beginOpts());
 const p=childRecord({directory,fixtureData:f,sessionHead:sessionPin(b),phase:'after-post-pending-sync'});
 assert.equal(p.status,85,p.stderr);
 await rejects(()=>j.inspect({expectedSessionHead:sessionPin(b)}),'ACQUISITION_SESSION_UNCERTAIN_COMMIT');
});
test('31M actual child-process crash after PRE pending fsync blocks inspection and mutation',async t=>{
 const f=fixture(),{directory,j}=await session(t),b=await j.begin(beginOpts());
 const p=childRecord({directory,fixtureData:f,sessionHead:sessionPin(b),phase:'after-pre-pending-sync'});
 assert.equal(p.status,85,p.stderr);
 await rejects(()=>j.inspect({expectedSessionHead:sessionPin(b)}),'ACQUISITION_SESSION_UNCERTAIN_COMMIT');
 await rejects(()=>j.record({...opts(f),expectedSessionHead:sessionPin(b)}),'ACQUISITION_SESSION_UNCERTAIN_COMMIT');
});
test('31M replay of completed manifest cannot mutate single-use session',async t=>{
 const f=fixture(),{j}=await session(t),b=await j.begin(beginOpts());const r=await j.record({...opts(f),expectedSessionHead:sessionPin(b)});
 await rejects(()=>j.record({...opts(f),expectedSessionHead:sessionPin(r)}),'ACQUISITION_SESSION_REVIEW_REQUIRED');
});
test('31M externally substituted forensic head is rejected before PRE staging',async t=>{
 const f=fixture(),{j}=await session(t),b=await j.begin(beginOpts());
 const altered={...heads,forensic:{count:1,headDigest:'a'.repeat(64)}};
 await rejects(()=>j.record({...opts(f),independentPins:altered,expectedSessionHead:sessionPin(b)}),'ACQUISITION_SESSION_BINDING_INVALID');
});
test('31M verified diagnostic fails when independent retention key changes',async t=>{
 const f=fixture(),{j}=await session(t),b=await j.begin(beginOpts()),r=await j.record({...opts(f),expectedSessionHead:sessionPin(b)});
 const rt={...f.retentionTrust,retentionWitnesses:f.retentionTrust.retentionWitnesses.map((w,i)=>i===0?{...w,publicKey:key().publicKey}:w)};
 await rejects(()=>j.verify({...opts(f),retentionTrust:rt,expectedSessionHead:sessionPin(r)}),'ACQUISITION_RECEIPT_SIGNATURE_INVALID');
});
test('31M unknown untracked journal file causes fail-closed history rejection',async t=>{
 const {directory,j}=await session(t),b=await j.begin(beginOpts());await writeFile(join(directory,'untracked.json'),'{}');
 await rejects(()=>j.inspect({expectedSessionHead:sessionPin(b)}),'ACQUISITION_SESSION_HISTORY_INVALID');
});
