import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign,createPublicKey} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {mkdtemp,rm,readFile,writeFile,unlink,symlink,link,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createOfflineAcquisitionCrossSessionIndex} from '../src/offline-acquisition-cross-session-index.mjs';
import {createOfflineAcquisitionSessionJournal} from '../src/offline-acquisition-session-journal.mjs';
import {createOfflineForensicPortableReviewBundle} from '../src/offline-forensic-portable-review.mjs';
import {OFFLINE_ACQUISITION_RECEIPT_SCHEMA,offlineAcquisitionReceiptSigningBytes,createOfflineAcquisitionReceipt,createOfflineForensicAcquisitionManifest} from '../src/offline-forensic-acquisition-provenance.mjs';
const ROOT='0'.repeat(64),zero={count:0,headDigest:ROOT},heads={forensic:zero,publication:zero,outbox:zero};
const key=()=>generateKeyPairSync('ed25519');
const rejects=(fn,code)=>assert.rejects(fn,e=>e?.code===code);
const head=x=>({count:x.count,headDigest:x.headDigest});
const hash=x=>createHash('sha256').update(x).digest('hex');
async function sandbox(t){const directory=await mkdtemp(join(tmpdir(),'tj31n-'));t.after(()=>rm(directory,{recursive:true,force:true}));return {directory,indexDirectory:join(directory,'index'),j:createOfflineAcquisitionCrossSessionIndex({directory:join(directory,'index')})};}
function fixture(){
 const retentionKeys=[key(),key(),key()],reviewKeys=[key(),key()],forensicKeys=[key(),key(),key()];
 const registryId='synthetic-acquisition-31n',anchorType='registry';
 const retentionTrust={registryId,anchorType,retentionWitnesses:retentionKeys.map((k,i)=>({id:`retention-witness-31n-${i}`,publicKey:k.publicKey})),retentionQuorum:2};
 const reviewers=reviewKeys.map((k,i)=>({id:`forensic-reviewer-31n-${i}`,publicKey:k.publicKey,readLatest:async()=>null}));
 const policy={reviewers,quorum:2};
 const forensicTrust={registryId,anchorType,witnesses:forensicKeys.map((k,i)=>({id:`forensic-witness-31n-${i}`,publicKey:k.publicKey})),witnessQuorum:2,reviewerPolicies:[policy],reviewerEpochs:[{startIndex:1,...policy}]};
 const envelope=createOfflineForensicPortableReviewBundle({registryId,anchorType,forensicEvents:[],publications:[],transitionCertificates:[],outboxEvents:[],declaredHeads:heads});
 const receiptHistory=[];
 function addPair(acquisitionId,hs=heads){
  const prior=head(receiptHistory.length?{count:receiptHistory.length,headDigest:receiptHistory.at(-1).digest}:zero);
  for(const phase of ['PRE','POST']){
   const body={schema:OFFLINE_ACQUISITION_RECEIPT_SCHEMA,registryId,anchorType,index:receiptHistory.length+1,previousDigest:receiptHistory.at(-1)?.digest??ROOT,acquisitionId,phase,heads:structuredClone(hs),bundleDigest:phase==='PRE'?ROOT:envelope.transportDigest,observedAt:1700000000000+receiptHistory.length*1000};
   const signatures=retentionKeys.slice(0,2).map((k,i)=>({witnessId:retentionTrust.retentionWitnesses[i].id,signature:sign(null,offlineAcquisitionReceiptSigningBytes(body),k.privateKey).toString('base64url')}));
   receiptHistory.push(createOfflineAcquisitionReceipt({body,signatures}));
  }
  const manifest=createOfflineForensicAcquisitionManifest({acquisitionId,envelope,receiptHistory:structuredClone(receiptHistory)});
  return {manifest,prior,retentionHead:{count:receiptHistory.length,headDigest:receiptHistory.at(-1).digest}};
 }
 return {retentionTrust,forensicTrust,retentionKeys,addPair};
}
async function evidence(root,f,id,hs=heads){
 const {manifest,prior,retentionHead}=f.addPair(id,hs),sessionDirectory=join(root,`session-${id}`);
 const session=createOfflineAcquisitionSessionJournal({directory:sessionDirectory});
 const begin=await session.begin({acquisitionId:id,independentPins:hs,priorRetentionHead:prior,expectedSessionHead:zero});
 const done=await session.record({manifest,independentPins:hs,forensicTrust:f.forensicTrust,retentionTrust:f.retentionTrust,independentRetentionHead:retentionHead,expectedSessionHead:head(begin)});
 return {acquisitionId:id,sessionDirectory,sessionHead:head(done),manifest,independentPins:hs,independentRetentionHead:retentionHead};
}
const opts=(f,p,expectedIndexHead=zero)=>({...p,expectedIndexHead,forensicTrust:f.forensicTrust,retentionTrust:f.retentionTrust});
const validId='acquisition-31n-primary',secondId='acquisition-31n-secondary';

test('31N first signed acquisition is indexed and verified against external index/session/retention pins',async t=>{
 const {directory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId),r=await j.append(opts(f,p));
 assert.equal(r.count,1);assert.equal(r.mayRetry,false);assert.equal(r.productionApproved,false);
 const v=await createOfflineAcquisitionCrossSessionIndex({directory:join(directory,'index')}).verify({expectedIndexHead:head(r),evidence:[p],forensicTrust:f.forensicTrust,retentionTrust:f.retentionTrust});
 assert.equal(v.verified,true);assert.equal(v.mayAcknowledge,false);
});
test('31N two separate complete sessions preserve signed retention continuity',async t=>{
 const {directory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId),a=await j.append(opts(f,p));
 const q=await evidence(directory,f,secondId),b=await j.append(opts(f,q,head(a)));
 assert.equal(b.count,2);assert.equal((await j.verify({expectedIndexHead:head(b),evidence:[p,q],forensicTrust:f.forensicTrust,retentionTrust:f.retentionTrust})).verified,true);
});
test('31N index requires independent external pin for every operation',async t=>{
 const {directory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId);
 await rejects(()=>j.append({...opts(f,p),expectedIndexHead:undefined}),'ACQUISITION_INDEX_EXTERNAL_PIN_REQUIRED');
 await rejects(()=>j.inspect(),'ACQUISITION_INDEX_EXTERNAL_PIN_REQUIRED');
 await rejects(()=>j.verify({evidence:[]}),'ACQUISITION_INDEX_EXTERNAL_PIN_REQUIRED');
});
test('31N stale index compare-and-swap prevents duplicate appends',async t=>{
 const {directory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId);await j.append(opts(f,p));
 await rejects(()=>j.append(opts(f,p)),'ACQUISITION_INDEX_STALE_PIN');
});
test('31N replayed acquisition ID is rejected even with fresh signed retention pair',async t=>{
 const {directory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId),a=await j.append(opts(f,p));
 await rejects(()=>evidence(join(directory,'replay'),f,validId),'ACQUISITION_SNAPSHOT_RACE_OR_REPLAY');assert.equal((await j.inspect({expectedIndexHead:head(a)})).count,1);
});
test('31N index cannot skip a signed intermediate acquisition',async t=>{
 const {directory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId),a=await j.append(opts(f,p));
 f.addPair('acquisition-31n-skipped');const q=await evidence(directory,f,secondId);
 await rejects(()=>j.append(opts(f,q,head(a))),'ACQUISITION_INDEX_RETENTION_GAP');
});
test('31N swapped independent retention head fails signature/pin verification',async t=>{
 const {directory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId);
 await rejects(()=>j.append(opts(f,{...p,independentRetentionHead:{count:2,headDigest:'a'.repeat(64)}})),'ACQUISITION_RETENTION_PIN_INVALID');
 assert.equal((await j.inspect({expectedIndexHead:zero})).count,0);
});
test('31N wrong session pin fails closed before index append',async t=>{
 const {directory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId);
 await rejects(()=>j.append(opts(f,{...p,sessionHead:{count:3,headDigest:'a'.repeat(64)}})),'ACQUISITION_SESSION_PIN_MISMATCH');
});
test('31N missing or incomplete evidence cannot claim independently verified history',async t=>{
 const {directory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId),a=await j.append(opts(f,p));
 await rejects(()=>j.verify({expectedIndexHead:head(a),evidence:[],forensicTrust:f.forensicTrust,retentionTrust:f.retentionTrust}),'ACQUISITION_INDEX_EVIDENCE_INCOMPLETE');
});
test('31N evidence substitution after index commit is detected',async t=>{
 const {directory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId),a=await j.append(opts(f,p));
 const altered={...p,manifest:structuredClone(p.manifest)};altered.manifest.envelope.transportDigest='a'.repeat(64);
 await assert.rejects(()=>j.verify({expectedIndexHead:head(a),evidence:[altered],forensicTrust:f.forensicTrust,retentionTrust:f.retentionTrust}));
});
test('31N reordering complete evidence across acquisitions is rejected',async t=>{
 const {directory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId),a=await j.append(opts(f,p)),q=await evidence(directory,f,secondId),b=await j.append(opts(f,q,head(a)));
 await rejects(()=>j.verify({expectedIndexHead:head(b),evidence:[q,p],forensicTrust:f.forensicTrust,retentionTrust:f.retentionTrust}),'ACQUISITION_INDEX_RETENTION_GAP');
});
test('31N full valid-prefix rollback is detected by independently pinned index head',async t=>{
 const {directory,indexDirectory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId),a=await j.append(opts(f,p)),q=await evidence(directory,f,secondId),b=await j.append(opts(f,q,head(a)));
 await unlink(join(indexDirectory,'0002.json'));await rejects(()=>j.inspect({expectedIndexHead:head(b)}),'ACQUISITION_INDEX_PIN_MISMATCH');
});
test('31N edited index payload is rejected by digest chain',async t=>{
 const {directory,indexDirectory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId),a=await j.append(opts(f,p));
 const file=join(indexDirectory,'0001.json'),e=JSON.parse(await readFile(file,'utf8'));e.payload.acquisitionId='forged-acquisition-31n';await writeFile(file,JSON.stringify(e));
 await rejects(()=>j.inspect({expectedIndexHead:head(a)}),'ACQUISITION_INDEX_HISTORY_INVALID');
});
test('31N symlink substitution is rejected',async t=>{
 const {directory,indexDirectory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId),a=await j.append(opts(f,p));
 await unlink(join(indexDirectory,'0001.json'));await symlink('/etc/passwd',join(indexDirectory,'0001.json'));
 await rejects(()=>j.inspect({expectedIndexHead:head(a)}),'ACQUISITION_INDEX_FILE_UNSAFE');
});
test('31N hardlinked index file is rejected',async t=>{
 const {directory,indexDirectory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId),a=await j.append(opts(f,p));
 await link(join(indexDirectory,'0001.json'),join(directory,'extra-hardlink'));
 await rejects(()=>j.inspect({expectedIndexHead:head(a)}),'ACQUISITION_INDEX_FILE_UNSAFE');
});
test('31N unsafe directory permissions reject append',async t=>{
 const {directory,indexDirectory,j}=await sandbox(t);await j.inspect({expectedIndexHead:zero});await chmod(indexDirectory,0o770);
 await rejects(()=>j.inspect({expectedIndexHead:zero}),'ACQUISITION_INDEX_DIRECTORY_UNSAFE');
});
test('31N concurrent appends serialize and cannot both claim the same index slot',async t=>{
 const {directory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId);
 const r=await Promise.allSettled([j.append(opts(f,p)),j.append(opts(f,p))]);
 assert.equal(r.filter(x=>x.status==='fulfilled').length,1);assert.equal(r.filter(x=>x.status==='rejected').length,1);
});
async function crashedAppend(t,crashPhase){
 const {directory,indexDirectory}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId);
 const mod=fileURLToPath(new URL('../src/offline-acquisition-cross-session-index.mjs',import.meta.url));
 const publicTrust=JSON.stringify({retentionTrust:{...f.retentionTrust,retentionWitnesses:f.retentionTrust.retentionWitnesses.map(w=>({...w,publicKey:w.publicKey.export({type:'spki',format:'pem'})}))},forensicTrust:{...f.forensicTrust,witnesses:f.forensicTrust.witnesses.map(w=>({...w,publicKey:w.publicKey.export({type:'spki',format:'pem'})})),reviewerPolicies:f.forensicTrust.reviewerPolicies.map(pol=>({...pol,reviewers:pol.reviewers.map(w=>({id:w.id,publicKey:w.publicKey.export({type:'spki',format:'pem'})}))})),reviewerEpochs:f.forensicTrust.reviewerEpochs.map(ep=>({...ep,reviewers:ep.reviewers.map(w=>({id:w.id,publicKey:w.publicKey.export({type:'spki',format:'pem'})}))}))}});
 const code=`import {createPublicKey} from 'node:crypto';import {createOfflineAcquisitionCrossSessionIndex} from ${JSON.stringify(mod)};const p=JSON.parse(process.argv[2]),t=JSON.parse(process.argv[3]);for(const w of t.retentionTrust.retentionWitnesses)w.publicKey=createPublicKey(w.publicKey);for(const w of t.forensicTrust.witnesses)w.publicKey=createPublicKey(w.publicKey);for(const pol of [...t.forensicTrust.reviewerPolicies,...t.forensicTrust.reviewerEpochs])for(const w of pol.reviewers){w.publicKey=createPublicKey(w.publicKey);w.readLatest=async()=>null;}const j=createOfflineAcquisitionCrossSessionIndex({directory:process.argv[1],injectFault:phase=>{if(phase===process.argv[4])process.exit(83);}});await j.append({...p,...t,expectedIndexHead:{count:0,headDigest:'0'.repeat(64)}});`;
 const r=spawnSync(process.execPath,['--input-type=module','-e',code,indexDirectory,JSON.stringify(p),publicTrust,crashPhase],{timeout:20000,encoding:'utf8'});
 assert.equal(r.status,83,r.stderr);return {indexDirectory,p,f};
}
test('31N actual child-process crash after pending fsync leaves unrecoverable marker',async t=>{
 const {indexDirectory}=await crashedAppend(t,'after-index-pending-sync');
 await rejects(()=>createOfflineAcquisitionCrossSessionIndex({directory:indexDirectory}).inspect({expectedIndexHead:zero}),'ACQUISITION_INDEX_UNCERTAIN_COMMIT');
});
test('31N actual child-process crash after committed fsync remains independently verifiable',async t=>{
 const {indexDirectory,p,f}=await crashedAppend(t,'after-index-commit-sync');
 const entry=JSON.parse(await readFile(join(indexDirectory,'0001.json'),'utf8'));
 const v=await createOfflineAcquisitionCrossSessionIndex({directory:indexDirectory}).verify({expectedIndexHead:{count:1,headDigest:entry.digest},evidence:[p],forensicTrust:f.forensicTrust,retentionTrust:f.retentionTrust});
 assert.equal(v.verified,true);assert.equal(v.mayRetry,false);assert.equal(v.productionApproved,false);
});
test('31N unknown untracked file rejects history',async t=>{
 const {directory,indexDirectory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId),a=await j.append(opts(f,p));
 await writeFile(join(indexDirectory,'unexpected.txt'),'bad');await rejects(()=>j.inspect({expectedIndexHead:head(a)}),'ACQUISITION_INDEX_HISTORY_INVALID');
});
test('31N forged retention witness key rejects verification despite matching local hash history',async t=>{
 const {directory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId),a=await j.append(opts(f,p));
 const fake={...f.retentionTrust,retentionWitnesses:f.retentionTrust.retentionWitnesses.map((w,i)=>i===0?{...w,publicKey:key().publicKey}:w)};
 await rejects(()=>j.verify({expectedIndexHead:head(a),evidence:[p],forensicTrust:f.forensicTrust,retentionTrust:fake}),'ACQUISITION_RECEIPT_SIGNATURE_INVALID');
});

test('31N rehashed local index cannot hide decreasing forensic head height',async t=>{
 const {directory,indexDirectory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId),a=await j.append(opts(f,p)),q=await evidence(directory,f,secondId);await j.append(opts(f,q,head(a)));
 const path1=join(indexDirectory,'0001.json'),path2=join(indexDirectory,'0002.json');
 const first=JSON.parse(await readFile(path1,'utf8')),second=JSON.parse(await readFile(path2,'utf8'));
 first.payload.forensicHeads.forensic={count:1,headDigest:'a'.repeat(64)};
 const digest=body=>hash(Buffer.from(`TJ-OFFLINE-ACQUISITION-CROSS-SESSION-1\0${JSON.stringify(body)}`));
 const {digest:_,...b1}=first;first.digest=digest(b1);second.previousDigest=first.digest;
 const {digest:__,...b2}=second;second.digest=digest(b2);
 await writeFile(path1,JSON.stringify(first));await writeFile(path2,JSON.stringify(second));
 await rejects(()=>j.inspect({expectedIndexHead:{count:2,headDigest:second.digest}}),'ACQUISITION_INDEX_HEAD_ROLLBACK');
});
test('31N equal-height divergent forensic heads are rejected after local chain rewrite',async t=>{
 const {directory,indexDirectory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId),a=await j.append(opts(f,p)),q=await evidence(directory,f,secondId);await j.append(opts(f,q,head(a)));
 const path1=join(indexDirectory,'0001.json'),path2=join(indexDirectory,'0002.json');
 const first=JSON.parse(await readFile(path1,'utf8')),second=JSON.parse(await readFile(path2,'utf8'));
 first.payload.forensicHeads.forensic={count:1,headDigest:'a'.repeat(64)};
 second.payload.forensicHeads.forensic={count:1,headDigest:'b'.repeat(64)};
 const digest=body=>hash(Buffer.from(`TJ-OFFLINE-ACQUISITION-CROSS-SESSION-1\0${JSON.stringify(body)}`));
 const {digest:_,...b1}=first;first.digest=digest(b1);second.previousDigest=first.digest;
 const {digest:__,...b2}=second;second.digest=digest(b2);
 await writeFile(path1,JSON.stringify(first));await writeFile(path2,JSON.stringify(second));
 await rejects(()=>j.inspect({expectedIndexHead:{count:2,headDigest:second.digest}}),'ACQUISITION_INDEX_HEAD_ROLLBACK');
});
test('31N disappearance of independently pinned session evidence blocks cryptographic verification',async t=>{
 const {directory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId),a=await j.append(opts(f,p));
 await rm(p.sessionDirectory,{recursive:true,force:true});
 await rejects(()=>j.verify({expectedIndexHead:head(a),evidence:[p],forensicTrust:f.forensicTrust,retentionTrust:f.retentionTrust}),'ACQUISITION_SESSION_PIN_MISMATCH');
});
test('31N manifest byte-level substitution is rejected even if its signed contents still validate',async t=>{
 const {directory,j}=await sandbox(t),f=fixture(),p=await evidence(directory,f,validId),a=await j.append(opts(f,p));
 const m=p.manifest,swapped={receiptHistory:m.receiptHistory,envelope:m.envelope,acquisitionId:m.acquisitionId,schema:m.schema};
 await rejects(()=>j.verify({expectedIndexHead:head(a),evidence:[{...p,manifest:swapped}],forensicTrust:f.forensicTrust,retentionTrust:f.retentionTrust}),'ACQUISITION_INDEX_EVIDENCE_MISMATCH');
});
