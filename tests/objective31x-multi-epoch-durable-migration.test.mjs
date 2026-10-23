import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign,createPublicKey} from 'node:crypto';
import {mkdtemp,rm,readFile,writeFile,unlink,symlink,link,chmod,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync,spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {OFFLINE_ACQUISITION_EXPORT_SCHEMA} from '../src/offline-acquisition-evidence-export.mjs';
import {OFFLINE_ACQUISITION_SESSION_SCHEMA} from '../src/offline-acquisition-session-journal.mjs';
import {OFFLINE_ACQUISITION_MANIFEST_SCHEMA} from '../src/offline-forensic-acquisition-provenance.mjs';
import {createOfflineExportReceiptRegistry,OFFLINE_EXPORT_RECEIPT_SCHEMA,offlineExportReceiptPolicyDigest,offlineExportReceiptSigningBytes} from '../src/offline-acquisition-export-receipt-registry.mjs';
import {OFFLINE_EXPORT_WITNESS_TRANSITION_SCHEMA,offlineExportWitnessTransitionSigningBytes,offlineExportWitnessTransitionPossessionBytes,offlineExportWitnessTransitionChainDigest} from '../src/offline-export-receipt-witness-rotation.mjs';
import {createOfflineExportReceiptCutoverRegistry} from '../src/offline-export-receipt-policy-cutover.mjs';
import {createOfflineMultiEpochExportReceiptRegistry} from '../src/offline-export-receipt-multi-epoch-registry.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const root='0'.repeat(64),now=1800000000000,registryId='multi_epoch_registry_31x',zero={count:0,headDigest:root};
const groups=[0,1,2,3].map(epoch=>Array.from({length:3},(_,i)=>({id:`witness_31x_${epoch}_${i}`,...generateKeyPairSync('ed25519')})));
const policies=groups.map(g=>({witnesses:g.map(k=>({id:k.id,publicKey:k.publicKey})),quorum:2}));
const digests=policies.map(offlineExportReceiptPolicyDigest);
const reject=(f,code)=>assert.rejects(f,e=>e?.code===code,code);
function archive(acquisitionId,variant=1){
 const pre={phase:'PRE',acquisitionId},post={phase:'POST',acquisitionId};
 const manifest={schema:OFFLINE_ACQUISITION_MANIFEST_SCHEMA,acquisitionId,envelope:{transportDigest:'a'.repeat(64)},receiptHistory:[pre,post]};
 let previous=root;const events=[];
 for(const [i,action,payload] of [[1,'BEGIN',{acquisitionId}],[2,'PRE',pre],[3,'POST',manifest]]){
  const body={schema:OFFLINE_ACQUISITION_SESSION_SCHEMA,index:i,previousDigest:previous,action,payload};
  const e={...body,digest:sha(Buffer.from(`${OFFLINE_ACQUISITION_SESSION_SCHEMA}\0${JSON.stringify(body)}`))};previous=e.digest;events.push(e);
 }
 const files=new Map([['manifest.json',manifest],['session/0001.json',events[0]],['session/0002.json',events[1]],['session/0003.json',events[2]],['evidence/branch_01.json',{variant}]]);
 const entries=[],payload=[];let offset=0;
 for(const [path,value] of [...files].sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0)){
  const bytes=Buffer.from(JSON.stringify(value));entries.push({path,offset,size:bytes.length,sha256:sha(bytes)});payload.push(bytes);offset+=bytes.length;
 }
 const body=Buffer.concat(payload),header=Buffer.from(JSON.stringify({schema:OFFLINE_ACQUISITION_EXPORT_SCHEMA,acquisitionId,files:entries,payloadBytes:body.length,payloadDigest:sha(body)}));
 const len=Buffer.alloc(4);len.writeUInt32BE(header.length);
 return Buffer.concat([Buffer.from(`${OFFLINE_ACQUISITION_EXPORT_SCHEMA}\n`),len,header,body]);
}
function receipt(epoch,sequence,previousDigest,{issuedAt=now-4000,acquisitionId=`acquisition_31x_${sequence}_0001`,exportId=`export_31x_${sequence}_0001`,nonce=`nonce_31x_${sequence}_0001`,variant=sequence}={}){
 const archiveBytes=archive(acquisitionId,variant);
 const body={schema:OFFLINE_EXPORT_RECEIPT_SCHEMA,registryId,sequence,previousDigest,exportId,acquisitionId,archiveDigest:sha(archiveBytes),archiveBytes:archiveBytes.length,issuedAt,expiresAt:issuedAt+60000,nonce,policyDigest:digests[epoch]};
 const bytes=offlineExportReceiptSigningBytes(body);
 const signatures=groups[epoch].slice(0,2).map(k=>({witnessId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}));
 return {receipt:{body,signatures},archiveBytes};
}
function transition(epoch,anchor,issuedAt=now-3000,changes={}){
 const body={schema:OFFLINE_EXPORT_WITNESS_TRANSITION_SCHEMA,registryId,fromEpoch:epoch-1,toEpoch:epoch,fromPolicyDigest:digests[epoch-1],toPolicyDigest:digests[epoch],anchorHead:anchor,issuedAt,expiresAt:issuedAt+60000,nonce:`nonce_multi_epoch_${epoch}_0001`,...changes};
 const bytes=offlineExportWitnessTransitionSigningBytes(body);
 const outgoingSignatures=groups[epoch-1].slice(0,2).map(k=>({witnessId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}));
 const incomingProofs=groups[epoch].map(k=>({witnessId:k.id,signature:sign(null,offlineExportWitnessTransitionPossessionBytes(body,k.id),k.privateKey).toString('base64url')}));
 return {body,outgoingSignatures,incomingProofs};
}
const pin=ts=>offlineExportWitnessTransitionChainDigest({transitions:ts});
const config=x=>({directory:x.directory,registryId,policies});
async function setup(t){
 const directory=await mkdtemp(join(tmpdir(),'tj31x-'));await chmod(directory,0o700);t.after(()=>rm(directory,{recursive:true,force:true}));
 const original=createOfflineExportReceiptRegistry({directory,registryId,...policies[0]});
 const first=await original.append({...receipt(0,1,root),expectedHead:zero,nowMs:now});
 const legacy=createOfflineExportReceiptCutoverRegistry({directory,registryId,oldPolicy:policies[0],newPolicy:policies[1]});
 const t1=transition(1,first.head),p1=pin([t1]);
 await legacy.cutover({transition:t1,expectedHead:first.head,expectedTransitionDigest:p1,nowMs:now});
 const second=await legacy.append({...receipt(1,2,first.head.headDigest,{issuedAt:now-2000}),expectedHead:first.head,expectedTransitionDigest:p1,nowMs:now});
 const multi=createOfflineMultiEpochExportReceiptRegistry({directory,registryId,policies});
 const t2=transition(2,second.head,now-1000),p2=pin([t1,t2]);
 return {directory,original,legacy,multi,first,second,t1,t2,p1,p2};
}
async function migrated(t){const x=await setup(t);const state=await x.multi.rotate({transition:x.t2,expectedHead:x.second.head,expectedTransitionDigest:x.p1,expectedNewTransitionDigest:x.p2,expectedEpoch:1,nowMs:now});return {...x,state};}
const inspect1=x=>x.multi.inspect({expectedHead:x.second.head,expectedTransitionDigest:x.p1,expectedEpoch:1,nowMs:now});
const inspect2=x=>x.multi.inspect({expectedHead:x.second.head,expectedTransitionDigest:x.p2,expectedEpoch:2,nowMs:now});
const append3=x=>x.multi.append({...receipt(2,3,x.second.head.headDigest,{issuedAt:now}),expectedHead:x.second.head,expectedTransitionDigest:x.p2,expectedEpoch:2,nowMs:now});
const rotate2=x=>x.multi.rotate({transition:x.t2,expectedHead:x.second.head,expectedTransitionDigest:x.p1,expectedNewTransitionDigest:x.p2,expectedEpoch:1,nowMs:now});
const cert2=x=>join(x.directory,'.witness-cutover-0002.json');
const pending=x=>join(x.directory,'.pending-multi-cutover.json');
const modulePath=fileURLToPath(new URL('../src/offline-export-receipt-multi-epoch-registry.mjs',import.meta.url));
const serialize=p=>({quorum:p.quorum,witnesses:p.witnesses.map(w=>({id:w.id,pem:w.publicKey.export({format:'pem',type:'spki'})}))});
const childCode=`import {createPublicKey} from 'node:crypto';import {createOfflineMultiEpochExportReceiptRegistry} from ${JSON.stringify(modulePath)};const a=JSON.parse(process.argv[1]);const policies=a.policies.map(p=>({quorum:p.quorum,witnesses:p.witnesses.map(w=>({id:w.id,publicKey:createPublicKey(w.pem)}))}));const r=createOfflineMultiEpochExportReceiptRegistry({directory:a.directory,registryId:a.registryId,policies,injectFault:async at=>{if(at===a.crash)process.kill(process.pid,'SIGKILL');}});try{await r.rotate(a.args);process.stdout.write('OK');}catch(e){process.stdout.write(e.code||'UNKNOWN');process.exitCode=2;}`;
const childArgs=(x,crash)=>({directory:x.directory,registryId,policies:policies.map(serialize),crash,args:{transition:x.t2,expectedHead:x.second.head,expectedTransitionDigest:x.p1,expectedNewTransitionDigest:x.p2,expectedEpoch:1,nowMs:now}});

// Each fixture starts from actual 31V durable receipts and its signed epoch-1 certificate.
test('31X verifies genuine 31V migration baseline before any new cutover',async t=>{const x=await setup(t);const s=await inspect1(x);assert.equal(s.epoch,1);assert.equal(s.head.count,2);assert.equal(s.transitionDigest,x.p1);assert.equal(s.productionApproved,false);});
test('31X commits epoch-2 certificate without rewriting 31V files',async t=>{const x=await setup(t),before=await readFile(join(x.directory,'.witness-cutover.json'));const s=await rotate2(x);assert.equal(s.epoch,2);assert.equal(s.head.count,2);assert.deepEqual(await readFile(join(x.directory,'.witness-cutover.json')),before);assert.equal((await inspect2(x)).epoch,2);});
test('31X appends an epoch-2 receipt, validates archive and keeps all historical epochs',async t=>{const x=await migrated(t);const a=await append3(x);assert.equal(a.head.count,3);assert.equal((await x.multi.inspect({expectedHead:a.head,expectedTransitionDigest:x.p2,expectedEpoch:2,nowMs:now})).epoch,2);});
test('31X persists three successive witness rotations (epochs 0,1,2,3)',async t=>{
 const x=await migrated(t),a=await append3(x),t3=transition(3,a.head,now+1000),p3=pin([x.t1,x.t2,t3]);
 const r=await x.multi.rotate({transition:t3,expectedHead:a.head,expectedTransitionDigest:x.p2,expectedNewTransitionDigest:p3,expectedEpoch:2,nowMs:now+2000});
 assert.equal(r.epoch,3);assert.equal(r.transitionDigest,p3);
 const last=await x.multi.append({...receipt(3,4,a.head.headDigest,{issuedAt:now+2000}),expectedHead:a.head,expectedTransitionDigest:p3,expectedEpoch:3,nowMs:now+2000});
 assert.equal(last.head.count,4);assert.equal((await x.multi.inspect({expectedHead:last.head,expectedTransitionDigest:p3,expectedEpoch:3,nowMs:now+2000})).epoch,3);
});
test('31X rejects missing external transition-chain pin',async t=>{const x=await setup(t);await reject(()=>x.multi.rotate({transition:x.t2,expectedHead:x.second.head,expectedEpoch:1,expectedNewTransitionDigest:x.p2,nowMs:now}),'MULTI_EPOCH_EXTERNAL_PINS_REQUIRED');});
test('31X rejects substituted prior transition pin',async t=>{const x=await setup(t);await reject(()=>x.multi.rotate({transition:x.t2,expectedHead:x.second.head,expectedEpoch:1,expectedTransitionDigest:'f'.repeat(64),expectedNewTransitionDigest:x.p2,nowMs:now}),'MULTI_EPOCH_TRANSITION_PIN_MISMATCH');});
test('31X rejects forged new chain pin without writing pending state',async t=>{const x=await setup(t);await reject(()=>x.multi.rotate({transition:x.t2,expectedHead:x.second.head,expectedEpoch:1,expectedTransitionDigest:x.p1,expectedNewTransitionDigest:'f'.repeat(64),nowMs:now}),'MULTI_EPOCH_NEW_CHAIN_PIN_MISMATCH');assert.ok(!(await readdir(x.directory)).includes('.pending-multi-cutover.json'));});
test('31X rejects stale receipt head',async t=>{const x=await setup(t);await reject(()=>x.multi.rotate({transition:x.t2,expectedHead:x.first.head,expectedEpoch:1,expectedTransitionDigest:x.p1,expectedNewTransitionDigest:x.p2,nowMs:now}),'MULTI_EPOCH_STALE_HEAD');});
test('31X rejects altered transition body despite genuine signatures',async t=>{const x=await setup(t),bad=structuredClone(x.t2);bad.body.nonce='nonce_multi_epoch_2_forged';await reject(()=>x.multi.rotate({transition:bad,expectedHead:x.second.head,expectedEpoch:1,expectedTransitionDigest:x.p1,expectedNewTransitionDigest:pin([x.t1,bad]),nowMs:now}),'MULTI_EPOCH_SIGNATURE_INVALID');});
test('31X rejects transition from wrong epoch',async t=>{const x=await setup(t),bad=transition(3,x.second.head,now-1000);await reject(()=>x.multi.rotate({transition:bad,expectedHead:x.second.head,expectedEpoch:1,expectedTransitionDigest:x.p1,expectedNewTransitionDigest:pin([x.t1,bad]),nowMs:now}),'MULTI_EPOCH_TRANSITION_INVALID');});
test('31X rejects forged outgoing witness signatures',async t=>{const x=await setup(t),bad=structuredClone(x.t2);bad.outgoingSignatures[0].signature='A'.repeat(86);await reject(()=>x.multi.rotate({transition:bad,expectedHead:x.second.head,expectedEpoch:1,expectedTransitionDigest:x.p1,expectedNewTransitionDigest:pin([x.t1,bad]),nowMs:now}),'MULTI_EPOCH_SIGNATURE_INVALID');});
test('31X rejects forged incoming proof of possession',async t=>{const x=await setup(t),bad=structuredClone(x.t2);bad.incomingProofs[0].signature='A'.repeat(86);await reject(()=>x.multi.rotate({transition:bad,expectedHead:x.second.head,expectedEpoch:1,expectedTransitionDigest:x.p1,expectedNewTransitionDigest:pin([x.t1,bad]),nowMs:now}),'MULTI_EPOCH_SIGNATURE_INVALID');});
test('31X rejects reused witness keys across nonadjacent epochs',async t=>{const x=await setup(t),bad=[...policies.slice(0,3),policies[0]];assert.throws(()=>createOfflineMultiEpochExportReceiptRegistry({...config(x),policies:bad}),e=>e.code==='MULTI_EPOCH_RETIRED_KEY_REUSE');});
test('31X rejects rollback to earlier externally pinned epoch after cutover',async t=>{const x=await migrated(t);await reject(()=>inspect1(x),'MULTI_EPOCH_UNPINNED_TRANSITION');});
test('31X rejects forged certificate file after durable cutover',async t=>{const x=await migrated(t),p=cert2(x),v=JSON.parse(await readFile(p));v.transition.body.nonce='forged_certificate_0001';await writeFile(p,JSON.stringify(v));await reject(()=>inspect2(x),'MULTI_EPOCH_SIGNATURE_INVALID');});
test('31X rejects symlink replacement of a durable certificate',async t=>{const x=await migrated(t),p=cert2(x);await unlink(p);await symlink('/etc/hosts',p);await reject(()=>inspect2(x),'MULTI_EPOCH_FILE_UNSAFE');});
test('31X rejects hardlink injection on certificate',async t=>{const x=await migrated(t);await link(cert2(x),join(x.directory,'foreign-hardlink'));await reject(()=>inspect2(x),'MULTI_EPOCH_FILE_UNSAFE');});
test('31X rejects tampered historical receipt even with unchanged signed policy chain',async t=>{const x=await migrated(t),p=join(x.directory,'0001.json'),v=JSON.parse(await readFile(p));v.receipt.body.exportId='forged_historical_export';await writeFile(p,JSON.stringify(v));await reject(()=>inspect2(x),'EXPORT_RECEIPT_SIGNATURE_INVALID');});
test('31X rejects active epoch-2 receipt signed with retired epoch-1 witnesses',async t=>{const x=await migrated(t),r=receipt(1,3,x.second.head.headDigest,{issuedAt:now});await reject(()=>x.multi.append({...r,expectedHead:x.second.head,expectedTransitionDigest:x.p2,expectedEpoch:2,nowMs:now}),'EXPORT_RECEIPT_POLICY_MISMATCH');});
test('31X rejects missing archive bytes and substituted archive content',async t=>{const x=await migrated(t),r=receipt(2,3,x.second.head.headDigest,{issuedAt:now});await reject(()=>x.multi.append({...r,archiveBytes:Buffer.from('wrong'),expectedHead:x.second.head,expectedTransitionDigest:x.p2,expectedEpoch:2,nowMs:now}),'MULTI_EPOCH_ARCHIVE_SIZE_MISMATCH');});
test('31X rejects stale append and duplicate export after successful epoch-2 append',async t=>{const x=await migrated(t),a=await append3(x);await reject(()=>append3(x),'MULTI_EPOCH_STALE_HEAD');await reject(()=>x.multi.append({...receipt(2,4,a.head.headDigest,{issuedAt:now,exportId:'export_31x_3_0001'}),expectedHead:a.head,expectedTransitionDigest:x.p2,expectedEpoch:2,nowMs:now}),'MULTI_EPOCH_REPLAY');});
test('31X actual SIGKILL after durable pending fsync fails closed without mutating 31V history',async t=>{const x=await setup(t),r=spawnSync(process.execPath,['--input-type=module','-e',childCode,JSON.stringify(childArgs(x,'after-multi-pending-sync'))],{encoding:'utf8',timeout:15000});assert.equal(r.signal,'SIGKILL',r.stderr);assert.ok((await readdir(x.directory)).includes('.pending-multi-cutover.json'));await reject(()=>inspect1(x),'MULTI_EPOCH_UNCERTAIN_COMMIT');assert.ok(!(await readdir(x.directory)).includes('.witness-cutover-0002.json'));});
test('31X actual SIGKILL after hardlink fsync blocks unsafe automatic recovery',async t=>{const x=await setup(t),r=spawnSync(process.execPath,['--input-type=module','-e',childCode,JSON.stringify(childArgs(x,'after-multi-link-sync'))],{encoding:'utf8',timeout:15000});assert.equal(r.signal,'SIGKILL',r.stderr);assert.ok((await readdir(x.directory)).includes('.pending-multi-cutover.json'));assert.ok((await readdir(x.directory)).includes('.witness-cutover-0002.json'));await reject(()=>inspect2(x),'MULTI_EPOCH_UNCERTAIN_COMMIT');});
test('31X two independent processes serialize competing epoch-2 cutovers',async t=>{
 const x=await setup(t),args=JSON.stringify(childArgs(x,null));
 const launch=()=>new Promise((ok,no)=>{const c=spawn(process.execPath,['--input-type=module','-e',childCode,args],{stdio:['ignore','pipe','pipe']});let out='',err='';c.stdout.on('data',b=>out+=b);c.stderr.on('data',b=>err+=b);c.once('error',no);c.once('close',(code,signal)=>ok({code,signal,out,err}));});
 const results=await Promise.all([launch(),launch()]);assert.equal(results.filter(r=>r.code===0&&r.out==='OK').length,1,JSON.stringify(results));assert.equal(results.filter(r=>r.code===2&&r.out==='MULTI_EPOCH_UNPINNED_TRANSITION').length,1,JSON.stringify(results));assert.equal((await inspect2(x)).epoch,2);
});
test('31X snapshots configured witness keys against later caller mutation',async t=>{
 const x=await setup(t),cloned=policies.map(p=>({quorum:p.quorum,witnesses:p.witnesses.map(w=>({...w}))}));
 const reg=createOfflineMultiEpochExportReceiptRegistry({...config(x),policies:cloned});
 cloned[1].witnesses[0].publicKey=groups[2][0].publicKey;cloned[1].quorum=3;
 assert.equal((await reg.inspect({expectedHead:x.second.head,expectedTransitionDigest:x.p1,expectedEpoch:1,nowMs:now})).epoch,1);
});
test('31X fails closed on unknown pending append marker',async t=>{const x=await setup(t);await writeFile(join(x.directory,'.pending.json'),'{}',{mode:0o600});await reject(()=>inspect1(x),'MULTI_EPOCH_UNCERTAIN_COMMIT');});
test('31X rejects a missing intermediate epoch-2 certificate even with later epoch present',async t=>{
 const x=await migrated(t),a=await append3(x),t3=transition(3,a.head,now+1000),p3=pin([x.t1,x.t2,t3]);
 await x.multi.rotate({transition:t3,expectedHead:a.head,expectedTransitionDigest:x.p2,expectedNewTransitionDigest:p3,expectedEpoch:2,nowMs:now+2000});
 await unlink(cert2(x));
 await reject(()=>x.multi.inspect({expectedHead:a.head,expectedTransitionDigest:p3,expectedEpoch:3,nowMs:now+2000}),'MULTI_EPOCH_MISSING_TRANSITION');
});
test('31X rejects changed durable chain digest despite valid signed certificate',async t=>{const x=await migrated(t),p=cert2(x),v=JSON.parse(await readFile(p));v.transitionDigest='f'.repeat(64);await writeFile(p,JSON.stringify(v));await reject(()=>inspect2(x),'MULTI_EPOCH_CERTIFICATE_CHAIN_INVALID');});
test('31X rejects world-readable witness certificates',async t=>{const x=await migrated(t);await chmod(cert2(x),0o644);await reject(()=>inspect2(x),'MULTI_EPOCH_FILE_UNSAFE');});
test('31X rejects expired rotation before writing a durable marker',async t=>{const x=await setup(t);await reject(()=>x.multi.rotate({transition:x.t2,expectedHead:x.second.head,expectedTransitionDigest:x.p1,expectedNewTransitionDigest:x.p2,expectedEpoch:1,nowMs:now+60000}),'MULTI_EPOCH_TRANSITION_INVALID');assert.ok(!(await readdir(x.directory)).includes('.pending-multi-cutover.json'));});
test('31X refuses wrong acquisition archive with valid length',async t=>{const x=await migrated(t),r=receipt(2,3,x.second.head.headDigest,{issuedAt:now});const wrong=Buffer.from(r.archiveBytes);wrong[wrong.length-1]^=1;await reject(()=>x.multi.append({...r,archiveBytes:wrong,expectedHead:x.second.head,expectedTransitionDigest:x.p2,expectedEpoch:2,nowMs:now}),'ACQUISITION_EXPORT_PIN_MISMATCH');});
test('31X rejects forged prior-epoch witness signature on a historical receipt',async t=>{const x=await migrated(t),p=join(x.directory,'0002.json'),v=JSON.parse(await readFile(p));v.receipt.signatures[0].signature='A'.repeat(86);await writeFile(p,JSON.stringify(v));await reject(()=>inspect2(x),'EXPORT_RECEIPT_SIGNATURE_INVALID');});
