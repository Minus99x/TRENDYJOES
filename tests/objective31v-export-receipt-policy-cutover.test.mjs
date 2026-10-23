import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign,createPublicKey} from 'node:crypto';
import {mkdtemp,rm,writeFile,readFile,unlink,symlink,link,readdir,chmod} from 'node:fs/promises';
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
const sha=b=>createHash('sha256').update(b).digest('hex');
const root='0'.repeat(64),nowMs=1800000000000,registryId='cutover_registry_31v';
const groups=[0,1].map(epoch=>Array.from({length:3},(_,i)=>({id:`witness_31v_${epoch}_${i}`, ...generateKeyPairSync('ed25519')})));
const policies=groups.map(g=>({witnesses:g.map(k=>({id:k.id,publicKey:k.publicKey})),quorum:2}));
const digests=policies.map(offlineExportReceiptPolicyDigest),zero={count:0,headDigest:root};
const reject=(f,code)=>assert.rejects(f,e=>e?.code===code,code);
const throws=(f,code)=>assert.throws(f,e=>e?.code===code,code);
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
function receipt(epoch,sequence,previousDigest,{acquisitionId=`acquisition_31v_${sequence}_0001`,exportId=`export_31v_${sequence}_0001`,nonce=`nonce_31v_${sequence}_0001`,issuedAt=nowMs-2000,variant=sequence}={}){
 const archiveBytes=archive(acquisitionId,variant);
 const body={schema:OFFLINE_EXPORT_RECEIPT_SCHEMA,registryId,sequence,previousDigest,exportId,acquisitionId,archiveDigest:sha(archiveBytes),archiveBytes:archiveBytes.length,issuedAt,expiresAt:issuedAt+60000,nonce,policyDigest:digests[epoch]};
 const bytes=offlineExportReceiptSigningBytes(body),signatures=groups[epoch].slice(0,2).map(k=>({witnessId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}));
 return {receipt:{body,signatures},archiveBytes};
}
function transition(head,changes={}){
 const body={schema:OFFLINE_EXPORT_WITNESS_TRANSITION_SCHEMA,registryId,fromEpoch:0,toEpoch:1,fromPolicyDigest:digests[0],toPolicyDigest:digests[1],anchorHead:head,issuedAt:nowMs-1000,expiresAt:nowMs+60000,nonce:'nonce_cutover_31v_0001',...changes};
 const bytes=offlineExportWitnessTransitionSigningBytes(body);
 const outgoingSignatures=groups[0].slice(0,2).map(k=>({witnessId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}));
 const incomingProofs=groups[1].map(k=>({witnessId:k.id,signature:sign(null,offlineExportWitnessTransitionPossessionBytes(body,k.id),k.privateKey).toString('base64url')}));
 return {body,outgoingSignatures,incomingProofs};
}
const pin=t=>offlineExportWitnessTransitionChainDigest({transitions:[t]});
async function setup(t,{injectFault}={}){
 const directory=await mkdtemp(join(tmpdir(),'tj31v-'));await chmod(directory,0o700);t.after(()=>rm(directory,{recursive:true,force:true}));
 const old=createOfflineExportReceiptRegistry({directory,registryId,...policies[0]});
 const first=await old.append({...receipt(0,1,root),expectedHead:zero,nowMs});
 const registry=createOfflineExportReceiptCutoverRegistry({directory,registryId,oldPolicy:policies[0],newPolicy:policies[1],injectFault});
 const tr=transition(first.head);return {directory,old,registry,first,tr,digest:pin(tr)};
}
async function activated(t,options){const x=await setup(t,options);const result=await x.registry.cutover({transition:x.tr,expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs});return {...x,result};}
const second=x=>receipt(1,2,x.first.head.headDigest,{issuedAt:nowMs});
const append=x=>x.registry.append({...second(x),expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs});
const cfg=x=>({directory:x.directory,registryId,oldPolicy:policies[0],newPolicy:policies[1]});

test('31V preserves and authenticates original 31S signed receipt during cutover',async t=>{const x=await activated(t);assert.equal(x.result.epoch,1);assert.equal(x.result.head.count,1);assert.equal(x.result.productionApproved,false);});
test('31V accepts signed receipt under incoming witnesses after cutover',async t=>{const x=await activated(t),s=await append(x);assert.equal(s.head.count,2);assert.equal(s.epoch,1);assert.equal((await x.registry.inspect({expectedHead:s.head,expectedTransitionDigest:x.digest,nowMs})).head.headDigest,s.head.headDigest);});
test('31V old 31S registry fails closed after new policy cutover',async t=>{const x=await activated(t);await reject(()=>x.old.inspect({expectedHead:x.first.head}),'EXPORT_REGISTRY_HISTORY_INVALID');});
test('31V no implicit transition trust when external pin missing',async t=>{const x=await activated(t);await reject(()=>x.registry.inspect({expectedHead:x.first.head,nowMs}),'CUTOVER_EXTERNAL_TRANSITION_PIN_REQUIRED');});
test('31V externally pinned transition digest cannot be substituted',async t=>{const x=await activated(t);await reject(()=>x.registry.inspect({expectedHead:x.first.head,expectedTransitionDigest:'f'.repeat(64),nowMs}),'CUTOVER_TRANSITION_PIN_MISMATCH');});
test('31V externally pinned head rejects rollback after append',async t=>{const x=await activated(t);await append(x);await reject(()=>x.registry.inspect({expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),'CUTOVER_STALE_HEAD');});
test('31V retired keys cannot sign a new receipt',async t=>{const x=await activated(t),p=receipt(0,2,x.first.head.headDigest,{issuedAt:nowMs});await reject(()=>x.registry.append({...p,expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),'EXPORT_RECEIPT_POLICY_MISMATCH');});
test('31V detects replayed acquisition across policy boundary',async t=>{const x=await activated(t),p=receipt(1,2,x.first.head.headDigest,{acquisitionId:'acquisition_31v_1_0001',issuedAt:nowMs});await reject(()=>x.registry.append({...p,expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),'CUTOVER_REPLAY');});
test('31V detects reused nonce across policy boundary',async t=>{const x=await activated(t),p=receipt(1,2,x.first.head.headDigest,{nonce:'nonce_31v_1_0001',issuedAt:nowMs});await reject(()=>x.registry.append({...p,expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),'CUTOVER_REPLAY');});
test('31V rejects archive substitution even when receipt signature valid',async t=>{const x=await activated(t),p=second(x);p.archiveBytes=archive(p.receipt.body.acquisitionId,9);await reject(()=>x.registry.append({...p,expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),'ACQUISITION_EXPORT_PIN_MISMATCH');});
test('31V rejects forged outgoing transition quorum',async t=>{const x=await setup(t);x.tr.outgoingSignatures[0].signature='A'.repeat(86);await reject(()=>x.registry.cutover({transition:x.tr,expectedHead:x.first.head,expectedTransitionDigest:pin(x.tr),nowMs}),'CUTOVER_SIGNATURE_INVALID');});
test('31V rejects forged incoming proof of possession',async t=>{const x=await setup(t);x.tr.incomingProofs[1].signature='A'.repeat(86);await reject(()=>x.registry.cutover({transition:x.tr,expectedHead:x.first.head,expectedTransitionDigest:pin(x.tr),nowMs}),'CUTOVER_SIGNATURE_INVALID');});
test('31V rejects cutover with stale external head',async t=>{const x=await setup(t);await reject(()=>x.registry.cutover({transition:x.tr,expectedHead:zero,expectedTransitionDigest:x.digest,nowMs}),'CUTOVER_STALE_HEAD');});
test('31V rejects forged transition pin even when certificate signatures valid',async t=>{const x=await setup(t);await reject(()=>x.registry.cutover({transition:x.tr,expectedHead:x.first.head,expectedTransitionDigest:'f'.repeat(64),nowMs}),'CUTOVER_TRANSITION_PIN_MISMATCH');});
test('31V rejects future cutover certificate',async t=>{const x=await setup(t),tr=transition(x.first.head,{issuedAt:nowMs+100,expiresAt:nowMs+60000});await reject(()=>x.registry.cutover({transition:tr,expectedHead:x.first.head,expectedTransitionDigest:pin(tr),nowMs}),'CUTOVER_EXPIRED_OR_FUTURE');});
test('31V rejects expired cutover certificate',async t=>{const x=await setup(t),tr=transition(x.first.head,{issuedAt:nowMs-61000,expiresAt:nowMs-1000});await reject(()=>x.registry.cutover({transition:tr,expectedHead:x.first.head,expectedTransitionDigest:pin(tr),nowMs}),'CUTOVER_EXPIRED_OR_FUTURE');});
test('31V historical cutover remains verifiable after certificate expiry',async t=>{const x=await activated(t);const y=await x.registry.inspect({expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs:nowMs+70000});assert.equal(y.epoch,1);});
test('31V second cutover attempt fails closed',async t=>{const x=await activated(t);await reject(()=>x.registry.cutover({transition:x.tr,expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),'CUTOVER_EXTERNAL_TRANSITION_PIN_REQUIRED');});
test('31V rejects symlinked cutover certificate',async t=>{const x=await activated(t),p=join(x.directory,'.witness-cutover.json');await unlink(p);await symlink('/etc/hosts',p);await reject(()=>x.registry.inspect({expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),'CUTOVER_FILE_UNSAFE');});
test('31V rejects hardlinked cutover certificate',async t=>{const x=await activated(t),p=join(x.directory,'.witness-cutover.json');await link(p,join(x.directory,'hardlink-test'));await reject(()=>x.registry.inspect({expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),'CUTOVER_HISTORY_INVALID');});
test('31V detects missing committed transition with external pin',async t=>{const x=await activated(t);await unlink(join(x.directory,'.witness-cutover.json'));await reject(()=>x.registry.inspect({expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),'CUTOVER_MISSING_PINNED_TRANSITION');});
test('31V rejects tampered committed certificate despite unchanged external digest',async t=>{const x=await activated(t),p=join(x.directory,'.witness-cutover.json');const c=JSON.parse(await readFile(p,'utf8'));c.transition.body.nonce='tampered_cutover_nonce';await writeFile(p,JSON.stringify(c));await reject(()=>x.registry.inspect({expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),'CUTOVER_SIGNATURE_INVALID');});
test('31V pending cutover after injected fault blocks reads and retries',async t=>{const x=await setup(t,{injectFault:async point=>{if(point==='after-cutover-pending-sync')throw Error('injected-crash');}});await assert.rejects(()=>x.registry.cutover({transition:x.tr,expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),/injected-crash/);await reject(()=>x.registry.inspect({expectedHead:x.first.head,nowMs}),'CUTOVER_UNCERTAIN_COMMIT');});
test('31V committed cutover after injected post-commit fault is independently inspectable',async t=>{const x=await setup(t,{injectFault:async point=>{if(point==='after-cutover-commit-sync')throw Error('injected-crash');}});await assert.rejects(()=>x.registry.cutover({transition:x.tr,expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),/injected-crash/);const r=createOfflineExportReceiptCutoverRegistry(cfg(x));assert.equal((await r.inspect({expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs})).epoch,1);});
test('31V pending rotated append after injected fault blocks all reads',async t=>{const x=await activated(t);const r=createOfflineExportReceiptCutoverRegistry({...cfg(x),injectFault:async point=>{if(point==='after-rotated-append-pending-sync')throw Error('injected-crash');}});await assert.rejects(()=>r.append({...second(x),expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),/injected-crash/);await reject(()=>x.registry.inspect({expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),'CUTOVER_UNCERTAIN_COMMIT');});
test('31V committed rotated append after post-commit fault is independently pinned',async t=>{const x=await activated(t);const r=createOfflineExportReceiptCutoverRegistry({...cfg(x),injectFault:async point=>{if(point==='after-rotated-append-commit-sync')throw Error('injected-crash');}});await assert.rejects(()=>r.append({...second(x),expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),/injected-crash/);const entries=(await readdir(x.directory)).filter(n=>/^\d{4}\.json$/.test(n));assert.equal(entries.length,2);await reject(()=>x.registry.inspect({expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),'CUTOVER_STALE_HEAD');});
test('31V simultaneous writers serialize and only one append succeeds',async t=>{const x=await activated(t),r=createOfflineExportReceiptCutoverRegistry(cfg(x));const a=await Promise.allSettled([append(x),r.append({...second(x),expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs})]);assert.equal(a.filter(v=>v.status==='fulfilled').length,1);assert.equal(a.filter(v=>v.status==='rejected').length,1);assert.equal(a.find(v=>v.status==='rejected').reason.code,'CUTOVER_STALE_HEAD');});
test('31V new policy cannot reuse retired witness identity',()=>{throws(()=>createOfflineExportReceiptCutoverRegistry({directory:'/tmp/tj31v-never',registryId,oldPolicy:policies[0],newPolicy:{witnesses:[{id:groups[0][0].id,publicKey:groups[1][0].publicKey},...policies[1].witnesses.slice(1)],quorum:2}}),'CUTOVER_CONFIGURATION');});

const modulePath=fileURLToPath(new URL('../src/offline-export-receipt-policy-cutover.mjs',import.meta.url));
function crashChild(x,point,operation){
 const serialize=p=>({quorum:p.quorum,witnesses:p.witnesses.map(w=>({id:w.id,pem:w.publicKey.export({format:'pem',type:'spki'})}))});
 const args={directory:x.directory,registryId,oldPolicy:serialize(policies[0]),newPolicy:serialize(policies[1]),point,operation,expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs,transition:x.tr,receipt:second(x).receipt,archive:second(x).archiveBytes.toString('base64')};
 const code=`import {createPublicKey} from 'node:crypto';import {createOfflineExportReceiptCutoverRegistry} from ${JSON.stringify(modulePath)};const x=JSON.parse(process.argv[1]);const policy=p=>({quorum:p.quorum,witnesses:p.witnesses.map(w=>({id:w.id,publicKey:createPublicKey(w.pem)}))});const r=createOfflineExportReceiptCutoverRegistry({directory:x.directory,registryId:x.registryId,oldPolicy:policy(x.oldPolicy),newPolicy:policy(x.newPolicy),injectFault:async at=>{if(at===x.point)process.kill(process.pid,'SIGKILL');}});const a={expectedHead:x.expectedHead,expectedTransitionDigest:x.expectedTransitionDigest,nowMs:x.nowMs};if(x.operation==='cutover')await r.cutover({...a,transition:x.transition});else await r.append({...a,receipt:x.receipt,archiveBytes:Buffer.from(x.archive,'base64')});`;
 return spawnSync(process.execPath,['--input-type=module','-e',code,JSON.stringify(args)],{encoding:'utf8',timeout:15000});
}
test('31V actual child-process SIGKILL before cutover rename leaves fail-closed pending marker',async t=>{const x=await setup(t),r=crashChild(x,'after-cutover-pending-sync','cutover');assert.equal(r.signal,'SIGKILL',r.stderr);await reject(()=>x.registry.inspect({expectedHead:x.first.head,nowMs}),'CUTOVER_UNCERTAIN_COMMIT');});
test('31V actual child-process SIGKILL after cutover fsync leaves verifiable committed policy',async t=>{const x=await setup(t),r=crashChild(x,'after-cutover-commit-sync','cutover');assert.equal(r.signal,'SIGKILL',r.stderr);assert.equal((await x.registry.inspect({expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs})).epoch,1);});
test('31V actual child-process SIGKILL before rotated append rename leaves fail-closed pending marker',async t=>{const x=await activated(t),r=crashChild(x,'after-rotated-append-pending-sync','append');assert.equal(r.signal,'SIGKILL',r.stderr);await reject(()=>x.registry.inspect({expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),'CUTOVER_UNCERTAIN_COMMIT');});
test('31V actual child-process SIGKILL after rotated append fsync prevents stale pinned read',async t=>{const x=await activated(t),r=crashChild(x,'after-rotated-append-commit-sync','append');assert.equal(r.signal,'SIGKILL',r.stderr);await reject(()=>x.registry.inspect({expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),'CUTOVER_STALE_HEAD');});
test('31V actual SIGKILL between hardlink and unlink leaves cutover uncertain, never silently accepted',async t=>{const x=await setup(t),r=crashChild(x,'after-cutover-link-sync','cutover');assert.equal(r.signal,'SIGKILL',r.stderr);await reject(()=>x.registry.inspect({expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),'CUTOVER_UNCERTAIN_COMMIT');});
test('31V actual SIGKILL between hardlink and unlink leaves rotated append uncertain',async t=>{const x=await activated(t),r=crashChild(x,'after-rotated-append-link-sync','append');assert.equal(r.signal,'SIGKILL',r.stderr);await reject(()=>x.registry.inspect({expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),'CUTOVER_UNCERTAIN_COMMIT');});
test('31V detects forged post-cutover receipt signatures',async t=>{const x=await activated(t),p=second(x);p.receipt.signatures[0].signature='A'.repeat(86);await reject(()=>x.registry.append({...p,expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),'EXPORT_RECEIPT_SIGNATURE_INVALID');});
test('31V detects tampered historic receipt after cutover',async t=>{const x=await activated(t),p=join(x.directory,'0001.json'),e=JSON.parse(await readFile(p,'utf8'));e.receipt.body.exportId='tampered_export_31v';await writeFile(p,JSON.stringify(e));await reject(()=>x.registry.inspect({expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),'EXPORT_RECEIPT_SIGNATURE_INVALID');});
test('31V rejects post-cutover receipt signed before policy activation',async t=>{const x=await activated(t),p=receipt(1,2,x.first.head.headDigest,{issuedAt:nowMs-1500});await reject(()=>x.registry.append({...p,expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),'CUTOVER_SEQUENCE_OR_EPOCH_INVALID');});
test('31V rejects duplicate committed receipt even with stale head replay',async t=>{const x=await activated(t);await append(x);await reject(()=>append(x),'CUTOVER_STALE_HEAD');});
test('31V old key material cannot be substituted into incoming witness set',()=>{throws(()=>createOfflineExportReceiptCutoverRegistry({directory:'/tmp/tj31v-never',registryId,oldPolicy:policies[0],newPolicy:{witnesses:[{id:'fresh_id_31v',publicKey:groups[0][0].publicKey},...policies[1].witnesses.slice(1)],quorum:2}}),'CUTOVER_CONFIGURATION');});
test('31V two independent Node processes racing same receipt serialize under shared OS flock',async t=>{
 const x=await activated(t);
 const serialize=p=>({quorum:p.quorum,witnesses:p.witnesses.map(w=>({id:w.id,pem:w.publicKey.export({format:'pem',type:'spki'})}))});
 const a={directory:x.directory,registryId,oldPolicy:serialize(policies[0]),newPolicy:serialize(policies[1]),expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs,receipt:second(x).receipt,archive:second(x).archiveBytes.toString('base64')};
 const code=`import {createPublicKey} from 'node:crypto';import {createOfflineExportReceiptCutoverRegistry} from ${JSON.stringify(modulePath)};const x=JSON.parse(process.argv[1]);const p=v=>({quorum:v.quorum,witnesses:v.witnesses.map(w=>({id:w.id,publicKey:createPublicKey(w.pem)}))});const r=createOfflineExportReceiptCutoverRegistry({directory:x.directory,registryId:x.registryId,oldPolicy:p(x.oldPolicy),newPolicy:p(x.newPolicy)});try{await r.append({receipt:x.receipt,archiveBytes:Buffer.from(x.archive,'base64'),expectedHead:x.expectedHead,expectedTransitionDigest:x.expectedTransitionDigest,nowMs:x.nowMs});process.stdout.write('OK');}catch(e){process.stdout.write(e.code||'UNKNOWN');process.exitCode=2;}`;
 const launch=()=>new Promise((ok,no)=>{const c=spawn(process.execPath,['--input-type=module','-e',code,JSON.stringify(a)],{stdio:['ignore','pipe','pipe']});let out='',err='';c.stdout.on('data',b=>out+=b);c.stderr.on('data',b=>err+=b);c.once('error',no);c.once('close',(code,signal)=>ok({code,signal,out,err}));});
 const results=await Promise.all([launch(),launch()]);assert.equal(results.filter(r=>r.code===0&&r.out==='OK').length,1,JSON.stringify(results));assert.equal(results.filter(r=>r.code===2&&r.out==='CUTOVER_STALE_HEAD').length,1,JSON.stringify(results));
});
