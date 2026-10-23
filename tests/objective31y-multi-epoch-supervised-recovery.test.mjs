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
import {createOfflineExportReceiptRegistry,OFFLINE_EXPORT_REGISTRY_SCHEMA,OFFLINE_EXPORT_RECEIPT_SCHEMA,offlineExportReceiptPolicyDigest,offlineExportReceiptSigningBytes} from '../src/offline-acquisition-export-receipt-registry.mjs';
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


const digestPending=async(x,kind='cutover')=>sha(await readFile(join(x.directory,kind==='cutover'?'.pending-multi-cutover.json':'.pending.json')));
const afterCutover=x=>({kind:'cutover',decision:'finalize-linked',expectedBeforeHead:x.second.head,expectedAfterHead:x.second.head,
 expectedBeforeTransitionDigest:x.p1,expectedAfterTransitionDigest:x.p2,expectedBeforeEpoch:1,expectedAfterEpoch:2,nowMs:now});
const abortCutover=x=>({...afterCutover(x),decision:'abort-unlinked'});
const afterAppend=(x,receiptData)=>({kind:'append',decision:'finalize-linked',expectedBeforeHead:x.second.head,
 expectedAfterHead:{count:3,headDigest:sha(Buffer.from(`${OFFLINE_EXPORT_REGISTRY_SCHEMA}\0${JSON.stringify({schema:OFFLINE_EXPORT_REGISTRY_SCHEMA,index:3,previousDigest:x.second.head.headDigest,receipt:receiptData.receipt})}`))},
 expectedBeforeTransitionDigest:x.p2,expectedAfterTransitionDigest:x.p2,expectedBeforeEpoch:2,expectedAfterEpoch:2,nowMs:now});
const appendChildCode=`import {createPublicKey} from 'node:crypto';import {createOfflineMultiEpochExportReceiptRegistry} from ${JSON.stringify(modulePath)};const a=JSON.parse(process.argv[1]);const policies=a.policies.map(p=>({quorum:p.quorum,witnesses:p.witnesses.map(w=>({id:w.id,publicKey:createPublicKey(w.pem)}))}));const r=createOfflineMultiEpochExportReceiptRegistry({directory:a.directory,registryId:a.registryId,policies,injectFault:async at=>{if(at===a.crash)process.kill(process.pid,'SIGKILL');}});try{await r.append({...a.args,archiveBytes:Buffer.from(a.archive,'base64')});process.stdout.write('OK');}catch(e){process.stdout.write(e.code||'UNKNOWN');process.exitCode=2;}`;
const recoverChildCode=`import {createPublicKey} from 'node:crypto';import {createOfflineMultiEpochExportReceiptRegistry} from ${JSON.stringify(modulePath)};const a=JSON.parse(process.argv[1]);const policies=a.policies.map(p=>({quorum:p.quorum,witnesses:p.witnesses.map(w=>({id:w.id,publicKey:createPublicKey(w.pem)}))}));const r=createOfflineMultiEpochExportReceiptRegistry({directory:a.directory,registryId:a.registryId,policies});try{await r.reconcilePending(a.args);process.stdout.write('OK');}catch(e){process.stdout.write(e.code||'UNKNOWN');process.exitCode=2;}`;
async function cutoverCrash(t,phase='after-multi-pending-sync'){
 const x=await setup(t),r=spawnSync(process.execPath,['--input-type=module','-e',childCode,JSON.stringify(childArgs(x,phase))],{encoding:'utf8',timeout:15000});
 assert.equal(r.signal,'SIGKILL',JSON.stringify(r));return {...x,expectedPendingDigest:await digestPending(x)};
}
async function appendCrash(t,phase='after-multi-append-pending-sync'){
 const x=await migrated(t),r=receipt(2,3,x.second.head.headDigest,{issuedAt:now});
 const args={receipt:r.receipt,expectedHead:x.second.head,expectedTransitionDigest:x.p2,expectedEpoch:2,nowMs:now};
 const payload={directory:x.directory,registryId,policies:policies.map(serialize),crash:phase,args,archive:r.archiveBytes.toString('base64')};
 const child=spawnSync(process.execPath,['--input-type=module','-e',appendChildCode,JSON.stringify(payload)],{encoding:'utf8',timeout:15000});
 assert.equal(child.signal,'SIGKILL',JSON.stringify(child));
 return {...x,r,expectedPendingDigest:await digestPending(x,'append')};
}
const recover=(x,args)=>x.multi.reconcilePending({...args,expectedPendingDigest:args.expectedPendingDigest??x.expectedPendingDigest});
const appendPins=x=>afterAppend(x,x.r);

// Genuine SIGKILL scenarios: pending fsync vs hardlink fsync are different
// durable outcomes. Recovery must never synthesize a missing destination.
test('31Y actual SIGKILL before cutover hardlink: externally pinned abort then clean retry',async t=>{
 const x=await cutoverCrash(t);await reject(()=>inspect1(x),'MULTI_EPOCH_UNCERTAIN_COMMIT');
 const s=await recover(x,abortCutover(x));assert.equal(s.status,'EXTERNALLY_PINNED_MULTI_ABORT_OFFLINE_ONLY');
 assert.equal((await inspect1(x)).epoch,1);assert.equal((await rotate2(x)).epoch,2);
});
test('31Y actual SIGKILL after cutover hardlink: independently pinned finalize',async t=>{
 const x=await cutoverCrash(t,'after-multi-link-sync');await reject(()=>inspect2(x),'MULTI_EPOCH_UNCERTAIN_COMMIT');
 const s=await recover(x,afterCutover(x));assert.equal(s.status,'EXTERNALLY_PINNED_MULTI_FINALIZATION_OFFLINE_ONLY');
 assert.equal((await inspect2(x)).epoch,2);assert.ok(!(await readdir(x.directory)).includes('.pending-multi-cutover.json'));
});
test('31Y actual SIGKILL before append hardlink: abort leaves history and permits retry',async t=>{
 const x=await appendCrash(t),args={...appendPins(x),decision:'abort-unlinked'};
 await reject(()=>x.multi.inspect({expectedHead:x.second.head,expectedTransitionDigest:x.p2,expectedEpoch:2,nowMs:now}),'MULTI_EPOCH_UNCERTAIN_COMMIT');
 const s=await recover(x,args);assert.equal(s.head.count,2);
 assert.equal((await append3(x)).head.count,3);
});
test('31Y actual SIGKILL after append hardlink: finalize keeps authenticated receipt',async t=>{
 const x=await appendCrash(t,'after-multi-append-link-sync'),args=appendPins(x);
 const s=await recover(x,args);assert.deepEqual(s.head,args.expectedAfterHead);
 assert.deepEqual((await x.multi.inspect({expectedHead:s.head,expectedTransitionDigest:x.p2,expectedEpoch:2,nowMs:now})).head,s.head);
});
test('31Y refuses wrong pending hash and preserves crash marker',async t=>{
 const x=await cutoverCrash(t);await reject(()=>recover(x,{...abortCutover(x),expectedPendingDigest:'f'.repeat(64)}),'MULTI_EPOCH_RECOVERY_PENDING_PIN_MISMATCH');
 assert.ok((await readdir(x.directory)).includes('.pending-multi-cutover.json'));
});
test('31Y refuses incorrect prior transition pin',async t=>{
 const x=await cutoverCrash(t);await reject(()=>recover(x,{...abortCutover(x),expectedBeforeTransitionDigest:'f'.repeat(64)}),'MULTI_EPOCH_TRANSITION_PIN_MISMATCH');
});
test('31Y refuses forged next transition pin even if old chain is genuine',async t=>{
 const x=await cutoverCrash(t);await reject(()=>recover(x,{...abortCutover(x),expectedAfterTransitionDigest:'f'.repeat(64)}),'MULTI_EPOCH_RECOVERY_RECORD_INVALID');
});
test('31Y refuses wrong externally supplied before head',async t=>{
 const x=await cutoverCrash(t);await reject(()=>recover(x,{...abortCutover(x),expectedBeforeHead:x.first.head,expectedAfterHead:x.first.head}),'MULTI_EPOCH_RECOVERY_RECORD_INVALID');
});
test('31Y refuses missing supervisor epoch pin and never infers it',async t=>{
 const x=await cutoverCrash(t);const a=abortCutover(x);delete a.expectedBeforeEpoch;
 await reject(()=>recover(x,a),'MULTI_EPOCH_RECOVERY_EXTERNAL_PINS_REQUIRED');
});
test('31Y refuses wrong epoch advancement for cutover',async t=>{
 const x=await cutoverCrash(t);await reject(()=>recover(x,{...abortCutover(x),expectedAfterEpoch:1}),'MULTI_EPOCH_RECOVERY_EXTERNAL_PINS_REQUIRED');
});
test('31Y refuses finalize when hardlink does not exist',async t=>{
 const x=await cutoverCrash(t);await reject(()=>recover(x,afterCutover(x)),'MULTI_EPOCH_RECOVERY_LINK_MISSING');
});
test('31Y refuses abort when hardlink already exists',async t=>{
 const x=await cutoverCrash(t,'after-multi-link-sync');await reject(()=>recover(x,abortCutover(x)),'MULTI_EPOCH_RECOVERY_LINK_EXISTS');
});
test('31Y refuses wrong marker kind and preserves both histories',async t=>{
 const x=await cutoverCrash(t);await reject(()=>recover(x,{...abortCutover(x),kind:'append'}),'MULTI_EPOCH_RECOVERY_EXTERNAL_PINS_REQUIRED');
});
test('31Y refuses symlink pending marker',async t=>{
 const x=await cutoverCrash(t);const p=join(x.directory,'.pending-multi-cutover.json');await unlink(p);await symlink('/etc/hosts',p);
 await reject(()=>recover(x,abortCutover(x)),'MULTI_EPOCH_FILE_UNSAFE');
});
test('31Y refuses unexpected hardlink count on unlinked pending',async t=>{
 const x=await cutoverCrash(t);await link(join(x.directory,'.pending-multi-cutover.json'),join(x.directory,'extra-link'));
 await reject(()=>recover(x,abortCutover(x)),'MULTI_EPOCH_FILE_UNSAFE');
});
test('31Y refuses tampered canonical pending bytes even with valid independent old pins',async t=>{
 const x=await cutoverCrash(t),p=join(x.directory,'.pending-multi-cutover.json'),v=JSON.parse(await readFile(p));v.transition.body.nonce='tampered_multi_epoch_0001';
 await writeFile(p,JSON.stringify(v));await reject(()=>recover(x,abortCutover(x)),'MULTI_EPOCH_RECOVERY_PENDING_PIN_MISMATCH');
});
test('31Y refuses substituted destination inode despite correct signed bytes',async t=>{
 const x=await cutoverCrash(t,'after-multi-link-sync'),p=cert2(x),v=await readFile(p);await unlink(p);await writeFile(p,v,{mode:0o600});
 await reject(()=>recover(x,afterCutover(x)),'MULTI_EPOCH_FILE_UNSAFE');
});
test('31Y refuses a missing linked certificate instead of recreating it',async t=>{
 const x=await cutoverCrash(t,'after-multi-link-sync');await unlink(cert2(x));
 await reject(()=>recover(x,afterCutover(x)),'MULTI_EPOCH_RECOVERY_LINK_MISSING');
});
test('31Y rejects append after-head digest forged by supervisor',async t=>{
 const x=await appendCrash(t);await reject(()=>recover(x,{...appendPins(x),decision:'abort-unlinked',expectedAfterHead:{count:3,headDigest:'f'.repeat(64)}}),'MULTI_EPOCH_RECOVERY_RECORD_INVALID');
});
test('31Y rejects append with forged epoch policy pin',async t=>{
 const x=await appendCrash(t);await reject(()=>recover(x,{...appendPins(x),decision:'abort-unlinked',expectedAfterTransitionDigest:'f'.repeat(64)}),'MULTI_EPOCH_RECOVERY_EXTERNAL_PINS_REQUIRED');
});
test('31Y rejects wrong signed receipt on pending append even with matching recomputed pending hash',async t=>{
 const x=await appendCrash(t),p=join(x.directory,'.pending.json'),v=JSON.parse(await readFile(p));v.receipt.signatures[0].signature='A'.repeat(86);
 await writeFile(p,JSON.stringify(v));x.expectedPendingDigest=await digestPending(x,'append');
 await reject(()=>recover(x,{...appendPins(x),decision:'abort-unlinked'}),'MULTI_EPOCH_RECOVERY_RECORD_INVALID');
});
test('31Y rejects append pending with wrong signed epoch',async t=>{
 const x=await appendCrash(t);await reject(()=>recover(x,{...appendPins(x),expectedBeforeEpoch:1,expectedAfterEpoch:1,expectedBeforeTransitionDigest:x.p1,expectedAfterTransitionDigest:x.p1,decision:'abort-unlinked'}),'EXPORT_RECEIPT_POLICY_MISMATCH');
});
test('31Y rejects a second recovery attempt; does not silently repeat a decision',async t=>{
 const x=await cutoverCrash(t);await recover(x,abortCutover(x));await reject(()=>recover(x,abortCutover(x)),'MULTI_EPOCH_RECOVERY_MARKER_MISMATCH');
});
test('31Y concurrent independent recovery processes serialize; exactly one succeeds',async t=>{
 const x=await cutoverCrash(t,'after-multi-link-sync'),payload=JSON.stringify({directory:x.directory,registryId,policies:policies.map(serialize),args:{...afterCutover(x),expectedPendingDigest:x.expectedPendingDigest}});
 const launch=()=>new Promise((ok,no)=>{const c=spawn(process.execPath,['--input-type=module','-e',recoverChildCode,payload],{stdio:['ignore','pipe','pipe']});let out='',err='';c.stdout.on('data',b=>out+=b);c.stderr.on('data',b=>err+=b);c.once('error',no);c.once('close',(code,signal)=>ok({code,signal,out,err}));});
 const results=await Promise.all([launch(),launch()]);assert.equal(results.filter(r=>r.code===0&&r.out==='OK').length,1,JSON.stringify(results));
 assert.equal(results.filter(r=>r.code===2&&r.out==='MULTI_EPOCH_RECOVERY_MARKER_MISMATCH').length,1,JSON.stringify(results));
 assert.equal((await inspect2(x)).epoch,2);
});
test('31Y repeated SIGKILL after recovery marker unlink is idempotently complete but not replayable',async t=>{
 const x=await cutoverCrash(t,'after-multi-link-sync');
 // Crash only in a child process: the parent remains alive and inspects the durable result.
 const payload={directory:x.directory,registryId,policies:policies.map(serialize),args:{...afterCutover(x),expectedPendingDigest:x.expectedPendingDigest}};
 const code=recoverChildCode.replace('const r=createOfflineMultiEpochExportReceiptRegistry({directory:a.directory,registryId:a.registryId,policies});',"const r=createOfflineMultiEpochExportReceiptRegistry({directory:a.directory,registryId:a.registryId,policies,injectFault:async phase=>{if(phase==='after-multi-recovery-marker-sync')process.kill(process.pid,'SIGKILL');}});");
 const c=spawnSync(process.execPath,['--input-type=module','-e',code,JSON.stringify(payload)],{encoding:'utf8',timeout:15000});assert.equal(c.signal,'SIGKILL',JSON.stringify(c));
 assert.equal((await inspect2(x)).epoch,2);await reject(()=>recover(x,afterCutover(x)),'MULTI_EPOCH_RECOVERY_MARKER_MISMATCH');
});

async function thirdEpochCrash(t,phase='after-multi-link-sync'){
 const x=await migrated(t),third=await append3(x),t3=transition(3,third.head,now+1000),p3=pin([x.t1,x.t2,t3]);
 const args={transition:t3,expectedHead:third.head,expectedTransitionDigest:x.p2,expectedNewTransitionDigest:p3,expectedEpoch:2,nowMs:now+2000};
 const payload={directory:x.directory,registryId,policies:policies.map(serialize),crash:phase,args};
 const c=spawnSync(process.execPath,['--input-type=module','-e',childCode,JSON.stringify(payload)],{encoding:'utf8',timeout:15000});
 assert.equal(c.signal,'SIGKILL',JSON.stringify(c));
 return {...x,third,t3,p3,expectedPendingDigest:await digestPending(x)};
}
const epoch3Pins=x=>({kind:'cutover',decision:'finalize-linked',expectedBeforeHead:x.third.head,expectedAfterHead:x.third.head,
 expectedBeforeTransitionDigest:x.p2,expectedAfterTransitionDigest:x.p3,expectedBeforeEpoch:2,expectedAfterEpoch:3,nowMs:now+2000});
test('31Y actual SIGKILL before epoch-3 link: safe abort retains all older certificates',async t=>{
 const x=await thirdEpochCrash(t,'after-multi-pending-sync'),old=await readFile(cert2(x));
 const s=await recover(x,{...epoch3Pins(x),decision:'abort-unlinked'});assert.equal(s.epoch,2);
 assert.deepEqual(await readFile(cert2(x)),old);assert.equal((await x.multi.inspect({expectedHead:x.third.head,expectedTransitionDigest:x.p2,expectedEpoch:2,nowMs:now+2000})).epoch,2);
});
test('31Y actual SIGKILL after epoch-3 link: finalize and accept epoch-3 receipt',async t=>{
 const x=await thirdEpochCrash(t),s=await recover(x,epoch3Pins(x));assert.equal(s.epoch,3);
 const next=receipt(3,4,x.third.head.headDigest,{issuedAt:now+2000});
 const a=await x.multi.append({...next,expectedHead:x.third.head,expectedTransitionDigest:x.p3,expectedEpoch:3,nowMs:now+2000});
 assert.equal(a.head.count,4);assert.equal((await x.multi.inspect({expectedHead:a.head,expectedTransitionDigest:x.p3,expectedEpoch:3,nowMs:now+2000})).epoch,3);
});
test('31Y rejects epoch-3 recovery pinned to retired epoch-1 history',async t=>{
 const x=await thirdEpochCrash(t);await reject(()=>recover(x,{...epoch3Pins(x),expectedBeforeTransitionDigest:x.p1}),'MULTI_EPOCH_RECOVERY_STALE_PIN');
 assert.ok((await readdir(x.directory)).includes('.pending-multi-cutover.json'));
});
test('31Y refuses world-readable linked marker during epoch-3 recovery',async t=>{
 const x=await thirdEpochCrash(t);await chmod(join(x.directory,'.pending-multi-cutover.json'),0o644);
 await reject(()=>recover(x,epoch3Pins(x)),'MULTI_EPOCH_FILE_UNSAFE');
});
test('31Y refuses unrelated hardlink on linked epoch-3 marker',async t=>{
 const x=await thirdEpochCrash(t);await link(join(x.directory,'.pending-multi-cutover.json'),join(x.directory,'third-link'));
 await reject(()=>recover(x,epoch3Pins(x)),'MULTI_EPOCH_FILE_UNSAFE');
});
test('31Y rejects forged certificate bytes even when caller repins pending digest',async t=>{
 const x=await thirdEpochCrash(t,'after-multi-pending-sync'),p=join(x.directory,'.pending-multi-cutover.json'),v=JSON.parse(await readFile(p));
 v.transition.outgoingSignatures[0].signature='A'.repeat(86);await writeFile(p,JSON.stringify(v));
 x.expectedPendingDigest=await digestPending(x);
 await reject(()=>recover(x,{...epoch3Pins(x),decision:'abort-unlinked'}),'MULTI_EPOCH_SIGNATURE_INVALID');
});
test('31Y refuses receipt recovery without externally pinned after head',async t=>{
 const x=await appendCrash(t),args={...appendPins(x),decision:'abort-unlinked'};delete args.expectedAfterHead;
 await reject(()=>recover(x,args),'MULTI_EPOCH_RECOVERY_EXTERNAL_PINS_REQUIRED');
});
test('31Y detects pending marker substitution after authenticated history inspection',async t=>{
 const x=await cutoverCrash(t),marker=join(x.directory,'.pending-multi-cutover.json');
 const reg=createOfflineMultiEpochExportReceiptRegistry({...config(x),injectFault:async phase=>{
  if(phase==='before-multi-recovery-unlink'){
   const bytes=await readFile(marker);await unlink(marker);await writeFile(marker,bytes,{mode:0o600});
  }
 }});
 await reject(()=>reg.reconcilePending({...abortCutover(x),expectedPendingDigest:x.expectedPendingDigest}),'MULTI_EPOCH_RECOVERY_MARKER_CHANGED');
 assert.ok((await readdir(x.directory)).includes('.pending-multi-cutover.json'));
});
test('31Y detects pending marker mutation immediately before recovery unlink',async t=>{
 const x=await cutoverCrash(t),marker=join(x.directory,'.pending-multi-cutover.json');
 const reg=createOfflineMultiEpochExportReceiptRegistry({...config(x),injectFault:async phase=>{
  if(phase==='before-multi-recovery-unlink')await writeFile(marker,Buffer.from('{}'));
 }});
 await reject(()=>reg.reconcilePending({...abortCutover(x),expectedPendingDigest:x.expectedPendingDigest}),'MULTI_EPOCH_RECOVERY_MARKER_CHANGED');
});
