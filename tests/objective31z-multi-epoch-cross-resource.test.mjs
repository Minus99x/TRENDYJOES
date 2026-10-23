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


import {createOfflineArchiveReceiptCoordinator} from '../src/offline-archive-receipt-coordinator.mjs';

async function multiFixture(t){
 const x=await migrated(t),archiveDirectory=await mkdtemp(join(tmpdir(),'tj31z-multi-'));
 t.after(()=>rm(archiveDirectory,{recursive:true,force:true}));
 const r=receipt(2,3,x.second.head.headDigest,{issuedAt:now});
 const record={schema:OFFLINE_EXPORT_REGISTRY_SCHEMA,index:3,previousDigest:x.second.head.headDigest,receipt:r.receipt};
 const after={count:3,headDigest:sha(Buffer.from(`${OFFLINE_EXPORT_REGISTRY_SCHEMA}\0${JSON.stringify(record)}`))};
 const args={expectedBeforeHead:x.second.head,expectedAfterHead:after,expectedTransitionDigest:x.p2,expectedEpoch:2,nowMs:now};
 const coordinator=createOfflineArchiveReceiptCoordinator({archiveDirectory,registryDirectory:x.directory,registry:x.multi,registryId,witnesses:policies[2].witnesses,quorum:2});
 return {...x,archiveDirectory,r,args,coordinator};
}
test('31Z actual multi-epoch signed history + archive staged across distinct durable directories',async t=>{
 const x=await multiFixture(t),staged=await x.coordinator.stage({receipt:x.r.receipt,archiveBytes:x.r.archiveBytes,...x.args});
 const pins={...x.args,expectedMarkerDigest:staged.expectedMarkerDigest,expectedArchiveDigest:staged.expectedArchiveDigest};
 const committed=await x.coordinator.commit(pins);assert.deepEqual(committed.head,x.args.expectedAfterHead);
 const done=await x.coordinator.reconcile({...pins,decision:'finalize-committed'});assert.equal(done.status,'EXTERNALLY_PINNED_FINALIZED');
 assert.equal((await x.multi.inspect({expectedHead:x.args.expectedAfterHead,expectedTransitionDigest:x.p2,expectedEpoch:2,nowMs:now})).head.count,3);
});
test('31Z multi-epoch receipt cannot be accepted under retired witness policy',async t=>{
 const x=await multiFixture(t),bad=createOfflineArchiveReceiptCoordinator({archiveDirectory:x.archiveDirectory,registryDirectory:x.directory,registry:x.multi,registryId,witnesses:policies[1].witnesses,quorum:2});
 await assert.rejects(()=>bad.stage({receipt:x.r.receipt,archiveBytes:x.r.archiveBytes,...x.args}),e=>e.code==='EXPORT_RECEIPT_POLICY_MISMATCH');
});
test('31Z multi-epoch rejects stale transition pin before writing staged archive',async t=>{
 const x=await multiFixture(t);await assert.rejects(()=>x.coordinator.stage({receipt:x.r.receipt,archiveBytes:x.r.archiveBytes,...x.args,expectedTransitionDigest:x.p1}),e=>e.code==='MULTI_EPOCH_TRANSITION_PIN_MISMATCH');
});
