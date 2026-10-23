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
import {mkdir} from 'node:fs/promises';
import {encodeOfflinePinnedArchiveInventory} from '../src/offline-pinned-multi-archive-inventory.mjs';
import {classifyOfflinePinnedArchiveOrphans} from '../src/offline-pinned-orphan-classifier.mjs';
async function multiInventory(t){
 const x=await migrated(t),archiveDirectory=await mkdtemp(join(tmpdir(),'tj32a-multi-'));await chmod(archiveDirectory,0o700);
 t.after(()=>rm(archiveDirectory,{recursive:true,force:true}));
 const third=receipt(2,3,x.second.head.headDigest,{issuedAt:now});
 const appended=await x.multi.append({...third,expectedHead:x.second.head,expectedTransitionDigest:x.p2,expectedEpoch:2,nowMs:now});
 const receipts=[receipt(0,1,root),receipt(1,2,x.first.head.headDigest,{issuedAt:now-2000}),third];
 const archives=[];
 for(let i=0;i<receipts.length;i++){
  const r=receipts[i],b=r.receipt.body;
  await writeFile(join(archiveDirectory,`${b.archiveDigest}.tjexport`),r.archiveBytes,{mode:0o600});
  archives.push({sequence:i+1,directoryIndex:0,acquisitionId:b.acquisitionId,archiveDigest:b.archiveDigest,archiveBytes:b.archiveBytes});
 }
 const manifestBytes=encodeOfflinePinnedArchiveInventory({registryId,expectedHead:appended.head,expectedEpoch:2,expectedTransitionDigest:x.p2,archives});
 const args={registry:x.multi,registryDirectory:x.directory,archiveDirectories:[archiveDirectory],registryId,manifestBytes,
  expectedManifestDigest:sha(manifestBytes),expectedHead:appended.head,expectedEpoch:2,expectedTransitionDigest:x.p2,nowMs:now};
 return {...x,archiveDirectory,args,run:changes=>classifyOfflinePinnedArchiveOrphans({...args,...changes})};
}
test('32B verifies three signed receipt epochs and emits no anomaly without authorizing actions',async t=>{
 const x=await multiInventory(t),r=await x.run();assert.equal(r.issueCount,0);assert.equal(r.epoch,2);assert.equal(r.head.count,3);
 assert.equal(r.productionApproved,false);assert.equal(r.mayRepair,false);assert.equal(r.mayDelete,false);
});
test('32B classifies orphan alongside genuine three-epoch receipt history',async t=>{
 const x=await multiInventory(t);await writeFile(join(x.archiveDirectory,'untracked.tjexport'),'orphan',{mode:0o600});const r=await x.run();
 assert.equal(r.issueCount,1);assert.ok(r.evidence.some(e=>e.classification==='UNTRACKED_ARCHIVE_UNVERIFIED'));
});
test('32B refuses tampered multi-epoch transition certificate before orphan classification',async t=>{
 const x=await multiInventory(t);await writeFile(join(x.directory,'.witness-cutover-0002.json'),'{}',{mode:0o600});await assert.rejects(()=>x.run());
});
test('32B refuses stale independent transition digest across witness rotation',async t=>{
 const x=await multiInventory(t);await assert.rejects(()=>x.run({expectedTransitionDigest:x.p1}));
});
test('32B classifies missing signed third-epoch archive while preserving historic evidence',async t=>{
 const x=await multiInventory(t);const m=JSON.parse(x.args.manifestBytes.toString());await unlink(join(x.archiveDirectory,`${m.archives[2].archiveDigest}.tjexport`));
 const r=await x.run();assert.equal(r.issueCount,1);assert.ok(r.evidence.some(e=>e.classification==='SIGNED_ARCHIVE_MISSING'));assert.equal(r.head.count,3);
});
