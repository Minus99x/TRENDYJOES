import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {mkdtemp,mkdir,rm,writeFile,readFile,unlink,symlink,link,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {OFFLINE_ACQUISITION_EXPORT_SCHEMA} from '../src/offline-acquisition-evidence-export.mjs';
import {OFFLINE_ACQUISITION_SESSION_SCHEMA} from '../src/offline-acquisition-session-journal.mjs';
import {OFFLINE_ACQUISITION_MANIFEST_SCHEMA} from '../src/offline-forensic-acquisition-provenance.mjs';
import {createOfflineExportReceiptRegistry,OFFLINE_EXPORT_RECEIPT_SCHEMA,offlineExportReceiptPolicyDigest,offlineExportReceiptSigningBytes} from '../src/offline-acquisition-export-receipt-registry.mjs';
import {encodeOfflinePinnedArchiveInventory} from '../src/offline-pinned-multi-archive-inventory.mjs';
import {classifyOfflinePinnedArchiveOrphans} from '../src/offline-pinned-orphan-classifier.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const ROOT='0'.repeat(64),registryId='inventory_registry_32a',nowMs=1800000000000;
const keys=[0,1,2].map(i=>({id:`inventory_witness_${i}`, ...generateKeyPairSync('ed25519')}));
const witnesses=keys.map(k=>({id:k.id,publicKey:k.publicKey})),quorum=2;
const policyDigest=offlineExportReceiptPolicyDigest({witnesses,quorum});
const error=(f,code)=>assert.rejects(f,e=>e?.code===code,code);
function archive(acquisitionId,variant){
 const pre={phase:'PRE',acquisitionId},post={phase:'POST',acquisitionId};
 const manifest={schema:OFFLINE_ACQUISITION_MANIFEST_SCHEMA,acquisitionId,envelope:{transportDigest:'a'.repeat(64)},receiptHistory:[pre,post]};
 let previous=ROOT;const events=[];
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
function signedReceipt(sequence,previousDigest,bytes){
 const acquisitionId=`acquisition_32a_${String(sequence).padStart(4,'0')}`;
 const body={schema:OFFLINE_EXPORT_RECEIPT_SCHEMA,registryId,sequence,previousDigest,exportId:`export_32a_${String(sequence).padStart(4,'0')}`,acquisitionId,
  archiveDigest:sha(bytes),archiveBytes:bytes.length,issuedAt:nowMs-1000,expiresAt:nowMs+60000,nonce:`nonce_32a_${String(sequence).padStart(4,'0')}`,policyDigest};
 const signing=offlineExportReceiptSigningBytes(body);
 return {body,signatures:keys.slice(0,2).map(k=>({witnessId:k.id,signature:sign(null,signing,k.privateKey).toString('base64url')}))};
}
async function fixture(t,{legacy=false}={}){
 const parent=await mkdtemp(join(tmpdir(),'tj32a-'));await chmod(parent,0o700);t.after(()=>rm(parent,{recursive:true,force:true}));
 const registryDirectory=join(parent,'registry'),archiveDirectories=legacy?[join(parent,'old1'),join(parent,'old2')]:[join(parent,'archives')];
 await mkdir(registryDirectory,{mode:0o700});for(const dir of archiveDirectories)await mkdir(dir,{mode:0o700});
 const registry=createOfflineExportReceiptRegistry({directory:registryDirectory,registryId,witnesses,quorum});
 let head={count:0,headDigest:ROOT};const archives=[];
 for(let i=1;i<=2;i++){
  const bytes=archive(`acquisition_32a_${String(i).padStart(4,'0')}`,i),receipt=signedReceipt(i,head.headDigest,bytes);
  const next=await registry.append({receipt,archiveBytes:bytes,expectedHead:head,nowMs});head=next.head;
  const directoryIndex=legacy?i-1:0;
  await writeFile(join(archiveDirectories[directoryIndex],`${sha(bytes)}.tjexport`),bytes,{mode:0o600});
  archives.push({sequence:i,directoryIndex,acquisitionId:receipt.body.acquisitionId,archiveDigest:sha(bytes),archiveBytes:bytes.length});
 }
 const expectedEpoch=0,expectedTransitionDigest=ROOT;
 const manifestBytes=encodeOfflinePinnedArchiveInventory({registryId,expectedHead:head,expectedEpoch,expectedTransitionDigest,archives});
 const args={registry,registryDirectory,archiveDirectories,registryId,manifestBytes,expectedManifestDigest:sha(manifestBytes),expectedHead:head,expectedEpoch,expectedTransitionDigest,nowMs};
 const run=changes=>classifyOfflinePinnedArchiveOrphans({...args,...changes});
 const file=(index=0)=>join(archiveDirectories[archives[index].directoryIndex],`${archives[index].archiveDigest}.tjexport`);
 return {parent,registryDirectory,archiveDirectories,registry,head,archives,args,run,file};
}
function rewrite(x,mutate){const m=JSON.parse(x.args.manifestBytes.toString());mutate(m);const bytes=Buffer.from(JSON.stringify(m));return {manifestBytes:bytes,expectedManifestDigest:sha(bytes)};}


const cls=r=>r.evidence.map(x=>x.classification);
const assertNoAuth=r=>{assert.equal(r.productionApproved,false);assert.equal(r.readOnly,true);assert.equal(r.mayDelete,false);assert.equal(r.mayRepair,false);assert.equal(r.mayManufacture,false);assert.equal(r.mayAcknowledge,false);assert.equal(Object.isFrozen(r),true);assert.equal(Object.isFrozen(r.evidence),true);};

test('32B authentic shared directory yields deterministic read-only no-anomaly evidence',async t=>{
 const x=await fixture(t),a=await x.run(),b=await x.run();assert.equal(a.status,'NO_ANOMALIES_OBSERVED');assert.equal(a.issueCount,0);
 assert.deepEqual(a,b);assert.equal(a.evidence.length,2);assertNoAuth(a);
});
test('32B authentic legacy multi-directory layout is supported',async t=>{
 const x=await fixture(t,{legacy:true}),r=await x.run();assert.equal(r.status,'NO_ANOMALIES_OBSERVED');assert.deepEqual(r.evidence.map(e=>e.directoryIndex).sort(),[0,1]);
});
test('32B detects extra untrusted archive with digest but never calls it authenticated',async t=>{
 const x=await fixture(t);await writeFile(join(x.archiveDirectories[0],'extra.tjexport'),'untrusted',{mode:0o600});const r=await x.run();
 assert.equal(r.issueCount,1);assert.ok(cls(r).includes('UNTRACKED_ARCHIVE_UNVERIFIED'));assert.equal(r.status,'SUPERVISORY_REVIEW_REQUIRED');assertNoAuth(r);
});
test('32B pending coordination marker requires supervisory review, never auto-finalizes',async t=>{
 const x=await fixture(t);await writeFile(join(x.archiveDirectories[0],'.pending-coordination.json'),'{}',{mode:0o600});const r=await x.run();
 assert.ok(cls(r).includes('PENDING_INTENT_UNVERIFIED'));assertNoAuth(r);
});
test('32B quarantined marker is not promoted to authentic evidence',async t=>{
 const x=await fixture(t);await writeFile(join(x.archiveDirectories[0],'.orphan-unknown.json'),'{}',{mode:0o600});assert.ok(cls(await x.run()).includes('QUARANTINE_UNVERIFIED'));
});
test('32B multiple directories retain distinct orphan indices',async t=>{
 const x=await fixture(t,{legacy:true});await writeFile(join(x.archiveDirectories[0],'extra1.tjexport'),'orphan1',{mode:0o600});
 await writeFile(join(x.archiveDirectories[1],'extra2.tjexport'),'orphan2',{mode:0o600});const r=await x.run();
 assert.equal(r.issueCount,2);assert.deepEqual(r.evidence.filter(e=>e.classification==='UNTRACKED_ARCHIVE_UNVERIFIED').map(e=>e.directoryIndex),[0,1]);
});
test('32B missing signed archive produces explicit missing evidence, not success',async t=>{
 const x=await fixture(t);await unlink(x.file(0));const r=await x.run();assert.ok(cls(r).includes('SIGNED_ARCHIVE_MISSING'));assert.equal(r.issueCount,1);
});
test('32B tampered signed archive produces explicit tamper evidence',async t=>{
 const x=await fixture(t);await writeFile(x.file(0),'malicious',{mode:0o600});assert.ok(cls(await x.run()).includes('SIGNED_ARCHIVE_TAMPERED'));
});
test('32B symlink signed archive is unsafe, never followed',async t=>{
 const x=await fixture(t);await unlink(x.file(0));await symlink('/etc/passwd',x.file(0));assert.ok(cls(await x.run()).includes('SIGNED_ARCHIVE_UNSAFE'));
});
test('32B hardlink signed archive is unsafe',async t=>{
 const x=await fixture(t);await link(x.file(0),join(x.parent,'outside'));assert.ok(cls(await x.run()).includes('SIGNED_ARCHIVE_UNSAFE'));
});
test('32B publicly readable signed archive is unsafe',async t=>{
 const x=await fixture(t);await chmod(x.file(0),0o644);assert.ok(cls(await x.run()).includes('SIGNED_ARCHIVE_UNSAFE'));
});
test('32B orphan symlink is unsafe without reading target',async t=>{
 const x=await fixture(t);await symlink('/etc/passwd',join(x.archiveDirectories[0],'bad.tjexport'));assert.ok(cls(await x.run()).includes('UNSAFE_UNTRACKED_ENTRY'));
});
test('32B orphan directory is unsafe without traversal',async t=>{
 const x=await fixture(t);await mkdir(join(x.archiveDirectories[0],'bad.tjexport'),{mode:0o700});assert.ok(cls(await x.run()).includes('UNSAFE_UNTRACKED_ENTRY'));
});
test('32B existing private coordination lock is informational, not an issue',async t=>{
 const x=await fixture(t);await writeFile(join(x.archiveDirectories[0],'.coordination-lock'),'lock',{mode:0o600});const r=await x.run();
 assert.equal(r.issueCount,0);assert.ok(cls(r).includes('COORDINATOR_LOCK'));
});
test('32B world-readable coordinator lock is unsafe',async t=>{
 const x=await fixture(t);await writeFile(join(x.archiveDirectories[0],'.coordination-lock'),'lock',{mode:0o644});assert.ok(cls(await x.run()).includes('UNSAFE_UNTRACKED_ENTRY'));
});
test('32B absent manifest pin fails closed',async t=>{
 const x=await fixture(t);await error(()=>x.run({expectedManifestDigest:undefined}),'ORPHAN_EXTERNAL_PINS_REQUIRED');
});
test('32B forged manifest pin fails closed',async t=>{
 const x=await fixture(t);await error(()=>x.run({expectedManifestDigest:'f'.repeat(64)}),'ORPHAN_MANIFEST_PIN_MISMATCH');
});
test('32B altered canonical manifest even with freshly computed digest fails external binding',async t=>{
 const x=await fixture(t);await error(()=>x.run(rewrite(x,m=>m.archives.pop())),'ORPHAN_MANIFEST_INVALID');
});
test('32B modified archive identity in repinned manifest fails signed registry binding',async t=>{
 const x=await fixture(t);await error(()=>x.run(rewrite(x,m=>m.archives[0].acquisitionId='acquisition_forged_32b')),'ORPHAN_RECEIPT_BINDING_INVALID');
});
test('32B altered signed registry record fails authenticated history inspection',async t=>{
 const x=await fixture(t);await writeFile(join(x.registryDirectory,'0001.json'),'{}',{mode:0o600});await assert.rejects(()=>x.run());
});
test('32B stale head pin fails registry inspect',async t=>{
 const x=await fixture(t);await error(()=>x.run({expectedHead:{count:2,headDigest:'f'.repeat(64)}}),'ORPHAN_MANIFEST_INVALID');
});
test('32B stale epoch pin fails manifest binding',async t=>{
 const x=await fixture(t);await error(()=>x.run({expectedEpoch:1}),'ORPHAN_MANIFEST_INVALID');
});
test('32B stale transition pin fails manifest binding',async t=>{
 const x=await fixture(t);await error(()=>x.run({expectedTransitionDigest:'f'.repeat(64)}),'ORPHAN_MANIFEST_INVALID');
});
test('32B refuses unsafe public archive directory',async t=>{
 const x=await fixture(t);await chmod(x.archiveDirectories[0],0o755);await error(()=>x.run(),'ORPHAN_DIRECTORY_UNSAFE');
});
test('32B refuses symlinked archive directory',async t=>{
 const x=await fixture(t),alias=join(x.parent,'alias');await symlink(x.archiveDirectories[0],alias);await error(()=>x.run({archiveDirectories:[alias]}),'ORPHAN_DIRECTORY_UNSAFE');
});
test('32B refuses duplicate or overlapping directories',async t=>{
 const x=await fixture(t);await error(()=>x.run({archiveDirectories:[x.archiveDirectories[0],x.archiveDirectories[0]]}),'ORPHAN_DIRECTORY_OVERLAP');
});
test('32B refuses registry/archive directory overlap',async t=>{
 const x=await fixture(t);await error(()=>x.run({archiveDirectories:[x.registryDirectory]}),'ORPHAN_DIRECTORY_OVERLAP');
});
test('32B rejects registry instance identity substitution',async t=>{
 const x=await fixture(t);await error(()=>x.run({registry:{registryId:'substitute',inspect:async()=>({head:x.head})}}),'ORPHAN_EXTERNAL_PINS_REQUIRED');
});
test('32B rejects unverifying registry inspect stub',async t=>{
 const x=await fixture(t);await error(()=>x.run({registry:{registryId,inspect:async()=>({head:x.head})}}),'ORPHAN_REGISTRY_UNVERIFIED');
});
test('32B detects new orphan introduced between passes',async t=>{
 const x=await fixture(t);await error(()=>x.run({injectFault:async()=>writeFile(join(x.archiveDirectories[0],'late.tjexport'),'late',{mode:0o600})}),'ORPHAN_CONCURRENT_CHANGE');
});
test('32B detects signed archive modification between passes',async t=>{
 const x=await fixture(t);await error(()=>x.run({injectFault:async()=>writeFile(x.file(0),'late',{mode:0o600})}),'ORPHAN_CONCURRENT_CHANGE');
});
test('32B detects registry record changed between passes',async t=>{
 const x=await fixture(t);await error(()=>x.run({injectFault:async()=>writeFile(join(x.registryDirectory,'0002.json'),'{}',{mode:0o600})}),'ORPHAN_CONCURRENT_CHANGE');
});
test('32B reports hash of untrusted names rather than treating unsafe filenames as instructions',async t=>{
 const x=await fixture(t);await writeFile(join(x.archiveDirectories[0],'name\ncontrol'),'untrusted',{mode:0o600});const r=await x.run();
 const e=r.evidence.find(e=>e.classification==='UNSAFE_UNTRACKED_ENTRY');assert.equal(e.name,null);assert.match(e.nameDigest,/^[a-f0-9]{64}$/);
});
test('32B never mutates observed orphan files or pending marker',async t=>{
 const x=await fixture(t),p=join(x.archiveDirectories[0],'.pending-coordination.json');await writeFile(p,'{}',{mode:0o600});
 const before=await readFile(p),r=await x.run(),after=await readFile(p);assert.deepEqual(before,after);assert.equal(r.issueCount,1);
});

test('32B accepts zero-byte private persistent coordinator lock',async t=>{const x=await fixture(t);await writeFile(join(x.archiveDirectories[0],'.coordination-lock'),Buffer.alloc(0),{mode:0o600});const r=await x.run();assert.equal(r.issueCount,0);assert.ok(cls(r).includes('COORDINATOR_LOCK'));});
test('32B rejects canonical manifest with extra untrusted field even if repinned',async t=>{const x=await fixture(t);await error(()=>x.run(rewrite(x,m=>m.allowRepair=true)),'ORPHAN_MANIFEST_INVALID');});
test('32B rejects unbounded external archive byte budget',async t=>{const x=await fixture(t);const z=rewrite(x,m=>{m.archives[0].archiveBytes=33570000;m.archives[1].archiveBytes=33570000;});await error(()=>x.run(z),'ORPHAN_SCAN_BUDGET_EXCEEDED');});
