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
import {encodeOfflinePinnedArchiveInventory,verifyOfflinePinnedArchiveInventory} from '../src/offline-pinned-multi-archive-inventory.mjs';

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
 const run=changes=>verifyOfflinePinnedArchiveInventory({...args,...changes});
 const file=(index=0)=>join(archiveDirectories[archives[index].directoryIndex],`${archives[index].archiveDigest}.tjexport`);
 return {parent,registryDirectory,archiveDirectories,registry,head,archives,args,run,file};
}
function rewrite(x,mutate){const m=JSON.parse(x.args.manifestBytes.toString());mutate(m);const bytes=Buffer.from(JSON.stringify(m));return {manifestBytes:bytes,expectedManifestDigest:sha(bytes)};}

test('32A two signed receipts reconcile to exact shared-directory inventory',async t=>{const x=await fixture(t),r=await x.run();assert.equal(r.count,2);assert.equal(r.archiveDirectoryCount,1);assert.equal(r.productionApproved,false);assert.equal(r.readOnly,true);});
test('32A legacy one-shot archive directories reconcile without rewrite',async t=>{const x=await fixture(t,{legacy:true}),r=await x.run();assert.equal(r.archiveDirectoryCount,2);});
test('32A accepts existing owner-only coordinator lock without modifying it',async t=>{const x=await fixture(t);await writeFile(join(x.archiveDirectories[0],'.coordination-lock'),'lock',{mode:0o600});assert.equal((await x.run()).count,2);});
test('32A refuses absent independent manifest pin',async t=>{const x=await fixture(t);await error(()=>x.run({expectedManifestDigest:undefined}),'PINNED_INVENTORY_EXTERNAL_PINS_REQUIRED');});
test('32A rejects forged external manifest digest',async t=>{const x=await fixture(t);await error(()=>x.run({expectedManifestDigest:'f'.repeat(64)}),'PINNED_INVENTORY_DIGEST_MISMATCH');});
test('32A rejects a truncated canonical manifest',async t=>{const x=await fixture(t);const b=x.args.manifestBytes.subarray(0,-1);await error(()=>x.run({manifestBytes:b,expectedManifestDigest:sha(b)}),'PINNED_INVENTORY_NOT_CANONICAL');});
test('32A rejects noncanonical whitespace even when hash is pinned',async t=>{const x=await fixture(t);const b=Buffer.concat([x.args.manifestBytes,Buffer.from(' ')]);await error(()=>x.run({manifestBytes:b,expectedManifestDigest:sha(b)}),'PINNED_INVENTORY_NOT_CANONICAL');});
test('32A rejects manifest rollback missing a signed receipt',async t=>{const x=await fixture(t);await error(()=>x.run(rewrite(x,m=>m.archives.pop())),'PINNED_INVENTORY_MANIFEST_MISMATCH');});
test('32A rejects manifest duplicate sequence',async t=>{const x=await fixture(t);await error(()=>x.run(rewrite(x,m=>m.archives[1].sequence=1)),'PINNED_INVENTORY_ENTRY_INVALID');});
test('32A rejects substituted acquisition identity',async t=>{const x=await fixture(t);await error(()=>x.run(rewrite(x,m=>m.archives[0].acquisitionId='acquisition_substitute_32a')),'PINNED_INVENTORY_RECEIPT_MISMATCH');});
test('32A rejects substituted archive digest',async t=>{const x=await fixture(t);await error(()=>x.run(rewrite(x,m=>m.archives[1].archiveDigest='f'.repeat(64))),'PINNED_INVENTORY_RECEIPT_MISMATCH');});
test('32A rejects altered byte count',async t=>{const x=await fixture(t);await error(()=>x.run(rewrite(x,m=>m.archives[0].archiveBytes++)),'PINNED_INVENTORY_RECEIPT_MISMATCH');});
test('32A rejects directory-index escape',async t=>{const x=await fixture(t);await error(()=>x.run(rewrite(x,m=>m.archives[0].directoryIndex=99)),'PINNED_INVENTORY_ENTRY_INVALID');});
test('32A rejects forged registry head pin',async t=>{const x=await fixture(t);await error(()=>x.run({expectedHead:{count:2,headDigest:'f'.repeat(64)}}),'PINNED_INVENTORY_MANIFEST_MISMATCH');});
test('32A rejects forged witness-policy epoch',async t=>{const x=await fixture(t);await error(()=>x.run({expectedEpoch:1}),'PINNED_INVENTORY_MANIFEST_MISMATCH');});
test('32A rejects forged witness transition pin',async t=>{const x=await fixture(t);await error(()=>x.run({expectedTransitionDigest:'f'.repeat(64)}),'PINNED_INVENTORY_MANIFEST_MISMATCH');});
test('32A rejects orphaned archive not present in signed receipts',async t=>{const x=await fixture(t);await writeFile(join(x.archiveDirectories[0],'orphan.tjexport'),'orphan',{mode:0o600});await error(()=>x.run(),'PINNED_INVENTORY_ORPHAN_MISSING_OR_PENDING');});
test('32A rejects pending cross-resource commit marker',async t=>{const x=await fixture(t);await writeFile(join(x.archiveDirectories[0],'.pending-coordination.json'),'{}',{mode:0o600});await error(()=>x.run(),'PINNED_INVENTORY_ORPHAN_MISSING_OR_PENDING');});
test('32A rejects quarantined orphan evidence',async t=>{const x=await fixture(t);await writeFile(join(x.archiveDirectories[0],'.orphan-uncertain.json'),'{}',{mode:0o600});await error(()=>x.run(),'PINNED_INVENTORY_ORPHAN_MISSING_OR_PENDING');});
test('32A rejects missing signed archive',async t=>{const x=await fixture(t);await unlink(x.file(1));await error(()=>x.run(),'PINNED_INVENTORY_FILE_UNSAFE');});
test('32A rejects archive substitution with forged bytes',async t=>{const x=await fixture(t);await writeFile(x.file(0),'tampered');await error(()=>x.run(),'PINNED_INVENTORY_ARCHIVE_TAMPERED');});
test('32A rejects archive symlink substitution',async t=>{const x=await fixture(t);await unlink(x.file(0));await symlink('/etc/passwd',x.file(0));await error(()=>x.run(),'PINNED_INVENTORY_FILE_UNSAFE');});
test('32A rejects archive hardlink substitution',async t=>{const x=await fixture(t);await link(x.file(0),join(x.parent,'hardlink'));await error(()=>x.run(),'PINNED_INVENTORY_FILE_UNSAFE');});
test('32A rejects world-readable archive evidence',async t=>{const x=await fixture(t);await chmod(x.file(0),0o644);await error(()=>x.run(),'PINNED_INVENTORY_FILE_UNSAFE');});
test('32A rejects world-readable archive directory',async t=>{const x=await fixture(t);await chmod(x.archiveDirectories[0],0o755);await error(()=>x.run(),'PINNED_INVENTORY_DIRECTORY_UNSAFE');});
test('32A rejects symlink archive directory',async t=>{const x=await fixture(t);const alias=join(x.parent,'alias');await symlink(x.archiveDirectories[0],alias);await error(()=>x.run({archiveDirectories:[alias]}),'PINNED_INVENTORY_DIRECTORY_UNSAFE');});
test('32A rejects overlapping registry and archive roots',async t=>{const x=await fixture(t);await error(()=>x.run({archiveDirectories:[x.registryDirectory]}),'PINNED_INVENTORY_DIRECTORY_OVERLAP');});
test('32A rejects duplicate archive directory aliases',async t=>{const x=await fixture(t);await error(()=>x.run({archiveDirectories:[x.archiveDirectories[0],x.archiveDirectories[0]]}),'PINNED_INVENTORY_DIRECTORY_OVERLAP');});
test('32A rejects untrusted extra manifest property',async t=>{const x=await fixture(t);await error(()=>x.run(rewrite(x,m=>m.authorized=true)),'PINNED_INVENTORY_MANIFEST_MISMATCH');});
test('32A rejects registry record tampering despite independently pinned inventory',async t=>{const x=await fixture(t),p=join(x.registryDirectory,'0001.json');await writeFile(p,'{}',{mode:0o600});await error(()=>x.run(),'EXPORT_REGISTRY_HISTORY_INVALID');});
test('32A detects archive modified between verification passes',async t=>{const x=await fixture(t);await error(()=>x.run({injectFault:async at=>{if(at==='before-final-reconciliation')await writeFile(x.file(1),'mutated',{mode:0o600});}}),'PINNED_INVENTORY_CONCURRENT_ARCHIVE_CHANGE');});
test('32A detects orphan introduced during verification window',async t=>{const x=await fixture(t);await error(()=>x.run({injectFault:async()=>writeFile(join(x.archiveDirectories[0],'late-orphan'),'{}',{mode:0o600})}),'PINNED_INVENTORY_ORPHAN_MISSING_OR_PENDING');});
test('32A refuses stale signed history when pinned head is a valid old prefix',async t=>{const x=await fixture(t);const old=JSON.parse(await readFile(join(x.registryDirectory,'0001.json'),'utf8'));const m=JSON.parse(x.args.manifestBytes.toString());m.head={count:1,headDigest:old.digest};m.archives.pop();const bytes=Buffer.from(JSON.stringify(m));await error(()=>x.run({expectedHead:m.head,manifestBytes:bytes,expectedManifestDigest:sha(bytes)}),'EXPORT_REGISTRY_PIN_MISMATCH');});

test('32A rejects mismatched registry instance identity before trusting inspect',async t=>{const x=await fixture(t);await error(()=>x.run({registry:{registryId:'different_registry',inspect:async()=>({head:x.head,readOnly:true,productionApproved:false})}}),'PINNED_INVENTORY_EXTERNAL_PINS_REQUIRED');});
test('32A rejects registry stub that does not return a verified pinned state',async t=>{const x=await fixture(t);await error(()=>x.run({registry:{registryId,inspect:async()=>({head:x.head})}}),'PINNED_INVENTORY_REGISTRY_INSPECTION_INVALID');});
test('32A detects registry record modified between verification passes',async t=>{const x=await fixture(t);await error(()=>x.run({injectFault:async()=>writeFile(join(x.registryDirectory,'0002.json'),'{}',{mode:0o600})}),'PINNED_INVENTORY_CONCURRENT_REGISTRY_CHANGE');});
test('32A rejects a canonical manifest that duplicates archive locations',async t=>{const x=await fixture(t);await error(()=>x.run(rewrite(x,m=>{m.archives[1].archiveDigest=m.archives[0].archiveDigest;m.archives[1].acquisitionId=m.archives[0].acquisitionId;m.archives[1].archiveBytes=m.archives[0].archiveBytes;})),'PINNED_INVENTORY_RECEIPT_MISMATCH');});
