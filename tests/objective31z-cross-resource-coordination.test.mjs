import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign,createPublicKey} from 'node:crypto';
import {mkdtemp,rm,readFile,writeFile,unlink,symlink,link,chmod,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {OFFLINE_ACQUISITION_EXPORT_SCHEMA} from '../src/offline-acquisition-evidence-export.mjs';
import {OFFLINE_ACQUISITION_SESSION_SCHEMA} from '../src/offline-acquisition-session-journal.mjs';
import {OFFLINE_ACQUISITION_MANIFEST_SCHEMA} from '../src/offline-forensic-acquisition-provenance.mjs';
import {createOfflineExportReceiptRegistry,offlineExportReceiptPolicyDigest,offlineExportReceiptSigningBytes,verifyOfflineExportReceipt,OFFLINE_EXPORT_RECEIPT_SCHEMA,OFFLINE_EXPORT_REGISTRY_SCHEMA} from '../src/offline-acquisition-export-receipt-registry.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const root='0'.repeat(64),registryId='receipt_registry_31s',nowMs=1800000000000;
const keys=Array.from({length:3},(_,i)=>({id:`witness_31s_${i+1}`, ...generateKeyPairSync('ed25519')}));
const witnesses=keys.map(k=>({id:k.id,publicKey:k.publicKey})),quorum=2;
const policyDigest=offlineExportReceiptPolicyDigest({witnesses,quorum});
const zero={count:0,headDigest:root};
const fail=(fn,code)=>assert.rejects(fn,e=>e?.code===code,code);
const failSync=(fn,code)=>assert.throws(fn,e=>e?.code===code,code);
const recordHash=b=>sha(Buffer.from(`${OFFLINE_EXPORT_REGISTRY_SCHEMA}\0${JSON.stringify(b)}`));
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
function makeReceipt({acquisitionId='acquisition_31s_0001',sequence=1,previousDigest=root,exportId=`export_31s_${sequence}_0001`,nonce=`nonce_31s_${sequence}_0001`,archiveBytes=archive(acquisitionId),overrides={},signerIndices=[0,1]}={}){
 const body={schema:OFFLINE_EXPORT_RECEIPT_SCHEMA,registryId,sequence,previousDigest,exportId,acquisitionId,archiveDigest:sha(archiveBytes),archiveBytes:archiveBytes.length,issuedAt:nowMs-1000,expiresAt:nowMs+60000,nonce,policyDigest,...overrides};
 const bytes=offlineExportReceiptSigningBytes(body);
 const signatures=signerIndices.map(i=>({witnessId:keys[i].id,signature:sign(null,bytes,keys[i].privateKey).toString('base64url')})).sort((a,b)=>a.witnessId<b.witnessId?-1:a.witnessId>b.witnessId?1:0);
 return {receipt:{body,signatures},archiveBytes};
}
async function sandbox(t,extra={}){
 const directory=await mkdtemp(join(tmpdir(),'tj31s-'));await chmod(directory,0o700);
 t.after(()=>rm(directory,{recursive:true,force:true}));
 const registry=createOfflineExportReceiptRegistry({directory,registryId,witnesses,quorum,...extra});
 return {directory,registry};
}
async function first(t){const x=await sandbox(t),p=makeReceipt(),a=await x.registry.append({...p,expectedHead:zero,nowMs});return {...x,p,a};}
const pin=a=>a.head;
const signBody=(body,signerIndices=[0,1])=>({body,signatures:signerIndices.map(i=>({witnessId:keys[i].id,signature:sign(null,offlineExportReceiptSigningBytes(body),keys[i].privateKey).toString('base64url')})).sort((a,b)=>a.witnessId<b.witnessId?-1:1)});

import {createOfflineArchiveReceiptCoordinator} from '../src/offline-archive-receipt-coordinator.mjs';
const transitionPin='0'.repeat(64);
async function fixture(t,options={}){
 const parent=await mkdtemp(join(tmpdir(),'tj31z-'));
 const archiveDirectory=join(parent,'archives'),registryDirectory=join(parent,'receipts');
 await (await import('node:fs/promises')).mkdir(archiveDirectory,{mode:0o700});
 await (await import('node:fs/promises')).mkdir(registryDirectory,{mode:0o700});
 t.after(()=>rm(parent,{recursive:true,force:true}));
 const registry=createOfflineExportReceiptRegistry({directory:registryDirectory,registryId,witnesses,quorum});
 const coord=createOfflineArchiveReceiptCoordinator({archiveDirectory,registryDirectory,registry,registryId,witnesses,quorum,...options});
 const p=makeReceipt(),record={schema:OFFLINE_EXPORT_REGISTRY_SCHEMA,index:1,previousDigest:root,receipt:p.receipt};
 const expectedAfterHead={count:1,headDigest:recordHash(record)};
 const args={expectedBeforeHead:zero,expectedAfterHead,expectedTransitionDigest:transitionPin,expectedEpoch:0,nowMs};
 return {parent,archiveDirectory,registryDirectory,registry,coord,p,args};
}
async function staged(t,options={}){const x=await fixture(t,options),stage=await x.coord.stage({...x.p,...x.args});return {...x,stage,supervisor:{...x.args,expectedMarkerDigest:stage.expectedMarkerDigest,expectedArchiveDigest:stage.expectedArchiveDigest}};}
const error=(fn,code)=>assert.rejects(fn,e=>e?.code===code,code);
test('31Z staged archive + real signed receipt commit + independently pinned finalize',async t=>{
 const x=await staged(t);assert.equal(x.stage.status,'STAGED_NOT_COMMITTED');
 assert.deepEqual((await x.registry.inspect({expectedHead:zero})).head,zero);
 const committed=await x.coord.commit(x.supervisor);assert.equal(committed.status,'COMMITTED_REQUIRES_SUPERVISED_FINALIZATION');
 assert.deepEqual(committed.head,x.args.expectedAfterHead);
 const done=await x.coord.reconcile({...x.supervisor,decision:'finalize-committed'});assert.equal(done.status,'EXTERNALLY_PINNED_FINALIZED');
 assert.deepEqual((await x.registry.inspect({expectedHead:x.args.expectedAfterHead})).head,x.args.expectedAfterHead);
 assert.ok((await readdir(x.archiveDirectory)).includes(`${x.stage.expectedArchiveDigest}.tjexport`));
 assert.equal(done.productionApproved,false);
});
test('31Z refuses missing independently pinned after-head',async t=>{const x=await fixture(t);await error(()=>x.coord.stage({...x.p,...x.args,expectedAfterHead:undefined}),'CROSS_RESOURCE_EXTERNAL_PINS_REQUIRED');});
test('31Z refuses forged externally pinned next digest',async t=>{const x=await fixture(t);await error(()=>x.coord.stage({...x.p,...x.args,expectedAfterHead:{count:1,headDigest:'f'.repeat(64)}}),'CROSS_RESOURCE_AFTER_HEAD_PIN_MISMATCH');});
test('31Z rejects invalid signed witness receipt before any archive write',async t=>{const x=await fixture(t);x.p.receipt.signatures[0].signature='A'.repeat(86);await error(()=>x.coord.stage({...x.p,...x.args}),'EXPORT_RECEIPT_SIGNATURE_INVALID');assert.deepEqual(await readdir(x.archiveDirectory),['.coordination-lock']);});
test('31Z rejects tampered archive bytes before staging',async t=>{const x=await fixture(t);const bytes=Buffer.from(x.p.archiveBytes);bytes[bytes.length-1]^=1;await error(()=>x.coord.stage({receipt:x.p.receipt,archiveBytes:bytes,...x.args}),'CROSS_RESOURCE_RECEIPT_BINDING');});
test('31Z rejects altered staged archive and preserves uncertainty marker',async t=>{const x=await staged(t),path=join(x.archiveDirectory,`${x.stage.expectedArchiveDigest}.tjexport`);await writeFile(path,Buffer.from('altered'),{mode:0o600});await error(()=>x.coord.commit(x.supervisor),'CROSS_RESOURCE_ARCHIVE_TAMPERED');assert.ok((await readdir(x.archiveDirectory)).includes('.pending-coordination.json'));});
test('31Z rejects symlink substitution of staged archive',async t=>{const x=await staged(t),path=join(x.archiveDirectory,`${x.stage.expectedArchiveDigest}.tjexport`);await unlink(path);await symlink('/etc/passwd',path);await error(()=>x.coord.commit(x.supervisor),'CROSS_RESOURCE_FILE_UNSAFE');});
test('31Z rejects hardlinked archive evidence',async t=>{const x=await staged(t),path=join(x.archiveDirectory,`${x.stage.expectedArchiveDigest}.tjexport`);await link(path,join(x.parent,'outside-hardlink'));await error(()=>x.coord.commit(x.supervisor),'CROSS_RESOURCE_FILE_UNSAFE');});
test('31Z rejects forged external marker hash',async t=>{const x=await staged(t);await error(()=>x.coord.commit({...x.supervisor,expectedMarkerDigest:'f'.repeat(64)}),'CROSS_RESOURCE_MARKER_PIN_MISMATCH');});
test('31Z rejects substituted marker contents even if attacker supplies recomputed hash',async t=>{const x=await staged(t),path=join(x.archiveDirectory,'.pending-coordination.json'),marker=JSON.parse(await readFile(path,'utf8'));marker.expectedEpoch=9;const bytes=Buffer.from(JSON.stringify(marker));await writeFile(path,bytes);await error(()=>x.coord.commit({...x.supervisor,expectedMarkerDigest:sha(bytes)}),'CROSS_RESOURCE_MARKER_INVALID');});
test('31Z cannot finalize uncommitted receipt and cannot infer commit from staged archive',async t=>{const x=await staged(t);await error(()=>x.coord.reconcile({...x.supervisor,decision:'finalize-committed'}),'EXPORT_REGISTRY_PIN_MISMATCH');});
test('31Z externally pinned quarantine preserves orphan and blocks silent reuse',async t=>{const x=await staged(t),r=await x.coord.reconcile({...x.supervisor,decision:'quarantine-uncommitted'});assert.equal(r.status,'EXTERNALLY_PINNED_ORPHAN_QUARANTINED');const names=await readdir(x.archiveDirectory);assert.ok(names.some(n=>n.startsWith('.orphan-')));await error(()=>x.coord.stage({...x.p,...x.args}),'CROSS_RESOURCE_ORPHAN_OR_UNTRACKED_FILE');});
test('31Z rejects quarantine decision after receipt already committed',async t=>{const x=await staged(t);await x.coord.commit(x.supervisor);await error(()=>x.coord.reconcile({...x.supervisor,decision:'quarantine-uncommitted'}),'EXPORT_REGISTRY_PIN_MISMATCH');});
test('31Z rejects replayed finalize after marker is removed',async t=>{const x=await staged(t);await x.coord.commit(x.supervisor);await x.coord.reconcile({...x.supervisor,decision:'finalize-committed'});await error(()=>x.coord.reconcile({...x.supervisor,decision:'finalize-committed'}),'CROSS_RESOURCE_FILE_UNSAFE');});
test('31Z rejects duplicate concurrent staging; at most one succeeds',async t=>{const x=await fixture(t);const result=await Promise.allSettled([x.coord.stage({...x.p,...x.args}),x.coord.stage({...x.p,...x.args})]);assert.equal(result.filter(r=>r.status==='fulfilled').length,1);assert.equal(result.filter(r=>r.status==='rejected').length,1);});
test('31Z rejects unsafe archive directory permissions',async t=>{const x=await fixture(t);await chmod(x.archiveDirectory,0o777);await error(()=>x.coord.stage({...x.p,...x.args}),'CROSS_RESOURCE_DIRECTORY_UNSAFE');});
test('31Z rejects unsafe receipt directory permissions',async t=>{const x=await fixture(t);await chmod(x.registryDirectory,0o777);await error(()=>x.coord.stage({...x.p,...x.args}),'CROSS_RESOURCE_DIRECTORY_UNSAFE');});
test('31Z rejects symlinked receipt directory',async t=>{const x=await fixture(t),alias=join(x.parent,'alias');await symlink(x.registryDirectory,alias);assert.throws(()=>createOfflineArchiveReceiptCoordinator({archiveDirectory:x.archiveDirectory,registryDirectory:x.archiveDirectory,registry:x.registry,registryId,witnesses,quorum}),e=>e.code==='CROSS_RESOURCE_SEPARATION_REQUIRED');const bad=createOfflineArchiveReceiptCoordinator({archiveDirectory:x.archiveDirectory,registryDirectory:alias,registry:x.registry,registryId,witnesses,quorum});await error(()=>bad.stage({...x.p,...x.args}),'CROSS_RESOURCE_DIRECTORY_UNSAFE');});
test('31Z rejects orphan/untracked archive before new stage',async t=>{const x=await fixture(t);await writeFile(join(x.archiveDirectory,'surprise.tjexport'),'x');await error(()=>x.coord.stage({...x.p,...x.args}),'CROSS_RESOURCE_ORPHAN_OR_UNTRACKED_FILE');});
test('31Z refuses unpinned recovery decision',async t=>{const x=await staged(t);await error(()=>x.coord.reconcile({...x.supervisor,decision:'guess'}),'CROSS_RESOURCE_DECISION_REQUIRED');});
const mod=fileURLToPath(new URL('../src/offline-archive-receipt-coordinator.mjs',import.meta.url));
const registryMod=fileURLToPath(new URL('../src/offline-acquisition-export-receipt-registry.mjs',import.meta.url));
function child(x,action,crash,supervisor=x.supervisor){
 const code=`import {createPublicKey} from 'node:crypto';import {createOfflineExportReceiptRegistry} from ${JSON.stringify(registryMod)};import {createOfflineArchiveReceiptCoordinator} from ${JSON.stringify(mod)};const x=JSON.parse(process.argv[1]);const witnesses=x.witnesses.map(w=>({id:w.id,publicKey:createPublicKey(w.pem)}));const registry=createOfflineExportReceiptRegistry({directory:x.registryDirectory,registryId:x.registryId,witnesses,quorum:2});const c=createOfflineArchiveReceiptCoordinator({archiveDirectory:x.archiveDirectory,registryDirectory:x.registryDirectory,registry,registryId:x.registryId,witnesses,quorum:2,injectFault:phase=>{if(phase===x.crash)process.kill(process.pid,'SIGKILL');}});await c[x.action](x.action==='stage'?{receipt:x.receipt,archiveBytes:Buffer.from(x.archive,'base64'),...x.args}:x.action==='reconcile'?{...x.supervisor,decision:'finalize-committed'}:x.supervisor);`;
 return spawnSync(process.execPath,['--input-type=module','-e',code,JSON.stringify({registryDirectory:x.registryDirectory,archiveDirectory:x.archiveDirectory,registryId,witnesses:witnesses.map(w=>({id:w.id,pem:w.publicKey.export({format:'pem',type:'spki'})})),action,crash,receipt:x.p.receipt,archive:x.p.archiveBytes.toString('base64'),args:x.args,supervisor})],{encoding:'utf8',timeout:15000});
}
test('31Z actual SIGKILL after archive temporary fsync leaves orphan and blocks reuse',async t=>{const x=await fixture(t),r=child(x,'stage','after-archive-temp-sync');assert.equal(r.signal,'SIGKILL',JSON.stringify(r));await error(()=>x.coord.stage({...x.p,...x.args}),'CROSS_RESOURCE_ORPHAN_OR_UNTRACKED_FILE');});
test('31Z actual SIGKILL after archive hardlink fsync leaves orphan and blocks reuse',async t=>{const x=await fixture(t),r=child(x,'stage','after-archive-link-sync');assert.equal(r.signal,'SIGKILL',JSON.stringify(r));await error(()=>x.coord.stage({...x.p,...x.args}),'CROSS_RESOURCE_ORPHAN_OR_UNTRACKED_FILE');});
test('31Z actual SIGKILL after durable coordination marker can be independently quarantined',async t=>{
 const x=await fixture(t),r=child(x,'stage','after-coordination-marker-sync');assert.equal(r.signal,'SIGKILL',JSON.stringify(r));
 const markerBytes=await readFile(join(x.archiveDirectory,'.pending-coordination.json'));
 const supervisor={...x.args,expectedMarkerDigest:sha(markerBytes),expectedArchiveDigest:x.p.receipt.body.archiveDigest};
 await error(()=>x.coord.stage({...x.p,...x.args}),'CROSS_RESOURCE_ORPHAN_OR_UNTRACKED_FILE');
 assert.equal((await x.coord.reconcile({...supervisor,decision:'quarantine-uncommitted'})).status,'EXTERNALLY_PINNED_ORPHAN_QUARANTINED');
});
test('31Z actual SIGKILL after real receipt append requires pinned finalize, no duplicate append',async t=>{
 const x=await staged(t),r=child(x,'commit','after-receipt-append');assert.equal(r.signal,'SIGKILL',JSON.stringify(r));
 await error(()=>x.coord.commit(x.supervisor),'EXPORT_REGISTRY_PIN_MISMATCH');
 assert.equal((await x.coord.reconcile({...x.supervisor,decision:'finalize-committed'})).status,'EXTERNALLY_PINNED_FINALIZED');
});
test('31Z actual SIGKILL after supervised finalization leaves committed evidence, cannot replay marker',async t=>{
 const x=await staged(t);await x.coord.commit(x.supervisor);const r=child(x,'reconcile','after-coordination-reconcile');assert.equal(r.signal,'SIGKILL',JSON.stringify(r));
 assert.deepEqual((await x.registry.inspect({expectedHead:x.args.expectedAfterHead})).head,x.args.expectedAfterHead);
 await error(()=>x.coord.reconcile({...x.supervisor,decision:'finalize-committed'}),'CROSS_RESOURCE_FILE_UNSAFE');
});
test('31Z missing archive after staging fails closed instead of reconstructing bytes',async t=>{const x=await staged(t);await unlink(join(x.archiveDirectory,`${x.stage.expectedArchiveDigest}.tjexport`));await error(()=>x.coord.commit(x.supervisor),'CROSS_RESOURCE_FILE_UNSAFE');});
test('31Z symlinked durable coordination marker fails closed',async t=>{const x=await staged(t),p=join(x.archiveDirectory,'.pending-coordination.json');await unlink(p);await symlink('/etc/passwd',p);await error(()=>x.coord.commit(x.supervisor),'CROSS_RESOURCE_FILE_UNSAFE');});
test('31Z actual SIGKILL immediately before receipt append can be quarantined, not mistaken for commit',async t=>{const x=await staged(t),r=child(x,'commit','before-receipt-append');assert.equal(r.signal,'SIGKILL',JSON.stringify(r));assert.deepEqual((await x.registry.inspect({expectedHead:zero})).head,zero);const v=await x.coord.reconcile({...x.supervisor,decision:'quarantine-uncommitted'});assert.equal(v.status,'EXTERNALLY_PINNED_ORPHAN_QUARANTINED');});
