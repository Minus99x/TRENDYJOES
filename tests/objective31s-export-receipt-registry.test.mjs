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

test('31S independently supplied policy digest is order invariant',()=>assert.equal(policyDigest,offlineExportReceiptPolicyDigest({witnesses:[...witnesses].reverse(),quorum})));
test('31S rejects minority quorum configuration',()=>failSync(()=>offlineExportReceiptPolicyDigest({witnesses,quorum:1}),'EXPORT_RECEIPT_POLICY_INVALID'));
test('31S rejects duplicate witness public keys',()=>failSync(()=>offlineExportReceiptPolicyDigest({witnesses:[witnesses[0],{...witnesses[0],id:'other_31s_witness'}],quorum:2}),'EXPORT_RECEIPT_DUPLICATE_KEY'));
test('31S valid quorum-signed receipt is non-authoritative',()=>{const p=makeReceipt(),v=verifyOfflineExportReceipt({receipt:p.receipt,witnesses,quorum,registryId,nowMs});assert.equal(v.verified,true);assert.equal(v.underlyingSignaturesVerified,false);assert.equal(v.productionApproved,false);});
test('31S valid durable append and externally pinned read-only inspection',async t=>{const {registry,a}=await first(t);const v=await registry.inspect({expectedHead:pin(a)});assert.equal(v.count,1);assert.equal(v.productionApproved,false);assert.equal(v.mayManufacture,false);});
test('31S signed receipts are bound to exact acquisition and archive bytes',async t=>{const {registry,a}=await first(t);const p=makeReceipt({acquisitionId:'acquisition_31s_0002',sequence:2,previousDigest:pin(a).headDigest});const b=await registry.append({...p,expectedHead:pin(a),nowMs});assert.equal(b.count,2);});
test('31S rejects forged receipt signature',()=>{const p=makeReceipt();p.receipt.signatures[0].signature=sign(null,offlineExportReceiptSigningBytes(p.receipt.body),generateKeyPairSync('ed25519').privateKey).toString('base64url');failSync(()=>verifyOfflineExportReceipt({receipt:p.receipt,witnesses,quorum,registryId,nowMs}),'EXPORT_RECEIPT_SIGNATURE_INVALID');});
test('31S rejects signature duplication',()=>{const p=makeReceipt();p.receipt.signatures[1]={...p.receipt.signatures[0]};failSync(()=>verifyOfflineExportReceipt({receipt:p.receipt,witnesses,quorum,registryId,nowMs}),'EXPORT_RECEIPT_SIGNATURE_INVALID');});
test('31S rejects minority-signed receipt',()=>{const p=makeReceipt({signerIndices:[0]});failSync(()=>verifyOfflineExportReceipt({receipt:p.receipt,witnesses,quorum,registryId,nowMs}),'EXPORT_RECEIPT_QUORUM_INVALID');});
test('31S rejects swapped witness trust',()=>{const p=makeReceipt(),bad=[{...witnesses[0],publicKey:generateKeyPairSync('ed25519').publicKey},...witnesses.slice(1)];failSync(()=>verifyOfflineExportReceipt({receipt:p.receipt,witnesses:bad,quorum,registryId,nowMs}),'EXPORT_RECEIPT_POLICY_MISMATCH');});
test('31S rejects tampered signed archive digest',()=>{const p=makeReceipt();p.receipt.body.archiveDigest='f'.repeat(64);failSync(()=>verifyOfflineExportReceipt({receipt:p.receipt,witnesses,quorum,registryId,nowMs}),'EXPORT_RECEIPT_SIGNATURE_INVALID');});
test('31S rejects unrecognized body authorization fields',()=>{const p=makeReceipt();p.receipt.body.allowManufacture=true;failSync(()=>verifyOfflineExportReceipt({receipt:p.receipt,witnesses,quorum,registryId,nowMs}),'EXPORT_RECEIPT_BODY_INVALID');});
test('31S rejects expired receipt',()=>{const p=makeReceipt();failSync(()=>verifyOfflineExportReceipt({receipt:p.receipt,witnesses,quorum,registryId,nowMs:nowMs+60000}),'EXPORT_RECEIPT_EXPIRED_OR_FUTURE');});
test('31S rejects future-dated receipt',()=>{const p=makeReceipt();failSync(()=>verifyOfflineExportReceipt({receipt:p.receipt,witnesses,quorum,registryId,nowMs:nowMs-1001}),'EXPORT_RECEIPT_EXPIRED_OR_FUTURE');});
test('31S rejects missing independent append head',async t=>{const {registry}=await sandbox(t);await fail(()=>registry.append({...makeReceipt(),nowMs}),'EXPORT_REGISTRY_EXTERNAL_PIN_REQUIRED');});
test('31S rejects stale externally pinned head',async t=>{const {registry}=await first(t);await fail(()=>registry.inspect({expectedHead:zero}),'EXPORT_REGISTRY_PIN_MISMATCH');});
test('31S rejects signed but wrong sequence',async t=>{const {registry,a}=await first(t);const p=makeReceipt({acquisitionId:'acquisition_31s_0002',sequence:3,previousDigest:pin(a).headDigest});await fail(()=>registry.append({...p,expectedHead:pin(a),nowMs}),'EXPORT_REGISTRY_SEQUENCE_INVALID');});
test('31S rejects signed but wrong predecessor',async t=>{const {registry,a}=await first(t);const p=makeReceipt({acquisitionId:'acquisition_31s_0002',sequence:2,previousDigest:'f'.repeat(64)});await fail(()=>registry.append({...p,expectedHead:pin(a),nowMs}),'EXPORT_REGISTRY_SEQUENCE_INVALID');});
test('31S rejects replayed acquisition with new export identity',async t=>{const {registry,a}=await first(t);const p=makeReceipt({sequence:2,previousDigest:pin(a).headDigest,exportId:'new_export_31s_0002'});await fail(()=>registry.append({...p,expectedHead:pin(a),nowMs}),'EXPORT_REGISTRY_REPLAY');});
test('31S rejects reused export identity with new acquisition',async t=>{const {registry,a}=await first(t);const p=makeReceipt({acquisitionId:'acquisition_31s_0002',sequence:2,previousDigest:pin(a).headDigest,exportId:'export_31s_1_0001'});await fail(()=>registry.append({...p,expectedHead:pin(a),nowMs}),'EXPORT_REGISTRY_REPLAY');});
test('31S rejects reused nonce',async t=>{const {registry,a}=await first(t);const p=makeReceipt({acquisitionId:'acquisition_31s_0002',sequence:2,previousDigest:pin(a).headDigest,nonce:'nonce_31s_1_0001'});await fail(()=>registry.append({...p,expectedHead:pin(a),nowMs}),'EXPORT_REGISTRY_REPLAY');});
test('31S rejects archive byte tampering even when signed receipt remains intact',async t=>{const {registry}=await sandbox(t),p=makeReceipt(),bad=Buffer.from(p.archiveBytes);bad[bad.length-1]^=1;await fail(()=>registry.append({...p,archiveBytes:bad,expectedHead:zero,nowMs}),'ACQUISITION_EXPORT_PIN_MISMATCH');});
test('31S rejects truncated archive despite valid signed receipt',async t=>{const {registry}=await sandbox(t),p=makeReceipt();await fail(()=>registry.append({...p,archiveBytes:p.archiveBytes.subarray(0,-1),expectedHead:zero,nowMs}),'EXPORT_REGISTRY_ARCHIVE_SIZE_MISMATCH');});
test('31S rejects archive substitution across acquisition identities',async t=>{const {registry}=await sandbox(t),other=archive('acquisition_31s_0002'),p=makeReceipt({overrides:{archiveDigest:sha(other),archiveBytes:other.length}});await fail(()=>registry.append({...p,archiveBytes:other,expectedHead:zero,nowMs}),'ACQUISITION_EXPORT_HEADER_INVALID');});
test('31S rejects malformed internally forged archive with newly signed outer hash',async t=>{const {registry}=await sandbox(t),bad=Buffer.from(archive('acquisition_31s_0001'));bad[bad.length-1]^=1;const p=makeReceipt({archiveBytes:bad});await fail(()=>registry.append({...p,expectedHead:zero,nowMs}),'ACQUISITION_EXPORT_TRUNCATED_OR_TAMPERED');});
test('31S missing archive bytes fail closed',async t=>{const {registry}=await sandbox(t),p=makeReceipt();await fail(()=>registry.append({receipt:p.receipt,expectedHead:zero,nowMs}),'EXPORT_REGISTRY_ARCHIVE_SIZE_MISMATCH');});
test('31S rejects modified durable receipt bytes',async t=>{const {registry,directory,a}=await first(t),path=join(directory,'0001.json'),e=JSON.parse(await readFile(path,'utf8'));e.receipt.body.exportId='forged_export_31s_1';await writeFile(path,JSON.stringify(e));await fail(()=>registry.inspect({expectedHead:pin(a)}),'EXPORT_RECEIPT_SIGNATURE_INVALID');});
test('31S detects rollback with independent head pin',async t=>{const {registry,directory,a}=await first(t);await unlink(join(directory,'0001.json'));await fail(()=>registry.inspect({expectedHead:pin(a)}),'EXPORT_REGISTRY_PIN_MISMATCH');});
test('31S rejects symlinked history file',async t=>{const {registry,directory,a}=await first(t);await unlink(join(directory,'0001.json'));await symlink('/etc/passwd',join(directory,'0001.json'));await fail(()=>registry.inspect({expectedHead:pin(a)}),'EXPORT_REGISTRY_FILE_UNSAFE');});
test('31S rejects hardlinked history file',async t=>{const {registry,directory,a}=await first(t);await link(join(directory,'0001.json'),join(directory,'copy-hardlink'));await fail(()=>registry.inspect({expectedHead:pin(a)}),'EXPORT_REGISTRY_HISTORY_INVALID');});
test('31S rejects unexpected untracked files',async t=>{const {registry,directory,a}=await first(t);await writeFile(join(directory,'surprise.txt'),'x');await fail(()=>registry.inspect({expectedHead:pin(a)}),'EXPORT_REGISTRY_HISTORY_INVALID');});
test('31S rejects unsafe directory permissions',async t=>{const {registry,directory,a}=await first(t);await chmod(directory,0o777);await fail(()=>registry.inspect({expectedHead:pin(a)}),'EXPORT_REGISTRY_DIRECTORY_UNSAFE');});
test('31S rejects unsafe lock permissions',async t=>{const {registry,directory,a}=await first(t);await chmod(join(directory,'.export-registry-lock'),0o666);await fail(()=>registry.inspect({expectedHead:pin(a)}),'EXPORT_REGISTRY_LOCK_UNSAFE');});
test('31S lock spans complete critical section and prevents concurrent same-slot append',async t=>{const {registry}=await sandbox(t,{injectFault:async phase=>{if(phase==='after-export-pending-sync')await new Promise(ok=>setTimeout(ok,100));}}),p=makeReceipt();const results=await Promise.allSettled([registry.append({...p,expectedHead:zero,nowMs}),registry.append({...p,expectedHead:zero,nowMs})]);assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.equal(results.filter(r=>r.status==='rejected').length,1);});
test('31S cross-process lock prevents independent simultaneous same-slot commits',async t=>{const {registry,directory}=await sandbox(t,{injectFault:async phase=>{if(phase==='after-export-pending-sync')await new Promise(ok=>setTimeout(ok,300));}}),p=makeReceipt();const mod=fileURLToPath(new URL('../src/offline-acquisition-export-receipt-registry.mjs',import.meta.url));const childCode=`import {createPublicKey} from 'node:crypto';import {createOfflineExportReceiptRegistry} from ${JSON.stringify(mod)};const x=JSON.parse(process.argv[1]);const w=x.witnesses.map(z=>({id:z.id,publicKey:createPublicKey(z.publicKey)}));const j=createOfflineExportReceiptRegistry({directory:x.directory,registryId:x.registryId,witnesses:w,quorum:2});try{await j.append({receipt:x.receipt,archiveBytes:Buffer.from(x.archiveBytes,'base64'),expectedHead:{count:0,headDigest:'0'.repeat(64)},nowMs:x.nowMs});process.exit(0);}catch(e){process.stderr.write(e.code);process.exit(19);}`;
 const childArgs=JSON.stringify({directory,registryId,witnesses:witnesses.map(w=>({id:w.id,publicKey:w.publicKey.export({format:'pem',type:'spki'})})),receipt:p.receipt,archiveBytes:p.archiveBytes.toString('base64'),nowMs});
 // spawnSync would block the event loop, so use an asynchronous child for the lock race.
 const {spawn}=await import('node:child_process');const child=spawn(process.execPath,['--input-type=module','-e',childCode,childArgs],{stdio:['ignore','ignore','pipe'],cwd:directory});let stderr='';child.stderr.on('data',d=>stderr+=d);
 const parent=registry.append({...p,expectedHead:zero,nowMs});const [a,b]=await Promise.all([parent.then(()=>0,()=>19),new Promise(ok=>child.on('close',ok))]);assert.equal([a,b].filter(c=>c===0).length,1,stderr);assert.equal([a,b].filter(c=>c!==0).length,1,stderr);
});
async function crashed(t,phase){
 const {directory}=await sandbox(t),p=makeReceipt();const mod=fileURLToPath(new URL('../src/offline-acquisition-export-receipt-registry.mjs',import.meta.url));
 const code=`import {createPublicKey} from 'node:crypto';import {createOfflineExportReceiptRegistry} from ${JSON.stringify(mod)};const x=JSON.parse(process.argv[1]);const witnesses=x.witnesses.map(w=>({id:w.id,publicKey:createPublicKey(w.publicKey)}));const r=createOfflineExportReceiptRegistry({directory:x.directory,registryId:x.registryId,witnesses,quorum:2,injectFault:phase=>{if(phase===x.phase)process.exit(83);}});await r.append({receipt:x.receipt,archiveBytes:Buffer.from(x.archiveBytes,'base64'),expectedHead:{count:0,headDigest:'0'.repeat(64)},nowMs:x.nowMs});`;
 const x={directory,registryId,witnesses:witnesses.map(w=>({id:w.id,publicKey:w.publicKey.export({format:'pem',type:'spki'})})),receipt:p.receipt,archiveBytes:p.archiveBytes.toString('base64'),nowMs,phase};
 const r=spawnSync(process.execPath,['--input-type=module','-e',code,JSON.stringify(x)],{encoding:'utf8',timeout:15000});assert.equal(r.status,83,r.stderr);
 return {directory,registry:createOfflineExportReceiptRegistry({directory,registryId,witnesses,quorum})};
}
test('31S actual child-process crash after pending fsync blocks silent retry',async t=>{const {registry}=await crashed(t,'after-export-pending-sync');await fail(()=>registry.inspect({expectedHead:zero}),'EXPORT_REGISTRY_UNCERTAIN_COMMIT');});
test('31S actual child-process crash after committed fsync leaves verifiable signed history',async t=>{const {registry,directory}=await crashed(t,'after-export-commit-sync'),e=JSON.parse(await readFile(join(directory,'0001.json'),'utf8'));const v=await registry.inspect({expectedHead:{count:1,headDigest:e.digest}});assert.equal(v.count,1);assert.equal(v.productionApproved,false);});
test('31S recorded history verifies signatures after receipt expiry without reauthorizing new append',async t=>{const {registry,a}=await first(t);const v=await registry.inspect({expectedHead:pin(a)});assert.equal(v.count,1);const p=makeReceipt({acquisitionId:'acquisition_31s_0002',sequence:2,previousDigest:pin(a).headDigest});await fail(()=>registry.append({...p,expectedHead:pin(a),nowMs:nowMs+60000}),'EXPORT_RECEIPT_EXPIRED_OR_FUTURE');});
test('31S rejected writes do not leave pending markers',async t=>{const {registry,directory}=await sandbox(t),p=makeReceipt();p.receipt.signatures[0].signature='invalid';await fail(()=>registry.append({...p,expectedHead:zero,nowMs}),'EXPORT_RECEIPT_SIGNATURE_INVALID');assert.equal((await readdir(directory)).includes('.pending.json'),false);});
test('31S rehashed local record cannot validate a forged unsigned receipt',async t=>{const {registry,directory,a}=await first(t),path=join(directory,'0001.json'),e=JSON.parse(await readFile(path,'utf8'));e.receipt.body.archiveDigest='b'.repeat(64);const {digest,...body}=e;e.digest=recordHash(body);await writeFile(path,JSON.stringify(e));await fail(()=>registry.inspect({expectedHead:{count:1,headDigest:e.digest}}),'EXPORT_RECEIPT_SIGNATURE_INVALID');});
test('31S changing registry identity fails independently signed trust binding',async t=>{const {directory,a}=await first(t);const other=createOfflineExportReceiptRegistry({directory,registryId:'different_registry_31s',witnesses,quorum});await fail(()=>other.inspect({expectedHead:pin(a)}),'EXPORT_RECEIPT_POLICY_MISMATCH');});
test('31S reject symlink substitution for lock file',async t=>{const {registry,directory,a}=await first(t);await unlink(join(directory,'.export-registry-lock'));await symlink('/etc/passwd',join(directory,'.export-registry-lock'));await fail(()=>registry.inspect({expectedHead:pin(a)}),'EXPORT_REGISTRY_LOCK_UNSAFE');});
test('31S hardlink outside registry is rejected by file nlink check',async t=>{const {registry,directory,a}=await first(t);const outside=join(tmpdir(),`tj31s-hardlink-${process.pid}-${Date.now()}`);await link(join(directory,'0001.json'),outside);t.after(()=>rm(outside,{force:true}));await fail(()=>registry.inspect({expectedHead:pin(a)}),'EXPORT_REGISTRY_FILE_UNSAFE');});
test('31S malicious path replacement with symlinked directory is rejected',async t=>{const {directory,a}=await first(t);const alias=directory+'-alias';await symlink(directory,alias);t.after(()=>rm(alias,{force:true}));const other=createOfflineExportReceiptRegistry({directory:alias,registryId,witnesses,quorum});await fail(()=>other.inspect({expectedHead:pin(a)}),'EXPORT_REGISTRY_DIRECTORY_UNSAFE');});
