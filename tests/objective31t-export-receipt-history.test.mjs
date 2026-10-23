import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {mkdtemp,rm,writeFile,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {OFFLINE_EXPORT_RECEIPT_SCHEMA,OFFLINE_EXPORT_REGISTRY_SCHEMA,offlineExportReceiptPolicyDigest,offlineExportReceiptSigningBytes,createOfflineExportReceiptRegistry} from '../src/offline-acquisition-export-receipt-registry.mjs';
import {OFFLINE_EXPORT_RECEIPT_HISTORY_SCHEMA,encodeOfflineExportReceiptHistory,verifyOfflineExportReceiptHistory,compareOfflineExportReceiptHistories} from '../src/offline-export-receipt-history.mjs';
import {OFFLINE_ACQUISITION_EXPORT_SCHEMA} from '../src/offline-acquisition-evidence-export.mjs';
import {OFFLINE_ACQUISITION_SESSION_SCHEMA} from '../src/offline-acquisition-session-journal.mjs';
import {OFFLINE_ACQUISITION_MANIFEST_SCHEMA} from '../src/offline-forensic-acquisition-provenance.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex'),ROOT='0'.repeat(64);
const registryId='receipt_registry_31t',nowMs=1800000000000;
const keys=Array.from({length:3},(_,i)=>({id:`witness_31t_${i+1}`,...generateKeyPairSync('ed25519')}));
const witnesses=keys.map(k=>({id:k.id,publicKey:k.publicKey})),quorum=2;
const policyDigest=offlineExportReceiptPolicyDigest({witnesses,quorum});
const zero={count:0,headDigest:ROOT};
const recordDigest=b=>sha(Buffer.from(`${OFFLINE_EXPORT_REGISTRY_SCHEMA}\0${JSON.stringify(b)}`));
const clone=x=>JSON.parse(JSON.stringify(x));
const reject=(f,code)=>assert.throws(f,e=>e?.code===code,code);
const rejectAsync=(f,code)=>assert.rejects(f,e=>e?.code===code,code);
const opts={registryId,witnesses,quorum};
function signed(body,signers=[0,1]){
 return {body,signatures:signers.map(i=>({witnessId:keys[i].id,signature:sign(null,offlineExportReceiptSigningBytes(body),keys[i].privateKey).toString('base64url')})).sort((a,b)=>a.witnessId.localeCompare(b.witnessId))};
}
function makeEntries(n,{branch='A',signers=[0,1],expired=false}={}){
 const entries=[];let previous=ROOT;
 for(let i=1;i<=n;i++){
  const suffix=i===2?branch:'common';
  const body={schema:OFFLINE_EXPORT_RECEIPT_SCHEMA,registryId,sequence:i,previousDigest:previous,exportId:`export_31t_${i}_${suffix}`,acquisitionId:`acquisition_31t_${i}_${suffix}`,archiveDigest:sha(Buffer.from(`archive-${i}-${suffix}`)),archiveBytes:100+i,issuedAt:nowMs+i*1000,expiresAt:nowMs+i*1000+(expired?1000:60000),nonce:`nonce_31t_${i}_${suffix}`,policyDigest};
  const record={schema:OFFLINE_EXPORT_REGISTRY_SCHEMA,index:i,previousDigest:previous,receipt:signed(body,signers)};
  const entry={...record,digest:recordDigest(record)};entries.push(entry);previous=entry.digest;
 }
 return entries;
}
const pin=entries=>({count:entries.length,headDigest:entries.length?entries.at(-1).digest:ROOT});
const encode=entries=>encodeOfflineExportReceiptHistory({...opts,entries,expectedHead:pin(entries)});
const verify=(bytes,expectedHead)=>verifyOfflineExportReceiptHistory({...opts,bytes,expectedHead});
const compare=(a,b)=>compareOfflineExportReceiptHistories({...opts,leftBytes:encode(a),rightBytes:encode(b),leftExpectedHead:pin(a),rightExpectedHead:pin(b)});
const parse=bytes=>JSON.parse(bytes.toString('utf8'));
const altered=(bytes,mutator)=>{const x=parse(bytes);mutator(x);return Buffer.from(JSON.stringify(x));};

// Construct a valid bounded 31R archive for real durable-registry integration.
function archive(acquisitionId){
 const pre={phase:'PRE',acquisitionId},post={phase:'POST',acquisitionId};
 const manifest={schema:OFFLINE_ACQUISITION_MANIFEST_SCHEMA,acquisitionId,envelope:{transportDigest:'a'.repeat(64)},receiptHistory:[pre,post]};
 let previous=ROOT;const events=[];
 for(const [i,action,payload] of [[1,'BEGIN',{acquisitionId}],[2,'PRE',pre],[3,'POST',manifest]]){
  const body={schema:OFFLINE_ACQUISITION_SESSION_SCHEMA,index:i,previousDigest:previous,action,payload};
  const e={...body,digest:sha(Buffer.from(`${OFFLINE_ACQUISITION_SESSION_SCHEMA}\0${JSON.stringify(body)}`))};previous=e.digest;events.push(e);
 }
 const files=new Map([['manifest.json',manifest],['session/0001.json',events[0]],['session/0002.json',events[1]],['session/0003.json',events[2]],['evidence/branch_01.json',{variant:1}]]);
 const entries=[],payload=[];let offset=0;
 for(const [path,value] of [...files].sort((a,b)=>a[0].localeCompare(b[0]))){const bytes=Buffer.from(JSON.stringify(value));entries.push({path,offset,size:bytes.length,sha256:sha(bytes)});payload.push(bytes);offset+=bytes.length;}
 const body=Buffer.concat(payload),header=Buffer.from(JSON.stringify({schema:OFFLINE_ACQUISITION_EXPORT_SCHEMA,acquisitionId,files:entries,payloadBytes:body.length,payloadDigest:sha(body)}));
 const len=Buffer.alloc(4);len.writeUInt32BE(header.length);return Buffer.concat([Buffer.from(`${OFFLINE_ACQUISITION_EXPORT_SCHEMA}\n`),len,header,body]);
}
function realReceipt(sequence,previousDigest,acquisitionId){
 const archiveBytes=archive(acquisitionId),body={schema:OFFLINE_EXPORT_RECEIPT_SCHEMA,registryId,sequence,previousDigest,exportId:`export_31t_real_${sequence}`,acquisitionId,archiveDigest:sha(archiveBytes),archiveBytes:archiveBytes.length,issuedAt:nowMs,expiresAt:nowMs+60000,nonce:`nonce_31t_real_${sequence}`,policyDigest};
 return {receipt:signed(body),archiveBytes};
}

test('31T canonical portable export verifies full independently pinned signed history',()=>{const entries=makeEntries(3),bytes=encode(entries),v=verify(bytes,pin(entries));assert.equal(v.count,3);assert.equal(v.productionApproved,false);assert.equal(v.mayManufacture,false);assert.equal(v.bundleDigest,sha(bytes));});
test('31T empty externally pinned history is read-only',()=>{const b=encode([]);assert.equal(verify(b,zero).count,0);});
test('31T historically expired receipts verify without reauthorization',()=>{const entries=makeEntries(2,{expired:true});assert.equal(verify(encode(entries),pin(entries)).verified,true);});
test('31T canonical serialization deterministic across repeated exports',()=>{const e=makeEntries(2);assert.deepEqual(encode(e),encode(e));});
test('31T input records cannot mutate serialized portable bytes afterward',()=>{const e=makeEntries(1),b=encode(e);e[0].receipt.body.exportId='mutated_after_export';assert.equal(verify(b,pin(makeEntries(1))).verified,true);});
test('31T missing independent pin fails closed',()=>reject(()=>verifyOfflineExportReceiptHistory({...opts,bytes:encode(makeEntries(1))}),'EXPORT_HISTORY_EXTERNAL_PIN_REQUIRED'));
test('31T unpinned export generation fails closed',()=>reject(()=>encodeOfflineExportReceiptHistory({...opts,entries:makeEntries(1)}),'EXPORT_HISTORY_EXTERNAL_PIN_REQUIRED'));
test('31T wrong pinned head rejects valid signed history',()=>reject(()=>verify(encode(makeEntries(1)),zero),'EXPORT_HISTORY_INVALID_OR_UNPINNED'));
test('31T wrong registry identity rejects portable bundle',()=>reject(()=>verifyOfflineExportReceiptHistory({...opts,registryId:'other_registry_31t',bytes:encode(makeEntries(1)),expectedHead:pin(makeEntries(1))}),'EXPORT_HISTORY_INVALID_OR_UNPINNED'));
test('31T substituted independently trusted witness key rejects policy',()=>{const e=makeEntries(1);reject(()=>verifyOfflineExportReceiptHistory({...opts,witnesses:[{...witnesses[0],publicKey:generateKeyPairSync('ed25519').publicKey},...witnesses.slice(1)],bytes:encode(e),expectedHead:pin(e)}),'EXPORT_HISTORY_INVALID_OR_UNPINNED');});
test('31T rejects unknown extra authorization field',()=>{const e=makeEntries(1);reject(()=>verify(altered(encode(e),x=>x.allowManufacture=true),pin(e)),'EXPORT_HISTORY_INVALID_OR_UNPINNED');});
test('31T rejects unknown record field even if signed receipt remains valid',()=>{const e=makeEntries(1);reject(()=>verify(altered(encode(e),x=>x.entries[0].manufactureApproved=true),pin(e)),'EXPORT_HISTORY_CHAIN_INVALID');});
test('31T rejects forged historical witness signature',()=>{const e=makeEntries(1);reject(()=>verify(altered(encode(e),x=>x.entries[0].receipt.signatures[0].signature='A'.repeat(86)),pin(e)),'EXPORT_RECEIPT_SIGNATURE_INVALID');});
test('31T rejects minority signature set',()=>{const e=makeEntries(1);reject(()=>verify(altered(encode(e),x=>x.entries[0].receipt.signatures.pop()),pin(e)),'EXPORT_RECEIPT_QUORUM_INVALID');});
test('31T rejects unsorted signatures',()=>{const e=makeEntries(1);reject(()=>verify(altered(encode(e),x=>x.entries[0].receipt.signatures.reverse()),pin(e)),'EXPORT_RECEIPT_SIGNATURE_INVALID');});
test('31T rejects duplicate signer',()=>{const e=makeEntries(1);reject(()=>verify(altered(encode(e),x=>x.entries[0].receipt.signatures[1]=x.entries[0].receipt.signatures[0]),pin(e)),'EXPORT_RECEIPT_SIGNATURE_INVALID');});
test('31T rejects tampered receipt body even with recalculated record digest',()=>{const e=makeEntries(1);const bytes=altered(encode(e),x=>{x.entries[0].receipt.body.archiveDigest='f'.repeat(64);const {digest,...body}=x.entries[0];x.entries[0].digest=recordDigest(body);x.head.headDigest=x.entries[0].digest;});reject(()=>verify(bytes,parse(bytes).head),'EXPORT_RECEIPT_SIGNATURE_INVALID');});
test('31T rejects rehashed record with substituted signed predecessor',()=>{const e=makeEntries(2);const b=altered(encode(e),x=>{x.entries[1].receipt.body.previousDigest='f'.repeat(64);const {digest,...body}=x.entries[1];x.entries[1].digest=recordDigest(body);x.head.headDigest=x.entries[1].digest;});reject(()=>verify(b,parse(b).head),'EXPORT_RECEIPT_SIGNATURE_INVALID');});
test('31T rejects skipped record index',()=>{const e=makeEntries(2);reject(()=>verify(altered(encode(e),x=>x.entries[1].index=3),pin(e)),'EXPORT_HISTORY_CHAIN_INVALID');});
test('31T rejects record deletion under retained external pin',()=>{const e=makeEntries(2);reject(()=>verify(altered(encode(e),x=>{x.entries.pop();x.head=pin(x.entries);}),pin(e)),'EXPORT_HISTORY_INVALID_OR_UNPINNED');});
test('31T rejects record digest tamper',()=>{const e=makeEntries(1);reject(()=>verify(altered(encode(e),x=>x.entries[0].digest='f'.repeat(64)),pin(e)),'EXPORT_HISTORY_CHAIN_INVALID');});
test('31T rejects replayed acquisition identity with distinct signed receipt',()=>{const e=makeEntries(2);const body={...e[1].receipt.body,acquisitionId:e[0].receipt.body.acquisitionId};e[1].receipt=signed(body);const {digest,...r}=e[1];e[1].digest=recordDigest(r);reject(()=>verify(encodeOfflineExportReceiptHistory({...opts,entries:e,expectedHead:pin(e)}),pin(e)),'EXPORT_HISTORY_REPLAY');});
test('31T rejects replayed export identity with distinct signed receipt',()=>{const e=makeEntries(2);e[1].receipt=signed({...e[1].receipt.body,exportId:e[0].receipt.body.exportId});const {digest,...r}=e[1];e[1].digest=recordDigest(r);reject(()=>encode(e),'EXPORT_HISTORY_REPLAY');});
test('31T rejects replayed nonce',()=>{const e=makeEntries(2);e[1].receipt=signed({...e[1].receipt.body,nonce:e[0].receipt.body.nonce});const {digest,...r}=e[1];e[1].digest=recordDigest(r);reject(()=>encode(e),'EXPORT_HISTORY_REPLAY');});
test('31T rejects replayed archive digest',()=>{const e=makeEntries(2);e[1].receipt=signed({...e[1].receipt.body,archiveDigest:e[0].receipt.body.archiveDigest});const {digest,...r}=e[1];e[1].digest=recordDigest(r);reject(()=>encode(e),'EXPORT_HISTORY_REPLAY');});
test('31T rejects nonmonotonic signed issuance timestamps',()=>{const e=makeEntries(2);e[1].receipt=signed({...e[1].receipt.body,issuedAt:nowMs-1000,expiresAt:nowMs+60000});const {digest,...r}=e[1];e[1].digest=recordDigest(r);reject(()=>encode(e),'EXPORT_HISTORY_CHAIN_INVALID');});
test('31T rejects invalid UTF-8',()=>{const e=makeEntries(1),b=encode(e);b[3]=0xff;reject(()=>verify(b,pin(e)),'EXPORT_HISTORY_ENCODING_INVALID');});
test('31T rejects whitespace/noncanonical JSON',()=>{const e=makeEntries(1);reject(()=>verify(Buffer.from(`${encode(e).toString()}\n`),pin(e)),'EXPORT_HISTORY_NOT_CANONICAL');});
test('31T rejects duplicate JSON keys',()=>{const e=makeEntries(1),raw=encode(e).toString();reject(()=>verify(Buffer.from(raw.replace('"schema":','"schema":"injected","schema":')),pin(e)),'EXPORT_HISTORY_NOT_CANONICAL');});
test('31T rejects truncated JSON',()=>{const e=makeEntries(1),b=encode(e);reject(()=>verify(b.subarray(0,-1),pin(e)),'EXPORT_HISTORY_ENCODING_INVALID');});
test('31T rejects oversized portable input before parsing',()=>reject(()=>verify(Buffer.alloc(32*1024*1024+1),zero),'EXPORT_HISTORY_BYTES_INVALID'));
test('31T rejects oversized entry count',()=>reject(()=>encodeOfflineExportReceiptHistory({...opts,entries:Array(2001).fill(null),expectedHead:zero}),'EXPORT_HISTORY_ENTRIES_INVALID'));
test('31T rejects malformed empty-history root',()=>reject(()=>verifyOfflineExportReceiptHistory({...opts,bytes:Buffer.from(JSON.stringify({schema:OFFLINE_EXPORT_RECEIPT_HISTORY_SCHEMA,registryId,policyDigest,head:{count:0,headDigest:'f'.repeat(64)},entries:[]})),expectedHead:zero}),'EXPORT_HISTORY_INVALID_OR_UNPINNED'));
test('31T identical independently pinned bundles do not claim conflict',()=>{const e=makeEntries(2),c=compare(e,e);assert.equal(c.status,'IDENTICAL');assert.equal(c.conflictEvidence,null);});
test('31T consistent signed prefix extension does not claim conflict',()=>{const a=makeEntries(1),b=makeEntries(3),c=compare(a,b);assert.equal(c.status,'CONSISTENT_PREFIX_EXTENSION');assert.equal(c.sharedPrefixCount,1);assert.equal(c.conflictEvidence,null);});
test('31T reverse prefix extension remains non-conflicting',()=>{const c=compare(makeEntries(3),makeEntries(1));assert.equal(c.status,'CONSISTENT_PREFIX_EXTENSION');});
test('31T contradictory signed receipts at same index yield portable conflict evidence',()=>{const a=makeEntries(2,{branch:'A'}),b=makeEntries(2,{branch:'B'}),c=compare(a,b);assert.equal(c.status,'SIGNED_RECEIPT_EQUIVOCATION');assert.equal(c.conflictEvidence.sequence,2);assert.equal(c.conflictEvidence.contradictorySignedBodies,true);assert.equal(c.left.head.headDigest,pin(a).headDigest);assert.equal(c.right.head.headDigest,pin(b).headDigest);});
test('31T differing valid signer subsets on identical body are not mislabeled contradictory',()=>{const a=makeEntries(1,{signers:[0,1]}),b=makeEntries(1,{signers:[0,2]}),c=compare(a,b);assert.equal(c.status,'SIGNED_HISTORY_ENCODING_FORK');assert.equal(c.conflictEvidence.contradictorySignedBodies,false);});
test('31T signed history encoding fork is distinguished from subsequent signed contradiction',()=>{const a=makeEntries(2,{branch:'A',signers:[0,1]}),b=makeEntries(2,{branch:'B',signers:[0,2]}),c=compare(a,b);assert.equal(c.status,'SIGNED_RECEIPT_EQUIVOCATION');assert.equal(c.conflictEvidence.sequence,2);});
test('31T rejects forged branch instead of producing spurious equivocation',()=>{const a=makeEntries(2,{branch:'A'}),b=makeEntries(2,{branch:'B'}),bad=altered(encode(b),x=>x.entries[1].receipt.signatures[0].signature='A'.repeat(86));reject(()=>compareOfflineExportReceiptHistories({...opts,leftBytes:encode(a),rightBytes:bad,leftExpectedHead:pin(a),rightExpectedHead:pin(b)}),'EXPORT_RECEIPT_SIGNATURE_INVALID');});
test('31T rejects unpinned branch comparison',()=>{const a=makeEntries(1),b=makeEntries(2);reject(()=>compareOfflineExportReceiptHistories({...opts,leftBytes:encode(a),rightBytes:encode(b),leftExpectedHead:pin(a)}),'EXPORT_HISTORY_EXTERNAL_PIN_REQUIRED');});
test('31T rejects forged external pin even with valid branch signatures',()=>{const a=makeEntries(1),b=makeEntries(2);reject(()=>compareOfflineExportReceiptHistories({...opts,leftBytes:encode(a),rightBytes:encode(b),leftExpectedHead:pin(a),rightExpectedHead:pin(a)}),'EXPORT_HISTORY_INVALID_OR_UNPINNED');});
test('31T comparing different registries fails closed',()=>{const a=makeEntries(1),b=makeEntries(1);reject(()=>compareOfflineExportReceiptHistories({...opts,registryId:'other_registry_31t',leftBytes:encode(a),rightBytes:encode(b),leftExpectedHead:pin(a),rightExpectedHead:pin(b)}),'EXPORT_HISTORY_INVALID_OR_UNPINNED');});
test('31T comparison output grants no manufacturing or checkout authority',()=>{const c=compare(makeEntries(1),makeEntries(2));assert.equal(c.productionApproved,false);assert.equal(c.readOnly,true);});
test('31T real durable registry exports canonical pinned signed history and detects local rollback',async t=>{
 const directory=await mkdtemp(join(tmpdir(),'tj31t-'));t.after(()=>rm(directory,{recursive:true,force:true}));
 const registry=createOfflineExportReceiptRegistry({directory,...opts});
 const p=realReceipt(1,ROOT,'acquisition_31t_real_1');const a=await registry.append({...p,expectedHead:zero,nowMs});
 const bytes=await registry.exportHistory({expectedHead:a.head});const verified=verify(bytes,a.head);
 assert.equal(verified.count,1);assert.equal(verified.productionApproved,false);
 await rejectAsync(()=>registry.exportHistory({expectedHead:zero}),'EXPORT_REGISTRY_PIN_MISMATCH');
 const second=realReceipt(2,a.head.headDigest,'acquisition_31t_real_2');const b=await registry.append({...second,expectedHead:a.head,nowMs});
 const newer=await registry.exportHistory({expectedHead:b.head});
 const cmp=compareOfflineExportReceiptHistories({...opts,leftBytes:bytes,rightBytes:newer,leftExpectedHead:a.head,rightExpectedHead:b.head});
 assert.equal(cmp.status,'CONSISTENT_PREFIX_EXTENSION');
 await writeFile(join(directory,'0001.json'),'{"tampered":true}');
 await rejectAsync(()=>registry.exportHistory({expectedHead:b.head}),'EXPORT_REGISTRY_HISTORY_INVALID');
});

test('31T portable history verifies in an independent Node child process',()=>{
 const e=makeEntries(3),bytes=encode(e),mod=fileURLToPath(new URL('../src/offline-export-receipt-history.mjs',import.meta.url));
 const code=`import {createPublicKey} from 'node:crypto';import {verifyOfflineExportReceiptHistory} from ${JSON.stringify(mod)};const x=JSON.parse(process.argv[1]);const w=x.witnesses.map(z=>({id:z.id,publicKey:createPublicKey(z.pem)}));const v=verifyOfflineExportReceiptHistory({bytes:Buffer.from(x.bytes,'base64'),expectedHead:x.expectedHead,registryId:x.registryId,witnesses:w,quorum:2});process.stdout.write(JSON.stringify({verified:v.verified,count:v.count,productionApproved:v.productionApproved}));`;
 const args={bytes:bytes.toString('base64'),expectedHead:pin(e),registryId,witnesses:witnesses.map(w=>({id:w.id,pem:w.publicKey.export({format:'pem',type:'spki'})}))};
 const result=spawnSync(process.execPath,['--input-type=module','-e',code,JSON.stringify(args)],{encoding:'utf8',timeout:15000});
 assert.equal(result.status,0,result.stderr);assert.deepEqual(JSON.parse(result.stdout),{verified:true,count:3,productionApproved:false});
});
test('31T independent child process rejects forged portable history',()=>{
 const e=makeEntries(2),bytes=altered(encode(e),x=>x.entries[1].receipt.signatures[0].signature='A'.repeat(86)),mod=fileURLToPath(new URL('../src/offline-export-receipt-history.mjs',import.meta.url));
 const code=`import {createPublicKey} from 'node:crypto';import {verifyOfflineExportReceiptHistory} from ${JSON.stringify(mod)};const x=JSON.parse(process.argv[1]);try{verifyOfflineExportReceiptHistory({bytes:Buffer.from(x.bytes,'base64'),expectedHead:x.expectedHead,registryId:x.registryId,witnesses:x.witnesses.map(z=>({id:z.id,publicKey:createPublicKey(z.pem)})),quorum:2});process.exit(0);}catch(e){process.stderr.write(e.code);process.exit(23);}`;
 const args={bytes:bytes.toString('base64'),expectedHead:pin(e),registryId,witnesses:witnesses.map(w=>({id:w.id,pem:w.publicKey.export({format:'pem',type:'spki'})}))};
 const result=spawnSync(process.execPath,['--input-type=module','-e',code,JSON.stringify(args)],{encoding:'utf8',timeout:15000});
 assert.equal(result.status,23,result.stderr);assert.equal(result.stderr,'EXPORT_RECEIPT_SIGNATURE_INVALID');
});
