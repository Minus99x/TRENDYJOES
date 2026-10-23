import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,lstat,rename,mkdir,rm,chmod,link,symlink,unlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA,offlineConflictAdjudicationInventoryGenesisHead} from '../src/offline-conflict-adjudication-transcript-inventory.mjs';
import {offlineConflictInventoryRecordBytesDigest} from '../src/offline-conflict-adjudication-inventory-record-evidence.mjs';
import {acquireOfflineConflictInventoryRecordsReadOnly,verifyOfflineConflictInventoryAcquisitionReceipt} from '../src/offline-conflict-inventory-filesystem-acquisition.mjs';
const hash=(domain,bytes)=>createHash('sha256').update(domain+'\0').update(bytes).digest('hex');
const sha=x=>createHash('sha256').update(x).digest('hex');
const ns='namespace_33n_test',scope=sha('33n-scope'),now=1792280000000;
const key=generateKeyPairSync('ed25519'),wrongKey=generateKeyPairSync('ed25519');
const head=(count,headDigest)=>({count,headDigest});
const t=(name,fn)=>test('33N '+name,fn);
const reject=(p,code)=>assert.rejects(p,e=>e?.code===code);
const throwCode=(fn,code)=>assert.throws(fn,e=>e?.code===code);
function makeRecord(index,prev,marker='original'){
 const body={schema:OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA,index,namespaceId:ns,
  journalScopeDigest:scope,previousRecordDigest:prev,pair:[{marker,index},{marker,index}]};
 return Buffer.from(JSON.stringify({...body,recordDigest:hash('TJ-33J-INVENTORY-RECORD',Buffer.from(JSON.stringify(body)))}));
}
async function fixture(){
 const directory=await mkdtemp(join(tmpdir(),'trendy33n-'));
 const genesis=offlineConflictAdjudicationInventoryGenesisHead(ns,scope),records=[],heads=[genesis],recordPins=[];
 for(let i=1;i<=2;i++){
  const bytes=makeRecord(i,heads.at(-1).headDigest);records.push(bytes);
  const next=head(i,JSON.parse(bytes).recordDigest);
  recordPins.push({expectedRecordBytesDigest:offlineConflictInventoryRecordBytesDigest(bytes),
   expectedFromHead:heads.at(-1),expectedToHead:next});heads.push(next);
  await writeFile(join(directory,String(i).padStart(4,'0')+'.json'),bytes,{mode:0o600});
 }
 const s=await lstat(directory,{bigint:true});
 const expectedDirectoryPin={dev:String(s.dev),ino:String(s.ino)};
 const args={directory,expectedDirectoryPin,recordPins,expectedFromHead:genesis,
  expectedToHead:heads[2],expectedNamespaceId:ns,expectedJournalScopeDigest:scope,
  hostId:'host_33n_001',observerId:'observer_33n_001',observerPrivateKey:key.privateKey,
  observedAt:now,expiresAt:now+60000,nonce:'nonce_33n_001',checkpoint:undefined};
 const verifier=(result,change={})=>({receiptBytes:result.receiptBytes,records:result.records,
  expectedObserverPublicKey:key.publicKey,expectedObserverId:args.observerId,expectedHostId:args.hostId,
  expectedDirectoryPin,recordPins,expectedFromHead:args.expectedFromHead,expectedToHead:args.expectedToHead,
  expectedNamespaceId:ns,expectedJournalScopeDigest:scope,nowMs:now+1000,
  seenNonces:[],seenDigests:[],...change});
 return {directory,args,records,recordPins,verifier,cleanup:()=>rm(directory,{recursive:true,force:true})};
}
async function scenario(fn){const x=await fixture();try{await fn(x);}finally{await x.cleanup();}}
const filename=i=>String(i).padStart(4,'0')+'.json';
t('real Linux directory and record FDs produce independently verifiable signed receipt',()=>scenario(async x=>{
 const out=await acquireOfflineConflictInventoryRecordsReadOnly(x.args);
 assert.deepEqual(out.records,x.records);
 const v=verifyOfflineConflictInventoryAcquisitionReceipt(x.verifier(out));
 assert.equal(v.verifiedWitnessSignature,true);assert.equal(v.verifiedSuppliedRecordBytes,true);
}));
t('acquisition and verification never assert remote disk, history prefix, checkout or production proof',()=>scenario(async x=>{
 const out=await acquireOfflineConflictInventoryRecordsReadOnly(x.args);
 const v=verifyOfflineConflictInventoryAcquisitionReceipt(x.verifier(out));
 for(const o of [out,v])for(const k of ['provesRemoteDiskState','provesHistoricalPrefix','authorizesCheckout','authorizesProduction'])
  assert.equal(o[k],false);
 assert.equal(v.durableReplayProtection,false);
}));
t('independent witness public key substitution rejected',()=>scenario(async x=>{
 const out=await acquireOfflineConflictInventoryRecordsReadOnly(x.args);
 throwCode(()=>verifyOfflineConflictInventoryAcquisitionReceipt(x.verifier(out,{expectedObserverPublicKey:wrongKey.publicKey})),'EXCHANGE33N_SIGNATURE_INVALID');
}));
t('altered signed receipt body rejected',()=>scenario(async x=>{
 const out=await acquireOfflineConflictInventoryRecordsReadOnly(x.args),r=JSON.parse(out.receiptBytes);
 r.body.nonce='nonce_33n_999';throwCode(()=>verifyOfflineConflictInventoryAcquisitionReceipt(x.verifier(out,{receiptBytes:Buffer.from(JSON.stringify(r))})),'EXCHANGE33N_SIGNATURE_INVALID');
}));
t('altered witness signature rejected',()=>scenario(async x=>{
 const out=await acquireOfflineConflictInventoryRecordsReadOnly(x.args),r=JSON.parse(out.receiptBytes);
 r.signature='A'+r.signature.slice(1);throwCode(()=>verifyOfflineConflictInventoryAcquisitionReceipt(x.verifier(out,{receiptBytes:Buffer.from(JSON.stringify(r))})),'EXCHANGE33N_SIGNATURE_INVALID');
}));
t('wrong externally pinned host rejected',()=>scenario(async x=>{
 const out=await acquireOfflineConflictInventoryRecordsReadOnly(x.args);
 throwCode(()=>verifyOfflineConflictInventoryAcquisitionReceipt(x.verifier(out,{expectedHostId:'host_33n_other'})),'EXCHANGE33N_RECEIPT_SCOPE_OR_TIME_INVALID');
}));
t('wrong externally pinned observer identity rejected',()=>scenario(async x=>{
 const out=await acquireOfflineConflictInventoryRecordsReadOnly(x.args);
 throwCode(()=>verifyOfflineConflictInventoryAcquisitionReceipt(x.verifier(out,{expectedObserverId:'observer_33n_other'})),'EXCHANGE33N_RECEIPT_SCOPE_OR_TIME_INVALID');
}));
t('independent directory inode substitution rejected',()=>scenario(async x=>{
 await reject(acquireOfflineConflictInventoryRecordsReadOnly({...x.args,expectedDirectoryPin:{...x.args.expectedDirectoryPin,ino:'1'}}),'EXCHANGE33N_DIRECTORY_UNSAFE');
}));
t('caller-supplied nonce replay rejected',()=>scenario(async x=>{
 const out=await acquireOfflineConflictInventoryRecordsReadOnly(x.args);
 throwCode(()=>verifyOfflineConflictInventoryAcquisitionReceipt(x.verifier(out,{seenNonces:[x.args.nonce]})),'EXCHANGE33N_REPLAY');
}));
t('caller-supplied receipt digest replay rejected',()=>scenario(async x=>{
 const out=await acquireOfflineConflictInventoryRecordsReadOnly(x.args);
 const v=verifyOfflineConflictInventoryAcquisitionReceipt(x.verifier(out));
 throwCode(()=>verifyOfflineConflictInventoryAcquisitionReceipt(x.verifier(out,{seenDigests:[v.receiptDigest]})),'EXCHANGE33N_REPLAY');
}));
t('expired witness receipt rejected',()=>scenario(async x=>{
 const out=await acquireOfflineConflictInventoryRecordsReadOnly(x.args);
 throwCode(()=>verifyOfflineConflictInventoryAcquisitionReceipt(x.verifier(out,{nowMs:now+60000})),'EXCHANGE33N_RECEIPT_SCOPE_OR_TIME_INVALID');
}));
t('future-dated witness receipt rejected',()=>scenario(async x=>{
 const out=await acquireOfflineConflictInventoryRecordsReadOnly(x.args);
 throwCode(()=>verifyOfflineConflictInventoryAcquisitionReceipt(x.verifier(out,{nowMs:now-1})),'EXCHANGE33N_RECEIPT_SCOPE_OR_TIME_INVALID');
}));
t('record byte substitution after acquisition rejected',()=>scenario(async x=>{
 const out=await acquireOfflineConflictInventoryRecordsReadOnly(x.args);
 const forged=out.records.map(Buffer.from);forged[0][100]^=1;
 assert.throws(()=>verifyOfflineConflictInventoryAcquisitionReceipt(x.verifier(out,{records:forged})));
}));
t('independently pinned record digest substitution rejected before filesystem read',()=>scenario(async x=>{
 const recordPins=structuredClone(x.recordPins);recordPins[0].expectedRecordBytesDigest=sha('wrong');
 await reject(acquireOfflineConflictInventoryRecordsReadOnly({...x.args,recordPins}),'EXCHANGE33N_RECORD_PIN_MISMATCH');
}));
t('omitted historical record rejected, never treated as shorter history',()=>scenario(async x=>{
 await unlink(join(x.directory,filename(1)));
 await reject(acquireOfflineConflictInventoryRecordsReadOnly(x.args),'EXCHANGE33N_DIRECTORY_CONTENTS_UNSAFE');
}));
t('unexpected unpinned inventory record rejected',()=>scenario(async x=>{
 await writeFile(join(x.directory,filename(3)),Buffer.from('{}'),{mode:0o600});
 await reject(acquireOfflineConflictInventoryRecordsReadOnly(x.args),'EXCHANGE33N_DIRECTORY_CONTENTS_UNSAFE');
}));
t('uncertain pending commit rejected read-only',()=>scenario(async x=>{
 await writeFile(join(x.directory,'.pending.json'),'{}',{mode:0o600});
 await reject(acquireOfflineConflictInventoryRecordsReadOnly(x.args),'EXCHANGE33N_DIRECTORY_CONTENTS_UNSAFE');
}));
t('symlinked record rejected by O_NOFOLLOW even with expected directory entry count',()=>scenario(async x=>{
 const path=join(x.directory,filename(1)),outside=await mkdtemp(join(tmpdir(),'trendy33n-symlink-'));
 try{const target=join(outside,'saved');await rename(path,target);await symlink(target,path);
  await reject(acquireOfflineConflictInventoryRecordsReadOnly(x.args),'EXCHANGE33N_RECORD_UNSAFE');}
 finally{await rm(outside,{recursive:true,force:true});}
}));
t('hardlinked record rejected',()=>scenario(async x=>{
 const dir=await mkdtemp(join(tmpdir(),'trendy33n-link-'));
 try{await link(join(x.directory,filename(1)),join(dir,'outside.json'));
  await reject(acquireOfflineConflictInventoryRecordsReadOnly(x.args),'EXCHANGE33N_RECORD_UNSAFE');}
 finally{await rm(dir,{recursive:true,force:true});}
}));
t('world-readable record rejected',()=>scenario(async x=>{
 await chmod(join(x.directory,filename(1)),0o644);
 await reject(acquireOfflineConflictInventoryRecordsReadOnly(x.args),'EXCHANGE33N_RECORD_UNSAFE');
}));
t('world-accessible inventory directory rejected',()=>scenario(async x=>{
 await chmod(x.directory,0o755);
 await reject(acquireOfflineConflictInventoryRecordsReadOnly(x.args),'EXCHANGE33N_DIRECTORY_UNSAFE');
}));
t('symlinked inventory directory rejected',()=>scenario(async x=>{
 const alias=x.directory+'-alias';await symlink(x.directory,alias);
 try{await reject(acquireOfflineConflictInventoryRecordsReadOnly({...x.args,directory:alias}),'EXCHANGE33N_DIRECTORY_UNSAFE');}
 finally{await unlink(alias);}
}));
t('rename replacement between open and read fails closed',()=>scenario(async x=>{
 const path=join(x.directory,filename(1));
 const checkpoint=async(stage,index)=>{if(stage==='after-open'&&index===1){
  await rename(path,join(x.directory,'old.json'));await writeFile(path,x.records[0],{mode:0o600});}};
 await reject(acquireOfflineConflictInventoryRecordsReadOnly({...x.args,checkpoint}),'EXCHANGE33N_TOCTOU_DETECTED');
}));
t('in-place rewrite after read fails closed even when bytes are identical',()=>scenario(async x=>{
 const checkpoint=async(stage,index)=>{if(stage==='after-read'&&index===1){
  const p=join(x.directory,filename(1));await writeFile(p,x.records[0]);}};
 await reject(acquireOfflineConflictInventoryRecordsReadOnly({...x.args,checkpoint}),'EXCHANGE33N_TOCTOU_DETECTED');
}));
t('directory replacement after read fails closed',()=>scenario(async x=>{
 const original=x.directory,old=original+'-old';
 const checkpoint=async(stage,index)=>{if(stage==='after-read'&&index===2){
  await rename(original,old);await mkdir(original,{mode:0o700});}};
 try{await reject(acquireOfflineConflictInventoryRecordsReadOnly({...x.args,checkpoint}),'EXCHANGE33N_DIRECTORY_CHANGED');}
 finally{await rm(old,{recursive:true,force:true});}
}));
t('historical rollback with valid JSON but stale pinned bytes rejected',()=>scenario(async x=>{
 const stale=makeRecord(1,x.args.expectedFromHead.headDigest,'stale');
 await writeFile(join(x.directory,filename(1)),stale);
 await reject(acquireOfflineConflictInventoryRecordsReadOnly(x.args),'EXCHANGE33N_RECORD_PIN_MISMATCH');
}));
t('reordered independent head pins rejected before filesystem acquisition',()=>scenario(async x=>{
 const recordPins=structuredClone(x.recordPins).reverse();
 await reject(acquireOfflineConflictInventoryRecordsReadOnly({...x.args,recordPins}),'EXCHANGE33N_EXTERNAL_PINS_INVALID');
}));
t('noncanonical duplicate JSON keys rejected even with recomputed external byte digest',()=>scenario(async x=>{
 const path=join(x.directory,filename(1));const bytes=Buffer.from(x.records[0].toString().replace('"schema":','"schema":"fake","schema":'));
 await writeFile(path,bytes);const recordPins=structuredClone(x.recordPins);
 recordPins[0].expectedRecordBytesDigest=offlineConflictInventoryRecordBytesDigest(bytes);
 await reject(acquireOfflineConflictInventoryRecordsReadOnly({...x.args,recordPins}),'EXCHANGE33N_RECORD_INVALID');
}));
t('noncanonical receipt whitespace rejected',()=>scenario(async x=>{
 const out=await acquireOfflineConflictInventoryRecordsReadOnly(x.args);
 throwCode(()=>verifyOfflineConflictInventoryAcquisitionReceipt(x.verifier(out,{receiptBytes:Buffer.concat([out.receiptBytes,Buffer.from(' ')])})),'EXCHANGE33N_RECEIPT_INVALID');
}));
t('unknown receipt field rejected even if reserialized',()=>scenario(async x=>{
 const out=await acquireOfflineConflictInventoryRecordsReadOnly(x.args),r=JSON.parse(out.receiptBytes);
 r.unsafe=true;throwCode(()=>verifyOfflineConflictInventoryAcquisitionReceipt(x.verifier(out,{receiptBytes:Buffer.from(JSON.stringify(r))})),'EXCHANGE33N_RECEIPT_INVALID');
}));
t('sparse record pins rejected',()=>scenario(async x=>{
 const pins=[...x.recordPins];delete pins[0];
 await reject(acquireOfflineConflictInventoryRecordsReadOnly({...x.args,recordPins:pins}),'EXCHANGE33N_EXTERNAL_PINS_INVALID');
}));
t('no Shopify, network, filesystem mutation or recovery authority is exposed',()=>scenario(async x=>{
 const before=await Promise.all([1,2].map(i=>readFile(join(x.directory,filename(i)))));
 const out=await acquireOfflineConflictInventoryRecordsReadOnly(x.args);
 const after=await Promise.all([1,2].map(i=>readFile(join(x.directory,filename(i)))));
 assert.deepEqual(before,after);assert.deepEqual(Object.keys(out).sort(),
  ['receiptBytes','records','locallyReadPinnedBytes','independentlyWitnessed','provesRemoteDiskState',
   'provesHistoricalPrefix','trustedTimestamp','authorizesCheckout','authorizesProduction'].sort());
}));
