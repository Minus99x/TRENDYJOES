import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,lstat,rename,symlink,link,chmod,unlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA,offlineConflictAdjudicationInventoryGenesisHead} from '../src/offline-conflict-adjudication-transcript-inventory.mjs';
import {offlineConflictInventoryRecordBytesDigest} from '../src/offline-conflict-adjudication-inventory-record-evidence.mjs';
import {acquireOfflineConflictInventoryRecordsReadOnly} from '../src/offline-conflict-inventory-filesystem-acquisition.mjs';
import {createOfflineConflictInventoryAcquisitionRegistry} from '../src/offline-conflict-inventory-acquisition-registry.mjs';
import {OFFLINE_CONFLICT_ACQUISITION_HEAD_PUBLICATION_SCHEMA as PUBSCHEMA,
 offlineConflictAcquisitionHeadPublicationBodyBytes,offlineConflictAcquisitionHeadPublicationDigest} from '../src/offline-conflict-acquisition-head-publications.mjs';
import {verifyOfflineConflictAcquisitionRegistryRecordEvidence as verify,
 acquireOfflineConflictAcquisitionRegistryRecordsReadOnly as acquire,
 offlineConflictAcquisitionRegistryRecordBytesDigest as bytesDigest} from '../src/offline-conflict-acquisition-registry-record-evidence.mjs';
const hash=(d,b)=>createHash('sha256').update(d+'\0').update(b).digest('hex');
const sha=s=>createHash('sha256').update(s).digest('hex');
const h=(count,headDigest)=>({count,headDigest});
const ns='namespace_33q_test',scope=sha('33q-scope'),host='host_33q_target',observer='observer_33q_001',target='registry_33q_target';
const now=1792280000000;
const witness=generateKeyPairSync('ed25519'),publishers=['publisher_33q_alpha','publisher_33q_bravo'].map(publisherId=>({publisherId,...generateKeyPairSync('ed25519')}));
const pub=k=>k.publicKey.export({format:'der',type:'spki'}).toString('base64url');
const dirPin=async p=>{const s=await lstat(p,{bigint:true});return {dev:String(s.dev),ino:String(s.ino)};};
const inventoryRecord=(index,previous)=>{const body={schema:OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA,index,
 namespaceId:ns,journalScopeDigest:scope,previousRecordDigest:previous,
 pair:[{fixture:'33q',index},{fixture:'33q',index}]};
 return Buffer.from(JSON.stringify({...body,recordDigest:hash('TJ-33J-INVENTORY-RECORD',Buffer.from(JSON.stringify(body)))}));};
function issue(p,config,change={}){
 const b={schema:PUBSCHEMA,namespaceId:ns,journalScopeDigest:scope,targetRegistryId:target,targetHostId:host,
  publisherId:p.publisherId,registryGenesisHead:config.genesis,registryHead:config.registryHead,
  inventoryHead:config.inventoryHead,registryDirectoryPin:config.registryPin,
  observedAtMs:now+1000,expiresAtMs:now+61000,nonce:`nonce_${p.publisherId}`,...change};
 return Buffer.from(JSON.stringify({body:b,signature:sign(null,offlineConflictAcquisitionHeadPublicationBodyBytes(b),p.privateKey).toString('base64url')}));
}
function republish(x,change={}){
 const config={genesis:x.genesisHead,registryHead:x.registryHead,inventoryHead:x.inventoryHead,registryPin:x.registryPin,...change};
 const receipts=publishers.map(p=>issue(p,config));
 x.args.publicationVerification={receipts,publisherPins:publishers.map((p,i)=>({publisherId:p.publisherId,
  publicKey:pub(p),expectedReceiptDigest:offlineConflictAcquisitionHeadPublicationDigest(receipts[i])})),
  expectedNamespaceId:ns,expectedJournalScopeDigest:scope,expectedTargetRegistryId:target,
  expectedTargetHostId:host,expectedRegistryGenesisHead:x.genesisHead,expectedRegistryDirectoryPin:x.registryPin,
  minimumPinnedHead:x.genesisHead,nowMs:now+2000,seenDigests:[],seenNonces:[]};
}
async function fixture(){
 const root=await mkdtemp(join(tmpdir(),'trendy33q-')),source=join(root,'source'),directory=join(root,'registry');
 await mkdir(source,{mode:0o700});await mkdir(directory,{mode:0o700});
 const sourcePin=await dirPin(source),registryPin=await dirPin(directory);
 const inv0=offlineConflictAdjudicationInventoryGenesisHead(ns,scope);
 const first=inventoryRecord(1,inv0.headDigest),inv1=h(1,JSON.parse(first).recordDigest);
 const second=inventoryRecord(2,inv1.headDigest),inv2=h(2,JSON.parse(second).recordDigest);
 const pin1={expectedRecordBytesDigest:offlineConflictInventoryRecordBytesDigest(first),expectedFromHead:inv0,expectedToHead:inv1};
 const pin2={expectedRecordBytesDigest:offlineConflictInventoryRecordBytesDigest(second),expectedFromHead:inv1,expectedToHead:inv2};
 await writeFile(join(source,'0001.json'),first,{mode:0o600});
 const acq=(nonce,from,to,pins)=>acquireOfflineConflictInventoryRecordsReadOnly({directory:source,
  expectedDirectoryPin:sourcePin,recordPins:pins,expectedFromHead:from,expectedToHead:to,
  expectedNamespaceId:ns,expectedJournalScopeDigest:scope,hostId:host,observerId:observer,
  observerPrivateKey:witness.privateKey,observedAt:now,expiresAt:now+60000,nonce,checkpoint:undefined});
 const one=await acq('nonce_33q_first',inv0,inv1,[pin1]);
 const config={directory,namespaceId:ns,journalScopeDigest:scope,hostId:host,observerId:observer,
  expectedObserverPublicKey:witness.publicKey,initialInventoryHead:inv0};
 const registry=createOfflineConflictInventoryAcquisitionRegistry(config),genesisHead=registry.genesisHead;
 const a1=await registry.accept({receiptBytes:one.receiptBytes,records:one.records,recordPins:[pin1],
  expectedDirectoryPin:sourcePin,expectedFromHead:inv0,expectedToHead:inv1,nowMs:now+1000,
  expectedHead:genesisHead,expectedRegistryDirectoryPin:registryPin});
 await writeFile(join(source,'0002.json'),second,{mode:0o600});
 const two=await acq('nonce_33q_second',inv1,inv2,[pin2]);
 const a2=await registry.accept({receiptBytes:two.receiptBytes,records:two.records,recordPins:[pin2],
  expectedDirectoryPin:sourcePin,expectedFromHead:inv1,expectedToHead:inv2,nowMs:now+1000,
  expectedHead:h(a1.count,a1.headDigest),expectedRegistryDirectoryPin:registryPin});
 const registryHead=h(a2.count,a2.headDigest),recordBytes=await Promise.all([1,2].map(i=>readFile(join(directory,String(i).padStart(4,'0')+'.json'))));
 const args={recordBytes,expectedRecordBytesDigests:recordBytes.map(bytesDigest),publicationVerification:null,
  namespaceId:ns,journalScopeDigest:scope,hostId:host,observerId:observer,
  expectedObserverPublicKey:witness.publicKey,initialInventoryHead:inv0,expectedRegistryDirectoryPin:registryPin};
 const x={root,source,directory,registryPin,genesisHead,registryHead,inventoryHead:inv2,inv0,inv1,inv2,args,
  cleanup:()=>rm(root,{recursive:true,force:true})};republish(x);return x;
}
async function scenario(fn){const x=await fixture();try{await fn(x);}finally{await x.cleanup();}}
const t=(name,fn)=>test('33Q '+name,fn);
const bad=(a,code)=>assert.throws(()=>verify(a),e=>e?.code===code);
const denied=(p,code)=>assert.rejects(p,e=>e?.code===code);
const acq=x=>acquire({directory:x.directory,...x.args});
const rewrite=(x,i,change)=>{const r=JSON.parse(x.args.recordBytes[i]);change(r);
 x.args.recordBytes[i]=Buffer.from(JSON.stringify(r));x.args.expectedRecordBytesDigests[i]=bytesDigest(x.args.recordBytes[i]);};
const rehash=x=>{let prev=x.genesisHead.headDigest;for(let i=0;i<x.args.recordBytes.length;i++){
  const r=JSON.parse(x.args.recordBytes[i]);r.previousRecordDigest=prev;
  const {recordDigest,...body}=r;r.recordDigest=hash('TJ-33O-ACQUISITION-REGISTRY-RECORD',Buffer.from(JSON.stringify(body)));
  x.args.recordBytes[i]=Buffer.from(JSON.stringify(r));x.args.expectedRecordBytesDigests[i]=bytesDigest(x.args.recordBytes[i]);prev=r.recordDigest;
 }x.registryHead=h(x.args.recordBytes.length,prev);republish(x);};
t('valid full 33O record bytes and two independently signed 33P head claims',()=>scenario(async x=>{
 const v=verify(x.args);assert.equal(v.recordCount,2);assert.deepEqual(v.registryHead,x.registryHead);assert.deepEqual(v.inventoryHead,x.inv2);
 assert.equal(v.verifiedEmbeddedWitnessSignatures,true);
}));
t('read-only Linux descriptor acquisition verifies actual pinned files',()=>scenario(async x=>{
 const v=await acq(x);assert.equal(v.records.length,2);assert.equal(v.verification.recordCount,2);assert.equal(v.locallyReadPinnedBytes,true);
}));
t('never asserts remote state, actual publication, time, recovery, checkout or production',()=>scenario(async x=>{
 const v=verify(x.args);for(const k of ['provesRemoteFilesystemState','provesActualPublication','provesTrustedTime','provesGlobalConsistency','authorizesRecovery','authorizesCheckout','authorizesProduction'])assert.equal(v[k],false);
}));
t('missing historical record rejected even when supplied remaining bytes are valid',()=>scenario(async x=>{
 x.args.recordBytes.shift();x.args.expectedRecordBytesDigests.shift();bad(x.args,'EXCHANGE33Q_RECORD_OMISSION_OR_ROLLBACK');
}));
t('missing last record rejected against signed count',()=>scenario(async x=>{
 x.args.recordBytes.pop();x.args.expectedRecordBytesDigests.pop();bad(x.args,'EXCHANGE33Q_RECORD_OMISSION_OR_ROLLBACK');
}));
t('reordered record bytes rejected even with repinned byte digests',()=>scenario(async x=>{
 x.args.recordBytes.reverse();x.args.expectedRecordBytesDigests=x.args.recordBytes.map(bytesDigest);bad(x.args,'EXCHANGE33Q_RECORD_INVALID');
}));
t('duplicated historical record rejected',()=>scenario(async x=>{
 x.args.recordBytes[1]=Buffer.from(x.args.recordBytes[0]);x.args.expectedRecordBytesDigests[1]=bytesDigest(x.args.recordBytes[1]);bad(x.args,'EXCHANGE33Q_RECORD_INVALID');
}));
t('tampered bytes rejected by independently retained record digest',()=>scenario(async x=>{
 x.args.recordBytes[0][100]^=1;bad(x.args,'EXCHANGE33Q_RECORD_BYTE_PIN_MISMATCH');
}));
t('repinned altered record fails cryptographic chain/hash verification',()=>scenario(async x=>{
 rewrite(x,0,r=>{r.nonce='nonce_33q_tampered';});bad(x.args,'EXCHANGE33Q_RECORD_HASH_MISMATCH');
}));
t('fully repinned forged 33O record still fails embedded witness verification',()=>scenario(async x=>{
 rewrite(x,1,r=>{r.entry.records[0]=Buffer.from('forged').toString('base64url');});rehash(x);
 bad(x.args,'EXCHANGE33Q_EMBEDDED_EVIDENCE_INVALID');
}));
t('same-height independently signed publisher fork never treated as consistent',()=>scenario(async x=>{
 const p=x.args.publicationVerification;const forged=issue(publishers[1],{genesis:x.genesisHead,
  registryHead:h(2,sha('fork')),inventoryHead:x.inv2,registryPin:x.registryPin});
 p.receipts[1]=forged;p.publisherPins[1].expectedReceiptDigest=offlineConflictAcquisitionHeadPublicationDigest(forged);
 bad(x.args,'EXCHANGE33Q_UNRESOLVED_PUBLICATIONS');
}));
t('different signed publication heights remain unresolved',()=>scenario(async x=>{
 const p=x.args.publicationVerification;const forged=issue(publishers[1],{genesis:x.genesisHead,
  registryHead:h(1,sha('short')),inventoryHead:x.inv2,registryPin:x.registryPin});
 p.receipts[1]=forged;p.publisherPins[1].expectedReceiptDigest=offlineConflictAcquisitionHeadPublicationDigest(forged);
 bad(x.args,'EXCHANGE33Q_UNRESOLVED_PUBLICATIONS');
}));
t('publisher omission rejected',()=>scenario(async x=>{
 x.args.publicationVerification.receipts.pop();bad(x.args,'EXCHANGE33P_EXTERNAL_PINS_REQUIRED');
}));
t('publisher signing key substitution rejected',()=>scenario(async x=>{
 x.args.publicationVerification.publisherPins[0].publicKey=pub(publishers[1]);bad(x.args,'EXCHANGE33P_SIGNATURE_INVALID');
}));
t('publisher signed receipt tampering rejected even if repinned',()=>scenario(async x=>{
 const p=x.args.publicationVerification;const r=JSON.parse(p.receipts[0]);r.body.nonce='nonce_33q_modified';
 p.receipts[0]=Buffer.from(JSON.stringify(r));p.publisherPins[0].expectedReceiptDigest=offlineConflictAcquisitionHeadPublicationDigest(p.receipts[0]);
 bad(x.args,'EXCHANGE33P_SIGNATURE_INVALID');
}));
t('expired publisher assertion rejected',()=>scenario(async x=>{
 x.args.publicationVerification.nowMs=now+62000;bad(x.args,'EXCHANGE33P_EXPIRED');
}));
t('registry scope substitution rejected',()=>scenario(async x=>{
 x.args.namespaceId='namespace_33q_wrong';bad(x.args,'EXCHANGE33Q_SCOPE_OR_GENESIS_MISMATCH');
}));
t('wrong independent witness key rejected by genesis binding',()=>scenario(async x=>{
 x.args.expectedObserverPublicKey=generateKeyPairSync('ed25519').publicKey;bad(x.args,'EXCHANGE33Q_SCOPE_OR_GENESIS_MISMATCH');
}));
t('initial inventory history substitution rejected',()=>scenario(async x=>{
 x.args.initialInventoryHead=h(0,sha('other'));bad(x.args,'EXCHANGE33Q_SCOPE_OR_GENESIS_MISMATCH');
}));
t('directory inode substitution rejected',()=>scenario(async x=>{
 x.args.expectedRegistryDirectoryPin={...x.registryPin,ino:'999'};bad(x.args,'EXCHANGE33Q_SCOPE_OR_GENESIS_MISMATCH');
}));
t('signed published inventory head substitution rejected',()=>scenario(async x=>{
 republish(x,{inventoryHead:h(2,sha('other'))});bad(x.args,'EXCHANGE33Q_PUBLISHED_HEAD_MISMATCH');
}));
t('signed published registry head substitution rejected',()=>scenario(async x=>{
 republish(x,{registryHead:h(2,sha('other'))});bad(x.args,'EXCHANGE33Q_PUBLISHED_HEAD_MISMATCH');
}));
t('external record-byte pins mandatory',()=>scenario(async x=>{
 x.args.expectedRecordBytesDigests=[];bad(x.args,'EXCHANGE33Q_EXTERNAL_PINS_REQUIRED');
}));
t('symlinked registry entry fails read-only acquisition',()=>scenario(async x=>{
 const p=join(x.directory,'0001.json'),other=join(x.root,'saved');await rename(p,other);await symlink(other,p);
 await denied(acq(x),'EXCHANGE33Q_RECORD_UNSAFE');
}));
t('hardlinked registry entry fails read-only acquisition',()=>scenario(async x=>{
 await link(join(x.directory,'0001.json'),join(x.root,'hardlink'));
 await denied(acq(x),'EXCHANGE33Q_RECORD_UNSAFE');
}));
t('world-readable registry entry fails read-only acquisition',()=>scenario(async x=>{
 await chmod(join(x.directory,'0001.json'),0o644);await denied(acq(x),'EXCHANGE33Q_RECORD_UNSAFE');
}));
t('unknown registry entry fails closed, including pending commit',()=>scenario(async x=>{
 await writeFile(join(x.directory,'.pending.json'),'{}',{mode:0o600});
 await denied(acq(x),'EXCHANGE33Q_DIRECTORY_CONTENTS_UNSAFE');
}));
t('removed historical record fails closed',()=>scenario(async x=>{
 await unlink(join(x.directory,'0001.json'));await denied(acq(x),'EXCHANGE33Q_DIRECTORY_CONTENTS_UNSAFE');
}));
t('file substitution between open and read is detected',()=>scenario(async x=>{
 const p=join(x.directory,'0001.json');
 await denied(acquire({directory:x.directory,...x.args,checkpoint:async(stage,i)=>{
  if(stage==='after-open'&&i===1){await rename(p,join(x.root,'old'));await writeFile(p,x.args.recordBytes[0],{mode:0o600});}
 }}),'EXCHANGE33Q_TOCTOU_DETECTED');
}));
t('file substitution after read is detected',()=>scenario(async x=>{
 const p=join(x.directory,'0001.json');
 await denied(acquire({directory:x.directory,...x.args,checkpoint:async(stage,i)=>{
  if(stage==='after-read'&&i===1){await rename(p,join(x.root,'old'));await writeFile(p,x.args.recordBytes[0],{mode:0o600});}
 }}),'EXCHANGE33Q_TOCTOU_DETECTED');
}));
t('directory inode substitution fails closed',()=>scenario(async x=>{
 await denied(acquire({directory:x.directory,...x.args,checkpoint:async(stage,i)=>{
  if(stage==='after-read'&&i===2){await rename(x.directory,join(x.root,'moved'));await mkdir(x.directory,{mode:0o700});}
 }}),'EXCHANGE33Q_DIRECTORY_CHANGED');
}));
t('malformed UTF-8 record rejected after attacker repins digest',()=>scenario(async x=>{
 x.args.recordBytes[0]=Buffer.alloc(150,0xff);x.args.expectedRecordBytesDigests[0]=bytesDigest(x.args.recordBytes[0]);
 bad(x.args,'EXCHANGE33Q_RECORD_INVALID');
}));
t('noncanonical JSON record rejected after attacker repins digest',()=>scenario(async x=>{
 x.args.recordBytes[0]=Buffer.concat([x.args.recordBytes[0],Buffer.from(' ')]);
 x.args.expectedRecordBytesDigests[0]=bytesDigest(x.args.recordBytes[0]);bad(x.args,'EXCHANGE33Q_RECORD_INVALID');
}));
t('replayed signed embedded witness nonce rejected even after attacker recomputes chain and publisher signatures',()=>scenario(async x=>{
 rewrite(x,1,r=>{
  const rec=JSON.parse(Buffer.from(r.entry.receipt,'base64url'));
  rec.body.nonce='nonce_33q_first';rec.signature=sign(null,Buffer.from(JSON.stringify(rec.body)),witness.privateKey).toString('base64url');
  const bytes=Buffer.from(JSON.stringify(rec));r.entry.receipt=bytes.toString('base64url');r.nonce='nonce_33q_first';
  r.receiptDigest=hash('TJ-33N-SIGNED-ACQUISITION-RECEIPT',bytes);
 });rehash(x);bad(x.args,'EXCHANGE33Q_REPLAY');
}));
