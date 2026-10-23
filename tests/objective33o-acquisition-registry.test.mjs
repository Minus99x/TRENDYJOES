import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,lstat,readdir,rename,symlink,unlink,chmod,link} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA,offlineConflictAdjudicationInventoryGenesisHead} from '../src/offline-conflict-adjudication-transcript-inventory.mjs';
import {offlineConflictInventoryRecordBytesDigest} from '../src/offline-conflict-adjudication-inventory-record-evidence.mjs';
import {acquireOfflineConflictInventoryRecordsReadOnly} from '../src/offline-conflict-inventory-filesystem-acquisition.mjs';
import {createOfflineConflictInventoryAcquisitionRegistry,offlineConflictAcquisitionRegistryGenesisHead} from '../src/offline-conflict-inventory-acquisition-registry.mjs';
const hash=(d,b)=>createHash('sha256').update(d+'\0').update(b).digest('hex');
const sha=b=>createHash('sha256').update(b).digest('hex');
const ns='namespace_33o_test',scope=sha('33o-scope'),host='host_33o_001',observer='observer_33o_001',now=1792280000000;
const keys=generateKeyPairSync('ed25519'),wrong=generateKeyPairSync('ed25519');
const t=(name,fn)=>test('33O '+name,fn);
const reject=(promise,code)=>assert.rejects(promise,e=>e?.code===code);
const head=(count,headDigest)=>({count,headDigest});
function makeRecord(index,previous){const body={schema:OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA,
 index,namespaceId:ns,journalScopeDigest:scope,previousRecordDigest:previous,
 pair:[{marker:'fixture',index},{marker:'fixture',index}]};
 return Buffer.from(JSON.stringify({...body,recordDigest:hash('TJ-33J-INVENTORY-RECORD',Buffer.from(JSON.stringify(body)))}));}
const dirPin=async directory=>{const s=await lstat(directory,{bigint:true});return {dev:String(s.dev),ino:String(s.ino)};};
async function fixture(){
 const root=await mkdtemp(join(tmpdir(),'trendy33o-')),source=join(root,'source'),directory=join(root,'registry');
 await mkdir(source,{mode:0o700});await mkdir(directory,{mode:0o700});
 const genesis=offlineConflictAdjudicationInventoryGenesisHead(ns,scope);
 const first=makeRecord(1,genesis.headDigest),h1=head(1,JSON.parse(first).recordDigest);
 const second=makeRecord(2,h1.headDigest),h2=head(2,JSON.parse(second).recordDigest);
 const pin1={expectedRecordBytesDigest:offlineConflictInventoryRecordBytesDigest(first),expectedFromHead:genesis,expectedToHead:h1};
 const pin2={expectedRecordBytesDigest:offlineConflictInventoryRecordBytesDigest(second),expectedFromHead:h1,expectedToHead:h2};
 const sourcePin=await dirPin(source),registryPin=await dirPin(directory);
 await writeFile(join(source,'0001.json'),first,{mode:0o600});
 const acquisition=(nonce,from,to,recordPins)=>acquireOfflineConflictInventoryRecordsReadOnly({
  directory:source,expectedDirectoryPin:sourcePin,recordPins,expectedFromHead:from,expectedToHead:to,
  expectedNamespaceId:ns,expectedJournalScopeDigest:scope,hostId:host,observerId:observer,
  observerPrivateKey:keys.privateKey,observedAt:now,expiresAt:now+60000,nonce,checkpoint:undefined});
 const out1=await acquisition('nonce_33o_001',genesis,h1,[pin1]);
 const alt1=await acquisition('nonce_33o_002',genesis,h1,[pin1]);
 await writeFile(join(source,'0002.json'),second,{mode:0o600});
 const out2=await acquisition('nonce_33o_003',h1,h2,[pin2]);
 const config={directory,namespaceId:ns,journalScopeDigest:scope,hostId:host,observerId:observer,
  expectedObserverPublicKey:keys.publicKey,initialInventoryHead:genesis};
 const registry=()=>createOfflineConflictInventoryAcquisitionRegistry(config);
 const genesisHead=registry().genesisHead;
 const admission=(out,recordPins,from,to,expectedHead=genesisHead)=>({
  receiptBytes:out.receiptBytes,records:out.records,recordPins,expectedDirectoryPin:sourcePin,
  expectedFromHead:from,expectedToHead:to,nowMs:now+1000,expectedHead,
  expectedRegistryDirectoryPin:registryPin});
 return {root,source,directory,sourcePin,registryPin,config,registry,genesisHead,genesis,h1,h2,
  pin1,pin2,out1,out2,alt1,first,second,one:admission(out1,[pin1],genesis,h1),
  alt:admission(alt1,[pin1],genesis,h1),two:(expectedHead)=>admission(out2,[pin2],h1,h2,expectedHead),
  cleanup:()=>rm(root,{recursive:true,force:true})};
}
async function scenario(fn){const x=await fixture();try{await fn(x);}finally{await x.cleanup();}}
async function child(script,input){return new Promise((resolve,reject)=>{
 const p=spawn(process.execPath,['--input-type=module','-e',script],{stdio:['pipe','pipe','pipe']});
 let stdout='',stderr='';p.stdout.on('data',d=>stdout+=d);p.stderr.on('data',d=>stderr+=d);
 p.on('error',reject);p.on('close',(code,signal)=>resolve({code,signal,stdout,stderr}));
 p.stdin.end(JSON.stringify(input));
});}
const moduleURL=new URL('../src/offline-conflict-inventory-acquisition-registry.mjs',import.meta.url).href;
const worker=`import {createOfflineConflictInventoryAcquisitionRegistry} from ${JSON.stringify(moduleURL)};
import {createPublicKey} from 'node:crypto';
let data='';for await(const chunk of process.stdin)data+=chunk;
const p=JSON.parse(data),key=createPublicKey(p.key);
const r=createOfflineConflictInventoryAcquisitionRegistry({...p.config,expectedObserverPublicKey:key,
 injectFault:p.fault?async stage=>{if(stage===p.fault)process.kill(process.pid,'SIGKILL');}:undefined});
const a={...p.admission,receiptBytes:Buffer.from(p.admission.receiptBytes,'base64url'),
 records:p.admission.records.map(x=>Buffer.from(x,'base64url'))};
try{const out=await r.accept(a);process.stdout.write(JSON.stringify(out));}
catch(e){process.stdout.write(e.code||e.message);process.exitCode=2;}`;
const childInput=(x,admission,fault)=>({key:keys.publicKey.export({format:'pem',type:'spki'}),
 config:{...x.config,expectedObserverPublicKey:undefined},fault,
 admission:{...admission,receiptBytes:admission.receiptBytes.toString('base64url'),
  records:admission.records.map(b=>b.toString('base64url'))}});
t('genesis is independently keyed to scope, witness key and initial inventory head',()=>scenario(async x=>{
 assert.deepEqual(x.registry().genesisHead,x.genesisHead);
 assert.notDeepEqual(offlineConflictAcquisitionRegistryGenesisHead({...x.config,expectedObserverPublicKey:wrong.publicKey}),x.genesisHead);
 assert.notDeepEqual(offlineConflictAcquisitionRegistryGenesisHead({...x.config,initialInventoryHead:x.h1}),x.genesisHead);
}));
t('first signed receipt admitted with externally pinned registry head and inode',()=>scenario(async x=>{
 const r=x.registry(),out=await r.accept(x.one);
 assert.equal(out.count,1);assert.deepEqual(out.inventoryHead,x.h1);
 assert.deepEqual(await r.inspect({expectedHead:{count:out.count,headDigest:out.headDigest},expectedRegistryDirectoryPin:x.registryPin}),out);
}));
t('second session must extend previously accepted inventory head',()=>scenario(async x=>{
 const r=x.registry(),first=await r.accept(x.one),second=await r.accept(x.two({count:first.count,headDigest:first.headDigest}));
 assert.equal(second.count,2);assert.deepEqual(second.inventoryHead,x.h2);
}));
t('cross-session rollback rejected with externally pinned registry head',()=>scenario(async x=>{
 const r=x.registry(),first=await r.accept(x.one);
 await reject(r.inspect({expectedHead:x.genesisHead,expectedRegistryDirectoryPin:x.registryPin}),'EXCHANGE33O_STALE_OR_ROLLED_BACK_HEAD');
 await reject(r.accept(x.two(x.genesisHead)),'EXCHANGE33O_STALE_OR_ROLLED_BACK_HEAD');
 assert.equal(first.count,1);
}));
t('duplicate receipt cannot be admitted even with forged new expected head',()=>scenario(async x=>{
 const r=x.registry(),first=await r.accept(x.one);
 await reject(r.accept({...x.one,expectedHead:{count:first.count,headDigest:first.headDigest}}),'EXCHANGE33O_NONCONTIGUOUS_SESSION');
}));
t('alternative signed receipt of same history rejected as noncontiguous',()=>scenario(async x=>{
 const r=x.registry(),first=await r.accept(x.one);
 await reject(r.accept({...x.alt,expectedHead:{count:first.count,headDigest:first.headDigest}}),'EXCHANGE33O_NONCONTIGUOUS_SESSION');
}));
t('wrong independently pinned witness key fails closed',()=>scenario(async x=>{
 const r=createOfflineConflictInventoryAcquisitionRegistry({...x.config,expectedObserverPublicKey:wrong.publicKey});
 await reject(r.accept({...x.one,expectedHead:r.genesisHead}),'EXCHANGE33N_SIGNATURE_INVALID');
}));
t('signed receipt tampering fails closed before any journal write',()=>scenario(async x=>{
 const r=x.registry(),tampered=Buffer.from(x.one.receiptBytes);tampered[tampered.length-2]^=1;
 await assert.rejects(r.accept({...x.one,receiptBytes:tampered}));
 assert.deepEqual(await readdir(x.directory),[]);
}));
t('substituted record bytes rejected without journal mutation',()=>scenario(async x=>{
 const r=x.registry(),records=x.one.records.map(Buffer.from);records[0][120]^=1;
 await assert.rejects(r.accept({...x.one,records}));assert.deepEqual(await readdir(x.directory),[]);
}));
t('stale, expired and future-dated admission rejected',()=>scenario(async x=>{
 const r=x.registry();
 await reject(r.accept({...x.one,nowMs:now+60000}),'EXCHANGE33N_RECEIPT_SCOPE_OR_TIME_INVALID');
 await reject(r.accept({...x.one,nowMs:now-1}),'EXCHANGE33N_RECEIPT_SCOPE_OR_TIME_INVALID');
}));
t('directory inode substitution rejected',()=>scenario(async x=>{
 await reject(x.registry().accept({...x.one,expectedRegistryDirectoryPin:{...x.registryPin,ino:'1'}}),'EXCHANGE33O_DIRECTORY_UNSAFE');
}));
t('missing external head or directory pin rejected',()=>scenario(async x=>{
 await reject(x.registry().accept({...x.one,expectedHead:undefined}),'EXCHANGE33O_EXTERNAL_HEAD_REQUIRED');
 await reject(x.registry().accept({...x.one,expectedRegistryDirectoryPin:undefined}),'EXCHANGE33O_EXTERNAL_DIRECTORY_PIN_REQUIRED');
}));
t('historical record corruption fails closed on inspection',()=>scenario(async x=>{
 const r=x.registry(),first=await r.accept(x.one),path=join(x.directory,'0001.json');
 const bytes=await readFile(path);bytes[bytes.length-2]^=1;await writeFile(path,bytes);
 await assert.rejects(r.inspect({expectedHead:{count:first.count,headDigest:first.headDigest},expectedRegistryDirectoryPin:x.registryPin}));
}));
t('missing historical record never accepted as clean genesis rollback',()=>scenario(async x=>{
 const r=x.registry(),committed=await r.accept(x.one);await unlink(join(x.directory,'0001.json'));
 await reject(r.inspect({expectedHead:{count:committed.count,headDigest:committed.headDigest},expectedRegistryDirectoryPin:x.registryPin}),'EXCHANGE33O_STALE_OR_ROLLED_BACK_HEAD');
}));
t('symlinked journal entry rejected',()=>scenario(async x=>{
 const r=x.registry(),first=await r.accept(x.one),p=join(x.directory,'0001.json');
 await rename(p,join(x.root,'saved.json'));await symlink(join(x.root,'saved.json'),p);
 await reject(r.inspect({expectedHead:{count:first.count,headDigest:first.headDigest},expectedRegistryDirectoryPin:x.registryPin}),'EXCHANGE33O_RECORD_UNSAFE');
}));
t('hardlinked journal entry rejected',()=>scenario(async x=>{
 const r=x.registry(),first=await r.accept(x.one);await link(join(x.directory,'0001.json'),join(x.root,'other'));
 await reject(r.inspect({expectedHead:{count:first.count,headDigest:first.headDigest},expectedRegistryDirectoryPin:x.registryPin}),'EXCHANGE33O_RECORD_UNSAFE');
}));
t('world-readable journal record rejected',()=>scenario(async x=>{
 const r=x.registry(),first=await r.accept(x.one);await chmod(join(x.directory,'0001.json'),0o644);
 await reject(r.inspect({expectedHead:{count:first.count,headDigest:first.headDigest},expectedRegistryDirectoryPin:x.registryPin}),'EXCHANGE33O_RECORD_UNSAFE');
}));
t('unknown journal files fail closed',()=>scenario(async x=>{
 const r=x.registry();await writeFile(join(x.directory,'surprise'),'bad',{mode:0o600});
 await reject(r.inspect({expectedHead:x.genesisHead,expectedRegistryDirectoryPin:x.registryPin}),'EXCHANGE33O_HISTORY_INVALID');
}));
t('uncertain pending commit fails closed',()=>scenario(async x=>{
 const r=x.registry();await writeFile(join(x.directory,'.pending.json'),'{}',{mode:0o600});
 await reject(r.inspect({expectedHead:x.genesisHead,expectedRegistryDirectoryPin:x.registryPin}),'EXCHANGE33O_UNCERTAIN_COMMIT');
}));
t('stale signed receipt cannot be reused with altered namespace',()=>scenario(async x=>{
 const r=createOfflineConflictInventoryAcquisitionRegistry({...x.config,namespaceId:'namespace_33o_other'});
 await reject(r.accept({...x.one,expectedHead:r.genesisHead}),'EXCHANGE33N_RECEIPT_SCOPE_OR_TIME_INVALID');
}));
t('same signed nonce reused in a later valid session is durably rejected',()=>scenario(async x=>{
 const r=x.registry(),first=await r.accept(x.one),altered=JSON.parse(x.out2.receiptBytes);
 altered.body.nonce='nonce_33o_001';altered.signature=sign(null,Buffer.from(JSON.stringify(altered.body)),keys.privateKey).toString('base64url');
 const receiptBytes=Buffer.from(JSON.stringify(altered));
 await reject(r.accept({...x.two({count:first.count,headDigest:first.headDigest}),receiptBytes}),'EXCHANGE33O_REPLAY');
}));
t('valid alternate signed first-session fork cannot replace independently pinned history',()=>scenario(async x=>{
 const r=x.registry(),first=await r.accept(x.one);
 await unlink(join(x.directory,'0001.json'));
 await reject(r.accept({...x.alt,expectedHead:{count:first.count,headDigest:first.headDigest}}),'EXCHANGE33O_STALE_OR_ROLLED_BACK_HEAD');
}));
t('replaced registry directory inode rejected despite copied record bytes',()=>scenario(async x=>{
 const r=x.registry(),first=await r.accept(x.one),old=x.directory+'-old';
 await rename(x.directory,old);await mkdir(x.directory,{mode:0o700});
 await writeFile(join(x.directory,'0001.json'),await readFile(join(old,'0001.json')),{mode:0o600});
 await reject(r.inspect({expectedHead:{count:first.count,headDigest:first.headDigest},expectedRegistryDirectoryPin:x.registryPin}),'EXCHANGE33O_DIRECTORY_UNSAFE');
}));
t('historical receipt witness signature is reverified on independent restart',()=>scenario(async x=>{
 const r=x.registry(),first=await r.accept(x.one);
 const fake=createOfflineConflictInventoryAcquisitionRegistry({...x.config,expectedObserverPublicKey:wrong.publicKey});
 await reject(fake.inspect({expectedHead:{count:first.count,headDigest:first.headDigest},expectedRegistryDirectoryPin:x.registryPin}),'EXCHANGE33O_HISTORY_INVALID');
}));
t('actual independent Node process admits a receipt and survives restart',()=>scenario(async x=>{
 const result=await child(worker,childInput(x,x.one));assert.equal(result.code,0,result.stderr+' '+result.stdout);
 const h=JSON.parse(result.stdout);const inspected=await x.registry().inspect({expectedHead:{count:h.count,headDigest:h.headDigest},expectedRegistryDirectoryPin:x.registryPin});
 assert.equal(inspected.count,1);
}));
t('two competing independent Node processes cannot both admit same expected head',()=>scenario(async x=>{
 const [a,b]=await Promise.all([child(worker,childInput(x,x.one)),child(worker,childInput(x,x.alt))]);
 assert.equal([a,b].filter(y=>y.code===0).length,1,JSON.stringify([a,b]));
 const winner=[a,b].find(y=>y.code===0),h=JSON.parse(winner.stdout);
 assert.equal((await x.registry().inspect({expectedHead:{count:h.count,headDigest:h.headDigest},expectedRegistryDirectoryPin:x.registryPin})).count,1);
}));
for(const boundary of ['after-pending-sync','after-link-sync','after-commit-sync']){
 t('real SIGKILL at '+boundary+' leaves explicit nonautomatic adjudication boundary',()=>scenario(async x=>{
  const out=await child(worker,childInput(x,x.one,boundary));assert.equal(out.signal,'SIGKILL',JSON.stringify(out));
  await reject(x.registry().inspect({expectedHead:x.genesisHead,expectedRegistryDirectoryPin:x.registryPin}),'EXCHANGE33O_LOCKED');
  // Test harness only removes orphaned lock; production module never repairs it.
  await rm(join(x.directory,'.registry-lock'),{recursive:true});
  if(boundary==='after-commit-sync'){
   const r=await readdir(x.directory);assert.deepEqual(r,['0001.json']);
   await reject(x.registry().inspect({expectedHead:x.genesisHead,expectedRegistryDirectoryPin:x.registryPin}),'EXCHANGE33O_STALE_OR_ROLLED_BACK_HEAD');
  }else await reject(x.registry().inspect({expectedHead:x.genesisHead,expectedRegistryDirectoryPin:x.registryPin}),'EXCHANGE33O_UNCERTAIN_COMMIT');
 }));
}
t('no checkout, production, remote-state or trusted-time claims',()=>scenario(async x=>{
 const r=x.registry(),out=await r.accept(x.one);
 for(const key of ['independentHeadPublication','independentlyWitnessed','trustedTimestamp','provesRemoteDiskState','authorizesCheckout','authorizesProduction'])assert.equal(out[key],false);
 assert.equal(out.durableLocalReplay,true);
}));
