import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign,createPublicKey} from 'node:crypto';
import {mkdtemp,rm,writeFile,readFile,unlink,symlink,link,readdir,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync,spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {OFFLINE_ACQUISITION_EXPORT_SCHEMA} from '../src/offline-acquisition-evidence-export.mjs';
import {OFFLINE_ACQUISITION_SESSION_SCHEMA} from '../src/offline-acquisition-session-journal.mjs';
import {OFFLINE_ACQUISITION_MANIFEST_SCHEMA} from '../src/offline-forensic-acquisition-provenance.mjs';
import {createOfflineExportReceiptRegistry,OFFLINE_EXPORT_RECEIPT_SCHEMA,offlineExportReceiptPolicyDigest,offlineExportReceiptSigningBytes} from '../src/offline-acquisition-export-receipt-registry.mjs';
import {OFFLINE_EXPORT_WITNESS_TRANSITION_SCHEMA,offlineExportWitnessTransitionSigningBytes,offlineExportWitnessTransitionPossessionBytes,offlineExportWitnessTransitionChainDigest} from '../src/offline-export-receipt-witness-rotation.mjs';
import {createOfflineExportReceiptCutoverRegistry} from '../src/offline-export-receipt-policy-cutover.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const root='0'.repeat(64),nowMs=1800000000000,registryId='cutover_registry_31v';
const groups=[0,1].map(epoch=>Array.from({length:3},(_,i)=>({id:`witness_31v_${epoch}_${i}`, ...generateKeyPairSync('ed25519')})));
const policies=groups.map(g=>({witnesses:g.map(k=>({id:k.id,publicKey:k.publicKey})),quorum:2}));
const digests=policies.map(offlineExportReceiptPolicyDigest),zero={count:0,headDigest:root};
const reject=(f,code)=>assert.rejects(f,e=>e?.code===code,code);
const throws=(f,code)=>assert.throws(f,e=>e?.code===code,code);
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
function receipt(epoch,sequence,previousDigest,{acquisitionId=`acquisition_31v_${sequence}_0001`,exportId=`export_31v_${sequence}_0001`,nonce=`nonce_31v_${sequence}_0001`,issuedAt=nowMs-2000,variant=sequence}={}){
 const archiveBytes=archive(acquisitionId,variant);
 const body={schema:OFFLINE_EXPORT_RECEIPT_SCHEMA,registryId,sequence,previousDigest,exportId,acquisitionId,archiveDigest:sha(archiveBytes),archiveBytes:archiveBytes.length,issuedAt,expiresAt:issuedAt+60000,nonce,policyDigest:digests[epoch]};
 const bytes=offlineExportReceiptSigningBytes(body),signatures=groups[epoch].slice(0,2).map(k=>({witnessId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}));
 return {receipt:{body,signatures},archiveBytes};
}
function transition(head,changes={}){
 const body={schema:OFFLINE_EXPORT_WITNESS_TRANSITION_SCHEMA,registryId,fromEpoch:0,toEpoch:1,fromPolicyDigest:digests[0],toPolicyDigest:digests[1],anchorHead:head,issuedAt:nowMs-1000,expiresAt:nowMs+60000,nonce:'nonce_cutover_31v_0001',...changes};
 const bytes=offlineExportWitnessTransitionSigningBytes(body);
 const outgoingSignatures=groups[0].slice(0,2).map(k=>({witnessId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}));
 const incomingProofs=groups[1].map(k=>({witnessId:k.id,signature:sign(null,offlineExportWitnessTransitionPossessionBytes(body,k.id),k.privateKey).toString('base64url')}));
 return {body,outgoingSignatures,incomingProofs};
}
const pin=t=>offlineExportWitnessTransitionChainDigest({transitions:[t]});
async function setup(t,{injectFault}={}){
 const directory=await mkdtemp(join(tmpdir(),'tj31v-'));await chmod(directory,0o700);t.after(()=>rm(directory,{recursive:true,force:true}));
 const old=createOfflineExportReceiptRegistry({directory,registryId,...policies[0]});
 const first=await old.append({...receipt(0,1,root),expectedHead:zero,nowMs});
 const registry=createOfflineExportReceiptCutoverRegistry({directory,registryId,oldPolicy:policies[0],newPolicy:policies[1],injectFault});
 const tr=transition(first.head);return {directory,old,registry,first,tr,digest:pin(tr)};
}
async function activated(t,options){const x=await setup(t,options);const result=await x.registry.cutover({transition:x.tr,expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs});return {...x,result};}
const second=x=>receipt(1,2,x.first.head.headDigest,{issuedAt:nowMs});
const append=x=>x.registry.append({...second(x),expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs});
const cfg=x=>({directory:x.directory,registryId,oldPolicy:policies[0],newPolicy:policies[1]});

const modulePath=fileURLToPath(new URL('../src/offline-export-receipt-policy-cutover.mjs',import.meta.url));
function crashChild(x,point,operation){
 const serialize=p=>({quorum:p.quorum,witnesses:p.witnesses.map(w=>({id:w.id,pem:w.publicKey.export({format:'pem',type:'spki'})}))});
 const args={directory:x.directory,registryId,oldPolicy:serialize(policies[0]),newPolicy:serialize(policies[1]),point,operation,expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs,transition:x.tr,receipt:second(x).receipt,archive:second(x).archiveBytes.toString('base64')};
 const code=`import {createPublicKey} from 'node:crypto';import {createOfflineExportReceiptCutoverRegistry} from ${JSON.stringify(modulePath)};const x=JSON.parse(process.argv[1]);const policy=p=>({quorum:p.quorum,witnesses:p.witnesses.map(w=>({id:w.id,publicKey:createPublicKey(w.pem)}))});const r=createOfflineExportReceiptCutoverRegistry({directory:x.directory,registryId:x.registryId,oldPolicy:policy(x.oldPolicy),newPolicy:policy(x.newPolicy),injectFault:async at=>{if(at===x.point)process.kill(process.pid,'SIGKILL');}});const a={expectedHead:x.expectedHead,expectedTransitionDigest:x.expectedTransitionDigest,nowMs:x.nowMs};if(x.operation==='cutover')await r.cutover({...a,transition:x.transition});else await r.append({...a,receipt:x.receipt,archiveBytes:Buffer.from(x.archive,'base64')});`;
 return spawnSync(process.execPath,['--input-type=module','-e',code,JSON.stringify(args)],{encoding:'utf8',timeout:15000});
}

const pendingPath=(x,kind)=>join(x.directory,kind==='cutover'?'.pending-cutover.json':'.pending.json');
async function uncertain(t,kind,linked=false){
 const x=kind==='cutover'?await setup(t):await activated(t);
 const point=kind==='cutover'?(linked?'after-cutover-link-sync':'after-cutover-pending-sync'):(linked?'after-rotated-append-link-sync':'after-rotated-append-pending-sync');
 const r=createOfflineExportReceiptCutoverRegistry({...cfg(x),injectFault:async at=>{if(at===point)throw Error('simulated-power-loss');}});
 await assert.rejects(()=>kind==='cutover'?r.cutover({transition:x.tr,expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}):r.append({...second(x),expectedHead:x.first.head,expectedTransitionDigest:x.digest,nowMs}),/simulated-power-loss/);
 const pending=JSON.parse(await readFile(pendingPath(x,kind),'utf8'));
 const expectedPendingDigest=sha(Buffer.from(JSON.stringify(pending)));
 const expectedAfterHead=kind==='cutover'?x.first.head:{count:pending.index,headDigest:pending.digest};
 const args={kind,decision:linked?'finalize-linked':'abort-unlinked',expectedBeforeHead:x.first.head,expectedAfterHead,expectedTransitionDigest:x.digest,expectedPendingDigest,nowMs};
 return {...x,pending,args};
}
for(const kind of ['cutover','append'])for(const linked of [false,true]){
 test(`31W supervised ${kind} ${linked?'linked-finalize':'unlinked-abort'} preserves signed history`,async t=>{
  const x=await uncertain(t,kind,linked);
  await reject(()=>x.registry.inspect({expectedHead:x.first.head,expectedTransitionDigest:kind==='append'?x.digest:undefined,nowMs}),'CUTOVER_UNCERTAIN_COMMIT');
  const result=await x.registry.reconcilePending(x.args);
  assert.equal(result.readOnly,true);assert.equal(result.productionApproved,false);
  assert.deepEqual(result.head,linked?x.args.expectedAfterHead:x.first.head);
  assert.equal((await readdir(x.directory)).includes(kind==='cutover'?'.pending-cutover.json':'.pending.json'),false);
  assert.equal((await x.registry.inspect({expectedHead:result.head,expectedTransitionDigest:kind==='append'||linked?x.digest:undefined,nowMs})).head.headDigest,result.head.headDigest);
 });
 test(`31W ${kind} ${linked?'linked':'unlinked'} rejects forged external pending digest`,async t=>{
  const x=await uncertain(t,kind,linked);
  await reject(()=>x.registry.reconcilePending({...x.args,expectedPendingDigest:'a'.repeat(64)}),'CUTOVER_RECOVERY_PENDING_PIN_MISMATCH');
  assert.ok((await readdir(x.directory)).includes(kind==='cutover'?'.pending-cutover.json':'.pending.json'));
 });
 test(`31W ${kind} ${linked?'linked':'unlinked'} rejects stale before-head pin`,async t=>{
  const x=await uncertain(t,kind,linked);
  await reject(()=>x.registry.reconcilePending({...x.args,expectedBeforeHead:zero}),linked?'CUTOVER_RECOVERY_RECORD_INVALID':'CUTOVER_RECOVERY_RECORD_INVALID');
 });
 test(`31W ${kind} ${linked?'linked':'unlinked'} refuses mismatched recovery decision`,async t=>{
  const x=await uncertain(t,kind,linked);
  const wrong=linked?'abort-unlinked':'finalize-linked';
  const code=linked?'CUTOVER_FILE_UNSAFE':'CUTOVER_FILE_UNSAFE';
  await reject(()=>x.registry.reconcilePending({...x.args,decision:wrong}),code);
 });
}
test('31W missing external transition digest cannot trigger recovery',async t=>{const x=await uncertain(t,'cutover');await reject(()=>x.registry.reconcilePending({...x.args,expectedTransitionDigest:undefined}),'CUTOVER_RECOVERY_EXTERNAL_PINS_REQUIRED');});
test('31W missing pending pin cannot trigger recovery',async t=>{const x=await uncertain(t,'append');await reject(()=>x.registry.reconcilePending({...x.args,expectedPendingDigest:undefined}),'CUTOVER_RECOVERY_EXTERNAL_PINS_REQUIRED');});
test('31W linked append requires independently pinned post head',async t=>{const x=await uncertain(t,'append',true);await reject(()=>x.registry.reconcilePending({...x.args,expectedAfterHead:x.first.head}),'CUTOVER_RECOVERY_STALE_PIN');});
test('31W linked cutover cannot be aborted as an unlinked pending commit',async t=>{const x=await uncertain(t,'cutover',true);await reject(()=>x.registry.reconcilePending({...x.args,decision:'abort-unlinked'}),'CUTOVER_FILE_UNSAFE');});
test('31W unlinked cutover cannot be finalized without a committed hardlink',async t=>{const x=await uncertain(t,'cutover');await reject(()=>x.registry.reconcilePending({...x.args,decision:'finalize-linked'}),'CUTOVER_FILE_UNSAFE');});
test('31W refuses symlinked pending marker without deleting it',async t=>{const x=await uncertain(t,'cutover'),p=pendingPath(x,'cutover');await unlink(p);await symlink('/etc/hosts',p);await reject(()=>x.registry.reconcilePending(x.args),'CUTOVER_FILE_UNSAFE');});
test('31W refuses altered pending bytes with original external pin',async t=>{const x=await uncertain(t,'append'),p=pendingPath(x,'append');const v=JSON.parse(await readFile(p,'utf8'));v.receipt.body.exportId='changed_after_crash';await writeFile(p,JSON.stringify(v));await reject(()=>x.registry.reconcilePending(x.args),'CUTOVER_RECOVERY_PENDING_PIN_MISMATCH');});
test('31W refuses forged committed hardlink substitution',async t=>{const x=await uncertain(t,'append',true),p=join(x.directory,'0002.json');await unlink(p);await writeFile(p,JSON.stringify(x.pending),{mode:0o600});await reject(()=>x.registry.reconcilePending(x.args),'CUTOVER_FILE_UNSAFE');});
test('31W recovery marker cannot be replayed after successful reconciliation',async t=>{const x=await uncertain(t,'append');await x.registry.reconcilePending(x.args);await reject(()=>x.registry.reconcilePending(x.args),'CUTOVER_RECOVERY_MARKER_MISMATCH');});
test('31W can safely append after supervised abort of an unlinked pending receipt',async t=>{const x=await uncertain(t,'append');await x.registry.reconcilePending(x.args);const r=await append(x);assert.equal(r.head.count,2);});
test('31W supervised finalized append rejects stale pre-crash writer',async t=>{const x=await uncertain(t,'append',true);await x.registry.reconcilePending(x.args);await reject(()=>append(x),'CUTOVER_STALE_HEAD');});
test('31W real child SIGKILL before cutover link is recoverable only with external pins',async t=>{const x=await setup(t),r=crashChild(x,'after-cutover-pending-sync','cutover');assert.equal(r.signal,'SIGKILL',r.stderr);const p=JSON.parse(await readFile(pendingPath(x,'cutover'),'utf8'));const a={kind:'cutover',decision:'abort-unlinked',expectedBeforeHead:x.first.head,expectedTransitionDigest:x.digest,expectedPendingDigest:sha(Buffer.from(JSON.stringify(p))),nowMs};assert.equal((await x.registry.reconcilePending(a)).epoch,0);});
test('31W real child SIGKILL after cutover hardlink is recoverable only with external pins',async t=>{const x=await setup(t),r=crashChild(x,'after-cutover-link-sync','cutover');assert.equal(r.signal,'SIGKILL',r.stderr);const p=JSON.parse(await readFile(pendingPath(x,'cutover'),'utf8'));const a={kind:'cutover',decision:'finalize-linked',expectedBeforeHead:x.first.head,expectedAfterHead:x.first.head,expectedTransitionDigest:x.digest,expectedPendingDigest:sha(Buffer.from(JSON.stringify(p))),nowMs};assert.equal((await x.registry.reconcilePending(a)).epoch,1);});
test('31W real child SIGKILL after rotated append hardlink recovers exact pinned post head',async t=>{const x=await activated(t),r=crashChild(x,'after-rotated-append-link-sync','append');assert.equal(r.signal,'SIGKILL',r.stderr);const p=JSON.parse(await readFile(pendingPath(x,'append'),'utf8'));const a={kind:'append',decision:'finalize-linked',expectedBeforeHead:x.first.head,expectedAfterHead:{count:p.index,headDigest:p.digest},expectedTransitionDigest:x.digest,expectedPendingDigest:sha(Buffer.from(JSON.stringify(p))),nowMs};assert.equal((await x.registry.reconcilePending(a)).head.count,2);});
test('31W SIGKILL after recovery marker fsync leaves valid externally pinned state',async t=>{const x=await uncertain(t,'append',true);// Exercise recovery in a dedicated child; never SIGKILL the test process.
 const serialize=p=>({quorum:p.quorum,witnesses:p.witnesses.map(w=>({id:w.id,pem:w.publicKey.export({format:'pem',type:'spki'})}))});
 const code=`import {createPublicKey} from 'node:crypto';import {createOfflineExportReceiptCutoverRegistry} from ${JSON.stringify(modulePath)};const a=JSON.parse(process.argv[1]);const pol=p=>({quorum:p.quorum,witnesses:p.witnesses.map(w=>({id:w.id,publicKey:createPublicKey(w.pem)}))});const reg=createOfflineExportReceiptCutoverRegistry({directory:a.directory,registryId:a.registryId,oldPolicy:pol(a.old),newPolicy:pol(a.new),injectFault:async at=>{if(at==='after-recovery-marker-sync')process.kill(process.pid,'SIGKILL')}});await reg.reconcilePending(a.args);`;
 const args={directory:x.directory,registryId,old:serialize(policies[0]),new:serialize(policies[1]),args:x.args};const child=spawnSync(process.execPath,['--input-type=module','-e',code,JSON.stringify(args)],{encoding:'utf8',timeout:15000});assert.equal(child.signal,'SIGKILL',child.stderr);
 assert.equal((await x.registry.inspect({expectedHead:x.args.expectedAfterHead,expectedTransitionDigest:x.digest,nowMs})).head.count,2);
});
test('31W two independent recovery processes serialize; only one can consume the pinned marker',async t=>{
 const x=await uncertain(t,'append',true);
 const serialize=p=>({quorum:p.quorum,witnesses:p.witnesses.map(w=>({id:w.id,pem:w.publicKey.export({format:'pem',type:'spki'})}))});
 const args={directory:x.directory,registryId,old:serialize(policies[0]),new:serialize(policies[1]),recovery:x.args};
 const code=`import {createPublicKey} from 'node:crypto';import {createOfflineExportReceiptCutoverRegistry} from ${JSON.stringify(modulePath)};const a=JSON.parse(process.argv[1]);const p=x=>({quorum:x.quorum,witnesses:x.witnesses.map(w=>({id:w.id,publicKey:createPublicKey(w.pem)}))});const r=createOfflineExportReceiptCutoverRegistry({directory:a.directory,registryId:a.registryId,oldPolicy:p(a.old),newPolicy:p(a.new)});try{await r.reconcilePending(a.recovery);process.stdout.write('OK');}catch(e){process.stdout.write(e.code||'UNKNOWN');process.exitCode=2;}`;
 const launch=()=>new Promise((ok,no)=>{const c=spawn(process.execPath,['--input-type=module','-e',code,JSON.stringify(args)],{stdio:['ignore','pipe','pipe']});let out='',err='';c.stdout.on('data',b=>out+=b);c.stderr.on('data',b=>err+=b);c.once('error',no);c.once('close',(code,signal)=>ok({code,signal,out,err}));});
 const results=await Promise.all([launch(),launch()]);assert.equal(results.filter(r=>r.code===0&&r.out==='OK').length,1,JSON.stringify(results));assert.equal(results.filter(r=>r.code===2&&r.out==='CUTOVER_RECOVERY_MARKER_MISMATCH').length,1,JSON.stringify(results));
 assert.equal((await x.registry.inspect({expectedHead:x.args.expectedAfterHead,expectedTransitionDigest:x.digest,nowMs})).head.count,2);
});
test('31W recovery refuses an externally substituted witness-transition digest',async t=>{const x=await uncertain(t,'cutover',true);await reject(()=>x.registry.reconcilePending({...x.args,expectedTransitionDigest:'f'.repeat(64)}),'CUTOVER_RECOVERY_RECORD_INVALID');});
test('31W recovery refuses hardlinked pending marker with unrelated third link',async t=>{const x=await uncertain(t,'append',true);await link(pendingPath(x,'append'),join(x.directory,'other-hardlink'));await reject(()=>x.registry.reconcilePending(x.args),'CUTOVER_FILE_UNSAFE');});
test('31W linked finalization without externally pinned post-head is forbidden',async t=>{const x=await uncertain(t,'append',true);await reject(()=>x.registry.reconcilePending({...x.args,expectedAfterHead:undefined}),'CUTOVER_EXTERNAL_HEAD_REQUIRED');});
