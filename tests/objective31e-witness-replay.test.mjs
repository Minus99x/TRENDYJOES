import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,unlink,chmod,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createOfflineDurableAnchorAdapter} from '../src/offline-durable-anchor-adapter.mjs';
import {createOfflineRecoveryAuthorizationLedger} from '../src/offline-recovery-authorization-ledger.mjs';
import {OFFLINE_WITNESS_SCHEMA,verifyOfflineWitnessQuorum,createOfflineWitnessedRecoveryGuard} from '../src/offline-recovery-witness.mjs';

const registryId='objective31e-test-registry';
const recoverySchema='TJ-OFFLINE-DURABLE-ANCHOR-RECOVERY-1';
const recoveryFields=['schema','registryId','anchorType','action','authorizationId','issuedAt','expiresAt','expectedAnchor','targetAnchor','pendingDigest','reason'];
const witnessFields=['schema','witnessId','registryId','anchorType','eventCount','historyDigest','anchor','challenge','issuedAt','expiresAt'];
const hash=x=>createHash('sha256').update(x).digest('hex');
const a=(n,c)=>({sequence:n,mac:c.repeat(64)});
const rejects=(promise,code)=>assert.rejects(promise,e=>e?.code===code);
const snap=s=>({anchor:s.anchor,eventCount:s.eventCount,historyDigest:s.historyDigest});
const id=()=>`permit-${randomBytes(12).toString('hex')}`;
const fixedChallenge=Buffer.alloc(32,1).toString('base64url');
async function fixture(t,{fault,ledgerFault}={}){
 const base=await mkdtemp(join(tmpdir(),'tj-31e-'));t.after(()=>rm(base,{recursive:true,force:true}));
 const anchorDirectory=join(base,'anchor'),ledgerDirectory=join(base,'ledger');
 const recoveryKeys=generateKeyPairSync('ed25519');
 const adapter=()=>createOfflineDurableAnchorAdapter({directory:anchorDirectory,registryId,anchorType:'registry',recovery:{publicKey:recoveryKeys.publicKey},injectFault:fault});
 const ledger=()=>createOfflineRecoveryAuthorizationLedger({directory:ledgerDirectory,registryId,anchorType:'registry',injectFault:ledgerFault});
 const witnessKeys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
 let pinned=null;
 const receipt=(w,snapshot,overrides={},challenge=fixedChallenge)=>{
  const now=Date.now();const body={schema:OFFLINE_WITNESS_SCHEMA,witnessId:w.id,registryId,anchorType:'registry',eventCount:snapshot.eventCount,historyDigest:snapshot.historyDigest,anchor:snapshot.anchor,challenge,issuedAt:now-1000,expiresAt:now+60000,...overrides};
  return {...body,signature:sign(null,Buffer.from(`${OFFLINE_WITNESS_SCHEMA}\0${JSON.stringify(Object.fromEntries(witnessFields.map(k=>[k,body[k]])))}`),w.privateKey).toString('base64url')};
 };
 const witnesses=witnessKeys.map((keys,i)=>{
  const w={id:`independent-witness-${i+1}`,publicKey:keys.publicKey,privateKey:keys.privateKey};
  return {...w,readLatest:async({challenge})=>receipt(w,pinned,{},challenge)};
 });
 const publicWitnesses=witnesses.map(({id,publicKey,readLatest})=>({id,publicKey,readLatest}));
 const pin=async(state)=>{pinned=structuredClone(state??await adapter().inspectRecoveryState());};
 const permit=(action,expectedAnchor,targetAnchor,pendingDigest,overrides={})=>{
  const now=Date.now();const body={schema:recoverySchema,registryId,anchorType:'registry',action,authorizationId:id(),issuedAt:now-1000,expiresAt:now+60000,expectedAnchor,targetAnchor,pendingDigest,reason:'Independent forensic approval after inspection',...overrides};
  return {...body,signature:sign(null,Buffer.from(`${recoverySchema}\0${JSON.stringify(Object.fromEntries(recoveryFields.map(k=>[k,body[k]])))}`),recoveryKeys.privateKey).toString('base64url')};
 };
 const guard=()=>createOfflineWitnessedRecoveryGuard({adapter:adapter(),ledger:ledger(),registryId,anchorType:'registry',witnesses:publicWitnesses,quorum:2});
 return {base,anchorDirectory,ledgerDirectory,adapter,ledger,witnesses,publicWitnesses,receipt,pin,permit,guard,pending:join(anchorDirectory,'.pending.json'),ledgerFile:n=>join(ledgerDirectory,`${String(n).padStart(10,'0')}.json`),anchorFile:n=>join(anchorDirectory,`${String(n).padStart(10,'0')}.json`)};
}
test('31E independently signed two-witness pin accepts matching committed snapshot',async t=>{
 const f=await fixture(t),x=f.adapter();await x.compareAndSet(null,a(1,'a'));await f.pin();
 const state=await f.guard().readVerified();assert.deepEqual(state.anchor,a(1,'a'));assert.equal(state.witnessVerified,true);assert.equal(state.productionApproved,false);
});
test('31E signed independent pin detects complete valid-prefix rollback of local anchor',async t=>{
 const f=await fixture(t),x=f.adapter();await x.compareAndSet(null,a(1,'a'));await x.compareAndSet(a(1,'a'),a(2,'b'));await f.pin();
 await unlink(f.anchorFile(2));assert.deepEqual(await x.read(),a(1,'a'));
 await rejects(f.guard().readVerified(),'WITNESS_RECEIPT_INVALID');
});
test('31E wrong signer cannot forge another witness receipt',async t=>{
 const f=await fixture(t),x=f.adapter();await x.compareAndSet(null,a(1,'a'));await f.pin();
 const s=await x.inspect();const r=f.witnesses.map(w=>f.receipt(w,s));
 r[0]={...r[0],signature:r[1].signature};
 await rejects(Promise.resolve().then(()=>verifyOfflineWitnessQuorum({registryId,anchorType:'registry',witnesses:f.publicWitnesses,quorum:2,challenge:fixedChallenge,receipts:r,snapshot:snap(s)})),'WITNESS_SIGNATURE_INVALID');
});
test('31E expired, future, and excessively long-lived signed witness receipts are denied',async t=>{
 const f=await fixture(t),s=await f.adapter().inspect();await f.pin();
 for(const delta of [{issuedAt:Date.now()-200000,expiresAt:Date.now()-100000},{issuedAt:Date.now()+5000,expiresAt:Date.now()+60000},{issuedAt:Date.now()-1000,expiresAt:Date.now()+3600000}]){
  const receipts=f.witnesses.map(w=>f.receipt(w,s,delta));
  await rejects(Promise.resolve().then(()=>verifyOfflineWitnessQuorum({registryId,anchorType:'registry',witnesses:f.publicWitnesses,quorum:2,challenge:fixedChallenge,receipts,snapshot:snap(s)})),'WITNESS_RECEIPT_INVALID');
 }
});
test('31E receipt substitutions for registry, type, event count and history digest fail closed',async t=>{
 const f=await fixture(t),s=await f.adapter().inspect();await f.pin();
 for(const delta of [{registryId:'other-registry-123'},{anchorType:'journal'},{eventCount:1},{historyDigest:'f'.repeat(64)}]){
  const receipts=f.witnesses.map(w=>f.receipt(w,s,delta));
  await rejects(Promise.resolve().then(()=>verifyOfflineWitnessQuorum({registryId,anchorType:'registry',witnesses:f.publicWitnesses,quorum:2,challenge:fixedChallenge,receipts,snapshot:snap(s)})),'WITNESS_RECEIPT_INVALID');
 }
});
test('31E duplicate witness identities cannot be counted twice for quorum',async t=>{
 const f=await fixture(t),s=await f.adapter().inspect();
 const r=f.receipt(f.witnesses[0],s);
 await rejects(Promise.resolve().then(()=>verifyOfflineWitnessQuorum({registryId,anchorType:'registry',witnesses:f.publicWitnesses,quorum:2,challenge:fixedChallenge,receipts:[r,r],snapshot:snap(s)})),'WITNESS_RECEIPT_INVALID');
});
test('31E nonmajority quorum and duplicate pinned keys are rejected at configuration',async t=>{
 const f=await fixture(t);
 assert.throws(()=>createOfflineWitnessedRecoveryGuard({adapter:f.adapter(),ledger:f.ledger(),registryId,anchorType:'registry',witnesses:f.publicWitnesses,quorum:1}),e=>e.code==='WITNESS_CONFIGURATION');
 assert.throws(()=>createOfflineWitnessedRecoveryGuard({adapter:f.adapter(),ledger:f.ledger(),registryId,anchorType:'registry',witnesses:[f.publicWitnesses[0],f.publicWitnesses[0]],quorum:2}),e=>e.code==='WITNESS_CONFIGURATION');
});
test('31E concurrent anchor advancement during witness read is rejected, not returned as fresh',async t=>{
 const f=await fixture(t),x=f.adapter();await x.compareAndSet(null,a(1,'a'));await f.pin();
 let changed=false;const witnesses=f.publicWitnesses.map(w=>({...w,readLatest:async({challenge})=>{
  if(!changed){changed=true;await x.compareAndSet(a(1,'a'),a(2,'b'));}return w.readLatest({challenge});
 }}));
 const g=createOfflineWitnessedRecoveryGuard({adapter:x,ledger:f.ledger(),registryId,anchorType:'registry',witnesses,quorum:2});
 await rejects(g.readVerified(),'WITNESS_CONCURRENT_ANCHOR_CHANGE');
});
test('31E durable reservation persists across reconstructed instances and refuses permit replay',async t=>{
 const f=await fixture(t),l=f.ledger();const d='a'.repeat(64),p='b'.repeat(64),auth=id();
 assert.equal((await l.reserve({authorizationId:auth,permitDigest:d,pendingDigest:p})).reserved,true);
 assert.equal((await f.ledger().inspect()).count,1);
 await rejects(f.ledger().reserve({authorizationId:auth,permitDigest:'c'.repeat(64),pendingDigest:p}),'RECOVERY_LEDGER_REPLAY');
 await rejects(f.ledger().reserve({authorizationId:id(),permitDigest:d,pendingDigest:p}),'RECOVERY_LEDGER_REPLAY');
});
test('31E concurrent in-process ledger reservations have one winner',async t=>{
 const f=await fixture(t),l=f.ledger(),payload={authorizationId:id(),permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64)};
 const results=await Promise.allSettled([l.reserve(payload),f.ledger().reserve(payload)]);
 assert.equal(results.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(results.filter(x=>x.status==='rejected'&&x.reason?.code==='RECOVERY_LEDGER_REPLAY').length,1);
 assert.equal((await l.inspect()).count,1);
});
test('31E independent processes cannot reserve the same authorization twice',async t=>{
 const f=await fixture(t),source=fileURLToPath(new URL('../src/offline-recovery-authorization-ledger.mjs',import.meta.url));
 const script=`import {createOfflineRecoveryAuthorizationLedger} from ${JSON.stringify(source)};try{await createOfflineRecoveryAuthorizationLedger({directory:process.argv[1],registryId:process.argv[2],anchorType:'registry'}).reserve({authorizationId:process.argv[3],permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64)});console.log('ok')}catch(e){console.log(e.code)}`;
 const auth=id();const run=()=>new Promise((ok,no)=>{
  const child=spawn(process.execPath,['--input-type=module','-e',script,f.ledgerDirectory,registryId,auth],{stdio:['ignore','pipe','pipe']});let out='',err='';child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>err+=b);child.once('error',no);child.once('close',c=>c===0?ok(out.trim()):no(Error(err)));
 });
 assert.deepEqual((await Promise.all([run(),run()])).sort(),['RECOVERY_LEDGER_REPLAY','ok']);
});
test('31E modified ledger history is rejected on reads and writes',async t=>{
 const f=await fixture(t),l=f.ledger();await l.reserve({authorizationId:id(),permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64)});
 const file=f.ledgerFile(1),raw=await readFile(file,'utf8');await writeFile(file,raw.replace('a'.repeat(64),'c'.repeat(64)));
 await rejects(l.inspect(),'RECOVERY_LEDGER_TAMPERED');
 await rejects(l.reserve({authorizationId:id(),permitDigest:'d'.repeat(64),pendingDigest:'e'.repeat(64)}),'RECOVERY_LEDGER_TAMPERED');
});
test('31E missing ledger event, unsafe mode and symlink are denied',async t=>{
 const f=await fixture(t),l=f.ledger();await l.reserve({authorizationId:id(),permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64)});
 const file=f.ledgerFile(1),raw=await readFile(file);await chmod(file,0o644);await rejects(l.inspect(),'RECOVERY_LEDGER_FILE_UNSAFE');
 await unlink(file);await symlink('/etc/hosts',file);await rejects(l.inspect(),'RECOVERY_LEDGER_FILE_UNSAFE');
 await unlink(file);await writeFile(f.ledgerFile(2),raw,{mode:0o600});await rejects(l.inspect(),'RECOVERY_LEDGER_HISTORY_GAP');
});
test('31E torn reservation is fail-closed after simulated process crash; never silently reused',async t=>{
 const f=await fixture(t,{ledgerFault:stage=>{if(stage==='after-pending-sync')throw Error('synthetic-crash');}}),l=f.ledger();
 await assert.rejects(l.reserve({authorizationId:id(),permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64)}),/synthetic-crash/);
 await rejects(f.ledger().inspect(),'RECOVERY_LEDGER_PENDING_REVIEW_REQUIRED');
 await rejects(f.ledger().reserve({authorizationId:id(),permitDigest:'c'.repeat(64),pendingDigest:'d'.repeat(64)}),'RECOVERY_LEDGER_PENDING_REVIEW_REQUIRED');
});
test('31E signed abort recovery reserves permit before action and burns it permanently',async t=>{
 const f=await fixture(t),x=f.adapter();await x.compareAndSet(null,a(1,'a'));
 await writeFile(f.pending,Buffer.alloc(0),{mode:0o600});await f.pin();
 const p=f.permit('abort-pending',a(1,'a'),null,hash(Buffer.alloc(0)));
 const result=await f.guard().recoverOnce({authorization:p});
 assert.equal(result.recovered,true);assert.equal(result.reservationIndex,1);
 assert.equal((await f.ledger().inspect()).count,1);
 await writeFile(f.pending,Buffer.alloc(0),{mode:0o600});
 await rejects(f.guard().recoverOnce({authorization:p}),'RECOVERY_LEDGER_REPLAY');
 assert.equal((await readFile(f.pending)).length,0);
});
test('31E forged recovery signature is rejected without consuming authorization',async t=>{
 const f=await fixture(t);await f.adapter().inspect();await writeFile(f.pending,Buffer.alloc(0),{mode:0o600});await f.pin();
 const p=f.permit('abort-pending',null,null,hash(Buffer.alloc(0)));
 await rejects(f.guard().recoverOnce({authorization:{...p,signature:'a'.repeat(86)}}),'DURABLE_ANCHOR_RECOVERY_DENIED');
 assert.equal((await f.ledger().inspect()).count,0);
});
test('31E stale witness denies recovery and leaves one-time authorization unused',async t=>{
 const f=await fixture(t),x=f.adapter();await x.compareAndSet(null,a(1,'a'));await f.pin();
 await x.compareAndSet(a(1,'a'),a(2,'b'));
 await writeFile(f.pending,Buffer.alloc(0),{mode:0o600});
 const p=f.permit('abort-pending',a(2,'b'),null,hash(Buffer.alloc(0)));
 await rejects(f.guard().recoverOnce({authorization:p}),'WITNESS_RECEIPT_INVALID');
 assert.equal((await f.ledger().inspect()).count,0);
});
test('31E signed commit recovery consumes authorization; witness must advance before trusted read',async t=>{
 const f=await fixture(t,{fault:stage=>{if(stage==='after-pending-sync')throw Error('synthetic-crash');}}),x=f.adapter();
 await f.pin();await assert.rejects(x.compareAndSet(null,a(1,'a')),/synthetic-crash/);
 const p=f.permit('commit-pending',null,a(1,'a'),hash(await readFile(f.pending)));
 const result=await f.guard().recoverOnce({authorization:p});assert.equal(result.action,'commit-pending');
 await rejects(f.guard().readVerified(),'WITNESS_RECEIPT_INVALID');
 await f.pin();assert.deepEqual((await f.guard().readVerified()).anchor,a(1,'a'));
});
test('31E invalid recovery pending bytes cannot be committed, but permit is conservatively burned',async t=>{
 const f=await fixture(t);await f.adapter().inspect();await writeFile(f.pending,'{bad',{mode:0o600});await f.pin();
 const p=f.permit('commit-pending',null,a(1,'a'),hash(Buffer.from('{bad')));
 await rejects(f.guard().recoverOnce({authorization:p}),'DURABLE_ANCHOR_RECOVERY_INVALID_PENDING');
 assert.equal((await f.ledger().inspect()).count,1);
 await rejects(f.guard().recoverOnce({authorization:p}),'RECOVERY_LEDGER_REPLAY');
});
test('31E stale pending substitution fails before ledger reservation',async t=>{
 const f=await fixture(t);await f.adapter().inspect();await writeFile(f.pending,'{bad',{mode:0o600});await f.pin();
 const p=f.permit('abort-pending',null,null,'f'.repeat(64));
 await rejects(f.guard().recoverOnce({authorization:p}),'WITNESS_RECOVERY_STATE_MISMATCH');
 assert.equal((await f.ledger().inspect()).count,0);
});
test('31E previously signed receipt cannot satisfy a fresh witness challenge',async t=>{
 const f=await fixture(t),s=await f.adapter().inspect();
 const receipts=f.witnesses.map(w=>f.receipt(w,s));
 await rejects(Promise.resolve().then(()=>verifyOfflineWitnessQuorum({registryId,anchorType:'registry',witnesses:f.publicWitnesses,quorum:2,receipts,challenge:randomBytes(32).toString('base64url'),snapshot:snap(s)})),'WITNESS_RECEIPT_INVALID');
});
test('31E duplicate signing keys with distinct witness identities cannot form quorum',async t=>{
 const f=await fixture(t);const [first,second]=f.publicWitnesses;
 assert.throws(()=>createOfflineWitnessedRecoveryGuard({adapter:f.adapter(),ledger:f.ledger(),registryId,anchorType:'registry',witnesses:[first,{...second,publicKey:first.publicKey}],quorum:2}),e=>e.code==='WITNESS_CONFIGURATION');
});
test('31E missing or unreachable witness fails closed, never trusts single available signer',async t=>{
 const f=await fixture(t);await f.pin();
 const [a,b]=f.publicWitnesses;
 const guard=createOfflineWitnessedRecoveryGuard({adapter:f.adapter(),ledger:f.ledger(),registryId,anchorType:'registry',witnesses:[a,{...b,readLatest:async()=>{throw Error('offline witness unreachable');}}],quorum:2});
 await assert.rejects(guard.readVerified(),/offline witness unreachable/);
});
test('31E witness response must include only exact canonical fields',async t=>{
 const f=await fixture(t),s=await f.adapter().inspect();
 const receipts=f.witnesses.map(w=>f.receipt(w,s));receipts[0].extra='unapproved';
 await rejects(Promise.resolve().then(()=>verifyOfflineWitnessQuorum({registryId,anchorType:'registry',witnesses:f.publicWitnesses,quorum:2,receipts,challenge:fixedChallenge,snapshot:snap(s)})),'WITNESS_RECEIPT_INVALID');
});
test('31E ledger committed valid prefix rollback requires an external retained pin',async t=>{
 const f=await fixture(t),l=f.ledger();
 await l.reserve({authorizationId:id(),permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64)});
 const pinned=await l.inspect();
 await l.reserve({authorizationId:id(),permitDigest:'c'.repeat(64),pendingDigest:'d'.repeat(64)});
 const latest=await l.inspect();await unlink(f.ledgerFile(2));
 await rejects(l.inspectPinned({count:latest.count,headDigest:latest.headDigest}),'RECOVERY_LEDGER_STALE_PIN');
 const rolled=await l.inspect();
 // Demonstrates the explicit remaining limitation: without an independently
 // retained higher head, an attacker controlling all local files can roll back.
 assert.equal(rolled.count,pinned.count);assert.equal(rolled.headDigest,pinned.headDigest);
});
test('31E real child-process crash during reservation leaves durable pending fail-closed',async t=>{
 const f=await fixture(t),source=fileURLToPath(new URL('../src/offline-recovery-authorization-ledger.mjs',import.meta.url));
 const script=`import {createOfflineRecoveryAuthorizationLedger} from ${JSON.stringify(source)};await createOfflineRecoveryAuthorizationLedger({directory:process.argv[1],registryId:process.argv[2],anchorType:'registry',injectFault:stage=>{if(stage==='after-pending-sync')process.exit(92)}}).reserve({authorizationId:process.argv[3],permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64)});`;
 const result=await new Promise((ok,no)=>{
  const child=spawn(process.execPath,['--input-type=module','-e',script,f.ledgerDirectory,registryId,id()],{stdio:['ignore','pipe','pipe']});let err='';child.stderr.on('data',b=>err+=b);child.once('error',no);child.once('close',c=>c===92?ok(c):no(Error(`exit ${c}: ${err}`)));
 });
 assert.equal(result,92);
 await rejects(f.ledger().inspect(),'RECOVERY_LEDGER_PENDING_REVIEW_REQUIRED');
});
test('31E crash after durable reservation commit burns permit despite uncertain caller result',async t=>{
 const f=await fixture(t,{ledgerFault:stage=>{if(stage==='after-commit-sync')throw Error('post-commit-uncertain');}}),auth=id();
 const payload={authorizationId:auth,permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64)};
 await assert.rejects(f.ledger().reserve(payload),/post-commit-uncertain/);
 assert.equal((await f.ledger().inspect()).count,1);
 await rejects(f.ledger().reserve(payload),'RECOVERY_LEDGER_REPLAY');
});
