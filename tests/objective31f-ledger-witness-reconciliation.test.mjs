import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,unlink,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createOfflineDurableAnchorAdapter} from '../src/offline-durable-anchor-adapter.mjs';
import {createOfflineRecoveryAuthorizationLedger} from '../src/offline-recovery-authorization-ledger.mjs';
import {OFFLINE_WITNESS_SCHEMA} from '../src/offline-recovery-witness.mjs';
import {OFFLINE_RECOVERY_LEDGER_WITNESS_SCHEMA,verifyOfflineRecoveryLedgerWitnessQuorum,createOfflineRecoveryReconciliationGuard} from '../src/offline-recovery-reconciliation.mjs';

const registryId='objective31f-test-registry';
const ROOT='0'.repeat(64);
const permitSchema='TJ-OFFLINE-DURABLE-ANCHOR-RECOVERY-1';
const anchorFields=['schema','witnessId','registryId','anchorType','eventCount','historyDigest','anchor','challenge','issuedAt','expiresAt'];
const ledgerFields=['schema','witnessId','registryId','anchorType','count','headDigest','challenge','issuedAt','expiresAt'];
const permitFields=['schema','registryId','anchorType','action','authorizationId','issuedAt','expiresAt','expectedAnchor','targetAnchor','pendingDigest','reason'];
const hash=x=>createHash('sha256').update(x).digest('hex');
const a=(n,c)=>({sequence:n,mac:c.repeat(64)});
const id=()=>`permit-${randomBytes(12).toString('hex')}`;
const fail=(p,code)=>assert.rejects(Promise.resolve().then(()=>typeof p==='function'?p():p),e=>e?.code===code);
const signBody=(schema,fields,body,key)=>sign(null,Buffer.from(`${schema}\0${JSON.stringify(Object.fromEntries(fields.map(k=>[k,body[k]])))}`),key).toString('base64url');
const c32=()=>randomBytes(32).toString('base64url');
const file=n=>`${String(n).padStart(10,'0')}.json`;

async function fixture(t,{anchorFault,ledgerFault}={}){
 const base=await mkdtemp(join(tmpdir(),'tj-31f-'));t.after(()=>rm(base,{recursive:true,force:true}));
 const anchorDirectory=join(base,'anchor'),ledgerDirectory=join(base,'ledger');
 const recoveryKeys=generateKeyPairSync('ed25519');
 const adapter=()=>createOfflineDurableAnchorAdapter({directory:anchorDirectory,registryId,anchorType:'registry',recovery:{publicKey:recoveryKeys.publicKey},injectFault:anchorFault});
 const ledger=()=>createOfflineRecoveryAuthorizationLedger({directory:ledgerDirectory,registryId,anchorType:'registry',injectFault:ledgerFault});
 const keysA=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')],keysL=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
 let pinA=null,pinL=null;
 const receipt=(domain,w,state,challenge,overrides={})=>{
  const schema=domain==='anchor'?OFFLINE_WITNESS_SCHEMA:OFFLINE_RECOVERY_LEDGER_WITNESS_SCHEMA;
  const fields=domain==='anchor'?anchorFields:ledgerFields;
  const now=Date.now();const payload=domain==='anchor'?{eventCount:state.eventCount,historyDigest:state.historyDigest,anchor:state.anchor}:{count:state.count,headDigest:state.headDigest};
  const body={schema,witnessId:w.id,registryId,anchorType:'registry',...payload,challenge,issuedAt:now-1000,expiresAt:now+60000,...overrides};
  return {...body,signature:signBody(schema,fields,body,w.privateKey)};
 };
 const witnesses=(domain,keys)=>keys.map((k,i)=>{
  const w={id:`${domain}-independent-witness-${i+1}`,publicKey:k.publicKey,privateKey:k.privateKey};
  return {...w,readLatest:async({challenge})=>receipt(domain,w,domain==='anchor'?pinA:pinL,challenge)};
 });
 const aw=witnesses('anchor',keysA),lw=witnesses('ledger',keysL);
 const pub=xs=>xs.map(({id,publicKey,readLatest})=>({id,publicKey,readLatest}));
 const anchorWitnesses=pub(aw),ledgerWitnesses=pub(lw);
 const pin=async()=>{pinA=await adapter().inspectRecoveryState();pinL=await ledger().inspect();};
 const permit=(action,expectedAnchor,targetAnchor,pendingDigest,overrides={})=>{
  const now=Date.now();const body={schema:permitSchema,registryId,anchorType:'registry',action,authorizationId:id(),issuedAt:now-1000,expiresAt:now+60000,expectedAnchor,targetAnchor,pendingDigest,reason:'Reviewed independent forensic evidence',...overrides};
  return {...body,signature:signBody(permitSchema,permitFields,body,recoveryKeys.privateKey)};
 };
 const guard=(overrides={})=>createOfflineRecoveryReconciliationGuard({adapter:adapter(),ledger:ledger(),registryId,anchorType:'registry',anchorWitnesses,anchorQuorum:2,ledgerWitnesses,ledgerQuorum:2,...overrides});
 const prepare=async()=>{await adapter().inspect();await writeFile(join(anchorDirectory,'.pending.json'),Buffer.alloc(0),{mode:0o600});await pin();return permit('abort-pending',null,null,hash(Buffer.alloc(0)));};
 return {base,anchorDirectory,ledgerDirectory,adapter,ledger,pin,prepare,permit,guard,aw,lw,anchorWitnesses,ledgerWitnesses,receipt,pub,pinA:()=>pinA,pinL:()=>pinL,ledgerFile:n=>join(ledgerDirectory,file(n)),pending:join(anchorDirectory,'.pending.json')};
}

test('31F pristine two-resource heads require independent quorum and return clean disposition',async t=>{
 const f=await fixture(t);await f.pin();const s=await f.guard().inspectReconciliation();
 assert.equal(s.disposition,'NO_PENDING_RESERVATIONS');assert.equal(s.ledger.count,0);assert.equal(s.ledger.headDigest,ROOT);assert.equal(s.independentlyWitnessed,true);assert.equal(s.automaticRepairAllowed,false);assert.equal(s.productionApproved,false);
});
test('31F prepared anchor is reported for forensic review, never auto-repaired',async t=>{
 const f=await fixture(t);await f.prepare();const s=await f.guard().inspectReconciliation();
 assert.equal(s.disposition,'PENDING_ANCHOR_REVIEW_REQUIRED');assert.equal(s.anchor.pending,true);
 assert.equal((await readFile(f.pending)).length,0);
});
test('31F committed reservation remains outcome-ambiguous even after anchor is clean',async t=>{
 const f=await fixture(t);await f.ledger().reserve({authorizationId:id(),permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64)});await f.pin();
 const s=await f.guard().inspectReconciliation();assert.equal(s.disposition,'RESERVATION_OUTCOME_REVIEW_REQUIRED');
});
test('31F independently witnessed ledger head rejects valid-prefix rollback',async t=>{
 const f=await fixture(t),l=f.ledger();await l.reserve({authorizationId:id(),permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64)});
 await l.reserve({authorizationId:id(),permitDigest:'c'.repeat(64),pendingDigest:'d'.repeat(64)});await f.pin();await unlink(f.ledgerFile(2));
 await fail(f.guard().inspectReconciliation(),'LEDGER_WITNESS_RECEIPT_INVALID');
});
test('31F signed witness detects whole-ledger replacement with empty valid prefix',async t=>{
 const f=await fixture(t),l=f.ledger();await l.reserve({authorizationId:id(),permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64)});await f.pin();await unlink(f.ledgerFile(1));
 await fail(f.guard().inspectReconciliation(),'LEDGER_WITNESS_RECEIPT_INVALID');
});
test('31F local event tamper is rejected before witness check',async t=>{
 const f=await fixture(t);await f.ledger().reserve({authorizationId:id(),permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64)});await f.pin();
 const p=f.ledgerFile(1);await writeFile(p,(await readFile(p,'utf8')).replace('a'.repeat(64),'c'.repeat(64)));
 await fail(f.guard().inspectReconciliation(),'RECOVERY_LEDGER_TAMPERED');
});
test('31F ledger pending file fails closed and is not repaired',async t=>{
 const f=await fixture(t,{ledgerFault:stage=>{if(stage==='after-pending-sync')throw Error('crash');}});
 await assert.rejects(f.ledger().reserve({authorizationId:id(),permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64)}),/crash/);
 await fail(f.guard().inspectReconciliation(),'RECOVERY_LEDGER_PENDING_REVIEW_REQUIRED');
});
test('31F ledger witness forged signature is rejected',async t=>{
 const f=await fixture(t);await f.pin();const challenge=c32(),s=f.pinL();
 const r=f.lw.map(w=>f.receipt('ledger',w,s,challenge));r[0]={...r[0],signature:r[1].signature};
 await fail(()=>verifyOfflineRecoveryLedgerWitnessQuorum({registryId,anchorType:'registry',witnesses:f.ledgerWitnesses,quorum:2,receipts:r,snapshot:{count:s.count,headDigest:s.headDigest},challenge}),'LEDGER_WITNESS_SIGNATURE_INVALID');
});
test('31F witness duplicate identity is not counted toward quorum',async t=>{
 const f=await fixture(t);await f.pin();const challenge=c32(),s=f.pinL(),r=f.receipt('ledger',f.lw[0],s,challenge);
 await fail(()=>verifyOfflineRecoveryLedgerWitnessQuorum({registryId,anchorType:'registry',witnesses:f.ledgerWitnesses,quorum:2,receipts:[r,r],snapshot:{count:s.count,headDigest:s.headDigest},challenge}),'LEDGER_WITNESS_RECEIPT_INVALID');
});
test('31F duplicate ledger signing keys are rejected at configuration',async t=>{
 const f=await fixture(t),[w1,w2]=f.ledgerWitnesses;
 assert.throws(()=>f.guard({ledgerWitnesses:[w1,{...w2,publicKey:w1.publicKey}]}),e=>e.code==='LEDGER_WITNESS_CONFIGURATION');
});
test('31F anchor and ledger witnesses cannot share the same signing key',async t=>{
 const f=await fixture(t);const [w1,w2]=f.ledgerWitnesses;
 assert.throws(()=>f.guard({ledgerWitnesses:[{...w1,publicKey:f.anchorWitnesses[0].publicKey},w2]}),e=>e.code==='RECOVERY_RECONCILIATION_SHARED_WITNESS_KEY');
});
test('31F nonmajority quorum is rejected',async t=>{
 const f=await fixture(t);assert.throws(()=>f.guard({ledgerQuorum:1}),e=>e.code==='LEDGER_WITNESS_CONFIGURATION');
 assert.throws(()=>f.guard({anchorQuorum:1}),e=>e.code==='RECOVERY_RECONCILIATION_CONFIGURATION');
});
test('31F expired, future and long-lived ledger witness receipts fail closed',async t=>{
 const f=await fixture(t);await f.pin();const s=f.pinL(),challenge=c32();
 for(const o of [{issuedAt:Date.now()-200000,expiresAt:Date.now()-100000},{issuedAt:Date.now()+5000,expiresAt:Date.now()+60000},{issuedAt:Date.now()-1000,expiresAt:Date.now()+500000}]){
  const r=f.lw.map(w=>f.receipt('ledger',w,s,challenge,o));await fail(()=>verifyOfflineRecoveryLedgerWitnessQuorum({registryId,anchorType:'registry',witnesses:f.ledgerWitnesses,quorum:2,receipts:r,snapshot:{count:s.count,headDigest:s.headDigest},challenge}),'LEDGER_WITNESS_RECEIPT_INVALID');
 }
});
test('31F substituted registry, type, count, digest and challenge are rejected',async t=>{
 const f=await fixture(t);await f.pin();const s=f.pinL(),challenge=c32();
 for(const o of [{registryId:'different-registry-xyz'},{anchorType:'journal'},{count:1},{headDigest:'f'.repeat(64)},{challenge:c32()}]){
  const r=f.lw.map(w=>f.receipt('ledger',w,s,challenge,o));await fail(()=>verifyOfflineRecoveryLedgerWitnessQuorum({registryId,anchorType:'registry',witnesses:f.ledgerWitnesses,quorum:2,receipts:r,snapshot:{count:s.count,headDigest:s.headDigest},challenge}),'LEDGER_WITNESS_RECEIPT_INVALID');
 }
});
test('31F noncanonical receipt fields and base64 signature are rejected',async t=>{
 const f=await fixture(t);await f.pin();const s=f.pinL(),challenge=c32();const r=f.lw.map(w=>f.receipt('ledger',w,s,challenge));
 r[0].extra='unexpected';await fail(()=>verifyOfflineRecoveryLedgerWitnessQuorum({registryId,anchorType:'registry',witnesses:f.ledgerWitnesses,quorum:2,receipts:r,snapshot:{count:s.count,headDigest:s.headDigest},challenge}),'LEDGER_WITNESS_RECEIPT_INVALID');
 r[0]=f.receipt('ledger',f.lw[0],s,challenge);r[0].signature='a'.repeat(86);await fail(()=>verifyOfflineRecoveryLedgerWitnessQuorum({registryId,anchorType:'registry',witnesses:f.ledgerWitnesses,quorum:2,receipts:r,snapshot:{count:s.count,headDigest:s.headDigest},challenge}),'LEDGER_WITNESS_SIGNATURE_INVALID');
});
test('31F witness receipts cannot be replayed for a new challenge',async t=>{
 const f=await fixture(t);await f.pin();const s=f.pinL(),challenge=c32(),r=f.lw.map(w=>f.receipt('ledger',w,s,challenge));
 await fail(()=>verifyOfflineRecoveryLedgerWitnessQuorum({registryId,anchorType:'registry',witnesses:f.ledgerWitnesses,quorum:2,receipts:r,snapshot:{count:s.count,headDigest:s.headDigest},challenge:c32()}),'LEDGER_WITNESS_RECEIPT_INVALID');
});
test('31F concurrent ledger advance during witness round trip fails closed',async t=>{
 const f=await fixture(t);await f.pin();let once=false;
 const ws=f.ledgerWitnesses.map(w=>({...w,readLatest:async x=>{const receipt=await w.readLatest(x);if(!once){once=true;await f.ledger().reserve({authorizationId:id(),permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64)});}return receipt;}}));
 await fail(f.guard({ledgerWitnesses:ws}).inspectReconciliation(),'RECOVERY_RECONCILIATION_CONCURRENT_CHANGE');
});
test('31F concurrent anchor advance during witness round trip fails closed',async t=>{
 const f=await fixture(t);await f.pin();let once=false;
 const ws=f.anchorWitnesses.map(w=>({...w,readLatest:async x=>{const receipt=await w.readLatest(x);if(!once){once=true;await f.adapter().compareAndSet(null,a(1,'a'));}return receipt;}}));
 await fail(f.guard({anchorWitnesses:ws}).inspectReconciliation(),'RECOVERY_RECONCILIATION_CONCURRENT_CHANGE');
});
test('31F ledger compare-and-reserve rejects a stale witnessed head',async t=>{
 const f=await fixture(t),l=f.ledger();const pin=await l.inspect();await l.reserve({authorizationId:id(),permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64)});
 await fail(l.reserve({authorizationId:id(),permitDigest:'c'.repeat(64),pendingDigest:'d'.repeat(64),expectedHead:{count:pin.count,headDigest:pin.headDigest}}),'RECOVERY_LEDGER_STALE_PIN');
 assert.equal((await l.inspect()).count,1);
});
test('31F stale compare-and-reserve denies cross-resource race without mutating anchor',async t=>{
 const f=await fixture(t);const p=await f.prepare(),real=f.ledger();
 const raced={inspect:()=>real.inspect(),reserve:async args=>{await real.reserve({authorizationId:id(),permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64)});return real.reserve(args);}};
 await fail(f.guard({ledger:raced}).recoverOnce({authorization:p}),'RECOVERY_LEDGER_STALE_PIN');
 assert.equal((await f.adapter().inspectRecoveryState()).pending,true);assert.equal((await real.inspect()).count,1);
});
test('31F successful signed abort burns permit and requires new independent witness',async t=>{
 const f=await fixture(t),p=await f.prepare();const result=await f.guard().recoverOnce({authorization:p});
 assert.equal(result.recovered,true);assert.equal(result.reservationIndex,1);assert.equal(result.disposition,'POST_RECOVERY_INDEPENDENT_REWITNESS_REQUIRED');
 await fail(f.guard().inspectReconciliation(),'LEDGER_WITNESS_RECEIPT_INVALID');
 await f.pin();const s=await f.guard().inspectReconciliation();assert.equal(s.disposition,'RESERVATION_OUTCOME_REVIEW_REQUIRED');
 await writeFile(f.pending,Buffer.alloc(0),{mode:0o600});await f.pin();
 await fail(f.guard().recoverOnce({authorization:p}),'RECOVERY_RECONCILIATION_REVIEW_REQUIRED');
});
test('31F invalid recovery signature does not burn permit',async t=>{
 const f=await fixture(t),p=await f.prepare();await fail(f.guard().recoverOnce({authorization:{...p,signature:'a'.repeat(86)}}),'DURABLE_ANCHOR_RECOVERY_DENIED');
 assert.equal((await f.ledger().inspect()).count,0);
});
test('31F mismatched pending digest does not burn permit',async t=>{
 const f=await fixture(t),p=await f.prepare();const q=f.permit('abort-pending',null,null,'f'.repeat(64));
 await fail(f.guard().recoverOnce({authorization:q}),'RECOVERY_RECONCILIATION_STATE_MISMATCH');assert.equal((await f.ledger().inspect()).count,0);
});
test('31F clean anchor rejects recovery without consuming a permit',async t=>{
 const f=await fixture(t);await f.pin();const p=f.permit('abort-pending',null,null,'a'.repeat(64));
 await fail(f.guard().recoverOnce({authorization:p}),'RECOVERY_RECONCILIATION_STATE_MISMATCH');assert.equal((await f.ledger().inspect()).count,0);
});
test('31F stale anchor witness blocks recovery before reservation',async t=>{
 const f=await fixture(t);await f.adapter().inspect();await f.pin();await f.adapter().compareAndSet(null,a(1,'a'));await writeFile(f.pending,Buffer.alloc(0),{mode:0o600});
 const p=f.permit('abort-pending',a(1,'a'),null,hash(Buffer.alloc(0)));
 await fail(f.guard().recoverOnce({authorization:p}),'WITNESS_RECEIPT_INVALID');assert.equal((await f.ledger().inspect()).count,0);
});
test('31F unavailable independent ledger witness fails closed',async t=>{
 const f=await fixture(t);await f.pin();const ws=f.ledgerWitnesses.map((w,i)=>i===0?{...w,readLatest:async()=>{throw Error('witness offline');}}:w);
 await assert.rejects(f.guard({ledgerWitnesses:ws}).inspectReconciliation(),/witness offline/);
});
test('31F crash after ledger commit leaves pending anchor and burned permit, no automatic retry',async t=>{
 const f=await fixture(t,{ledgerFault:stage=>{if(stage==='after-commit-sync')throw Error('crash-after-ledger');}}),p=await f.prepare();
 await assert.rejects(f.guard().recoverOnce({authorization:p}),/crash-after-ledger/);
 assert.equal((await f.ledger().inspect()).count,1);assert.equal((await f.adapter().inspectRecoveryState()).pending,true);
 await fail(f.guard().inspectReconciliation(),'LEDGER_WITNESS_RECEIPT_INVALID');
 await f.pin();assert.equal((await f.guard().inspectReconciliation()).disposition,'PENDING_ANCHOR_REVIEW_REQUIRED');
 await fail(f.guard().recoverOnce({authorization:p}),'RECOVERY_RECONCILIATION_REVIEW_REQUIRED');
});
test('31F actual child crash between durable reservation and anchor recovery leaves two-resource review state',async t=>{
 const f=await fixture(t),p=await f.prepare();const source=fileURLToPath(new URL('../src/offline-recovery-authorization-ledger.mjs',import.meta.url));
 const script=`import {createOfflineRecoveryAuthorizationLedger} from ${JSON.stringify(source)};const l=createOfflineRecoveryAuthorizationLedger({directory:process.argv[1],registryId:process.argv[2],anchorType:'registry'});const s=await l.inspect();await l.reserve({authorizationId:process.argv[3],permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64),expectedHead:{count:s.count,headDigest:s.headDigest}});process.exit(93)`;
 const exit=await new Promise((ok,no)=>{const c=spawn(process.execPath,['--input-type=module','-e',script,f.ledgerDirectory,registryId,p.authorizationId],{stdio:['ignore','ignore','pipe']});let err='';c.stderr.on('data',b=>err+=b);c.once('error',no);c.once('close',code=>code===93?ok(code):no(Error(`exit ${code} ${err}`)));});
 assert.equal(exit,93);assert.equal((await f.ledger().inspect()).count,1);assert.equal((await f.adapter().inspectRecoveryState()).pending,true);
 await fail(f.guard().inspectReconciliation(),'LEDGER_WITNESS_RECEIPT_INVALID');await f.pin();
 assert.equal((await f.guard().inspectReconciliation()).disposition,'PENDING_ANCHOR_REVIEW_REQUIRED');
});
test('31F cross-process compare-and-reserve serializes two distinct permits at one witnessed head',async t=>{
 const f=await fixture(t),source=fileURLToPath(new URL('../src/offline-recovery-authorization-ledger.mjs',import.meta.url));const s=await f.ledger().inspect();
 const script=`import {createOfflineRecoveryAuthorizationLedger} from ${JSON.stringify(source)};try{await createOfflineRecoveryAuthorizationLedger({directory:process.argv[1],registryId:process.argv[2],anchorType:'registry'}).reserve({authorizationId:process.argv[3],permitDigest:process.argv[4],pendingDigest:'b'.repeat(64),expectedHead:{count:0,headDigest:'0'.repeat(64)}});console.log('ok')}catch(e){console.log(e.code)}`;
 const run=(permitDigest)=>new Promise((ok,no)=>{const c=spawn(process.execPath,['--input-type=module','-e',script,f.ledgerDirectory,registryId,id(),permitDigest],{stdio:['ignore','pipe','pipe']});let out='',err='';c.stdout.on('data',b=>out+=b);c.stderr.on('data',b=>err+=b);c.once('error',no);c.once('close',code=>code===0?ok(out.trim()):no(Error(err)));});
 assert.equal(s.count,0);assert.deepEqual((await Promise.all([run('a'.repeat(64)),run('c'.repeat(64))])).sort(),['RECOVERY_LEDGER_STALE_PIN','ok']);assert.equal((await f.ledger().inspect()).count,1);
});
test('31F expectedHead input is strictly canonical, and old reserve API stays compatible',async t=>{
 const f=await fixture(t),l=f.ledger();
 await fail(l.reserve({authorizationId:id(),permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64),expectedHead:{count:0,headDigest:ROOT,extra:true}}),'RECOVERY_LEDGER_RESERVATION_INVALID');
 const r=await l.reserve({authorizationId:id(),permitDigest:'c'.repeat(64),pendingDigest:'d'.repeat(64)});assert.equal(r.index,1);
});

test('31F even a fresh valid permit cannot bypass unresolved earlier reservation after re-witness',async t=>{
 const f=await fixture(t),p=await f.prepare();await f.guard().recoverOnce({authorization:p});
 await writeFile(f.pending,Buffer.alloc(0),{mode:0o600});await f.pin();
 const fresh=f.permit('abort-pending',null,null,hash(Buffer.alloc(0)));
 await fail(f.guard().recoverOnce({authorization:fresh}),'RECOVERY_RECONCILIATION_REVIEW_REQUIRED');
 assert.equal((await f.ledger().inspect()).count,1);assert.equal((await f.adapter().inspectRecoveryState()).pending,true);
});

test('31F impossible nonempty ledger with genesis digest is rejected before signatures',async t=>{
 const f=await fixture(t);await f.pin();const challenge=c32(),snapshot={count:1,headDigest:ROOT};
 const r=f.lw.map(w=>f.receipt('ledger',w,snapshot,challenge));
 await fail(()=>verifyOfflineRecoveryLedgerWitnessQuorum({registryId,anchorType:'registry',witnesses:f.ledgerWitnesses,quorum:2,receipts:r,snapshot,challenge}),'LEDGER_WITNESS_SNAPSHOT_INVALID');
});
test('31F unknown ledger witness identity cannot satisfy quorum',async t=>{
 const f=await fixture(t);await f.pin();const challenge=c32(),s=f.pinL();const r=f.lw.map(w=>f.receipt('ledger',w,s,challenge));
 r[0]=f.receipt('ledger',f.lw[0],s,challenge,{witnessId:'unrecognized-witness-123'});
 await fail(()=>verifyOfflineRecoveryLedgerWitnessQuorum({registryId,anchorType:'registry',witnesses:f.ledgerWitnesses,quorum:2,receipts:r,snapshot:{count:s.count,headDigest:s.headDigest},challenge}),'LEDGER_WITNESS_RECEIPT_INVALID');
});
