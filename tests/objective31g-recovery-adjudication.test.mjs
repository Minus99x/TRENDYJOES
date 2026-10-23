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

const registryId='objective31g-test-registry';
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
 const base=await mkdtemp(join(tmpdir(),'tj-31g-'));t.after(()=>rm(base,{recursive:true,force:true}));
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

import {OFFLINE_RECOVERY_ADJUDICATION_SCHEMA,verifyOfflineRecoveryAdjudicationQuorum} from '../src/offline-recovery-adjudication.mjs';
const reviewFields=['schema','reviewerId','registryId','anchorType','ledgerCount','ledgerHeadDigest','historyDigest','anchorStateDigest','caseDigest','outcomesDigest','authorizationDigest','challenge','issuedAt','expiresAt'];
const evidence=()=>hash(Buffer.from('independent forensic case review - synthetic evidence'));
const signReview=(key,id,{challenge,history,anchor,caseDigest,outcomes,authorizationDigest},overrides={})=>{
 const now=Date.now();const body={schema:OFFLINE_RECOVERY_ADJUDICATION_SCHEMA,reviewerId:id,registryId,anchorType:'registry',ledgerCount:history.count,ledgerHeadDigest:history.headDigest,historyDigest:hash(Buffer.from(JSON.stringify(history.events))),anchorStateDigest:hash(Buffer.from(JSON.stringify(anchor))),caseDigest,outcomesDigest:hash(Buffer.from(JSON.stringify(outcomes))),authorizationDigest,challenge,issuedAt:now-1000,expiresAt:now+60000,...overrides};
 return {...body,signature:signBody(OFFLINE_RECOVERY_ADJUDICATION_SCHEMA,reviewFields,body,key)};
};
const reviewers=(options={})=>{
 const keys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
 return keys.map((key,i)=>({id:`forensic-independent-reviewer-${i+1}`,publicKey:key.publicKey,readLatest:async args=>{
  if(options.before)await options.before(args,i);
  const r=signReview(key.privateKey,`forensic-independent-reviewer-${i+1}`,args,options.override?.(args,i)??{});
  return options.after?.(r,args,i)??r;
 }}));
};
const outcomes=(history,{result='RESOLVED_NOT_APPLIED',overrides={}}={})=>history.events.map(e=>({index:e.index,authorizationId:e.authorizationId,permitDigest:e.permitDigest,pendingDigest:e.pendingDigest,result,evidenceDigest:evidence(),...overrides}));
async function prepared(t,{oldPendingDigest='b'.repeat(64),ledgerFault}={}){
 const f=await fixture(t,{ledgerFault});
 await f.ledger().reserve({authorizationId:id(),permitDigest:'a'.repeat(64),pendingDigest:oldPendingDigest});
 const p=await f.prepare();const history=await f.ledger().inspectHistory();
 const forensicReview={caseDigest:evidence(),outcomes:outcomes(history)};
 const rs=reviewers();const g=(override={})=>f.guard({reviewers:rs,reviewQuorum:2,...override});
 return {f,p,history,forensicReview,rs,g};
}

test('31G verified independent forensic quorum reopens only with NEW permit, burns it, and requires fresh re-witness',async t=>{
 const {f,p,g,forensicReview}=await prepared(t);
 const result=await g().recoverOnce({authorization:p,forensicReview});
 assert.equal(result.recovered,true);assert.equal(result.reservationIndex,2);assert.equal(result.forensicReviewVerified,true);
 assert.match(result.adjudicationDigest,/^[a-f0-9]{64}$/);
 assert.equal((await f.ledger().inspect()).count,2);
 await fail(g().inspectReconciliation(),'LEDGER_WITNESS_RECEIPT_INVALID');
 await f.pin();assert.equal((await g().inspectReconciliation()).disposition,'RESERVATION_OUTCOME_REVIEW_REQUIRED');
});
test('31G previous guard without opt-in reviewers stays fail closed',async t=>{
 const {f,p,forensicReview}=await prepared(t);
 await fail(f.guard().recoverOnce({authorization:p,forensicReview}),'RECOVERY_RECONCILIATION_REVIEW_REQUIRED');
 assert.equal((await f.ledger().inspect()).count,1);
});
test('31G missing review fails without burning a new permit',async t=>{
 const {f,p,g}=await prepared(t);await fail(g().recoverOnce({authorization:p}),'RECOVERY_RECONCILIATION_REVIEW_REQUIRED');assert.equal((await f.ledger().inspect()).count,1);
});
test('31G malformed review request fails before new reservation',async t=>{
 const {f,p,g,forensicReview}=await prepared(t);
 await fail(g().recoverOnce({authorization:p,forensicReview:{...forensicReview,extra:true}}),'RECOVERY_RECONCILIATION_REVIEW_REQUIRED');
 assert.equal((await f.ledger().inspect()).count,1);
});
test('31G forged signature fails closed',async t=>{
 const {f,p,g}=await prepared(t);const rs=reviewers({after:(r,args,i)=>i===0?{...r,signature:'a'.repeat(86)}:r});
 await fail(g({reviewers:rs}).recoverOnce({authorization:p,forensicReview:{caseDigest:evidence(),outcomes:outcomes(await f.ledger().inspectHistory())}}),'RECOVERY_ADJUDICATION_SIGNATURE_INVALID');
 assert.equal((await f.ledger().inspect()).count,1);
});
test('31G wrong history digest in signed receipt rejected',async t=>{
 const {f,p,g,forensicReview}=await prepared(t);const rs=reviewers({override:()=>({historyDigest:'f'.repeat(64)})});
 await fail(g({reviewers:rs}).recoverOnce({authorization:p,forensicReview}),'RECOVERY_ADJUDICATION_RECEIPT_INVALID');assert.equal((await f.ledger().inspect()).count,1);
});
test('31G wrong anchor snapshot digest in signed receipt rejected',async t=>{
 const {f,p,g,forensicReview}=await prepared(t);const rs=reviewers({override:()=>({anchorStateDigest:'f'.repeat(64)})});
 await fail(g({reviewers:rs}).recoverOnce({authorization:p,forensicReview}),'RECOVERY_ADJUDICATION_RECEIPT_INVALID');assert.equal((await f.ledger().inspect()).count,1);
});
test('31G wrong forensic case digest rejected',async t=>{
 const {f,p,g,forensicReview}=await prepared(t);const rs=reviewers({override:()=>({caseDigest:'f'.repeat(64)})});
 await fail(g({reviewers:rs}).recoverOnce({authorization:p,forensicReview}),'RECOVERY_ADJUDICATION_RECEIPT_INVALID');
});
test('31G stale challenge is rejected',async t=>{
 const {p,g,forensicReview}=await prepared(t);const rs=reviewers({override:()=>({challenge:c32()})});
 await fail(g({reviewers:rs}).recoverOnce({authorization:p,forensicReview}),'RECOVERY_ADJUDICATION_RECEIPT_INVALID');
});
test('31G expired receipt rejected',async t=>{
 const {p,g,forensicReview}=await prepared(t);const rs=reviewers({override:()=>({issuedAt:Date.now()-200000,expiresAt:Date.now()-100000})});
 await fail(g({reviewers:rs}).recoverOnce({authorization:p,forensicReview}),'RECOVERY_ADJUDICATION_RECEIPT_INVALID');
});
test('31G future and overlong receipts rejected',async t=>{
 const {p,g,forensicReview}=await prepared(t);
 for(const override of [{issuedAt:Date.now()+2000},{expiresAt:Date.now()+400000}]){
  const rs=reviewers({override:()=>override});await fail(g({reviewers:rs}).recoverOnce({authorization:p,forensicReview}),'RECOVERY_ADJUDICATION_RECEIPT_INVALID');
 }
});
test('31G duplicate reviewer identity rejected at configuration',async t=>{
 const {f,rs}=await prepared(t);
 assert.throws(()=>f.guard({reviewers:[rs[0],{...rs[1],id:rs[0].id}],reviewQuorum:2}),e=>e.code==='RECOVERY_ADJUDICATION_CONFIGURATION');
});
test('31G duplicate reviewer signing key rejected at configuration',async t=>{
 const {f,rs}=await prepared(t);
 assert.throws(()=>f.guard({reviewers:[rs[0],{...rs[1],publicKey:rs[0].publicKey}],reviewQuorum:2}),e=>e.code==='RECOVERY_ADJUDICATION_SHARED_OR_DUPLICATE_KEY');
});
test('31G reviewers may not share anchor witness keys',async t=>{
 const {f,rs}=await prepared(t);
 assert.throws(()=>f.guard({reviewers:[{...rs[0],publicKey:f.anchorWitnesses[0].publicKey},rs[1]],reviewQuorum:2}),e=>e.code==='RECOVERY_ADJUDICATION_SHARED_OR_DUPLICATE_KEY');
});
test('31G reviewers may not share ledger witness keys',async t=>{
 const {f,rs}=await prepared(t);
 assert.throws(()=>f.guard({reviewers:[{...rs[0],publicKey:f.ledgerWitnesses[0].publicKey},rs[1]],reviewQuorum:2}),e=>e.code==='RECOVERY_ADJUDICATION_SHARED_OR_DUPLICATE_KEY');
});
test('31G nonmajority reviewer quorum rejected',async t=>{
 const {f,rs}=await prepared(t);
 assert.throws(()=>f.guard({reviewers:rs,reviewQuorum:1}),e=>e.code==='RECOVERY_ADJUDICATION_CONFIGURATION');
});
test('31G no reviewer service response fails closed',async t=>{
 const {p,g,forensicReview}=await prepared(t);const rs=reviewers({before:async(args,i)=>{if(i===0)throw Error('review service offline');}});
 await assert.rejects(g({reviewers:rs}).recoverOnce({authorization:p,forensicReview}),/review service offline/);
});
test('31G incomplete outcome coverage rejected',async t=>{
 const {p,g,forensicReview}=await prepared(t);
 await fail(g().recoverOnce({authorization:p,forensicReview:{...forensicReview,outcomes:[]}}),'RECOVERY_ADJUDICATION_OUTCOMES_INVALID');
});
test('31G mismatched authorization ID rejected',async t=>{
 const {p,g,forensicReview}=await prepared(t);
 const bad={...forensicReview,outcomes:forensicReview.outcomes.map(x=>({...x,authorizationId:id()}))};
 await fail(g().recoverOnce({authorization:p,forensicReview:bad}),'RECOVERY_ADJUDICATION_OUTCOMES_INVALID');
});
test('31G changed permit digest rejected',async t=>{
 const {p,g,forensicReview}=await prepared(t);
 const bad={...forensicReview,outcomes:forensicReview.outcomes.map(x=>({...x,permitDigest:'c'.repeat(64)}))};
 await fail(g().recoverOnce({authorization:p,forensicReview:bad}),'RECOVERY_ADJUDICATION_OUTCOMES_INVALID');
});
test('31G unresolved outcome is never enough to reopen',async t=>{
 const {p,g,forensicReview}=await prepared(t);
 const bad={...forensicReview,outcomes:forensicReview.outcomes.map(x=>({...x,result:'UNRESOLVED'}))};
 await fail(g().recoverOnce({authorization:p,forensicReview:bad}),'RECOVERY_ADJUDICATION_OUTCOMES_INVALID');
});
test('31G zero or invalid evidence digest rejected',async t=>{
 const {p,g,forensicReview}=await prepared(t);
 for(const evidenceDigest of [ROOT,'bad']){
  const bad={...forensicReview,outcomes:forensicReview.outcomes.map(x=>({...x,evidenceDigest}))};
  await fail(g().recoverOnce({authorization:p,forensicReview:bad}),'RECOVERY_ADJUDICATION_OUTCOMES_INVALID');
 }
});
test('31G applied outcome for same pending digest cannot be reopened',async t=>{
 const pendingDigest=hash(Buffer.alloc(0));const {f,p,g,forensicReview}=await prepared(t,{oldPendingDigest:pendingDigest});
 const bad={...forensicReview,outcomes:forensicReview.outcomes.map(x=>({...x,result:'RESOLVED_APPLIED'}))};
 await fail(g().recoverOnce({authorization:p,forensicReview:bad}),'RECOVERY_ADJUDICATION_ALREADY_APPLIED');
 assert.equal((await f.ledger().inspect()).count,1);
});
test('31G not-applied forensic result permits NEW authorization for same pending digest',async t=>{
 const pendingDigest=hash(Buffer.alloc(0));const {p,g,forensicReview}=await prepared(t,{oldPendingDigest:pendingDigest});
 const result=await g().recoverOnce({authorization:p,forensicReview});assert.equal(result.recovered,true);assert.equal(result.forensicReviewVerified,true);
});
test('31G anchor mutation during forensic reviewer roundtrip fails closed',async t=>{
 const {f,p,g,forensicReview}=await prepared(t);let done=false;
 // A pending anchor blocks CAS; mutate the pending proposal during the
 // simulated independent reviewer round trip to exercise reinspection.
 const rs2=reviewers({before:async()=>{if(!done){done=true;await writeFile(f.pending,Buffer.from('different'),{mode:0o600});}}});
 await fail(g({reviewers:rs2}).recoverOnce({authorization:p,forensicReview}),'RECOVERY_ADJUDICATION_CONCURRENT_CHANGE');
 assert.equal((await f.ledger().inspect()).count,1);
});
test('31G ledger advance during forensic reviewer roundtrip fails closed',async t=>{
 const {f,p,g,forensicReview}=await prepared(t);let done=false;
 const rs=reviewers({before:async()=>{if(!done){done=true;await f.ledger().reserve({authorizationId:id(),permitDigest:'d'.repeat(64),pendingDigest:'e'.repeat(64)});}}});
 await fail(g({reviewers:rs}).recoverOnce({authorization:p,forensicReview}),'RECOVERY_ADJUDICATION_CONCURRENT_CHANGE');
 assert.equal((await f.ledger().inspect()).count,2);
});
test('31G invalid signed recovery permit rejected before review or reservation',async t=>{
 const {f,p,g,forensicReview}=await prepared(t);
 await fail(g().recoverOnce({authorization:{...p,signature:'a'.repeat(86)},forensicReview}),'DURABLE_ANCHOR_RECOVERY_DENIED');
 assert.equal((await f.ledger().inspect()).count,1);
});
test('31G prior reservation replay is rejected even with fresh independent review',async t=>{
 const {f,p,g,forensicReview}=await prepared(t);
 const old=await f.ledger().inspectHistory();const prior=old.events[0];
 const replay=f.permit('abort-pending',null,null,hash(Buffer.alloc(0)),{authorizationId:prior.authorizationId});
 await fail(g().recoverOnce({authorization:replay,forensicReview}),'RECOVERY_LEDGER_REPLAY');
 assert.equal((await f.ledger().inspect()).count,1);
});
test('31G tampered history cannot be independently adjudicated',async t=>{
 const {f,p,g,forensicReview}=await prepared(t);
 await writeFile(f.ledgerFile(1),(await readFile(f.ledgerFile(1),'utf8')).replace('a'.repeat(64),'c'.repeat(64)));
 await fail(g().recoverOnce({authorization:p,forensicReview}),'RECOVERY_LEDGER_TAMPERED');
});
test('31G inspector never automatically reopens despite configured reviewers',async t=>{
 const {g}=await prepared(t);
 const result=await g().inspectReconciliation();assert.equal(result.disposition,'PENDING_ANCHOR_REVIEW_REQUIRED');assert.equal(result.automaticRepairAllowed,false);
});
test('31G signed outcome for all burned reservations required, not just latest',async t=>{
 const {f,p,g,forensicReview}=await prepared(t);
 await f.ledger().reserve({authorizationId:id(),permitDigest:'d'.repeat(64),pendingDigest:'e'.repeat(64)});await f.pin();
 await fail(g().recoverOnce({authorization:p,forensicReview}),'RECOVERY_ADJUDICATION_OUTCOMES_INVALID');
 const history=await f.ledger().inspectHistory();
 const result=await g().recoverOnce({authorization:p,forensicReview:{caseDigest:evidence(),outcomes:outcomes(history)}});
 assert.equal(result.reservationIndex,3);
});
test('31G real child-process crash after burned reservation requires fresh independent review and a new permit',async t=>{
 const f=await fixture(t);await f.adapter().inspect();
 const source=fileURLToPath(new URL('../src/offline-recovery-authorization-ledger.mjs',import.meta.url));
 const script=`import {createOfflineRecoveryAuthorizationLedger} from ${JSON.stringify(source)};const l=createOfflineRecoveryAuthorizationLedger({directory:process.argv[1],registryId:process.argv[2],anchorType:'registry'});await l.reserve({authorizationId:process.argv[3],permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64)});process.exit(93)`;
 const exit=await new Promise((ok,no)=>{const c=spawn(process.execPath,['--input-type=module','-e',script,f.ledgerDirectory,registryId,id()],{stdio:['ignore','ignore','pipe']});let err='';c.stderr.on('data',b=>err+=b);c.once('error',no);c.once('close',code=>code===93?ok(code):no(Error(`exit ${code}: ${err}`)));});
 assert.equal(exit,93);
 await writeFile(f.pending,Buffer.alloc(0),{mode:0o600});await f.pin();
 const p=f.permit('abort-pending',null,null,hash(Buffer.alloc(0)));
 const forensicReview={caseDigest:evidence(),outcomes:outcomes(await f.ledger().inspectHistory())};
 const g=f.guard({reviewers:reviewers(),reviewQuorum:2});
 const r=await g.recoverOnce({authorization:p,forensicReview});assert.equal(r.reservationIndex,2);assert.equal(r.forensicReviewVerified,true);
});
test('31G actual competing child-process ledger advance during reviewer roundtrip fails closed',async t=>{
 const {f,p,g,forensicReview}=await prepared(t);let done=false;
 const source=fileURLToPath(new URL('../src/offline-recovery-authorization-ledger.mjs',import.meta.url));
 const script=`import {createOfflineRecoveryAuthorizationLedger} from ${JSON.stringify(source)};const l=createOfflineRecoveryAuthorizationLedger({directory:process.argv[1],registryId:process.argv[2],anchorType:'registry'});await l.reserve({authorizationId:process.argv[3],permitDigest:'d'.repeat(64),pendingDigest:'e'.repeat(64)});process.exit(0)`;
 const rs=reviewers({before:async()=>{if(done)return;done=true;await new Promise((ok,no)=>{const c=spawn(process.execPath,['--input-type=module','-e',script,f.ledgerDirectory,registryId,id()],{stdio:['ignore','ignore','pipe']});let err='';c.stderr.on('data',b=>err+=b);c.once('error',no);c.once('close',code=>code===0?ok():no(Error(err)));});}});
 await fail(g({reviewers:rs}).recoverOnce({authorization:p,forensicReview}),'RECOVERY_ADJUDICATION_CONCURRENT_CHANGE');
 assert.equal((await f.ledger().inspect()).count,2);
});
test('31G captured signed receipts cannot be replayed with a different challenge',async t=>{
 const {f,p,history,forensicReview,rs}=await prepared(t);const anchor=await f.adapter().inspectRecoveryState();
 const challenge=c32(),authorizationDigest=hash(Buffer.from(JSON.stringify(p))),args={challenge,history,anchor,...forensicReview,authorizationDigest};
 const receipts=await Promise.all(rs.map(r=>r.readLatest(args)));
 assert.equal(verifyOfflineRecoveryAdjudicationQuorum({registryId,anchorType:'registry',reviewers:rs,quorum:2,receipts,history,anchor,caseDigest:forensicReview.caseDigest,outcomes:forensicReview.outcomes,authorizationDigest,challenge}).verified,true);
 await fail(()=>verifyOfflineRecoveryAdjudicationQuorum({registryId,anchorType:'registry',reviewers:rs,quorum:2,receipts,history,anchor,caseDigest:forensicReview.caseDigest,outcomes:forensicReview.outcomes,authorizationDigest,challenge:c32()}),'RECOVERY_ADJUDICATION_RECEIPT_INVALID');
});
test('31G valid signed quorum rejects any extra contradictory receipt',async t=>{
 const {f,p,history,forensicReview,rs}=await prepared(t);const anchor=await f.adapter().inspectRecoveryState(),challenge=c32(),authorizationDigest=hash(Buffer.from(JSON.stringify(p))),args={challenge,history,anchor,...forensicReview,authorizationDigest};
 const receipts=await Promise.all(rs.map(r=>r.readLatest(args)));
 await fail(()=>verifyOfflineRecoveryAdjudicationQuorum({registryId,anchorType:'registry',reviewers:rs,quorum:2,receipts:[...receipts,receipts[0]],history,anchor,caseDigest:forensicReview.caseDigest,outcomes:forensicReview.outcomes,authorizationDigest,challenge}),'RECOVERY_ADJUDICATION_REQUEST_INVALID');
});
test('31G all signed reviewer receipts must agree on complete outcome digest',async t=>{
 const {p,g,forensicReview}=await prepared(t);
 const rs=reviewers({override:(args,i)=>i===0?{outcomesDigest:'f'.repeat(64)}:{}});
 await fail(g({reviewers:rs}).recoverOnce({authorization:p,forensicReview}),'RECOVERY_ADJUDICATION_RECEIPT_INVALID');
});
test('31G reviewer signatures bind the exact NEW signed recovery permit',async t=>{
 const {f,p,history,forensicReview,rs}=await prepared(t);
 const anchor=await f.adapter().inspectRecoveryState(),challenge=c32();
 const authorizationDigest=hash(Buffer.from(JSON.stringify(p)));
 const args={challenge,history,anchor,...forensicReview,authorizationDigest};
 const receipts=await Promise.all(rs.map(r=>r.readLatest(args)));
 await fail(()=>verifyOfflineRecoveryAdjudicationQuorum({registryId,anchorType:'registry',reviewers:rs,quorum:2,receipts,history,anchor,caseDigest:forensicReview.caseDigest,outcomes:forensicReview.outcomes,authorizationDigest:'f'.repeat(64),challenge}),'RECOVERY_ADJUDICATION_RECEIPT_INVALID');
});
test('31G reviewer quorum rejects duplicate authorization IDs in fabricated signed history',async t=>{
 const {f,p,history,forensicReview,rs}=await prepared(t);
 const anchor=await f.adapter().inspectRecoveryState(),challenge=c32();
 const first=history.events[0];
 const body={schema:first.schema,registryId,anchorType:'registry',index:2,previousDigest:first.digest,authorizationId:first.authorizationId,permitDigest:'c'.repeat(64),pendingDigest:'d'.repeat(64)};
 const second={...body,digest:hash(Buffer.from(`${body.schema}\0${JSON.stringify(body)}`))};
 const duplicate={count:2,headDigest:second.digest,events:[first,second]};
 const os=outcomes(duplicate),authorizationDigest=hash(Buffer.from(JSON.stringify(p)));
 const args={challenge,history:duplicate,anchor,caseDigest:forensicReview.caseDigest,outcomes:os,authorizationDigest};
 const receipts=await Promise.all(rs.map(r=>r.readLatest(args)));
 await fail(()=>verifyOfflineRecoveryAdjudicationQuorum({registryId,anchorType:'registry',reviewers:rs,quorum:2,receipts,history:duplicate,anchor,caseDigest:forensicReview.caseDigest,outcomes:os,authorizationDigest,challenge}),'RECOVERY_ADJUDICATION_HISTORY_INVALID');
});
