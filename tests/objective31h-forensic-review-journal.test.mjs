import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,unlink,symlink,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {createHash,generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {createOfflineRecoveryAuthorizationLedger} from '../src/offline-recovery-authorization-ledger.mjs';
import {createOfflineForensicReviewJournal,OFFLINE_FORENSIC_JOURNAL_WITNESS_SCHEMA,verifyOfflineForensicJournalWitnessQuorum} from '../src/offline-forensic-review-journal.mjs';
import {OFFLINE_RECOVERY_ADJUDICATION_SCHEMA} from '../src/offline-recovery-adjudication.mjs';
import {createOfflineRecoveryReconciliationGuard,OFFLINE_RECOVERY_LEDGER_WITNESS_SCHEMA} from '../src/offline-recovery-reconciliation.mjs';
import {OFFLINE_WITNESS_SCHEMA} from '../src/offline-recovery-witness.mjs';

const registryId='objective31h-forensic-registry',anchorType='registry',ROOT='0'.repeat(64);
const sha=x=>createHash('sha256').update(x).digest('hex');
const id=()=>`synthetic-${randomBytes(12).toString('hex')}`;
const challenge=()=>randomBytes(32).toString('base64url');
const reviewFields=['schema','reviewerId','registryId','anchorType','ledgerCount','ledgerHeadDigest','historyDigest','anchorStateDigest','caseDigest','outcomesDigest','authorizationDigest','challenge','issuedAt','expiresAt'];
const witnessFields=['schema','witnessId','registryId','anchorType','count','headDigest','challenge','issuedAt','expiresAt'];
const anchorFields=['schema','witnessId','registryId','anchorType','eventCount','historyDigest','anchor','challenge','issuedAt','expiresAt'];
const ledgerFields=['schema','witnessId','registryId','anchorType','count','headDigest','challenge','issuedAt','expiresAt'];
const signFields=(schema,fields,body,key)=>sign(null,Buffer.from(`${schema}\0${JSON.stringify(Object.fromEntries(fields.map(k=>[k,body[k]])))}`),key).toString('base64url');
const fail=(p,code)=>assert.rejects(Promise.resolve().then(()=>typeof p==='function'?p():p),e=>e?.code===code);
const pathFor=(base,n)=>join(base,'forensic',String(n).padStart(10,'0')+'.json');

async function fixture(t){
 const base=await mkdtemp(join(tmpdir(),'tj-31h-'));t.after(()=>rm(base,{recursive:true,force:true}));
 const ledger=createOfflineRecoveryAuthorizationLedger({directory:join(base,'ledger'),registryId,anchorType});
 await ledger.reserve({authorizationId:id(),permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64)});
 const history=await ledger.inspectHistory();
 const anchor={anchor:null,eventCount:0,historyDigest:ROOT,pending:true,pendingDigest:'c'.repeat(64),productionApproved:false};
 const reviewKeys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
 const reviewers=reviewKeys.map((k,i)=>({id:`forensic-reviewer-31h-${i+1}`,publicKey:k.publicKey,readLatest:async()=>{throw Error('unused');}}));
 const caseEvidence=Buffer.from('Synthetic forensic case evidence, not actual customer data');
 const outcomeEvidence=history.events.map((_,i)=>Buffer.from(`Synthetic outcome evidence ${i}`));
 const outcomes=history.events.map((e,i)=>({index:e.index,authorizationId:e.authorizationId,permitDigest:e.permitDigest,pendingDigest:e.pendingDigest,result:'RESOLVED_NOT_APPLIED',evidenceDigest:sha(outcomeEvidence[i])}));
 const review=(changes={})=>{
  const now=Date.now(),c=challenge(),authorizationDigest=sha(randomBytes(16)),caseDigest=sha(caseEvidence);
  const receipts=reviewKeys.map((key,i)=>{
   const body={schema:OFFLINE_RECOVERY_ADJUDICATION_SCHEMA,reviewerId:reviewers[i].id,registryId,anchorType,ledgerCount:history.count,ledgerHeadDigest:history.headDigest,historyDigest:sha(Buffer.from(JSON.stringify(history.events))),anchorStateDigest:sha(Buffer.from(JSON.stringify(anchor))),caseDigest,outcomesDigest:sha(Buffer.from(JSON.stringify(outcomes))),authorizationDigest,challenge:c,issuedAt:now-1000,expiresAt:now+60000};
   return {...body,signature:signFields(OFFLINE_RECOVERY_ADJUDICATION_SCHEMA,reviewFields,body,key.privateKey)};
  });
  return {history,anchor,caseDigest,outcomes,authorizationDigest,challenge:c,receipts,...changes};
 };
 const directory=join(base,'forensic');
 const journal=(options={})=>createOfflineForensicReviewJournal({directory,registryId,anchorType,reviewers,reviewQuorum:2,...options});
 const input=(changes={})=>({review:review(),caseEvidence,outcomeEvidence,expectedHead:{count:0,headDigest:ROOT},...changes});
 const witnessKeys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];let witnessPin={count:0,headDigest:ROOT};
 const witnesses=witnessKeys.map((k,i)=>{
  const witnessId=`forensic-head-witness-31h-${i+1}`;
  return {id:witnessId,publicKey:k.publicKey,readLatest:async({challenge:c})=>{
   const now=Date.now(),body={schema:OFFLINE_FORENSIC_JOURNAL_WITNESS_SCHEMA,witnessId,registryId,anchorType,...witnessPin,challenge:c,issuedAt:now-1000,expiresAt:now+60000};
   return {...body,signature:signFields(OFFLINE_FORENSIC_JOURNAL_WITNESS_SCHEMA,witnessFields,body,k.privateKey)};
  }};
 });
 const pin=async()=>{const s=await journal().inspect();witnessPin={count:s.count,headDigest:s.headDigest};};
 return {base,directory,ledger,history,anchor,reviewKeys,reviewers,journal,review,input,caseEvidence,outcomeEvidence,witnesses,pin,setWitnessPin:s=>{witnessPin=s;},getWitnessPin:()=>witnessPin};
}

// Full replay verification of the signed bundle and every stored evidence byte.
test('31H persists a complete signed forensic review and evidence bytes, with durable head',async t=>{
 const f=await fixture(t),out=await f.journal().append(f.input());
 assert.equal(out.index,1);assert.match(out.headDigest,/^[0-9a-f]{64}$/);
 const h=await f.journal().inspectHistory();assert.equal(h.events.length,1);
 assert.deepEqual(Buffer.from(h.events[0].evidence.caseEvidence,'base64url'),f.caseEvidence);
 assert.deepEqual(Buffer.from(h.events[0].evidence.outcomeEvidence[0],'base64url'),f.outcomeEvidence[0]);
 assert.deepEqual(await f.journal().inspect(),{count:1,headDigest:out.headDigest,productionApproved:false});
});
test('31H appends a second fresh review with linked predecessor and monotonic index',async t=>{
 const f=await fixture(t),j=f.journal(),one=await j.append(f.input());
 const two=await j.append(f.input({expectedHead:{count:one.index,headDigest:one.headDigest}}));
 const h=await j.inspectHistory();assert.equal(two.index,2);assert.equal(h.events[1].previousDigest,one.headDigest);
});
test('31H stale pinned head cannot append',async t=>{const f=await fixture(t);await f.journal().append(f.input());await fail(f.journal().append(f.input()),'FORENSIC_JOURNAL_STALE_PIN');});
test('31H replayed authorization digest is rejected with a fresh challenge',async t=>{
 const f=await fixture(t),one=f.input(),out=await f.journal().append(one);
 await fail(f.journal().append(f.input({review:one.review,expectedHead:{count:1,headDigest:out.headDigest}})),'FORENSIC_JOURNAL_REPLAY');
});
test('31H missing or mismatched case evidence fails before writing',async t=>{const f=await fixture(t);await fail(f.journal().append(f.input({caseEvidence:Buffer.from('wrong')})),'FORENSIC_EVIDENCE_DIGEST_MISMATCH');assert.equal((await f.journal().inspect()).count,0);});
test('31H missing or mismatched outcome evidence fails before writing',async t=>{const f=await fixture(t);await fail(f.journal().append(f.input({outcomeEvidence:[Buffer.from('wrong')]})),'FORENSIC_EVIDENCE_DIGEST_MISMATCH');assert.equal((await f.journal().inspect()).count,0);});
test('31H missing reviewer quorum is rejected',async t=>{const f=await fixture(t),r=f.review();await fail(f.journal().append(f.input({review:{...r,receipts:[r.receipts[0]]}})),'RECOVERY_ADJUDICATION_REQUEST_INVALID');});
test('31H forged forensic signature is rejected',async t=>{const f=await fixture(t),r=f.review();r.receipts[0].signature='a'.repeat(86);await fail(f.journal().append(f.input({review:r})),'RECOVERY_ADJUDICATION_SIGNATURE_INVALID');});
test('31H forged reviewer identity cannot be accepted',async t=>{const f=await fixture(t),r=f.review();r.receipts[0].reviewerId='unrecognized-reviewer-31h';await fail(f.journal().append(f.input({review:r})),'RECOVERY_ADJUDICATION_RECEIPT_INVALID');});
test('31H expired forensic receipt cannot be recorded',async t=>{const f=await fixture(t),r=f.review();r.receipts[0].expiresAt=Date.now()-1;await fail(f.journal().append(f.input({review:r})),'RECOVERY_ADJUDICATION_RECEIPT_INVALID');});
test('31H tampered evidence file fails closed on inspection',async t=>{
 const f=await fixture(t);await f.journal().append(f.input());const path=pathFor(f.base,1),e=JSON.parse(await readFile(path,'utf8'));e.evidence.caseEvidence=Buffer.from('forged').toString('base64url');await writeFile(path,JSON.stringify(e));await fail(f.journal().inspect(),'FORENSIC_EVIDENCE_DIGEST_MISMATCH');
});
test('31H altered event digest fails closed',async t=>{const f=await fixture(t);await f.journal().append(f.input());const path=pathFor(f.base,1),e=JSON.parse(await readFile(path,'utf8'));e.digest='f'.repeat(64);await writeFile(path,JSON.stringify(e));await fail(f.journal().inspect(),'FORENSIC_JOURNAL_TAMPERED');});
test('31H missing intermediate event cannot be silently skipped',async t=>{const f=await fixture(t),j=f.journal(),one=await j.append(f.input());await j.append(f.input({expectedHead:{count:1,headDigest:one.headDigest}}));await unlink(pathFor(f.base,1));await fail(j.inspect(),'FORENSIC_JOURNAL_HISTORY_GAP');});
test('31H event symlink substitution is rejected',async t=>{const f=await fixture(t);await f.journal().append(f.input());await unlink(pathFor(f.base,1));await symlink('/etc/hosts',pathFor(f.base,1));await fail(f.journal().inspect(),'FORENSIC_JOURNAL_FILE_UNSAFE');});
test('31H world-readable evidence event is rejected',async t=>{const f=await fixture(t);await f.journal().append(f.input());await chmod(pathFor(f.base,1),0o644);await fail(f.journal().inspect(),'FORENSIC_JOURNAL_FILE_UNSAFE');});
test('31H independently witnessed current head passes',async t=>{const f=await fixture(t);await f.journal().append(f.input());await f.pin();const s=await f.journal().inspectWitnessed({witnesses:f.witnesses,quorum:2});assert.equal(s.count,1);assert.equal(s.independentlyWitnessed,true);});
test('31H independent witness detects full local rollback to empty state',async t=>{const f=await fixture(t);await f.journal().append(f.input());await f.pin();await unlink(pathFor(f.base,1));assert.equal((await f.journal().inspect()).count,0);await fail(f.journal().inspectWitnessed({witnesses:f.witnesses,quorum:2}),'FORENSIC_WITNESS_RECEIPT_INVALID');});
test('31H independent witness detects stale head after legitimate append',async t=>{const f=await fixture(t);await f.journal().append(f.input());await fail(f.journal().inspectWitnessed({witnesses:f.witnesses,quorum:2}),'FORENSIC_WITNESS_RECEIPT_INVALID');});
test('31H forged witness signature is rejected',async t=>{const f=await fixture(t);const bad=f.witnesses.map((w,i)=>i===0?{...w,readLatest:async args=>({...await w.readLatest(args),signature:'a'.repeat(86)})}:w);await fail(f.journal().inspectWitnessed({witnesses:bad,quorum:2}),'FORENSIC_WITNESS_SIGNATURE_INVALID');});
test('31H replayed witness receipt with stale challenge fails',async t=>{const f=await fixture(t);const stale=await f.witnesses[0].readLatest({challenge:challenge()});const bad=f.witnesses.map((w,i)=>i===0?{...w,readLatest:async()=>stale}:w);await fail(f.journal().inspectWitnessed({witnesses:bad,quorum:2}),'FORENSIC_WITNESS_RECEIPT_INVALID');});
test('31H forensic witness cannot reuse reviewer signing key',async t=>{const f=await fixture(t),w=[{...f.witnesses[0],publicKey:f.reviewers[0].publicKey},f.witnesses[1]];await fail(f.journal().inspectWitnessed({witnesses:w,quorum:2}),'FORENSIC_WITNESS_SHARED_KEY');});
test('31H independent witness quorum cannot contain duplicate key',async t=>{const f=await fixture(t),w=[f.witnesses[0],{...f.witnesses[1],publicKey:f.witnesses[0].publicKey}];await fail(f.journal().inspectWitnessed({witnesses:w,quorum:2}),'FORENSIC_WITNESS_SHARED_KEY');});
test('31H cannot silently reuse forensic challenge after another event',async t=>{const f=await fixture(t),one=f.input(),out=await f.journal().append(one);await fail(f.journal().append(f.input({review:one.review,expectedHead:{count:1,headDigest:out.headDigest}})),'FORENSIC_JOURNAL_REPLAY');});


test('31H independent witness detects rollback to a valid earlier prefix',async t=>{
 const f=await fixture(t),j=f.journal(),one=await j.append(f.input());await j.append(f.input({expectedHead:{count:1,headDigest:one.headDigest}}));await f.pin();
 await unlink(pathFor(f.base,2));assert.equal((await j.inspect()).count,1);
 await fail(j.inspectWitnessed({witnesses:f.witnesses,quorum:2}),'FORENSIC_WITNESS_RECEIPT_INVALID');
});
test('31H signed but equivocal independent witness cannot override current head',async t=>{
 const f=await fixture(t),bad=f.witnesses.map((w,i)=>i===0?{...w,readLatest:async args=>{
  const original=await w.readLatest(args);return {...original,headDigest:'f'.repeat(64)};
 }}:w);
 await fail(f.journal().inspectWitnessed({witnesses:bad,quorum:2}),'FORENSIC_WITNESS_RECEIPT_INVALID');
});
test('31H concurrent journal append during witness roundtrip is rejected',async t=>{
 const f=await fixture(t),j=f.journal();await f.pin();let changed=false;
 const ws=f.witnesses.map((w,i)=>i===0?{...w,readLatest:async args=>{
  const receipt=await w.readLatest(args);
  if(!changed){changed=true;await j.append(f.input());}
  return receipt;
 }}:w);
 await fail(j.inspectWitnessed({witnesses:ws,quorum:2}),'FORENSIC_JOURNAL_CONCURRENT_CHANGE');
});
test('31H monotonic review timestamp rejects forged history clock rollback',async t=>{
 const f=await fixture(t),j=f.journal(),one=await j.append(f.input());await j.append(f.input({expectedHead:{count:1,headDigest:one.headDigest}}));
 const first=JSON.parse(await readFile(pathFor(f.base,1),'utf8')),second=JSON.parse(await readFile(pathFor(f.base,2),'utf8'));
 second.observedAt=first.observedAt-1;const {digest,...body}=second;second.digest=sha(Buffer.from(`${second.schema}\0${JSON.stringify(body)}`));
 await writeFile(pathFor(f.base,2),JSON.stringify(second));
 await fail(j.inspect(),'FORENSIC_JOURNAL_CLOCK_ROLLBACK');
});
test('31H invalid pinned head shape is rejected before any evidence write',async t=>{
 const f=await fixture(t);await fail(f.journal().append(f.input({expectedHead:{count:0,headDigest:ROOT,extra:true}})),'FORENSIC_JOURNAL_APPEND_INVALID');
 assert.equal((await f.journal().inspect()).count,0);
});

function runChild(script,env){return new Promise((resolve,reject)=>{const child=spawn(process.execPath,['--input-type=module','-e',script],{env:{...process.env,...env},stdio:['ignore','pipe','pipe']});let out='',err='';child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>err+=b);child.on('error',reject);child.on('close',code=>resolve({code,out,err}));});}
const childScript=`import {createPublicKey} from 'node:crypto';import {readFileSync} from 'node:fs';import {createOfflineForensicReviewJournal} from ${JSON.stringify(new URL('../src/offline-forensic-review-journal.mjs',import.meta.url).href)};
const data=JSON.parse(readFileSync(process.env.INPUT,'utf8'));
const reviewers=data.keys.map((pem,i)=>({id:'forensic-reviewer-31h-'+(i+1),publicKey:createPublicKey(pem),readLatest:async()=>{}}));
const injectFault=process.env.FAULT?async step=>{if(step===process.env.FAULT)process.exit(73);}:undefined;
const j=createOfflineForensicReviewJournal({directory:process.env.DIRECTORY,registryId:${JSON.stringify(registryId)},anchorType:'registry',reviewers,reviewQuorum:2,injectFault});
try{const r=await j.append({...data.input,caseEvidence:Buffer.from(data.input.caseEvidence,'base64url'),outcomeEvidence:data.input.outcomeEvidence.map(s=>Buffer.from(s,'base64url'))});console.log(JSON.stringify(r));}catch(e){console.log(e.code||e.message);process.exit(17);}`;
async function childInput(f,input){const file=join(f.base,'child-input.json');await writeFile(file,JSON.stringify({keys:f.reviewKeys.map(k=>k.publicKey.export({type:'spki',format:'pem'})),input:{...input,caseEvidence:input.caseEvidence.toString('base64url'),outcomeEvidence:input.outcomeEvidence.map(b=>b.toString('base64url'))}}));return {INPUT:file,DIRECTORY:f.directory};}
test('31H real child-process crash after pending sync blocks replay and inspection',async t=>{
 const f=await fixture(t),env=await childInput(f,f.input()),child=await runChild(childScript,{...env,FAULT:'after-pending-sync'});
 assert.equal(child.code,73,child.err);await fail(f.journal().inspect(),'FORENSIC_JOURNAL_PENDING_REVIEW_REQUIRED');await fail(f.journal().append(f.input()),'FORENSIC_JOURNAL_PENDING_REVIEW_REQUIRED');
});
test('31H real child-process crash after committed fsync preserves valid event and blocks replay',async t=>{
 const f=await fixture(t),input=f.input(),env=await childInput(f,input),child=await runChild(childScript,{...env,FAULT:'after-commit-sync'});
 assert.equal(child.code,73,child.err);assert.equal((await f.journal().inspect()).count,1);
 await fail(f.journal().append({...input,expectedHead:{count:1,headDigest:(await f.journal().inspect()).headDigest}}),'FORENSIC_JOURNAL_REPLAY');
});
test('31H concurrent independent processes cannot both commit same review',async t=>{
 const f=await fixture(t),env=await childInput(f,f.input()),[a,b]=await Promise.all([runChild(childScript,env),runChild(childScript,env)]);
 assert.deepEqual([a.code,b.code].sort((x,y)=>x-y),[0,17],JSON.stringify([a,b]));assert.equal((await f.journal().inspect()).count,1);
});

// Opt-in integration: the recovery guard must persist independently signed
// evidence BEFORE burning the new permit. No production recovery is simulated.
async function guardedFixture(t,{reserveFailure=false}={}){
 const f=await fixture(t),j=f.journal(),input=f.input();await f.pin();
 const anchorKeys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')],ledgerKeys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
 const aw=anchorKeys.map((k,i)=>({id:`independent-anchor-31h-${i}`,publicKey:k.publicKey,readLatest:async({challenge:c})=>{
  const now=Date.now(),body={schema:OFFLINE_WITNESS_SCHEMA,witnessId:`independent-anchor-31h-${i}`,registryId,anchorType,eventCount:f.anchor.eventCount,historyDigest:f.anchor.historyDigest,anchor:f.anchor.anchor,challenge:c,issuedAt:now-1000,expiresAt:now+60000};return {...body,signature:signFields(OFFLINE_WITNESS_SCHEMA,anchorFields,body,k.privateKey)};
 }}));
 const lh=await f.ledger.inspect();const lw=ledgerKeys.map((k,i)=>({id:`independent-ledger-31h-${i}`,publicKey:k.publicKey,readLatest:async({challenge:c})=>{
  const now=Date.now(),body={schema:OFFLINE_RECOVERY_LEDGER_WITNESS_SCHEMA,witnessId:`independent-ledger-31h-${i}`,registryId,anchorType,count:lh.count,headDigest:lh.headDigest,challenge:c,issuedAt:now-1000,expiresAt:now+60000};return {...body,signature:signFields(OFFLINE_RECOVERY_LEDGER_WITNESS_SCHEMA,ledgerFields,body,k.privateKey)};
 }}));
 const permit={authorizationId:id(),pendingDigest:f.anchor.pendingDigest,expectedAnchor:null};
 const adapter={inspectRecoveryState:async()=>structuredClone(f.anchor),validateRecoveryAuthorization:x=>{if(x!==permit)throw Error('invalid');},recoverInterruptedCommit:async()=>({recovered:true})};
 const rs=f.reviewers.map((r,i)=>({...r,readLatest:async({challenge:c,history,anchor,caseDigest,outcomes,authorizationDigest})=>{
  const now=Date.now(),body={schema:OFFLINE_RECOVERY_ADJUDICATION_SCHEMA,reviewerId:r.id,registryId,anchorType,ledgerCount:history.count,ledgerHeadDigest:history.headDigest,historyDigest:sha(Buffer.from(JSON.stringify(history.events))),anchorStateDigest:sha(Buffer.from(JSON.stringify(anchor))),caseDigest,outcomesDigest:sha(Buffer.from(JSON.stringify(outcomes))),authorizationDigest,challenge:c,issuedAt:now-1000,expiresAt:now+60000};return {...body,signature:signFields(OFFLINE_RECOVERY_ADJUDICATION_SCHEMA,reviewFields,body,f.reviewKeys[i].privateKey)};
 }}));
 let attempts=0;const ledger=reserveFailure?{inspect:f.ledger.inspect,inspectHistory:f.ledger.inspectHistory,reserve:async args=>{if(++attempts===1)throw Object.assign(Error('synthetic reservation failure'),{code:'SYNTHETIC_RESERVATION_FAILURE'});return f.ledger.reserve(args);}}:f.ledger;
 const guard=createOfflineRecoveryReconciliationGuard({adapter,ledger,registryId,anchorType,anchorWitnesses:aw,anchorQuorum:2,ledgerWitnesses:lw,ledgerQuorum:2,reviewers:rs,reviewQuorum:2,forensicJournal:j,forensicWitnesses:f.witnesses,forensicWitnessQuorum:2});
 const forensicReview={caseDigest:sha(f.caseEvidence),outcomes:input.review.outcomes};
 const forensicEvidence={caseEvidence:f.caseEvidence,outcomeEvidence:f.outcomeEvidence};
 return {f,j,guard,permit,forensicReview,forensicEvidence};
}
test('31H guarded recovery requires durable evidence and writes journal before ledger reservation',async t=>{
 const {f,j,guard,permit,forensicReview,forensicEvidence}=await guardedFixture(t);
 await fail(guard.recoverOnce({authorization:permit,forensicReview}),'FORENSIC_JOURNAL_EVIDENCE_REQUIRED');assert.equal((await f.ledger.inspect()).count,1);
 const result=await guard.recoverOnce({authorization:permit,forensicReview,forensicEvidence});
 assert.equal(result.recovered,true);assert.equal(result.forensicJournalRecorded,true);assert.equal((await j.inspect()).count,1);assert.equal((await f.ledger.inspect()).count,2);
});
test('31H failed ledger reservation after forensic fsync burns review and forbids same-permit retry',async t=>{
 const {f,j,guard,permit,forensicReview,forensicEvidence}=await guardedFixture(t,{reserveFailure:true});
 await fail(guard.recoverOnce({authorization:permit,forensicReview,forensicEvidence}),'SYNTHETIC_RESERVATION_FAILURE');
 assert.equal((await j.inspect()).count,1);assert.equal((await f.ledger.inspect()).count,1);
 await f.pin();
 await fail(guard.recoverOnce({authorization:permit,forensicReview,forensicEvidence}),'FORENSIC_JOURNAL_REPLAY');
 assert.equal((await f.ledger.inspect()).count,1);
});
