import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,unlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {createOfflineRecoveryAuthorizationLedger} from '../src/offline-recovery-authorization-ledger.mjs';
import {createOfflineForensicReviewJournal,verifyOfflineForensicEvidenceBundle} from '../src/offline-forensic-review-journal.mjs';
import {OFFLINE_RECOVERY_ADJUDICATION_SCHEMA} from '../src/offline-recovery-adjudication.mjs';

const registryId='synthetic-31i-rotation-registry',anchorType='registry',ROOT='0'.repeat(64);
const sha=x=>createHash('sha256').update(x).digest('hex');
const receiptFields=['schema','reviewerId','registryId','anchorType','ledgerCount','ledgerHeadDigest','historyDigest','anchorStateDigest','caseDigest','outcomesDigest','authorizationDigest','challenge','issuedAt','expiresAt'];
const reject=(p,code)=>assert.rejects(Promise.resolve().then(()=>p),e=>e?.code===code);
async function setup(t){
 const base=await mkdtemp(join(tmpdir(),'tj-31i-'));t.after(()=>rm(base,{recursive:true,force:true}));
 const ledger=createOfflineRecoveryAuthorizationLedger({directory:join(base,'ledger'),registryId,anchorType});
 await ledger.reserve({authorizationId:'synthetic-auth-31i-001',permitDigest:'a'.repeat(64),pendingDigest:'b'.repeat(64)});
 const history=await ledger.inspectHistory();
 const anchor={anchor:null,eventCount:0,historyDigest:ROOT,pending:true,pendingDigest:'c'.repeat(64),productionApproved:false};
 const oldKeys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
 const newKeys=[generateKeyPairSync('ed25519'),generateKeyPairSync('ed25519')];
 const reviewers=keys=>keys.map((k,i)=>({id:`synthetic-reviewer-31i-${i+1}`,publicKey:k.publicKey,readLatest:async()=>{throw Error('not used');}}));
 const old=reviewers(oldKeys),current=reviewers(newKeys);
 const epochs=[{startIndex:1,reviewers:old,quorum:2},{startIndex:2,reviewers:current,quorum:2}];
 const directory=join(base,'forensic');
 const journal=(changes={})=>createOfflineForensicReviewJournal({directory,registryId,anchorType,reviewers:current,reviewQuorum:2,reviewerEpochs:epochs,...changes});
 const caseEvidence=Buffer.from('Synthetic forensic case 31I');
 const outcomeEvidence=[Buffer.from('Synthetic forensic outcome 31I')];
 const outcomes=history.events.map((e,i)=>({index:e.index,authorizationId:e.authorizationId,permitDigest:e.permitDigest,pendingDigest:e.pendingDigest,result:'RESOLVED_NOT_APPLIED',evidenceDigest:sha(outcomeEvidence[i])}));
 const make=(keys,expectedHead={count:0,headDigest:ROOT})=>{
  const now=Date.now(),challenge=randomBytes(32).toString('base64url'),authorizationDigest=sha(randomBytes(32)),caseDigest=sha(caseEvidence);
  const receipts=keys.map((key,i)=>{
   const body={schema:OFFLINE_RECOVERY_ADJUDICATION_SCHEMA,reviewerId:`synthetic-reviewer-31i-${i+1}`,registryId,anchorType,ledgerCount:history.count,ledgerHeadDigest:history.headDigest,historyDigest:sha(Buffer.from(JSON.stringify(history.events))),anchorStateDigest:sha(Buffer.from(JSON.stringify(anchor))),caseDigest,outcomesDigest:sha(Buffer.from(JSON.stringify(outcomes))),authorizationDigest,challenge,issuedAt:now-1000,expiresAt:now+60000};
   const canonical=Object.fromEntries(receiptFields.map(k=>[k,body[k]]));
   return {...body,signature:sign(null,Buffer.from(`${OFFLINE_RECOVERY_ADJUDICATION_SCHEMA}\0${JSON.stringify(canonical)}`),key.privateKey).toString('base64url')};
  });
  return {review:{history,anchor,caseDigest,outcomes,authorizationDigest,challenge,receipts},caseEvidence,outcomeEvidence,expectedHead};
 };
 const appendTwo=async()=>{
  const j=journal(),first=await j.append(make(oldKeys));
  const second=await j.append(make(newKeys,{count:1,headDigest:first.headDigest}));
  return {first,second,events:(await j.inspectHistory()).events};
 };
 return {base,directory,oldKeys,newKeys,old,current,epochs,journal,make,appendTwo};
}
const portable=(f,events,head,epochs=f.epochs)=>verifyOfflineForensicEvidenceBundle({registryId,anchorType,events,reviewerEpochs:epochs,expectedHead:head});
test('31I rotated reviewer quorum preserves historical signatures and validates new event',async t=>{
 const f=await setup(t),{second,events}=await f.appendTwo();
 assert.equal((await f.journal().inspect()).count,2);
 assert.deepEqual(portable(f,events,{count:2,headDigest:second.headDigest}),{verified:true,count:2,headDigest:second.headDigest,productionApproved:false});
});
test('31I old reviewer keys cannot sign events after rotation',async t=>{
 const f=await setup(t),first=await f.journal().append(f.make(f.oldKeys));
 await reject(f.journal().append(f.make(f.oldKeys,{count:1,headDigest:first.headDigest})),'RECOVERY_ADJUDICATION_SIGNATURE_INVALID');
 assert.equal((await f.journal().inspect()).count,1);
});
test('31I new reviewer keys cannot sign events before rotation',async t=>{
 const f=await setup(t);await reject(f.journal().append(f.make(f.newKeys)),'RECOVERY_ADJUDICATION_SIGNATURE_INVALID');
});
test('31I portable verifier rejects truncated valid prefix with pinned head',async t=>{
 const f=await setup(t),{second,events}=await f.appendTwo();
 assert.throws(()=>portable(f,events.slice(0,1),{count:2,headDigest:second.headDigest}),{code:'FORENSIC_PORTABLE_HEAD_MISMATCH'});
});
test('31I portable verifier rejects wrong externally pinned head digest',async t=>{
 const f=await setup(t),{events}=await f.appendTwo();
 assert.throws(()=>portable(f,events,{count:2,headDigest:'f'.repeat(64)}),{code:'FORENSIC_PORTABLE_HEAD_MISMATCH'});
});
test('31I portable verifier rejects reordered evidence',async t=>{
 const f=await setup(t),{second,events}=await f.appendTwo();
 assert.throws(()=>portable(f,[events[1],events[0]],{count:2,headDigest:second.headDigest}),{code:'FORENSIC_JOURNAL_HISTORY_GAP'});
});
test('31I portable verifier rejects altered forensic evidence bytes',async t=>{
 const f=await setup(t),{second,events}=await f.appendTwo();events[0].evidence.caseEvidence=Buffer.from('forged').toString('base64url');
 assert.throws(()=>portable(f,events,{count:2,headDigest:second.headDigest}),{code:'FORENSIC_EVIDENCE_DIGEST_MISMATCH'});
});
test('31I portable verifier rejects forged old reviewer key policy',async t=>{
 const f=await setup(t),{second,events}=await f.appendTwo();
 const bad=[{startIndex:1,reviewers:f.current,quorum:2},f.epochs[1]];
 assert.throws(()=>portable(f,events,{count:2,headDigest:second.headDigest},bad),{code:'RECOVERY_ADJUDICATION_SIGNATURE_INVALID'});
});
test('31I epoch configuration rejects non-monotonic starts',async t=>{
 const f=await setup(t);assert.throws(()=>f.journal({reviewerEpochs:[f.epochs[0],{...f.epochs[1],startIndex:1}]}),{code:'FORENSIC_REVIEWER_EPOCH_CONFIGURATION'});
});
test('31I epoch configuration rejects mismatch with current reviewer policy',async t=>{
 const f=await setup(t);assert.throws(()=>f.journal({reviewerEpochs:[f.epochs[0]]}),{code:'FORENSIC_REVIEWER_EPOCH_CURRENT_MISMATCH'});
});
test('31I epoch configuration rejects reuse of retired signing key by another reviewer ID',async t=>{
 const f=await setup(t),bad=f.current.map((r,i)=>i===0?{...r,id:'synthetic-reassigned-31i',publicKey:f.old[0].publicKey}:r);
 assert.throws(()=>f.journal({reviewers:bad,reviewerEpochs:[f.epochs[0],{startIndex:2,reviewers:bad,quorum:2}]}),{code:'FORENSIC_REVIEWER_KEY_REASSIGNED'});
});
test('31I historical journal inspection fails closed without pinned old key policy',async t=>{
 const f=await setup(t);await f.appendTwo();
 const legacy=createOfflineForensicReviewJournal({directory:f.directory,registryId,anchorType,reviewers:f.current,reviewQuorum:2});
 await reject(legacy.inspect(),'RECOVERY_ADJUDICATION_SIGNATURE_INVALID');
});
test('31I tampered old event cannot be laundered through rotation',async t=>{
 const f=await setup(t);await f.appendTwo();const p=join(f.directory,'0000000001.json'),e=JSON.parse(await readFile(p,'utf8'));
 e.review.receipts[0].signature='a'.repeat(86);await writeFile(p,JSON.stringify(e));
 await reject(f.journal().inspect(),'RECOVERY_ADJUDICATION_SIGNATURE_INVALID');
});
test('31I historical key cannot be reused as independent journal witness',async t=>{
 const f=await setup(t);await f.appendTwo();
 const witnesses=[f.old[0],{...f.current[1],id:'synthetic-witness-31i-002'}];
 await reject(f.journal().inspectWitnessed({witnesses,quorum:2}),'FORENSIC_WITNESS_SHARED_KEY');
});
test('31I portable verifier rejects untrusted empty history if head is nonempty',async t=>{
 const f=await setup(t),{second}=await f.appendTwo();
 assert.throws(()=>portable(f,[],{count:2,headDigest:second.headDigest}),{code:'FORENSIC_PORTABLE_HEAD_MISMATCH'});
});
test('31I retired reviewer key cannot silently return in later epoch',async t=>{
 const f=await setup(t);
 assert.throws(()=>f.journal({reviewers:f.old,reviewerEpochs:[f.epochs[0],f.epochs[1],{startIndex:3,reviewers:f.old,quorum:2}]}),{code:'FORENSIC_REVIEWER_KEY_ROLLBACK'});
});
