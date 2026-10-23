import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {createOfflineConflictExchangeJournal} from '../src/offline-conflict-exchange-journal.mjs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {createOfflineConflictRecoveryReceiptStore,offlineConflictRecoveryReceiptGenesisHead} from '../src/offline-conflict-exchange-recovery-receipts.mjs';
import {offlineConflictExchangeRecoveryReviewerPolicyDigest,offlineConflictExchangeRecoveryDecisionBytes,
 OFFLINE_CONFLICT_EXCHANGE_RECOVERY_SCHEMA} from '../src/offline-conflict-exchange-recovery.mjs';
import {OFFLINE_CONFLICT_RECOVERY_POLICY_EPOCH_SCHEMA,offlineConflictRecoveryPolicyEpochGenesisDigest,
 offlineConflictRecoveryPolicyTransitionBytes,offlineConflictRecoveryPolicyTransitionDigest,
 verifyOfflineConflictRecoveryPolicyEpochHistory} from '../src/offline-conflict-recovery-policy-epochs.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const gen=sha('32p independent genesis');
const now=1792200000000;
const keyGroup=(prefix)=>[1,2,3].map(n=>({reviewerId:`${prefix}_reviewer_${n}`, ...generateKeyPairSync('ed25519')}));
const old=keyGroup('old'),next=keyGroup('next'),third=keyGroup('third');
const pub=group=>group.map(({reviewerId,publicKey})=>({reviewerId,publicKey}));
const oldPolicy=pub(old),nextPolicy=pub(next),thirdPolicy=pub(third);
const policyDigest=group=>offlineConflictExchangeRecoveryReviewerPolicyDigest(pub(group));
const head0=offlineConflictRecoveryReceiptGenesisHead(gen);
const epoch0=offlineConflictRecoveryPolicyEpochGenesisDigest({genesisExchangeDigest:gen,initialPolicyDigest:policyDigest(old)});
const signatures=(body,group,bytes)=>group.slice(0,2).map(k=>({reviewerId:k.reviewerId,
 signature:sign(null,bytes(body),k.privateKey).toString('base64url')})).sort((a,b)=>a.reviewerId.localeCompare(b.reviewerId));
const err=code=>e=>e?.code===code;
const t=(name,fn)=>test('32P '+name,fn);
const clone=o=>structuredClone(o);
function decision(group,index){
 const policy=policyDigest(group),pendingRecordDigest=sha(`32p record ${index}`);
 const body={schema:OFFLINE_CONFLICT_EXCHANGE_RECOVERY_SCHEMA,action:'abort',genesisExchangeDigest:gen,
  reviewerPolicyDigest:policy,preHead:{count:index-1,headDigest:sha(`32p before ${index}`)},
  postHead:{count:index,headDigest:pendingRecordDigest},pendingRecordDigest,pendingBytesDigest:sha(`32p pending ${index}`),
  issuedAt:now+index*3000,expiresAt:now+index*3000+30000,nonce:`decision_nonce_${index}_32p`};
 return {body,signatures:signatures(body,group,offlineConflictExchangeRecoveryDecisionBytes)};
}
function transition({from=old,to=next,sequence=1,previousTransitionDigest=epoch0,receiptHead,issuedAt=now+5000,nonce='epoch_nonce_32p_01'}={}){
 const body={schema:OFFLINE_CONFLICT_RECOVERY_POLICY_EPOCH_SCHEMA,sequence,previousTransitionDigest,
  genesisExchangeDigest:gen,fromPolicyDigest:policyDigest(from),toPolicyDigest:policyDigest(to),
  receiptHead,issuedAt,expiresAt:issuedAt+30000,nonce};
 return {body,outgoingSignatures:signatures(body,from,offlineConflictRecoveryPolicyTransitionBytes),
  incomingSignatures:signatures(body,to,offlineConflictRecoveryPolicyTransitionBytes)};
}
async function fixture(fn){
 const root=await mkdtemp(join(tmpdir(),'tj32p-'));
 try{
  const journalDirectory=join(root,'journal');
  const store=createOfflineConflictRecoveryReceiptStore({directory:join(journalDirectory,'.recovery-receipts'),genesisExchangeDigest:gen});
  const d1=decision(old,1),d2=decision(next,2);
  const r1=await store.recordAttempt({decision:d1,reviewers:oldPolicy,expectedReviewerPolicyDigest:policyDigest(old),expectedHead:head0,nowMs:now+4000});
  const r2=await store.recordAttempt({decision:d2,reviewers:nextPolicy,expectedReviewerPolicyDigest:policyDigest(next),expectedHead:{count:1,headDigest:r1.headDigest},nowMs:now+7000});
  const records=[JSON.parse(await readFile(join(journalDirectory,'.recovery-receipts','0001.json'))),JSON.parse(await readFile(join(journalDirectory,'.recovery-receipts','0002.json')))];
  const proof=transition({receiptHead:{count:1,headDigest:r1.headDigest}});
  const pin={count:1,headDigest:offlineConflictRecoveryPolicyTransitionDigest({transition:proof})};
  const args={genesisExchangeDigest:gen,reviewerPolicies:[oldPolicy,nextPolicy],transitions:[proof],segments:[[records[0]],[records[1]]],
   expectedTransitionHead:pin,expectedFinalReceiptHead:{count:2,headDigest:r2.headDigest},
   expectedFinalPolicyDigest:policyDigest(next),nowMs:now+10000};
  return await fn({args,records,proof,r1,r2,journalDirectory});
 }finally{await rm(root,{recursive:true,force:true});}
}
const verify=a=>verifyOfflineConflictRecoveryPolicyEpochHistory(a);
t('valid real 32O receipts and dual-quorum policy rotation verify against external pins',()=>fixture(({args})=>{
 const r=verify(args);assert.equal(r.verifiedTransitions,1);assert.equal(r.verifiedReceiptRecords,2);
 assert.equal(r.authorizesRecovery,false);assert.equal(r.independentlyPublished,false);
}));
t('no-transition genesis history verifies only with independently supplied pins',()=>{
 const r=verify({genesisExchangeDigest:gen,reviewerPolicies:[oldPolicy],transitions:[],segments:[[]],
  expectedTransitionHead:{count:0,headDigest:epoch0},expectedFinalReceiptHead:head0,
  expectedFinalPolicyDigest:policyDigest(old),nowMs:now});assert.equal(r.verifiedTransitions,0);
});
t('missing transition pin rejects',()=>fixture(({args})=>assert.throws(()=>verify({...args,expectedTransitionHead:undefined}),err('EXCHANGE32P_EXTERNAL_PINS_REQUIRED'))));
t('missing receipt pin rejects',()=>fixture(({args})=>assert.throws(()=>verify({...args,expectedFinalReceiptHead:undefined}),err('EXCHANGE32P_EXTERNAL_PINS_REQUIRED'))));
t('missing final policy pin rejects',()=>fixture(({args})=>assert.throws(()=>verify({...args,expectedFinalPolicyDigest:undefined}),err('EXCHANGE32P_EXTERNAL_PINS_REQUIRED'))));
t('wrong independently supplied transition digest rejects',()=>fixture(({args})=>assert.throws(()=>verify({...args,expectedTransitionHead:{count:1,headDigest:sha('fork')}}),err('EXCHANGE32P_EXTERNAL_PIN_MISMATCH'))));
t('wrong independently supplied receipt digest rejects',()=>fixture(({args})=>assert.throws(()=>verify({...args,expectedFinalReceiptHead:{count:2,headDigest:sha('rollback')}}),err('EXCHANGE32P_EXTERNAL_PIN_MISMATCH'))));
t('historical receipt omission rejects',()=>fixture(({args})=>assert.throws(()=>verify({...args,segments:[args.segments[0],[]]}),err('EXCHANGE32P_EXTERNAL_PIN_MISMATCH'))));
t('earlier receipt omission rejects sequence',()=>fixture(({args})=>assert.throws(()=>verify({...args,segments:[[],args.segments[1]]}),err('EXCHANGE32P_EPOCH_FORK_OR_ROLLBACK'))));
t('receipt tamper rejects despite recomputed claimed terminal pin',()=>fixture(({args})=>{
 const changed=clone(args.segments);changed[1][0].action='finalize';
 assert.throws(()=>verify({...args,segments:changed,expectedFinalReceiptHead:{count:2,headDigest:sha('tampered')}}),err('EXCHANGE32P_RECEIPT_INVALID'));
}));
t('receipt policy substitution rejects even if old policy signature valid',()=>fixture(({args})=>{
 const changed=clone(args.segments);changed[1][0].reviewerPolicyDigest=policyDigest(old);
 assert.throws(()=>verify({...args,segments:changed}),err('EXCHANGE32P_RECEIPT_POLICY_MISMATCH'));
}));
t('receipt segment reordering rejects',()=>fixture(({args})=>assert.throws(()=>verify({...args,segments:[args.segments[1],args.segments[0]]}),err('EXCHANGE32P_RECEIPT_POLICY_MISMATCH'))));
t('receipt replay across epochs rejects',()=>fixture(({args})=>{
 const changed=clone(args.segments);changed[1].push(changed[0][0]);
 assert.throws(()=>verify({...args,segments:changed}),err('EXCHANGE32P_RECEIPT_POLICY_MISMATCH'));
}));
t('forged outgoing signature rejects even if new majority valid',()=>fixture(({args})=>{
 const changed=clone(args.transitions);changed[0].outgoingSignatures[0].signature='A'.repeat(86);
 assert.throws(()=>verify({...args,transitions:changed}),err('EXCHANGE32P_SIGNATURE_INVALID'));
}));
t('forged incoming signature rejects even if old majority valid',()=>fixture(({args})=>{
 const changed=clone(args.transitions);changed[0].incomingSignatures[0].signature='A'.repeat(86);
 assert.throws(()=>verify({...args,transitions:changed}),err('EXCHANGE32P_SIGNATURE_INVALID'));
}));
t('outgoing minority rejects',()=>fixture(({args})=>{
 const changed=clone(args.transitions);changed[0].outgoingSignatures.pop();
 assert.throws(()=>verify({...args,transitions:changed}),err('EXCHANGE32P_QUORUM_REQUIRED'));
}));
t('incoming minority rejects',()=>fixture(({args})=>{
 const changed=clone(args.transitions);changed[0].incomingSignatures.pop();
 assert.throws(()=>verify({...args,transitions:changed}),err('EXCHANGE32P_QUORUM_REQUIRED'));
}));
t('duplicate signer rejects',()=>fixture(({args})=>{
 const changed=clone(args.transitions);changed[0].outgoingSignatures[1]=changed[0].outgoingSignatures[0];
 assert.throws(()=>verify({...args,transitions:changed}),err('EXCHANGE32P_SIGNATURE_INVALID'));
}));
t('reversed signer order rejects',()=>fixture(({args})=>{
 const changed=clone(args.transitions);changed[0].incomingSignatures.reverse();
 assert.throws(()=>verify({...args,transitions:changed}),err('EXCHANGE32P_SIGNATURE_INVALID'));
}));
t('untrusted replacement roster rejects external policy pin',()=>fixture(({args})=>{
 assert.throws(()=>verify({...args,reviewerPolicies:[oldPolicy,thirdPolicy]}),err('EXCHANGE32P_EPOCH_FORK_OR_ROLLBACK'));
}));
t('retired reviewer ID reuse rejects even with fresh key',()=>fixture(({args})=>{
 const altered=nextPolicy.map((r,i)=>i===0?{reviewerId:oldPolicy[0].reviewerId,publicKey:r.publicKey}:r);
 assert.throws(()=>verify({...args,reviewerPolicies:[oldPolicy,altered]}),err('EXCHANGE32P_EPOCH_FORK_OR_ROLLBACK'));
}));
t('retired key reuse rejects independently even with different reviewer ID',()=>fixture(({args})=>{
 const altered=nextPolicy.map((r,i)=>i===0?{reviewerId:r.reviewerId,publicKey:oldPolicy[0].publicKey}:r);
 assert.throws(()=>verify({...args,reviewerPolicies:[oldPolicy,altered]}),err('EXCHANGE32P_EPOCH_FORK_OR_ROLLBACK'));
}));
t('wrong predecessor transition digest rejects',()=>fixture(({args})=>{
 const changed=clone(args.transitions);changed[0].body.previousTransitionDigest=sha('wrong predecessor');
 assert.throws(()=>verify({...args,transitions:changed}),err('EXCHANGE32P_EPOCH_FORK_OR_ROLLBACK'));
}));
t('wrong receipt-head transition anchor rejects',()=>fixture(({args})=>{
 const changed=clone(args.transitions);changed[0].body.receiptHead={count:1,headDigest:sha('fake')};
 assert.throws(()=>verify({...args,transitions:changed}),err('EXCHANGE32P_EPOCH_FORK_OR_ROLLBACK'));
}));
t('future transition issuance rejects',()=>fixture(({args})=>{
 const changed=clone(args.transitions);changed[0].body.issuedAt=now+50000;changed[0].body.expiresAt=now+80000;
 assert.throws(()=>verify({...args,transitions:changed}),err('EXCHANGE32P_EPOCH_FORK_OR_ROLLBACK'));
}));
t('recovery receipt predating new epoch rejects',()=>fixture(({args})=>{
 const changed=clone(args.segments);changed[1][0].attemptAt=now+1000;
 assert.throws(()=>verify({...args,segments:changed}),err('EXCHANGE32P_RECEIPT_TIME_ROLLBACK'));
}));
t('invalid transition time window rejects',()=>fixture(({args})=>{
 const changed=clone(args.transitions);changed[0].body.expiresAt=changed[0].body.issuedAt;
 assert.throws(()=>verify({...args,transitions:changed}),err('EXCHANGE32P_TRANSITION_INVALID'));
}));
t('unexpected production claim on transition rejected',()=>fixture(({args})=>{
 const changed=clone(args.transitions);changed[0].body.productionApproved=true;
 assert.throws(()=>verify({...args,transitions:changed}),err('EXCHANGE32P_TRANSITION_INVALID'));
}));
t('unexpected production claim on receipt rejected',()=>fixture(({args})=>{
 const changed=clone(args.segments);changed[1][0].productionApproved=true;
 assert.throws(()=>verify({...args,segments:changed}),err('EXCHANGE32P_RECEIPT_INVALID'));
}));
t('malformed Ed25519 signature rejects',()=>fixture(({args})=>{
 const changed=clone(args.transitions);changed[0].incomingSignatures[0].signature='not-a-signature';
 assert.throws(()=>verify({...args,transitions:changed}),err('EXCHANGE32P_SIGNATURE_INVALID'));
}));
t('no trust inferred from provided policy when external policy digest mismatches',()=>fixture(({args})=>{
 assert.throws(()=>verify({...args,expectedFinalPolicyDigest:sha('untrusted')}),err('EXCHANGE32P_EXTERNAL_PIN_MISMATCH'));
}));
t('second authenticated transition and terminal pin verify',()=>fixture(({args})=>{
 const first=args.transitions[0];const firstDigest=offlineConflictRecoveryPolicyTransitionDigest({transition:first});
 const second=transition({from:next,to:third,sequence:2,previousTransitionDigest:firstDigest,
  receiptHead:args.expectedFinalReceiptHead,issuedAt:now+9000,nonce:'epoch_nonce_32p_02'});
 const extended={...args,reviewerPolicies:[oldPolicy,nextPolicy,thirdPolicy],transitions:[first,second],
  segments:[args.segments[0],args.segments[1],[]],expectedTransitionHead:{count:2,headDigest:offlineConflictRecoveryPolicyTransitionDigest({transition:second})},
  expectedFinalPolicyDigest:policyDigest(third),nowMs:now+12000};
 assert.equal(verify(extended).verifiedTransitions,2);
}));
t('second transition cannot fork first digest',()=>fixture(({args})=>{
 const first=args.transitions[0];const second=transition({from:next,to:third,sequence:2,previousTransitionDigest:sha('fork'),
  receiptHead:args.expectedFinalReceiptHead,issuedAt:now+9000,nonce:'epoch_nonce_32p_02'});
 const extended={...args,reviewerPolicies:[oldPolicy,nextPolicy,thirdPolicy],transitions:[first,second],
  segments:[args.segments[0],args.segments[1],[]],expectedTransitionHead:{count:2,headDigest:offlineConflictRecoveryPolicyTransitionDigest({transition:second})},
  expectedFinalPolicyDigest:policyDigest(third),nowMs:now+12000};
 assert.throws(()=>verify(extended),err('EXCHANGE32P_EPOCH_FORK_OR_ROLLBACK'));
}));
t('validly rehashed duplicate nonce across epochs still rejects',()=>fixture(({args})=>{
 const changed=clone(args.segments);changed[1][0].nonce=changed[0][0].nonce;
 assert.throws(()=>verify({...args,segments:changed}),err('EXCHANGE32P_RECEIPT_INVALID'));
}));
t('validly rehashed duplicate pending digest across epochs still rejects',()=>fixture(({args})=>{
 const changed=clone(args.segments);changed[1][0].pendingBytesDigest=changed[0][0].pendingBytesDigest;
 assert.throws(()=>verify({...args,segments:changed}),err('EXCHANGE32P_RECEIPT_INVALID'));
}));
t('future recovery receipt attempt rejects',()=>fixture(({args})=>{
 const changed=clone(args.segments);changed[1][0].attemptAt=now+100000;
 assert.throws(()=>verify({...args,segments:changed}),err('EXCHANGE32P_RECEIPT_TIME_ROLLBACK'));
}));
t('second signed transition reusing first nonce rejects',()=>fixture(({args})=>{
 const first=args.transitions[0];const second=transition({from:next,to:third,sequence:2,
  previousTransitionDigest:offlineConflictRecoveryPolicyTransitionDigest({transition:first}),
  receiptHead:args.expectedFinalReceiptHead,issuedAt:now+9000,nonce:first.body.nonce});
 const extended={...args,reviewerPolicies:[oldPolicy,nextPolicy,thirdPolicy],transitions:[first,second],
  segments:[args.segments[0],args.segments[1],[]],expectedTransitionHead:{count:2,headDigest:offlineConflictRecoveryPolicyTransitionDigest({transition:second})},
  expectedFinalPolicyDigest:policyDigest(third),nowMs:now+12000};
 assert.throws(()=>verify(extended),err('EXCHANGE32P_EPOCH_FORK_OR_ROLLBACK'));
}));
t('signed rotation reusing retired reviewer ID rejects explicitly',()=>fixture(({args})=>{
 const overlap=next.map((r,i)=>i===0?{...r,reviewerId:old[0].reviewerId}:r);
 const proof=transition({from:old,to:overlap,receiptHead:args.transitions[0].body.receiptHead});
 assert.throws(()=>verify({...args,reviewerPolicies:[oldPolicy,pub(overlap)],transitions:[proof],
  expectedTransitionHead:{count:1,headDigest:offlineConflictRecoveryPolicyTransitionDigest({transition:proof})},
  expectedFinalPolicyDigest:policyDigest(overlap)}),err('EXCHANGE32P_RETIRED_KEY_REUSE'));
}));
t('signed rotation reusing retired Ed25519 key under new ID rejects explicitly',()=>fixture(({args})=>{
 const overlap=next.map((r,i)=>i===0?{...r,publicKey:old[0].publicKey,privateKey:old[0].privateKey}:r);
 const proof=transition({from:old,to:overlap,receiptHead:args.transitions[0].body.receiptHead});
 assert.throws(()=>verify({...args,reviewerPolicies:[oldPolicy,pub(overlap)],transitions:[proof],
  expectedTransitionHead:{count:1,headDigest:offlineConflictRecoveryPolicyTransitionDigest({transition:proof})},
  expectedFinalPolicyDigest:policyDigest(overlap)}),err('EXCHANGE32P_RETIRED_KEY_REUSE'));
}));

t('journal read-only integration verifies on-disk receipt head and dual quorum',()=>fixture(async({args,journalDirectory})=>{
 const journal=createOfflineConflictExchangeJournal({directory:journalDirectory,genesisExchangeDigest:gen});
 const result=await journal.inspectRecoveryPolicyEpochHistory(args);
 assert.equal(result.localReceiptInventoryMatchesPin,true);
 assert.equal(result.verifiedReceiptRecords,2);
}));
t('journal read-only integration rejects a valid proof for a missing local receipt',()=>fixture(async({args,journalDirectory})=>{
 const journal=createOfflineConflictExchangeJournal({directory:journalDirectory,genesisExchangeDigest:gen});
 const {unlink}=await import('node:fs/promises');
 await unlink(join(journalDirectory,'.recovery-receipts','0002.json'));
 await assert.rejects(journal.inspectRecoveryPolicyEpochHistory(args),err('EXCHANGE32O_ROLLBACK_OR_FORK'));
}));
t('journal integration rejects mismatched genesis even with caller-supplied proof',()=>fixture(async({args,journalDirectory})=>{
 const journal=createOfflineConflictExchangeJournal({directory:journalDirectory,genesisExchangeDigest:gen});
 await assert.rejects(journal.inspectRecoveryPolicyEpochHistory({...args,genesisExchangeDigest:sha('other')}),err('EXCHANGE32P_GENESIS_MISMATCH'));
}));
