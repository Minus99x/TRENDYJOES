import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,unlink,link,symlink,stat,readdir,mkdir,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {make,now} from './support/objective32l-fixture.mjs';
import {createOfflineConflictExchangeOffer,acceptOfflineConflictExchangeOffer,encodeOfflineConflictExchangeTranscript} from '../src/offline-conflict-proof-exchange.mjs';
import {createOfflineConflictExchangeJournal,offlineConflictExchangeJournalGenesisHead} from '../src/offline-conflict-exchange-journal.mjs';
import {createOfflineConflictRecoveryReceiptStore,offlineConflictRecoveryReceiptGenesisHead} from '../src/offline-conflict-exchange-recovery-receipts.mjs';
import {OFFLINE_CONFLICT_EXCHANGE_RECOVERY_SCHEMA,offlineConflictExchangeRecoveryDecisionBytes,offlineConflictExchangeRecoveryReviewerPolicyDigest,verifyOfflineConflictExchangeRecoveryDecision} from '../src/offline-conflict-exchange-recovery.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const genesisExchangeDigest=sha('independent-32n-genesis');
const head0=offlineConflictExchangeJournalGenesisHead(genesisExchangeDigest);
const sender=generateKeyPairSync('ed25519'),receiver=generateKeyPairSync('ed25519');
const judges=['judge_0001','judge_0002','judge_0003'].map(reviewerId=>({reviewerId,...generateKeyPairSync('ed25519')}));
const reviewers=judges.map(({reviewerId,publicKey})=>({reviewerId,publicKey}));
const expectedReviewerPolicyDigest=offlineConflictExchangeRecoveryReviewerPolicyDigest(reviewers);
const proof=make();
const context={sessionId:'session_32n_0001',senderId:'sender_32n_0001',receiverId:'receiver_32n_0001',
 senderNonce:'sender_nonce_32n_0001',receiverChallenge:'receiver_challenge_32n_0001',sequence:1,previousExchangeDigest:genesisExchangeDigest};
const common={proofBytes:proof.bytes,expectedPin:proof.pinCandidate,expectedProofDigest:sha(proof.bytes),
 senderPublicKey:sender.publicKey,receiverPublicKey:receiver.publicKey,nowMs:now+2000};
const offer=createOfflineConflictExchangeOffer({...common,...context,senderPrivateKey:sender.privateKey,issuedAt:now,expiresAt:now+60000});
const ack=acceptOfflineConflictExchangeOffer({...common,...context,offer,receiverPrivateKey:receiver.privateKey,nowMs:now+1000,issuedAt:now+1000,expiresAt:now+59000});
const transcriptBytes=encodeOfflineConflictExchangeTranscript({offer,ack});
const verificationArgs={...common,...context};
const err=code=>e=>e?.code===code;
const t=(name,fn)=>test('32O '+name,fn);
const j=(directory,injectFault)=>createOfflineConflictExchangeJournal({directory,genesisExchangeDigest,injectFault});
const claim=journal=>journal.claim({transcriptBytes,verificationArgs,expectedHead:head0});
async function fixture(phase,fn){
 const root=await mkdtemp(join(tmpdir(),'tj32n-')),directory=join(root,'journal');
 try{
  const journal=j(directory,point=>{if(point===phase)throw Error('SIMULATED_POWER_LOSS');});
  await assert.rejects(claim(journal),/SIMULATED_POWER_LOSS/);
  const pendingBytes=await readFile(join(directory,'.pending.json'));
  const pending=JSON.parse(pendingBytes);
  return await fn({root,directory,pendingBytes,pending,preHead:head0,postHead:{count:1,headDigest:pending.recordDigest}});
 }finally{await rm(root,{recursive:true,force:true});}
}
function decision(f,{action='abort',bodyChanges={},signers=judges.slice(0,2),signatureChanges={},policy=reviewers}={}){
 const body={schema:OFFLINE_CONFLICT_EXCHANGE_RECOVERY_SCHEMA,action,genesisExchangeDigest,
  reviewerPolicyDigest:offlineConflictExchangeRecoveryReviewerPolicyDigest(policy),
  preHead:f.preHead,postHead:f.postHead,pendingRecordDigest:f.pending.recordDigest,
  pendingBytesDigest:sha(f.pendingBytes),issuedAt:now,expiresAt:now+30000,nonce:'recovery_nonce_32n_0001',...bodyChanges};
 const bytes=offlineConflictExchangeRecoveryDecisionBytes(body);
 return {body,signatures:signers.map(x=>({reviewerId:x.reviewerId,
  signature:sign(null,bytes,x.privateKey).toString('base64url'),...signatureChanges})).sort((a,b)=>a.reviewerId.localeCompare(b.reviewerId))};
}
const apply=(f,d,overrides={})=>j(f.directory).adjudicatePending({decision:d,reviewers,expectedReviewerPolicyDigest,nowMs:now+1000,
 expectedHead:d.body.action==='abort'?f.preHead:f.postHead,...overrides});

const receipt0=offlineConflictRecoveryReceiptGenesisHead(genesisExchangeDigest);
const applyReceipt=(f,d,opts={})=>apply(f,d,{expectedReceiptHead:receipt0,...opts});
const receiptFile=f=>join(f.directory,'.recovery-receipts','0001.json');
t('genesis receipt head is domain-separated and deterministic',()=>{
 assert.deepEqual(receipt0,offlineConflictRecoveryReceiptGenesisHead(genesisExchangeDigest));
 assert.notEqual(receipt0.headDigest,head0.headDigest);
 assert.throws(()=>offlineConflictRecoveryReceiptGenesisHead('invalid'),err('EXCHANGE32O_GENESIS_INVALID'));
});
t('pre-link authorized abort durably consumes signed nonce before unlink',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);const v=await applyReceipt(f,d);
 assert.equal(v.recoveryAction,'abort');assert.equal(v.recoveryReceiptCompletionProven,false);
 const r=JSON.parse(await readFile(receiptFile(f),'utf8'));
 assert.equal(r.nonce,d.body.nonce);assert.equal(r.action,'abort');
 assert.equal(r.pendingBytesDigest,sha(f.pendingBytes));
 assert.deepEqual(await j(f.directory).inspectRecoveryReceipts({expectedReceiptHead:v.recoveryAttemptReceiptHead}),
  {...v.recoveryAttemptReceiptHead,localOnly:true,externallyPublished:false,completionProven:false});
}));
t('post-link authorized finalize records durable attempt and commits journal',()=>fixture('after-link-sync',async f=>{
 const d=decision(f,{action:'finalize'});const v=await applyReceipt(f,d);
 assert.equal(v.count,1);assert.equal(v.recoveryAction,'finalize');
 assert.equal(JSON.parse(await readFile(receiptFile(f),'utf8')).action,'finalize');
 assert.equal((await j(f.directory).inspect({expectedHead:f.postHead})).count,1);
}));
t('once receipt inventory exists legacy recovery cannot bypass replay ledger',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);const faulty=j(f.directory,phase=>{if(phase==='after-recovery-receipt-sync')throw Error('CRASH');});
 await assert.rejects(faulty.adjudicatePending({decision:d,reviewers,expectedReviewerPolicyDigest,nowMs:now+1,expectedHead:head0,expectedReceiptHead:receipt0}),/CRASH/);
 await assert.rejects(apply(f,d),err('EXCHANGE32O_RECEIPT_PIN_REQUIRED'));
}));
t('crash after durable receipt before unlink consumes nonce and fails closed',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);const faulty=j(f.directory,phase=>{if(phase==='after-recovery-receipt-sync')throw Error('CRASH');});
 await assert.rejects(faulty.adjudicatePending({decision:d,reviewers,expectedReviewerPolicyDigest,nowMs:now+1,expectedHead:head0,expectedReceiptHead:receipt0}),/CRASH/);
 const first=JSON.parse(await readFile(receiptFile(f),'utf8'));
 const pin={count:1,headDigest:first.receiptDigest};
 await assert.rejects(applyReceipt(f,d,{expectedReceiptHead:pin}),err('EXCHANGE32O_REPLAY_OR_FORK'));
 assert.equal((await readdir(f.directory)).includes('.pending.json'),true);
}));
t('fresh nonce cannot reuse pending bytes after interrupted receipt commit',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);const faulty=j(f.directory,phase=>{if(phase==='after-recovery-receipt-sync')throw Error('CRASH');});
 await assert.rejects(faulty.adjudicatePending({decision:d,reviewers,expectedReviewerPolicyDigest,nowMs:now+1,expectedHead:head0,expectedReceiptHead:receipt0}),/CRASH/);
 const first=JSON.parse(await readFile(receiptFile(f),'utf8'));
 const fresh=decision(f,{bodyChanges:{nonce:'recovery_nonce_32o_fresh'}});
 await assert.rejects(applyReceipt(f,fresh,{expectedReceiptHead:{count:1,headDigest:first.receiptDigest}}),err('EXCHANGE32O_REPLAY_OR_FORK'));
}));
t('reissued identical pending after successful abort cannot be adjudicated again',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);const v=await applyReceipt(f,d);
 await writeFile(join(f.directory,'.pending.json'),f.pendingBytes,{mode:0o600});
 const fresh=decision(f,{bodyChanges:{nonce:'recovery_nonce_32o_reissued'}});
 await assert.rejects(applyReceipt(f,fresh,{expectedReceiptHead:v.recoveryAttemptReceiptHead}),err('EXCHANGE32O_REPLAY_OR_FORK'));
}));
t('recovery without independently supplied receipt pin rejects',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);
 await assert.rejects(applyReceipt(f,d,{expectedReceiptHead:null}),err('EXCHANGE32O_EXTERNAL_PIN_REQUIRED'));
}));
t('incorrect independent receipt pin rejects before mutation',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);
 await assert.rejects(applyReceipt(f,d,{expectedReceiptHead:{count:0,headDigest:sha('false-pin')}}),err('EXCHANGE32O_ROLLBACK_OR_FORK'));
 assert.equal((await readdir(f.directory)).includes('.pending.json'),true);
}));
t('forged signature cannot create durable receipt',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);d.signatures[0].signature=(d.signatures[0].signature[0]==='A'?'B':'A')+d.signatures[0].signature.slice(1);
 await assert.rejects(applyReceipt(f,d),err('EXCHANGE32N_SIGNATURE_INVALID'));
 assert.equal((await readdir(f.directory)).includes('.recovery-receipts'),false);
}));
t('wrong reviewer policy pin rejects before receipt write',()=>fixture('after-pending-sync',async f=>{
 await assert.rejects(applyReceipt(f,decision(f),{expectedReviewerPolicyDigest:sha('other')}),err('EXCHANGE32N_POLICY_PIN_MISMATCH'));
}));
t('altered durable receipt bytes reject independently pinned inspection',()=>fixture('after-pending-sync',async f=>{
 const v=await applyReceipt(f,decision(f));const p=receiptFile(f);const r=JSON.parse(await readFile(p,'utf8'));
 r.action='finalize';await writeFile(p,JSON.stringify(r));
 await assert.rejects(j(f.directory).inspectRecoveryReceipts({expectedReceiptHead:v.recoveryAttemptReceiptHead}),err('EXCHANGE32O_RECEIPT_INVALID'));
}));
t('deleted receipt cannot satisfy independently pinned history',()=>fixture('after-pending-sync',async f=>{
 const v=await applyReceipt(f,decision(f));await unlink(receiptFile(f));
 await assert.rejects(j(f.directory).inspectRecoveryReceipts({expectedReceiptHead:v.recoveryAttemptReceiptHead}),err('EXCHANGE32O_ROLLBACK_OR_FORK'));
}));
t('injected additional conflicting receipt is rejected',()=>fixture('after-pending-sync',async f=>{
 const v=await applyReceipt(f,decision(f));await writeFile(join(f.directory,'.recovery-receipts','0002.json'),'{}',{mode:0o600});
 await assert.rejects(j(f.directory).inspectRecoveryReceipts({expectedReceiptHead:v.recoveryAttemptReceiptHead}),err('EXCHANGE32O_RECEIPT_INVALID'));
}));
t('receipt inventory gap fails closed',()=>fixture('after-pending-sync',async f=>{
 await applyReceipt(f,decision(f));await writeFile(join(f.directory,'.recovery-receipts','0003.json'),'{}',{mode:0o600});
 await assert.rejects(j(f.directory).inspectRecoveryReceipts({expectedReceiptHead:receipt0}),err('EXCHANGE32O_INVENTORY_INVALID'));
}));
t('receipt symlink substitution is rejected',()=>fixture('after-pending-sync',async f=>{
 await applyReceipt(f,decision(f));const p=receiptFile(f);const data=await readFile(p);await unlink(p);
 await writeFile(join(f.root,'external.json'),data,{mode:0o600});await symlink(join(f.root,'external.json'),p);
 await assert.rejects(j(f.directory).inspectRecoveryReceipts({expectedReceiptHead:receipt0}),err('EXCHANGE32O_FILE_UNSAFE'));
}));
t('receipt directory permissive mode rejected',()=>fixture('after-pending-sync',async f=>{
 await applyReceipt(f,decision(f));await chmod(join(f.directory,'.recovery-receipts'),0o755);
 await assert.rejects(j(f.directory).inspectRecoveryReceipts({expectedReceiptHead:receipt0}),err('EXCHANGE32O_DIRECTORY_UNSAFE'));
}));
t('crash before receipt write leaves no consumed nonce and permits retry',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);const faulty=j(f.directory,phase=>{if(phase==='before-recovery-unlink')throw Error('CRASH_BEFORE_RECEIPT');});
 await assert.rejects(faulty.adjudicatePending({decision:d,reviewers,expectedReviewerPolicyDigest,nowMs:now+1,expectedHead:head0,expectedReceiptHead:receipt0}),/CRASH_BEFORE_RECEIPT/);
 const v=await applyReceipt(f,d);assert.equal(v.recoveryAction,'abort');
}));
t('crash after recovery sync retains receipt and prevents nonce replay',()=>fixture('after-link-sync',async f=>{
 const d=decision(f,{action:'finalize'});const faulty=j(f.directory,phase=>{if(phase==='after-recovery-sync')throw Error('CRASH_AFTER_SYNC');});
 await assert.rejects(faulty.adjudicatePending({decision:d,reviewers,expectedReviewerPolicyDigest,nowMs:now+1,expectedHead:f.postHead,expectedReceiptHead:receipt0}),/CRASH_AFTER_SYNC/);
 const r=JSON.parse(await readFile(receiptFile(f),'utf8'));
 await assert.rejects(applyReceipt(f,d,{expectedHead:f.postHead,expectedReceiptHead:{count:1,headDigest:r.receiptDigest}}),err('EXCHANGE32N_PENDING_REQUIRED'));
 assert.equal((await j(f.directory).inspect({expectedHead:f.postHead})).count,1);
}));
t('concurrent recoveries serialize and record only one receipt',()=>fixture('after-link-sync',async f=>{
 const d=decision(f,{action:'finalize'});
 const x=await Promise.allSettled([applyReceipt(f,d),applyReceipt(f,d)]);
 assert.equal(x.filter(y=>y.status==='fulfilled').length,1);
 assert.equal(x.filter(y=>y.status==='rejected').length,1);
 assert.equal((await readdir(join(f.directory,'.recovery-receipts'))).length,1);
}));
t('receipt inspection requires independent pin even when directory is empty',async()=>{
 const root=await mkdtemp(join(tmpdir(),'tj32o-empty-'));
 try{
  const store=createOfflineConflictRecoveryReceiptStore({directory:join(root,'receipts'),genesisExchangeDigest});
  await assert.rejects(store.inspect(),err('EXCHANGE32O_EXTERNAL_PIN_REQUIRED'));
  assert.equal((await store.inspect({expectedHead:receipt0})).count,0);
 }finally{await rm(root,{recursive:true,force:true});}
});
t('no receipt field can assert production authorization',()=>fixture('after-pending-sync',async f=>{
 const v=await applyReceipt(f,decision(f));const r=JSON.parse(await readFile(receiptFile(f),'utf8'));
 r.productionApproved=true;await writeFile(receiptFile(f),JSON.stringify(r));
 await assert.rejects(j(f.directory).inspectRecoveryReceipts({expectedReceiptHead:v.recoveryAttemptReceiptHead}),err('EXCHANGE32O_RECEIPT_INVALID'));
}));
t('valid receipt history cannot be rolled back to genesis pin',()=>fixture('after-pending-sync',async f=>{
 await applyReceipt(f,decision(f));
 await assert.rejects(j(f.directory).inspectRecoveryReceipts({expectedReceiptHead:receipt0}),err('EXCHANGE32O_ROLLBACK_OR_FORK'));
}));
t('receipt hardlink substitution is rejected',()=>fixture('after-pending-sync',async f=>{
 const v=await applyReceipt(f,decision(f));await link(receiptFile(f),join(f.root,'linked-receipt.json'));
 await assert.rejects(j(f.directory).inspectRecoveryReceipts({expectedReceiptHead:v.recoveryAttemptReceiptHead}),err('EXCHANGE32O_FILE_UNSAFE'));
}));
t('receipt directory symlink substitution is rejected',()=>fixture('after-pending-sync',async f=>{
 const v=await applyReceipt(f,decision(f));
 const p=join(f.directory,'.recovery-receipts'),other=join(f.root,'other-receipts');
 await mkdir(other,{mode:0o700});await writeFile(join(other,'0001.json'),await readFile(receiptFile(f)),{mode:0o600});
 await rm(p,{recursive:true});await symlink(other,p);
 await assert.rejects(j(f.directory).inspectRecoveryReceipts({expectedReceiptHead:v.recoveryAttemptReceiptHead}),err('EXCHANGE32O_DIRECTORY_UNSAFE'));
}));
t('attacker-rehashed receipt cannot match independently pinned head',()=>fixture('after-pending-sync',async f=>{
 const v=await applyReceipt(f,decision(f));const r=JSON.parse(await readFile(receiptFile(f),'utf8'));
 r.attemptAt++;const {receiptDigest,...body}=r;
 r.receiptDigest=sha(Buffer.concat([Buffer.from('TJ-32O-RECEIPT\0'),Buffer.from(JSON.stringify(body))]));
 await writeFile(receiptFile(f),JSON.stringify(r));
 await assert.rejects(j(f.directory).inspectRecoveryReceipts({expectedReceiptHead:v.recoveryAttemptReceiptHead}),err('EXCHANGE32O_ROLLBACK_OR_FORK'));
}));
