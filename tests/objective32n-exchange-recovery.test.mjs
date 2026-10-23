import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,unlink,link,symlink,stat,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {make,now} from './support/objective32l-fixture.mjs';
import {createOfflineConflictExchangeOffer,acceptOfflineConflictExchangeOffer,encodeOfflineConflictExchangeTranscript} from '../src/offline-conflict-proof-exchange.mjs';
import {createOfflineConflictExchangeJournal,offlineConflictExchangeJournalGenesisHead} from '../src/offline-conflict-exchange-journal.mjs';
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
const t=(name,fn)=>test('32N '+name,fn);
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
t('abort pre-link pending only after independently signed majority approval',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);const v=await apply(f,d);assert.equal(v.recoveryAction,'abort');assert.equal(v.count,0);
 assert.equal(v.recoveryReviewerCount,2);assert.equal(v.authorizesRemediation,false);
 assert.equal((await readdir(f.directory)).includes('.pending.json'),false);
 assert.equal((await j(f.directory).inspect({expectedHead:head0})).count,0);
}));
t('finalize hardlinked pending only after independent signed majority approval',()=>fixture('after-link-sync',async f=>{
 const d=decision(f,{action:'finalize'});const v=await apply(f,d);
 assert.equal(v.recoveryAction,'finalize');assert.equal(v.count,1);
 assert.equal(v.headDigest,f.pending.recordDigest);assert.equal(v.independentlyPublished,false);
 assert.equal((await readdir(f.directory)).includes('.pending.json'),false);
 assert.equal((await stat(join(f.directory,'0001.json'))).nlink,1);
 assert.equal((await j(f.directory).inspect({expectedHead:f.postHead})).count,1);
}));
t('majority signature verifier authenticates canonical decision',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);assert.equal(verifyOfflineConflictExchangeRecoveryDecision({decision:d,reviewers,expectedReviewerPolicyDigest,nowMs:now+1}).reviewerCount,2);
}));
t('one signature cannot adjudicate',()=>fixture('after-pending-sync',async f=>{
 await assert.rejects(apply(f,decision(f,{signers:judges.slice(0,1)})),err('EXCHANGE32N_QUORUM_REQUIRED'));
}));
t('forged signature cannot adjudicate',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);d.signatures[0].signature=(d.signatures[0].signature[0]==='A'?'B':'A')+d.signatures[0].signature.slice(1);
 await assert.rejects(apply(f,d),err('EXCHANGE32N_SIGNATURE_INVALID'));
}));
t('duplicate signer cannot be counted twice',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);d.signatures[1]={...d.signatures[0]};
 await assert.rejects(apply(f,d),err('EXCHANGE32N_SIGNATURE_INVALID'));
}));
t('unsorted signatures rejected',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);d.signatures.reverse();await assert.rejects(apply(f,d),err('EXCHANGE32N_SIGNATURE_INVALID'));
}));
t('untrusted reviewer signature rejected',()=>fixture('after-pending-sync',async f=>{
 const outsider={reviewerId:'judge_outside',...generateKeyPairSync('ed25519')};
 await assert.rejects(apply(f,decision(f,{signers:[judges[0],outsider]})),err('EXCHANGE32N_SIGNATURE_INVALID'));
}));
t('duplicate public key under different identity rejected',()=>fixture('after-pending-sync',async f=>{
 const dup=[reviewers[0],{reviewerId:'judge_0002',publicKey:reviewers[0].publicKey},reviewers[2]];
 await assert.rejects(apply(f,decision(f),{reviewers:dup}),err('EXCHANGE32N_POLICY_INVALID'));
}));
t('two reviewers are not an independently credible majority policy',()=>fixture('after-pending-sync',async f=>{
 await assert.rejects(apply(f,decision(f),{reviewers:reviewers.slice(0,2)}),err('EXCHANGE32N_POLICY_INVALID'));
}));
t('stale or rolled-back externally pinned head rejected',()=>fixture('after-pending-sync',async f=>{
 await assert.rejects(apply(f,decision(f),{expectedHead:{count:0,headDigest:sha('forged-head')}}),err('EXCHANGE32N_EXTERNAL_HEAD_MISMATCH'));
}));
t('recovery action cannot be changed after signing',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);d.body.action='finalize';await assert.rejects(apply(f,d),err('EXCHANGE32N_SIGNATURE_INVALID'));
}));
t('post-link cannot be aborted even with valid abort quorum',()=>fixture('after-link-sync',async f=>{
 await assert.rejects(apply(f,decision(f)),err('EXCHANGE32N_FORK_OR_LINK_CONFLICT'));
}));
t('pre-link cannot be finalized even with valid finalize quorum',()=>fixture('after-pending-sync',async f=>{
 await assert.rejects(apply(f,decision(f,{action:'finalize'})),err('EXCHANGE32N_FORK_OR_LINK_CONFLICT'));
}));
t('wrong genesis binding fails closed',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f,{bodyChanges:{genesisExchangeDigest:sha('another-genesis')}});
 await assert.rejects(apply(f,d),err('EXCHANGE32N_GENESIS_MISMATCH'));
}));
t('wrong pending bytes pin rejected despite valid signatures',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f,{bodyChanges:{pendingBytesDigest:sha('different-pending')}});
 await assert.rejects(apply(f,d),err('EXCHANGE32N_PENDING_INVALID'));
}));
t('tampered pending bytes rejected despite valid decision',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);await writeFile(join(f.directory,'.pending.json'),Buffer.from(f.pendingBytes.toString().replace(f.pending.exchangeDigest,sha('tampered-exchange'))));
 await assert.rejects(apply(f,d),err('EXCHANGE32N_PENDING_INVALID'));
}));
t('pending file symlink rejected',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);await writeFile(join(f.root,'evil.json'),f.pendingBytes);
 await unlink(join(f.directory,'.pending.json'));await symlink(join(f.root,'evil.json'),join(f.directory,'.pending.json'));
 await assert.rejects(apply(f,d),err('EXCHANGE32M_RECORD_UNSAFE'));
}));
t('post-link replaced numbered inode is rejected as fork',()=>fixture('after-link-sync',async f=>{
 const d=decision(f,{action:'finalize'});
 await unlink(join(f.directory,'0001.json'));await writeFile(join(f.directory,'0001.json'),f.pendingBytes,{mode:0o600});
 await assert.rejects(apply(f,d),err('EXCHANGE32N_FORK_OR_LINK_CONFLICT'));
}));
t('pre-link forged numbered record is rejected as fork',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);await writeFile(join(f.directory,'0001.json'),f.pendingBytes,{mode:0o600});
 await assert.rejects(apply(f,d),err('EXCHANGE32N_FORK_OR_LINK_CONFLICT'));
}));
t('expired signed adjudication cannot mutate',()=>fixture('after-pending-sync',async f=>{
 await assert.rejects(apply(f,decision(f),{nowMs:now+40000}),err('EXCHANGE32N_DECISION_EXPIRED'));
}));
t('future issued signed adjudication cannot mutate',()=>fixture('after-pending-sync',async f=>{
 await assert.rejects(apply(f,decision(f),{nowMs:now-1}),err('EXCHANGE32N_DECISION_EXPIRED'));
}));
t('excessive validity interval is rejected',()=>fixture('after-pending-sync',async f=>{
 assert.throws(()=>decision(f,{bodyChanges:{expiresAt:now+3600001}}),err('EXCHANGE32N_DECISION_INVALID'));
}));
t('extra decision fields are rejected',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);d.body.productionApproved=true;
 await assert.rejects(apply(f,d),err('EXCHANGE32N_DECISION_INVALID'));
}));
t('extra envelope fields are rejected',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);d.allowShopifyWrites=true;
 await assert.rejects(apply(f,d),err('EXCHANGE32N_POLICY_INVALID'));
}));
t('pre-link pending record cannot be replayed after abort',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);await apply(f,d);await assert.rejects(apply(f,d),err('EXCHANGE32N_PENDING_REQUIRED'));
}));
t('post-link pending record cannot be replayed after finalize',()=>fixture('after-link-sync',async f=>{
 const d=decision(f,{action:'finalize'});await apply(f,d);
 await assert.rejects(apply(f,d),err('EXCHANGE32N_PENDING_REQUIRED'));
}));
t('injected interruption before adjudication unlink preserves fail-closed pending',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);const faulty=j(f.directory,phase=>{if(phase==='before-recovery-unlink')throw Error('RECOVERY_POWER_LOSS');});
 await assert.rejects(faulty.adjudicatePending({decision:d,reviewers,expectedReviewerPolicyDigest,nowMs:now+1,expectedHead:head0}),/RECOVERY_POWER_LOSS/);
 await assert.rejects(j(f.directory).inspect({expectedHead:head0}),err('EXCHANGE32M_UNCERTAIN_COMMIT'));
 await apply(f,d);assert.equal((await j(f.directory).inspect({expectedHead:head0})).count,0);
}));
t('injected interruption after adjudication fsync does not allow replay',()=>fixture('after-link-sync',async f=>{
 const d=decision(f,{action:'finalize'});const faulty=j(f.directory,phase=>{if(phase==='after-recovery-sync')throw Error('RECOVERY_POWER_LOSS');});
 await assert.rejects(faulty.adjudicatePending({decision:d,reviewers,expectedReviewerPolicyDigest,nowMs:now+1,expectedHead:f.postHead}),/RECOVERY_POWER_LOSS/);
 await assert.rejects(apply(f,d),err('EXCHANGE32N_PENDING_REQUIRED'));
 assert.equal((await j(f.directory).inspect({expectedHead:f.postHead})).count,1);
}));
t('cross-directory pending evidence substitution fails',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);const bad=j(f.directory);
 const another=decision(f,{bodyChanges:{pendingBytesDigest:sha('other')}});
 await assert.rejects(bad.adjudicatePending({decision:another,reviewers,expectedReviewerPolicyDigest,nowMs:now+1,expectedHead:head0}),err('EXCHANGE32N_PENDING_INVALID'));
 assert.equal((await apply(f,d)).recoveryAction,'abort');
}));
t('invalid nowMs fails closed',()=>fixture('after-pending-sync',async f=>{
 await assert.rejects(apply(f,decision(f),{nowMs:NaN}),err('EXCHANGE32N_POLICY_INVALID'));
}));
t('two concurrent authorized recoveries serialize and cannot double-adjudicate',()=>fixture('after-link-sync',async f=>{
 const d=decision(f,{action:'finalize'});
 const outcomes=await Promise.allSettled([apply(f,d),apply(f,d)]);
 assert.equal(outcomes.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(outcomes.filter(x=>x.status==='rejected'&&x.reason.code==='EXCHANGE32N_PENDING_REQUIRED').length,1);
 assert.equal((await j(f.directory).inspect({expectedHead:f.postHead})).count,1);
}));
t('three of five distinct reviewers meet majority',()=>fixture('after-pending-sync',async f=>{
 const extra=['judge_0004','judge_0005'].map(reviewerId=>({reviewerId,...generateKeyPairSync('ed25519')}));
 const five=[...reviewers,...extra.map(({reviewerId,publicKey})=>({reviewerId,publicKey}))];
 const d=decision(f,{signers:[...judges.slice(0,2),extra[0]],policy:five});
 assert.equal((await apply(f,d,{reviewers:five,expectedReviewerPolicyDigest:offlineConflictExchangeRecoveryReviewerPolicyDigest(five)})).recoveryReviewerCount,3);
}));
t('two of five distinct reviewers cannot authorize',()=>fixture('after-pending-sync',async f=>{
 const extra=['judge_0004','judge_0005'].map(reviewerId=>({reviewerId,...generateKeyPairSync('ed25519')}));
 const five=[...reviewers,...extra.map(({reviewerId,publicKey})=>({reviewerId,publicKey}))];
 await assert.rejects(apply(f,decision(f,{policy:five}),{reviewers:five,expectedReviewerPolicyDigest:offlineConflictExchangeRecoveryReviewerPolicyDigest(five)}),err('EXCHANGE32N_QUORUM_REQUIRED'));
}));
t('signed predecessor head substitution fails signature verification',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);d.body.preHead={count:0,headDigest:sha('replacement-predecessor')};
 await assert.rejects(apply(f,d),err('EXCHANGE32N_SIGNATURE_INVALID'));
}));
t('independent reviewer-policy pin mismatch blocks valid signatures',()=>fixture('after-pending-sync',async f=>{
 await assert.rejects(apply(f,decision(f),{expectedReviewerPolicyDigest:sha('untrusted-roster')}),err('EXCHANGE32N_POLICY_PIN_MISMATCH'));
}));
t('signed reviewer-policy substitution fails closed',()=>fixture('after-pending-sync',async f=>{
 const d=decision(f);d.body.reviewerPolicyDigest=sha('forged-policy');
 await assert.rejects(apply(f,d),err('EXCHANGE32N_POLICY_PIN_MISMATCH'));
}));
t('missing independent reviewer-policy pin blocks recovery',()=>fixture('after-pending-sync',async f=>{
 await assert.rejects(apply(f,decision(f),{expectedReviewerPolicyDigest:undefined}),err('EXCHANGE32N_POLICY_INVALID'));
}));
