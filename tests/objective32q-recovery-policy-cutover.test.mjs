import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,unlink,symlink,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {createOfflineConflictExchangeJournal} from '../src/offline-conflict-exchange-journal.mjs';
import {offlineConflictRecoveryReceiptGenesisHead} from '../src/offline-conflict-exchange-recovery-receipts.mjs';
import {offlineConflictRecoveryPolicyEpochGenesisDigest,offlineConflictRecoveryPolicyTransitionBytes,
 offlineConflictRecoveryPolicyTransitionDigest,OFFLINE_CONFLICT_RECOVERY_POLICY_EPOCH_SCHEMA} from '../src/offline-conflict-recovery-policy-epochs.mjs';
import {offlineConflictExchangeRecoveryReviewerPolicyDigest,offlineConflictExchangeRecoveryDecisionBytes,
 OFFLINE_CONFLICT_EXCHANGE_RECOVERY_SCHEMA} from '../src/offline-conflict-exchange-recovery.mjs';
import {offlineConflictRecoveryCutoverDigest,OFFLINE_CONFLICT_RECOVERY_CUTOVER_SCHEMA} from '../src/offline-conflict-recovery-policy-cutover.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const gen=sha('32q genesis');const now=1792200000000;
const group=prefix=>[1,2,3].map(i=>({reviewerId:`${prefix}_reviewer_${i}`,...generateKeyPairSync('ed25519')}));
const old=group('previous'),next=group('successor');
const pub=g=>g.map(({reviewerId,publicKey})=>({reviewerId,publicKey}));
const digest=g=>offlineConflictExchangeRecoveryReviewerPolicyDigest(pub(g));
const signers=(body,g,bytes)=>g.slice(0,2).map(k=>({reviewerId:k.reviewerId,signature:sign(null,bytes(body),k.privateKey).toString('base64url')}));
const genesisReceipt=offlineConflictRecoveryReceiptGenesisHead(gen);
const epochGenesis=offlineConflictRecoveryPolicyEpochGenesisDigest({genesisExchangeDigest:gen,initialPolicyDigest:digest(old)});
const transitionBody={schema:OFFLINE_CONFLICT_RECOVERY_POLICY_EPOCH_SCHEMA,sequence:1,previousTransitionDigest:epochGenesis,
 genesisExchangeDigest:gen,fromPolicyDigest:digest(old),toPolicyDigest:digest(next),receiptHead:genesisReceipt,
 issuedAt:now-1000,expiresAt:now+30000,nonce:'epoch_nonce_32q_01'};
const transition={body:transitionBody,outgoingSignatures:signers(transitionBody,old,offlineConflictRecoveryPolicyTransitionBytes),
 incomingSignatures:signers(transitionBody,next,offlineConflictRecoveryPolicyTransitionBytes)};
const transitionHead={count:1,headDigest:offlineConflictRecoveryPolicyTransitionDigest({transition})};
const history=()=>({genesisExchangeDigest:gen,reviewerPolicies:[pub(old),pub(next)],transitions:[transition],segments:[[],[]],
 expectedTransitionHead:transitionHead,expectedFinalReceiptHead:genesisReceipt,expectedFinalPolicyDigest:digest(next),nowMs:now});
const body=()=>({schema:OFFLINE_CONFLICT_RECOVERY_CUTOVER_SCHEMA,genesisExchangeDigest:gen,previousPolicyDigest:digest(old),
 activePolicyDigest:digest(next),transitionHead,receiptHead:genesisReceipt,activatedAt:now});
const pin=()=>offlineConflictRecoveryCutoverDigest(body());
const error=code=>e=>e?.code===code;
const clone=structuredClone;
async function fixture(fn,{injectFault}={}){
 const root=await mkdtemp(join(tmpdir(),'tj32q-'));
 try{const journal=createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen,injectFault});
 return await fn({root,journal,args:{history:history(),expectedPriorPolicyDigest:digest(old),expectedCutoverDigest:pin(),expectedExchangeJournalHead:journal.genesisHead}});
 }finally{await rm(root,{recursive:true,force:true});}
}
const t=(name,fn)=>test('32Q '+name,fn);
t('activates dual-majority proof with independently supplied exact cutover pin',()=>fixture(async({journal,args})=>{
 const r=await journal.activateRecoveryPolicyCutover(args);assert.equal(r.cutoverDigest,pin());assert.equal(r.activePolicyDigest,digest(next));
 assert.equal(r.authorizesProduction,false);assert.equal(r.independentlyPublished,false);
 assert.equal((await journal.inspectActiveRecoveryPolicy({expectedCutoverDigest:pin()})).cutoverDigest,pin());
}));
t('restarts with persistent policy activation marker',()=>fixture(async({root,journal,args})=>{
 await journal.activateRecoveryPolicyCutover(args);
 const restarted=createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen});
 assert.equal((await restarted.inspectActiveRecoveryPolicy({expectedCutoverDigest:pin()})).activePolicyDigest,digest(next));
}));
t('cutover is single-use and cannot silently rotate again',()=>fixture(async({journal,args})=>{
 await journal.activateRecoveryPolicyCutover(args);
 await assert.rejects(journal.activateRecoveryPolicyCutover(args),error('EXCHANGE32Q_ALREADY_OR_UNCERTAIN'));
}));
t('wrong independently supplied cutover pin rejects before writes',()=>fixture(async({journal,args,root})=>{
 await assert.rejects(journal.activateRecoveryPolicyCutover({...args,expectedCutoverDigest:sha('wrong')}),error('EXCHANGE32Q_EXTERNAL_PIN_MISMATCH'));
 assert.equal((await readdir(root)).includes('.recovery-policy-cutover.json'),false);
}));
t('wrong previous reviewer policy pin rejects',()=>fixture(async({journal,args})=>{
 await assert.rejects(journal.activateRecoveryPolicyCutover({...args,expectedPriorPolicyDigest:sha('fake')}),error('EXCHANGE32Q_CUTOVER_PRECONDITION'));
}));
t('forged outgoing reviewer majority rejects activation',()=>fixture(async({journal,args})=>{
 const h=history();h.transitions=clone(h.transitions);h.transitions[0].outgoingSignatures[0].signature='A'.repeat(86);
 await assert.rejects(journal.activateRecoveryPolicyCutover({...args,history:h}),error('EXCHANGE32P_SIGNATURE_INVALID'));
}));
t('forged incoming reviewer majority rejects activation',()=>fixture(async({journal,args})=>{
 const h=history();h.transitions=clone(h.transitions);h.transitions[0].incomingSignatures[0].signature='A'.repeat(86);
 await assert.rejects(journal.activateRecoveryPolicyCutover({...args,history:h}),error('EXCHANGE32P_SIGNATURE_INVALID'));
}));
t('incoming minority rejects activation',()=>fixture(async({journal,args})=>{
 const h=history();h.transitions=clone(h.transitions);h.transitions[0].incomingSignatures.pop();
 await assert.rejects(journal.activateRecoveryPolicyCutover({...args,history:h}),error('EXCHANGE32P_QUORUM_REQUIRED'));
}));
t('forked transition pin rejects activation',()=>fixture(async({journal,args})=>{
 const h=history();h.expectedTransitionHead={count:1,headDigest:sha('fork')};
 await assert.rejects(journal.activateRecoveryPolicyCutover({...args,history:h}),error('EXCHANGE32P_EXTERNAL_PIN_MISMATCH'));
}));
t('omitted or extra transition rejected by single-cutover contract',()=>fixture(async({journal,args})=>{
 const h=history();h.transitions=[];
 await assert.rejects(journal.activateRecoveryPolicyCutover({...args,history:h}),error('EXCHANGE32Q_HISTORY_REQUIRED'));
}));
t('post-transition unverified receipt segment blocks cutover',()=>fixture(async({journal,args})=>{
 const h=history();h.segments=[[],[{}]];
 await assert.rejects(journal.activateRecoveryPolicyCutover({...args,history:h}),error('EXCHANGE32Q_HISTORY_REQUIRED'));
}));
t('expired signed transition cannot be activated',()=>fixture(async({journal,args})=>{
 const h=history();h.nowMs=transitionBody.expiresAt+1;
 await assert.rejects(journal.activateRecoveryPolicyCutover({...args,history:h}),error('EXCHANGE32Q_CUTOVER_PRECONDITION'));
}));
t('cutover marker tampering rejected even with original external pin',()=>fixture(async({journal,args,root})=>{
 await journal.activateRecoveryPolicyCutover(args);
 const path=join(root,'.recovery-policy-cutover.json');const obj=JSON.parse(await readFile(path));obj.activePolicyDigest=sha('altered');
 await writeFile(path,JSON.stringify(obj));
 await assert.rejects(journal.inspectActiveRecoveryPolicy({expectedCutoverDigest:pin()}),error('EXCHANGE32Q_CUTOVER_INVALID'));
}));
t('substituted valid marker is rejected by independently pinned digest',()=>fixture(async({journal,args})=>{
 await journal.activateRecoveryPolicyCutover(args);
 await assert.rejects(journal.inspectActiveRecoveryPolicy({expectedCutoverDigest:sha('other')}),error('EXCHANGE32Q_FORK_OR_ROLLBACK'));
}));
t('missing external pin fails closed after cutover',()=>fixture(async({journal,args})=>{
 await journal.activateRecoveryPolicyCutover(args);
 await assert.rejects(journal.inspectActiveRecoveryPolicy(),error('EXCHANGE32Q_EXTERNAL_PIN_REQUIRED'));
}));
t('deleted cutover marker fails closed when external pin is supplied',()=>fixture(async({journal,args,root})=>{
 await journal.activateRecoveryPolicyCutover(args);await unlink(join(root,'.recovery-policy-cutover.json'));
 await assert.rejects(journal.inspectActiveRecoveryPolicy({expectedCutoverDigest:pin()}),error('EXCHANGE32Q_NOT_ACTIVE'));
}));
t('symlinked cutover marker rejects',()=>fixture(async({journal,args,root})=>{
 await journal.activateRecoveryPolicyCutover(args);const p=join(root,'.recovery-policy-cutover.json');
 await unlink(p);await symlink('/etc/passwd',p);
 await assert.rejects(journal.inspectActiveRecoveryPolicy({expectedCutoverDigest:pin()}));
}));
t('pending-only interrupted commit remains fail-closed on restart',()=>fixture(async({journal,args,root})=>{
 await assert.rejects(journal.activateRecoveryPolicyCutover(args),error('SIMULATED_CUTOVER_CRASH'));
 const restarted=createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen});
 await assert.rejects(restarted.inspectActiveRecoveryPolicy({expectedCutoverDigest:pin()}),error('EXCHANGE32Q_UNCERTAIN_CUTOVER'));
 await assert.rejects(restarted.activateRecoveryPolicyCutover(args),error('EXCHANGE32Q_UNCERTAIN_CUTOVER'));
},{injectFault:stage=>{if(stage==='after-cutover-pending-sync')throw Object.assign(new Error('simulated'),{code:'SIMULATED_CUTOVER_CRASH'});}}));
t('linked-but-pending interrupted commit stays fail-closed',()=>fixture(async({journal,args,root})=>{
 await assert.rejects(journal.activateRecoveryPolicyCutover(args),error('SIMULATED_CUTOVER_CRASH'));
 const restarted=createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen});
 await assert.rejects(restarted.inspectActiveRecoveryPolicy({expectedCutoverDigest:pin()}),error('EXCHANGE32Q_UNCERTAIN_CUTOVER'));
},{injectFault:stage=>{if(stage==='after-cutover-link-sync')throw Object.assign(new Error('simulated'),{code:'SIMULATED_CUTOVER_CRASH'});}}));
t('post-commit crash leaves verified active policy',()=>fixture(async({journal,args,root})=>{
 await assert.rejects(journal.activateRecoveryPolicyCutover(args),error('SIMULATED_CUTOVER_CRASH'));
 const restarted=createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen});
 assert.equal((await restarted.inspectActiveRecoveryPolicy({expectedCutoverDigest:pin()})).cutoverDigest,pin());
},{injectFault:stage=>{if(stage==='after-cutover-commit-sync')throw Object.assign(new Error('simulated'),{code:'SIMULATED_CUTOVER_CRASH'});}}));
function decision(group){const b={schema:OFFLINE_CONFLICT_EXCHANGE_RECOVERY_SCHEMA,action:'abort',genesisExchangeDigest:gen,
 reviewerPolicyDigest:digest(group),preHead:{count:0,headDigest:sha('pre')},postHead:{count:1,headDigest:sha('post')},
 pendingRecordDigest:sha('post'),pendingBytesDigest:sha('pending'),issuedAt:now-100,expiresAt:now+10000,nonce:'decision_nonce_32q'};
 return {body:b,signatures:signers(b,group,offlineConflictExchangeRecoveryDecisionBytes)};}
t('old reviewer quorum is rejected after opt-in activation',()=>fixture(async({journal,args})=>{
 await journal.activateRecoveryPolicyCutover(args);
 await assert.rejects(journal.adjudicatePending({decision:decision(old),reviewers:pub(old),expectedReviewerPolicyDigest:digest(old),
 nowMs:now,expectedHead:decision(old).body.preHead,expectedReceiptHead:genesisReceipt,expectedActivePolicyPin:pin()}),error('EXCHANGE32Q_RETIRED_POLICY'));
}));
t('new reviewer quorum still requires external cutover pin',()=>fixture(async({journal,args})=>{
 await journal.activateRecoveryPolicyCutover(args);
 await assert.rejects(journal.adjudicatePending({decision:decision(next),reviewers:pub(next),expectedReviewerPolicyDigest:digest(next),
 nowMs:now,expectedHead:decision(next).body.preHead,expectedReceiptHead:genesisReceipt}),error('EXCHANGE32Q_EXTERNAL_PIN_REQUIRED'));
}));
t('valid active policy does not bypass missing pending journal record',()=>fixture(async({journal,args})=>{
 await journal.activateRecoveryPolicyCutover(args);
 await assert.rejects(journal.adjudicatePending({decision:decision(next),reviewers:pub(next),expectedReviewerPolicyDigest:digest(next),
 nowMs:now,expectedHead:decision(next).body.preHead,expectedReceiptHead:genesisReceipt,expectedActivePolicyPin:pin()}),error('EXCHANGE32N_PENDING_REQUIRED'));
}));
t('concurrent activations serialize to one durable winner',()=>fixture(async({journal,args,root})=>{
 const other=createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen});
 const outcomes=await Promise.allSettled([journal.activateRecoveryPolicyCutover(args),other.activateRecoveryPolicyCutover(args)]);
 assert.equal(outcomes.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(outcomes.filter(x=>x.status==='rejected').length,1);
 assert.equal((await journal.inspectActiveRecoveryPolicy({expectedCutoverDigest:pin()})).activePolicyDigest,digest(next));
}));
t('extra cutover fields cannot smuggle production authorization',()=>{
 assert.throws(()=>offlineConflictRecoveryCutoverDigest({...body(),productionApproved:true}),error('EXCHANGE32Q_CUTOVER_INVALID'));
});

t('missing independent exchange journal pin rejects cutover',()=>fixture(async({journal,args})=>{
 await assert.rejects(journal.activateRecoveryPolicyCutover({...args,expectedExchangeJournalHead:undefined}),error('EXCHANGE32M_EXTERNAL_HEAD_REQUIRED'));
}));
t('forked exchange journal pin rejects cutover',()=>fixture(async({journal,args})=>{
 await assert.rejects(journal.activateRecoveryPolicyCutover({...args,expectedExchangeJournalHead:{count:0,headDigest:sha('wrong')}}),error('EXCHANGE32M_STALE_OR_ROLLED_BACK_HEAD'));
}));
t('uncertain policy cutover blocks exchange claim mutations',()=>fixture(async({journal,args,root})=>{
 await assert.rejects(journal.activateRecoveryPolicyCutover(args),error('SIMULATED_CUTOVER_CRASH'));
 const restarted=createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen});
 await assert.rejects(restarted.claim({transcriptBytes:Buffer.from('invalid'),verificationArgs:{},expectedHead:restarted.genesisHead}),error('EXCHANGE32Q_UNCERTAIN_CUTOVER'));
},{injectFault:stage=>{if(stage==='after-cutover-pending-sync')throw Object.assign(new Error('simulated'),{code:'SIMULATED_CUTOVER_CRASH'});}}));
async function withPreCutoverReceipt(root){
 const {createOfflineConflictRecoveryReceiptStore}=await import('../src/offline-conflict-exchange-recovery-receipts.mjs');
 const store=createOfflineConflictRecoveryReceiptStore({directory:join(root,'.recovery-receipts'),genesisExchangeDigest:gen});
 const b={...decision(old).body,issuedAt:now-8000,expiresAt:now-1000,nonce:'receipt_nonce_before_cutover_32q'};
 const d={body:b,signatures:signers(b,old,offlineConflictExchangeRecoveryDecisionBytes)};
 const receiptHead=await store.recordAttempt({decision:d,reviewers:pub(old),expectedReviewerPolicyDigest:digest(old),
  expectedHead:genesisReceipt,nowMs:now-5000});
 const receipt=JSON.parse(await readFile(join(root,'.recovery-receipts','0001.json')));
 const b2={...transitionBody,receiptHead:{count:receiptHead.count,headDigest:receiptHead.headDigest},
  issuedAt:now-3000,expiresAt:now+20000};
 const proof={body:b2,outgoingSignatures:signers(b2,old,offlineConflictRecoveryPolicyTransitionBytes),
  incomingSignatures:signers(b2,next,offlineConflictRecoveryPolicyTransitionBytes)};
 const h={...history(),transitions:[proof],segments:[[receipt],[]],
  expectedTransitionHead:{count:1,headDigest:offlineConflictRecoveryPolicyTransitionDigest({transition:proof})},
  expectedFinalReceiptHead:{count:receiptHead.count,headDigest:receiptHead.headDigest}};
 const marker={...body(),transitionHead:h.expectedTransitionHead,receiptHead:h.expectedFinalReceiptHead};
 return {history:h,expectedCutoverDigest:offlineConflictRecoveryCutoverDigest(marker)};
}
t('cutover verifies genuine historical recovery receipt inventory before rotation',()=>fixture(async({root,journal,args})=>{
 const {history:h,expectedCutoverDigest}=await withPreCutoverReceipt(root);
 const r=await journal.activateRecoveryPolicyCutover({...args,history:h,expectedCutoverDigest});
 assert.equal(r.receiptHead.count,1);
 assert.equal(r.cutoverDigest,expectedCutoverDigest);
}));
t('local historical receipt omission blocks cutover even with valid signed proof',()=>fixture(async({root,journal,args})=>{
 const {history:h,expectedCutoverDigest}=await withPreCutoverReceipt(root);
 await unlink(join(root,'.recovery-receipts','0001.json'));
 await assert.rejects(journal.activateRecoveryPolicyCutover({...args,history:h,expectedCutoverDigest}),error('EXCHANGE32O_ROLLBACK_OR_FORK'));
}));
