import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,unlink,readdir,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {spawn} from 'node:child_process';
import {createOfflineConflictExchangeJournal} from '../src/offline-conflict-exchange-journal.mjs';
import {offlineConflictRecoveryReceiptGenesisHead} from '../src/offline-conflict-exchange-recovery-receipts.mjs';
import {offlineConflictRecoveryPolicyEpochGenesisDigest,offlineConflictRecoveryPolicyTransitionBytes,
 offlineConflictRecoveryPolicyTransitionDigest,OFFLINE_CONFLICT_RECOVERY_POLICY_EPOCH_SCHEMA} from '../src/offline-conflict-recovery-policy-epochs.mjs';
import {offlineConflictExchangeRecoveryReviewerPolicyDigest} from '../src/offline-conflict-exchange-recovery.mjs';
import {offlineConflictRecoveryCutoverDigest,OFFLINE_CONFLICT_RECOVERY_CUTOVER_SCHEMA} from '../src/offline-conflict-recovery-policy-cutover.mjs';
import {offlineConflictCutoverAdjudicationBytes,offlineConflictCutoverAdjudicationDigest,
 OFFLINE_CONFLICT_CUTOVER_ADJUDICATION_SCHEMA} from '../src/offline-conflict-recovery-cutover-adjudication.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const gen=sha('32r genesis');const now=1792200000000;
const group=prefix=>[1,2,3].map(i=>({reviewerId:`${prefix}_reviewer_${i}`,...generateKeyPairSync('ed25519')}));
const old=group('old32r'),next=group('new32r');
const pub=g=>g.map(({reviewerId,publicKey})=>({reviewerId,publicKey}));
const digest=g=>offlineConflictExchangeRecoveryReviewerPolicyDigest(pub(g));
const signatures=(b,g,fn)=>g.slice(0,2).map(k=>({reviewerId:k.reviewerId,signature:sign(null,fn(b),k.privateKey).toString('base64url')}));
const receiptHead=offlineConflictRecoveryReceiptGenesisHead(gen);
const transitionBody={schema:OFFLINE_CONFLICT_RECOVERY_POLICY_EPOCH_SCHEMA,sequence:1,
 previousTransitionDigest:offlineConflictRecoveryPolicyEpochGenesisDigest({genesisExchangeDigest:gen,initialPolicyDigest:digest(old)}),
 genesisExchangeDigest:gen,fromPolicyDigest:digest(old),toPolicyDigest:digest(next),receiptHead,
 issuedAt:now-1000,expiresAt:now+30000,nonce:'epoch_nonce_32r_01'};
const transition={body:transitionBody,outgoingSignatures:signatures(transitionBody,old,offlineConflictRecoveryPolicyTransitionBytes),
 incomingSignatures:signatures(transitionBody,next,offlineConflictRecoveryPolicyTransitionBytes)};
const transitionHead={count:1,headDigest:offlineConflictRecoveryPolicyTransitionDigest({transition})};
const history=()=>({genesisExchangeDigest:gen,reviewerPolicies:[pub(old),pub(next)],transitions:[transition],segments:[[],[]],
 expectedTransitionHead:transitionHead,expectedFinalReceiptHead:receiptHead,expectedFinalPolicyDigest:digest(next),nowMs:now});
const cutoverBody=()=>({schema:OFFLINE_CONFLICT_RECOVERY_CUTOVER_SCHEMA,genesisExchangeDigest:gen,
 previousPolicyDigest:digest(old),activePolicyDigest:digest(next),transitionHead,receiptHead,activatedAt:now});
const pin=()=>offlineConflictRecoveryCutoverDigest(cutoverBody());
const err=code=>e=>e?.code===code;
const decisionFor=({action,pendingBytesDigest,head})=>{
 const body={schema:OFFLINE_CONFLICT_CUTOVER_ADJUDICATION_SCHEMA,action,genesisExchangeDigest:gen,
  cutoverDigest:pin(),pendingBytesDigest,previousPolicyDigest:digest(old),activePolicyDigest:digest(next),
  exchangeJournalHead:head,receiptHead,issuedAt:now-500,expiresAt:now+10000,nonce:'cutover_recovery_nonce_32r'};
 return {body,outgoingSignatures:signatures(body,old,offlineConflictCutoverAdjudicationBytes),
 incomingSignatures:signatures(body,next,offlineConflictCutoverAdjudicationBytes)};
};
const resolutionPin=(action,pendingBytesDigest,decisionDigest)=>sha('TJ-32R-RESOLUTION-RECEIPT\0'+JSON.stringify({
 schema:'TJ-OFFLINE-CONFLICT-CUTOVER-RESOLUTION-1',action,genesisExchangeDigest:gen,cutoverDigest:pin(),
 pendingBytesDigest,decisionDigest,resolvedAt:now}));
async function fixture(fn,{stage='after-cutover-pending-sync'}={}){
 const root=await mkdtemp(join(tmpdir(),'tj32r-'));
 try{
  const journal=createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen,
   injectFault:s=>{if(s===stage)throw Object.assign(new Error('simulated crash'),{code:'SIMULATED_CUTOVER_CRASH'});}});
  await assert.rejects(journal.activateRecoveryPolicyCutover({history:history(),expectedPriorPolicyDigest:digest(old),
   expectedCutoverDigest:pin(),expectedExchangeJournalHead:journal.genesisHead}),err('SIMULATED_CUTOVER_CRASH'));
  const bytes=await readFile(join(root,'.recovery-policy-cutover.pending'));
  const pendingBytesDigest=sha(bytes);
  const action=stage==='after-cutover-link-sync'?'finalize':'abort';
  const decision=decisionFor({action,pendingBytesDigest,head:journal.genesisHead});
  const expectedDecisionDigest=offlineConflictCutoverAdjudicationDigest(decision);
  const expectedResolutionDigest=resolutionPin(action,pendingBytesDigest,expectedDecisionDigest);
  const args={decision,history:history(),expectedDecisionDigest,expectedCutoverDigest:pin(),
   expectedPendingBytesDigest:pendingBytesDigest,expectedResolutionDigest,expectedExchangeJournalHead:journal.genesisHead,nowMs:now};
  const restarted=createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen});
  return await fn({root,journal:restarted,args});
 }finally{await rm(root,{recursive:true,force:true});}
}
const t=(name,fn,options)=>test('32R '+name,fn,options);
t('authorized dual-majority aborts unlinked pending cutover with durable receipt',()=>fixture(async({journal,args,root})=>{
 const r=await journal.adjudicateInterruptedRecoveryPolicyCutover(args);
 assert.equal(r.action,'abort');assert.equal(r.receiptDigest,args.expectedResolutionDigest);
 assert.equal(r.authorizesProduction,false);assert.equal(r.independentlyPublished,false);
 assert.equal((await readdir(root)).includes('.recovery-policy-cutover.pending'),false);
 assert.equal((await journal.inspectRecoveryPolicyCutoverResolution({expectedResolutionDigest:args.expectedResolutionDigest})).action,'abort');
 await assert.rejects(journal.activateRecoveryPolicyCutover({history:history(),expectedPriorPolicyDigest:digest(old),
  expectedCutoverDigest:pin(),expectedExchangeJournalHead:journal.genesisHead}),err('EXCHANGE32R_RESOLVED_CUTOVER'));
}));
t('authorized dual-majority finalizes hard-linked pending cutover',()=>fixture(async({journal,args})=>{
 const r=await journal.adjudicateInterruptedRecoveryPolicyCutover(args);assert.equal(r.action,'finalize');
 assert.equal((await journal.inspectActiveRecoveryPolicy({expectedCutoverDigest:pin()})).activePolicyDigest,digest(next));
},{stage:'after-cutover-link-sync'}));
t('missing outgoing majority fails closed',()=>fixture(async({journal,args})=>{
 const d=structuredClone(args.decision);d.outgoingSignatures.pop();
 await assert.rejects(journal.adjudicateInterruptedRecoveryPolicyCutover({...args,decision:d,
 expectedDecisionDigest:offlineConflictCutoverAdjudicationDigest(d)}),err('EXCHANGE32R_QUORUM_REQUIRED'));
}));
t('missing incoming majority fails closed',()=>fixture(async({journal,args})=>{
 const d=structuredClone(args.decision);d.incomingSignatures.pop();
 await assert.rejects(journal.adjudicateInterruptedRecoveryPolicyCutover({...args,decision:d,
 expectedDecisionDigest:offlineConflictCutoverAdjudicationDigest(d)}),err('EXCHANGE32R_QUORUM_REQUIRED'));
}));
t('forged incoming signature rejected with recomputed decision pin',()=>fixture(async({journal,args})=>{
 const d=structuredClone(args.decision);d.incomingSignatures[0].signature='A'.repeat(86);
 await assert.rejects(journal.adjudicateInterruptedRecoveryPolicyCutover({...args,decision:d,
 expectedDecisionDigest:offlineConflictCutoverAdjudicationDigest(d)}),err('EXCHANGE32R_SIGNATURE_INVALID'));
}));
t('forged outgoing signature rejected',()=>fixture(async({journal,args})=>{
 const d=structuredClone(args.decision);d.outgoingSignatures[0].signature='A'.repeat(86);
 await assert.rejects(journal.adjudicateInterruptedRecoveryPolicyCutover({...args,decision:d,
 expectedDecisionDigest:offlineConflictCutoverAdjudicationDigest(d)}),err('EXCHANGE32R_SIGNATURE_INVALID'));
}));
t('expired signed decision rejected',()=>fixture(async({journal,args})=>{
 await assert.rejects(journal.adjudicateInterruptedRecoveryPolicyCutover({...args,nowMs:now+20000}),err('EXCHANGE32R_DECISION_EXPIRED'));
}));
t('wrong external decision pin rejected',()=>fixture(async({journal,args})=>{
 await assert.rejects(journal.adjudicateInterruptedRecoveryPolicyCutover({...args,expectedDecisionDigest:sha('fork')}),err('EXCHANGE32R_EXTERNAL_PIN_MISMATCH'));
}));
t('wrong external receipt pin rejected before mutation',()=>fixture(async({journal,args,root})=>{
 await assert.rejects(journal.adjudicateInterruptedRecoveryPolicyCutover({...args,expectedResolutionDigest:sha('fork')}),err('EXCHANGE32R_RESOLUTION_PIN_MISMATCH'));
 assert.equal((await readdir(root)).includes('.recovery-policy-cutover.pending'),true);
}));
t('wrong pending byte pin rejected',()=>fixture(async({journal,args})=>{
 await assert.rejects(journal.adjudicateInterruptedRecoveryPolicyCutover({...args,expectedPendingBytesDigest:sha('fork')}),err('EXCHANGE32R_STATE_PIN_MISMATCH'));
}));
t('tampered pending marker rejected',()=>fixture(async({journal,args,root})=>{
 const p=join(root,'.recovery-policy-cutover.pending');const e=JSON.parse(await readFile(p));e.activatedAt++;
 await writeFile(p,JSON.stringify(e));
 await assert.rejects(journal.adjudicateInterruptedRecoveryPolicyCutover(args),err('EXCHANGE32R_PENDING_PIN_MISMATCH'));
}));
t('wrong journal pin rejected',()=>fixture(async({journal,args})=>{
 await assert.rejects(journal.adjudicateInterruptedRecoveryPolicyCutover({...args,
 expectedExchangeJournalHead:{count:0,headDigest:sha('wrong')}}),err('EXCHANGE32M_STALE_OR_ROLLED_BACK_HEAD'));
}));
t('substituted reviewer policy rejected',()=>fixture(async({journal,args})=>{
 const h=history();h.reviewerPolicies[1]=pub(group('attacker'));
 await assert.rejects(journal.adjudicateInterruptedRecoveryPolicyCutover({...args,history:h}));
}));
t('cannot abort already hard-linked pending marker',()=>fixture(async({journal,args})=>{
 const d=decisionFor({action:'abort',pendingBytesDigest:args.expectedPendingBytesDigest,head:journal.genesisHead});
 const dig=offlineConflictCutoverAdjudicationDigest(d);
 await assert.rejects(journal.adjudicateInterruptedRecoveryPolicyCutover({...args,decision:d,
 expectedDecisionDigest:dig,expectedResolutionDigest:resolutionPin('abort',args.expectedPendingBytesDigest,dig)}),err('EXCHANGE32R_UNSAFE_ABORT'));
},{stage:'after-cutover-link-sync'}));
t('cannot finalize pending-only marker',()=>fixture(async({journal,args})=>{
 const d=decisionFor({action:'finalize',pendingBytesDigest:args.expectedPendingBytesDigest,head:journal.genesisHead});
 const dig=offlineConflictCutoverAdjudicationDigest(d);
 await assert.rejects(journal.adjudicateInterruptedRecoveryPolicyCutover({...args,decision:d,
 expectedDecisionDigest:dig,expectedResolutionDigest:resolutionPin('finalize',args.expectedPendingBytesDigest,dig)}),err('EXCHANGE32R_UNSAFE_FINALIZE'));
}));
t('replay of authorized decision rejected after successful resolution',()=>fixture(async({journal,args})=>{
 await journal.adjudicateInterruptedRecoveryPolicyCutover(args);
 await assert.rejects(journal.adjudicateInterruptedRecoveryPolicyCutover(args),err('EXCHANGE32R_ALREADY_ADJUDICATED'));
}));
t('independent receipt pin detects substitution',()=>fixture(async({journal,args})=>{
 await journal.adjudicateInterruptedRecoveryPolicyCutover(args);
 await assert.rejects(journal.inspectRecoveryPolicyCutoverResolution({expectedResolutionDigest:sha('fork')}),err('EXCHANGE32R_RESOLUTION_PIN_MISMATCH'));
}));
t('resolution receipt tampering rejected',()=>fixture(async({journal,args,root})=>{
 await journal.adjudicateInterruptedRecoveryPolicyCutover(args);
 const p=join(root,'.recovery-policy-cutover-resolution.json');const e=JSON.parse(await readFile(p));e.resolvedAt++;
 await writeFile(p,JSON.stringify(e));
 await assert.rejects(journal.inspectRecoveryPolicyCutoverResolution({expectedResolutionDigest:args.expectedResolutionDigest}),err('EXCHANGE32R_RECEIPT_INVALID'));
}));
t('symlink receipt substitution rejected',()=>fixture(async({journal,args,root})=>{
 await journal.adjudicateInterruptedRecoveryPolicyCutover(args);
 const p=join(root,'.recovery-policy-cutover-resolution.json');await unlink(p);await symlink('/etc/passwd',p);
 await assert.rejects(journal.inspectRecoveryPolicyCutoverResolution({expectedResolutionDigest:args.expectedResolutionDigest}));
}));
t('crash after durable receipt fsync remains fail-closed without deleting pending',()=>fixture(async({journal,args,root})=>{
 const crash=createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen,
  injectFault:s=>{if(s==='after-cutover-resolution-receipt-sync')throw Object.assign(new Error('crash'),{code:'SIMULATED_RESOLUTION_CRASH'});}});
 await assert.rejects(crash.adjudicateInterruptedRecoveryPolicyCutover(args),err('SIMULATED_RESOLUTION_CRASH'));
 assert.equal((await readdir(root)).includes('.recovery-policy-cutover.pending'),true);
 await assert.rejects(journal.adjudicateInterruptedRecoveryPolicyCutover(args),err('EXCHANGE32R_ALREADY_ADJUDICATED'));
 await assert.rejects(journal.inspectRecoveryPolicyCutoverResolution({expectedResolutionDigest:args.expectedResolutionDigest}),err('EXCHANGE32R_UNCERTAIN_RESOLUTION'));
}));
t('crash after unlink leaves independently verifiable resolution receipt',()=>fixture(async({journal,args,root})=>{
 const crash=createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen,
  injectFault:s=>{if(s==='after-cutover-resolution-unlink-sync')throw Object.assign(new Error('crash'),{code:'SIMULATED_RESOLUTION_CRASH'});}});
 await assert.rejects(crash.adjudicateInterruptedRecoveryPolicyCutover(args),err('SIMULATED_RESOLUTION_CRASH'));
 assert.equal((await journal.inspectRecoveryPolicyCutoverResolution({expectedResolutionDigest:args.expectedResolutionDigest})).action,'abort');
}));
t('two independent journal instances serialize competing recovery attempts',()=>fixture(async({journal,args,root})=>{
 const other=createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen});
 const out=await Promise.allSettled([journal.adjudicateInterruptedRecoveryPolicyCutover(args),other.adjudicateInterruptedRecoveryPolicyCutover(args)]);
 assert.equal(out.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(out.filter(x=>x.status==='rejected').length,1);
}));
t('unexpected authorization flags rejected before signing',()=>fixture(async({args})=>{
 assert.throws(()=>offlineConflictCutoverAdjudicationBytes({...args.decision.body,productionApproved:true}),err('EXCHANGE32R_DECISION_INVALID'));
}));

const serializeArgs=args=>({...args,history:{...args.history,reviewerPolicies:args.history.reviewerPolicies.map(g=>g.map(r=>({
 reviewerId:r.reviewerId,publicKey:r.publicKey.export({format:'pem',type:'spki'})})))}});
async function runWorker(payloadPath){
 return new Promise((resolve,reject)=>{
  const child=spawn(process.execPath,[new URL('./fixtures/objective32r-worker.mjs',import.meta.url).pathname,payloadPath],
   {stdio:['ignore','pipe','pipe']});let out='',error='';
  child.stdout.on('data',d=>out+=d);child.stderr.on('data',d=>error+=d);
  child.once('error',reject);child.once('close',code=>resolve({code,out,error}));
 });
}
t('real cross-process contention admits exactly one authenticated recovery winner',()=>fixture(async({journal,args,root})=>{
 const payload=join(tmpdir(),`tj32r-worker-${process.pid}-${Date.now()}-${Math.random()}.json`);
 await writeFile(payload,JSON.stringify({root,gen,args:serializeArgs(args)}));
 // Payload is an out-of-band test artifact; the journal must never interpret it as a history record.
 // Keep it outside the protected directory to avoid the fail-closed unknown-file check.
 const [a,b]=await Promise.all([runWorker(payload),runWorker(payload)]);
 assert.equal([a,b].filter(r=>r.code===0).length,1,JSON.stringify([a,b]));
 assert.equal([a,b].filter(r=>r.code===2).length,1);
 assert.equal((await journal.inspectRecoveryPolicyCutoverResolution({expectedResolutionDigest:args.expectedResolutionDigest})).action,'abort');
 await unlink(payload);
}));
t('real child-process termination after fsync leaves durable uncertain receipt and no automatic repair',()=>fixture(async({journal,args,root})=>{
 const payload=join(tmpdir(),`tj32r-worker-crash-${process.pid}-${Date.now()}-${Math.random()}.json`);
 await writeFile(payload,JSON.stringify({root,gen,args:serializeArgs(args),crashAt:'after-cutover-resolution-receipt-sync'}));
 const crashed=await runWorker(payload);assert.equal(crashed.code,87,crashed.error);
 await assert.rejects(journal.adjudicateInterruptedRecoveryPolicyCutover(args),err('EXCHANGE32R_ALREADY_ADJUDICATED'));
 await assert.rejects(journal.inspectRecoveryPolicyCutoverResolution({expectedResolutionDigest:args.expectedResolutionDigest}),err('EXCHANGE32R_UNCERTAIN_RESOLUTION'));
 await unlink(payload);
}));
t('aborted receipt rejects substituted active marker',()=>fixture(async({journal,args,root})=>{
 await journal.adjudicateInterruptedRecoveryPolicyCutover(args);
 await writeFile(join(root,'.recovery-policy-cutover.json'),JSON.stringify({...cutoverBody(),cutoverDigest:pin()}),{mode:0o600});
 await assert.rejects(journal.inspectRecoveryPolicyCutoverResolution({expectedResolutionDigest:args.expectedResolutionDigest}),err('EXCHANGE32R_RESOLUTION_STATE_CONFLICT'));
}));
t('finalized receipt rejects missing active marker',()=>fixture(async({journal,args,root})=>{
 await journal.adjudicateInterruptedRecoveryPolicyCutover(args);
 await unlink(join(root,'.recovery-policy-cutover.json'));
 await assert.rejects(journal.inspectRecoveryPolicyCutoverResolution({expectedResolutionDigest:args.expectedResolutionDigest}),err('EXCHANGE32R_RESOLUTION_STATE_CONFLICT'));
},{stage:'after-cutover-link-sync'}));
t('missing independent receipt pin rejected',()=>fixture(async({journal,args})=>{
 await journal.adjudicateInterruptedRecoveryPolicyCutover(args);
 await assert.rejects(journal.inspectRecoveryPolicyCutoverResolution(),err('EXCHANGE32R_EXTERNAL_PINS_REQUIRED'));
}));
