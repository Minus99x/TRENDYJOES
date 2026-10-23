/**
 * Objective 32M — opt-in, Linux single-host, fail-closed durable replay journal
 * for *already signed and independently pinned* offline 32L exchanges.
 * Not a hosted service, independent monotonic anchor, distributed transaction,
 * identity provider, recovery grant, or Shopify integration.
 */
import {createHash} from 'node:crypto';
import {constants as F} from 'node:fs';
import {mkdir,open,lstat,realpath,readdir,link,unlink} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {resolve,join} from 'node:path';
import {decodeOfflineConflictExchangeTranscript,offlineConflictExchangeTranscriptDigest,
 verifyOfflineConflictExchange} from './offline-conflict-proof-exchange.mjs';
import {verifyOfflineConflictExchangeRecoveryDecision} from './offline-conflict-exchange-recovery.mjs';
import {createOfflineConflictRecoveryReceiptStore} from './offline-conflict-exchange-recovery-receipts.mjs';
import {verifyOfflineConflictRecoveryPolicyEpochHistory} from './offline-conflict-recovery-policy-epochs.mjs';
import {createOfflineConflictRecoveryPolicyCutover,offlineConflictRecoveryCutoverDigest,OFFLINE_CONFLICT_RECOVERY_CUTOVER_SCHEMA} from './offline-conflict-recovery-policy-cutover.mjs';
import {offlineConflictExchangeRecoveryReviewerPolicyDigest} from './offline-conflict-exchange-recovery.mjs';
import {verifyOfflineConflictCutoverAdjudication} from './offline-conflict-recovery-cutover-adjudication.mjs';

export const OFFLINE_CONFLICT_EXCHANGE_JOURNAL_SCHEMA='TJ-OFFLINE-CONFLICT-EXCHANGE-JOURNAL-1';
const HEX=/^[a-f0-9]{64}$/;
const MAX_RECORDS=4096,MAX_RECORD_BYTES=2048;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const sha=b=>createHash('sha256').update(b).digest('hex');
const digest=(domain,data)=>sha(Buffer.concat([Buffer.from(domain+'\0'),Buffer.isBuffer(data)?data:Buffer.from(data)]));
const exact=(o,fields)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Object.keys(o).length===fields.length&&
 fields.every(k=>Object.getOwnPropertyDescriptor(o,k)?.value!==undefined&&Object.getOwnPropertyDescriptor(o,k)?.enumerable)&&
 Object.keys(o).every(k=>fields.includes(k));
const HEAD=['count','headDigest'];
const recordFields=['schema','index','previousRecordDigest','exchangeDigest','transcriptDigest',
 'sequence','previousExchangeDigest','proofDigest','proofInventoryDigest','contextDigest','recordDigest'];
const filename=i=>String(i).padStart(4,'0')+'.json';
const headCheck=h=>exact(h,HEAD)&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=MAX_RECORDS&&HEX.test(h.headDigest);
export function offlineConflictExchangeJournalGenesisHead(genesisExchangeDigest){
 if(!HEX.test(genesisExchangeDigest||''))fail('EXCHANGE32M_GENESIS_INVALID');
 return Object.freeze({count:0,headDigest:digest('TJ-32M-GENESIS',genesisExchangeDigest)});
}
const recordDigest=r=>digest('TJ-32M-RECORD',JSON.stringify(r));
const unsafe=e=>['ELOOP','EISDIR','ENOTDIR'].includes(e?.code);
export function createOfflineConflictExchangeJournal({directory,genesisExchangeDigest,lockTimeoutMs=3000,injectFault}={}){
 if(process.platform!=='linux'||!F.O_NOFOLLOW||typeof directory!=='string'||!directory.trim()||
 !HEX.test(genesisExchangeDigest||'')||!Number.isSafeInteger(lockTimeoutMs)||lockTimeoutMs<0||lockTimeoutMs>10000||
 (injectFault!==undefined&&typeof injectFault!=='function'))fail('EXCHANGE32M_CONFIGURATION');
 const dir=resolve(directory),lockPath=join(dir,'.exchange-lock'),pending=join(dir,'.pending.json');
 const receiptDirectory=join(dir,'.recovery-receipts');
 const receipts=createOfflineConflictRecoveryReceiptStore({directory:receiptDirectory,genesisExchangeDigest});
 const cutover=createOfflineConflictRecoveryPolicyCutover({directory:dir,genesisExchangeDigest,injectFault});
 const genesis=offlineConflictExchangeJournalGenesisHead(genesisExchangeDigest);
 async function safeDir(){
  await mkdir(dir,{recursive:true,mode:0o700});
  const [s,r]=await Promise.all([lstat(dir),realpath(dir)]);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0||r!==dir)
   fail('EXCHANGE32M_DIRECTORY_UNSAFE');
  return s;
 }
 async function withLock(fn){
  const ds=await safeDir();let h;
  try{
   h=await open(lockPath,F.O_RDWR|F.O_CREAT|F.O_NOFOLLOW,0o600);
   const [s,p]=await Promise.all([h.stat(),lstat(lockPath)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev)
    fail('EXCHANGE32M_LOCK_UNSAFE');
   await new Promise((ok,no)=>{
    const c=spawn('/usr/bin/flock',['-x','-w',(lockTimeoutMs/1000).toFixed(3),'3'],
     {stdio:['ignore','ignore','ignore',h.fd]});
    c.once('error',()=>no(Object.assign(new Error('EXCHANGE32M_LOCK_UNAVAILABLE'),{code:'EXCHANGE32M_LOCK_UNAVAILABLE'})));
    c.once('close',code=>code===0?ok():no(Object.assign(new Error('EXCHANGE32M_LOCK_UNAVAILABLE'),{code:'EXCHANGE32M_LOCK_UNAVAILABLE'})));
   });
   const check=async()=>{
    const [a,b]=await Promise.all([lstat(dir),lstat(lockPath)]);
    if(!a.isDirectory()||a.ino!==ds.ino||a.dev!==ds.dev||!b.isFile()||b.nlink!==1||b.ino!==s.ino||b.dev!==s.dev)
     fail('EXCHANGE32M_LOCK_UNSAFE');
   };
   await check();return await fn(check);
  }catch(e){if(unsafe(e))fail('EXCHANGE32M_LOCK_UNSAFE');throw e;}
  finally{if(h)await h.close();}
 }
 async function readSafe(path,{allowLinked=false}={}){
  let h;try{
   h=await open(path,F.O_RDONLY|F.O_NOFOLLOW);
   const [s,p]=await Promise.all([h.stat(),lstat(path)]);
   if(!s.isFile()||!(s.nlink===1||(allowLinked&&s.nlink===2))||s.uid!==process.getuid()||(s.mode&0o077)!==0||
    s.ino!==p.ino||s.dev!==p.dev||s.size<2||s.size>MAX_RECORD_BYTES)fail('EXCHANGE32M_RECORD_UNSAFE');
   return await h.readFile();
  }catch(e){if(unsafe(e))fail('EXCHANGE32M_RECORD_UNSAFE');throw e;}
  finally{if(h)await h.close();}
 }
 async function state({allowPending=false,allowLinkedIndex=0}={}){
  const names=await readdir(dir);
  if(names.includes('.pending.json')&&!allowPending)fail('EXCHANGE32M_UNCERTAIN_COMMIT');
  const files=names.filter(n=>n!=='.exchange-lock'&&n!=='.pending.json'&&n!=='.recovery-receipts'&&n!=='.recovery-policy-cutover.json'&&n!=='.recovery-policy-cutover.pending'&&n!=='.recovery-policy-cutover-resolution.json');
  if(files.length>MAX_RECORDS||files.some(n=>!/^\d{4}\.json$/.test(n)))fail('EXCHANGE32M_HISTORY_INVALID');
  let previousRecordDigest=genesis.headDigest,previousExchangeDigest=genesisExchangeDigest;
  const seen=new Set(),entries=[];
  for(let i=1;i<=files.length;i++){
   if(!names.includes(filename(i)))fail('EXCHANGE32M_HISTORY_INVALID');
   const bytes=await readSafe(join(dir,filename(i)),{allowLinked:i===allowLinkedIndex});let e;
   try{e=JSON.parse(bytes.toString('utf8'));}catch{fail('EXCHANGE32M_HISTORY_INVALID');}
   if(!exact(e,recordFields)||!Buffer.from(JSON.stringify(e)).equals(bytes)||
    e.schema!==OFFLINE_CONFLICT_EXCHANGE_JOURNAL_SCHEMA||e.index!==i||e.sequence!==i||
    e.previousRecordDigest!==previousRecordDigest||e.previousExchangeDigest!==previousExchangeDigest||
    ![e.exchangeDigest,e.transcriptDigest,e.proofDigest,e.proofInventoryDigest,e.contextDigest,e.recordDigest].every(x=>HEX.test(x||''))||
    seen.has(e.exchangeDigest))fail('EXCHANGE32M_HISTORY_INVALID');
   const {recordDigest:claimed,...body}=e;
   if(recordDigest(body)!==claimed)fail('EXCHANGE32M_HISTORY_INVALID');
   seen.add(e.exchangeDigest);entries.push(e);
   previousRecordDigest=e.recordDigest;previousExchangeDigest=e.exchangeDigest;
  }
  return {entries,seen,head:{count:entries.length,headDigest:previousRecordDigest},lastExchangeDigest:previousExchangeDigest};
 }
 async function syncDir(){const h=await open(dir,F.O_RDONLY|F.O_DIRECTORY|F.O_NOFOLLOW);try{await h.sync();}finally{await h.close();}}
 function pinned(s,expectedHead){
  if(!headCheck(expectedHead))fail('EXCHANGE32M_EXTERNAL_HEAD_REQUIRED');
  if(s.head.count!==expectedHead.count||s.head.headDigest!==expectedHead.headDigest)
   fail('EXCHANGE32M_STALE_OR_ROLLED_BACK_HEAD');
 }
 function result(s){return Object.freeze({...s.head,lastExchangeDigest:s.lastExchangeDigest,
  readOnly:true,singleHostReplayJournal:true,externallyAnchored:false,hostedAuthentication:false,
  productionApproved:false,authorizesCheckout:false,authorizesRemediation:false});}
 async function inspect({expectedHead}={}){return withLock(async()=>{const s=await state();pinned(s,expectedHead);return result(s);});}
 async function claim({transcriptBytes,verificationArgs,expectedHead}={}){
  if(!Buffer.isBuffer(transcriptBytes)||!verificationArgs||typeof verificationArgs!=='object'||!headCheck(expectedHead))
   fail('EXCHANGE32M_REQUEST_INVALID');
  return withLock(async check=>{
   await cutover.assertNoPending();
   const s=await state();pinned(s,expectedHead);
   if(s.entries.length>=MAX_RECORDS)fail('EXCHANGE32M_HISTORY_FULL');
   const {offer,ack}=decodeOfflineConflictExchangeTranscript(transcriptBytes);
   // The transcript, not caller-supplied receipt objects, is authoritative.
   const v=verifyOfflineConflictExchange({...verificationArgs,offer,ack,seenExchangeDigests:[]});
   if(v.sequence!==s.head.count+1||offer.body.previousExchangeDigest!==s.lastExchangeDigest)
    fail('EXCHANGE32M_SEQUENCE_OR_PREDECESSOR');
   if(s.seen.has(v.exchangeDigest))fail('EXCHANGE32M_REPLAY');
   const contextDigest=digest('TJ-32M-CONTEXT',JSON.stringify({sessionId:offer.body.sessionId,
    senderId:offer.body.senderId,receiverId:offer.body.receiverId,senderNonce:offer.body.senderNonce,
    receiverChallenge:offer.body.receiverChallenge}));
   const body={schema:OFFLINE_CONFLICT_EXCHANGE_JOURNAL_SCHEMA,index:s.head.count+1,
    previousRecordDigest:s.head.headDigest,exchangeDigest:v.exchangeDigest,
    transcriptDigest:offlineConflictExchangeTranscriptDigest(transcriptBytes),sequence:v.sequence,
    previousExchangeDigest:offer.body.previousExchangeDigest,proofDigest:v.proofDigest,
    proofInventoryDigest:v.proofInventoryDigest,contextDigest};
   const e={...body,recordDigest:recordDigest(body)},raw=Buffer.from(JSON.stringify(e));
   if(raw.length>MAX_RECORD_BYTES)fail('EXCHANGE32M_RECORD_TOO_LARGE');
   await check();let h;
   try{
    h=await open(pending,F.O_WRONLY|F.O_CREAT|F.O_EXCL|F.O_NOFOLLOW,0o600);
    await h.writeFile(raw);await h.sync();
   }catch(err){if(err.code==='EEXIST'||unsafe(err))fail('EXCHANGE32M_UNCERTAIN_COMMIT');throw err;}
   finally{if(h)await h.close();}
   await syncDir();if(injectFault)await injectFault('after-pending-sync');
   await check();
   try{await link(pending,join(dir,filename(e.index)));}
   catch(err){if(err.code==='EEXIST')fail('EXCHANGE32M_UNCERTAIN_COMMIT');throw err;}
   await syncDir();if(injectFault)await injectFault('after-link-sync');
   await unlink(pending);await syncDir();
   if(injectFault)await injectFault('after-commit-sync');
   const committed=await state();
   if(committed.head.headDigest!==e.recordDigest||committed.head.count!==e.index)
    fail('EXCHANGE32M_UNCERTAIN_COMMIT');
   return result(committed);
  });
 }
 async function adjudicatePending({decision,reviewers,expectedReviewerPolicyDigest,nowMs,expectedHead,expectedReceiptHead,expectedActivePolicyPin}={}){
  // This path never trusts a head or signing key obtained from the journal.
  if(!headCheck(expectedHead))fail('EXCHANGE32M_EXTERNAL_HEAD_REQUIRED');
  const approval=verifyOfflineConflictExchangeRecoveryDecision({decision,reviewers,expectedReviewerPolicyDigest,nowMs});
  if(approval.genesisExchangeDigest!==genesisExchangeDigest)fail('EXCHANGE32N_GENESIS_MISMATCH');
  const pinnedHead=approval.action==='abort'?approval.preHead:approval.postHead;
  if(expectedHead.count!==pinnedHead.count||expectedHead.headDigest!==pinnedHead.headDigest)
   fail('EXCHANGE32N_EXTERNAL_HEAD_MISMATCH');
  return withLock(async check=>{
   const active=await cutover.inspect({expectedCutoverDigest:expectedActivePolicyPin,allowAbsent:true});
   if(active&&active.activePolicyDigest!==approval.reviewerPolicyDigest)fail('EXCHANGE32Q_RETIRED_POLICY');
   // Once the opt-in receipt inventory exists, legacy unreceipted adjudication
   // cannot bypass nonce and pending-byte replay controls.
   const receiptExists=(await readdir(dir)).includes('.recovery-receipts');
   if(receiptExists&&expectedReceiptHead===undefined)fail('EXCHANGE32O_RECEIPT_PIN_REQUIRED');
   if(expectedReceiptHead!==undefined)await receipts.inspect({expectedHead:expectedReceiptHead});
   await check();let bytes;
   try{bytes=await readSafe(pending,{allowLinked:true});}
   catch(e){if(e?.code==='ENOENT')fail('EXCHANGE32N_PENDING_REQUIRED');throw e;}
   let e;try{e=JSON.parse(bytes.toString('utf8'));}catch{fail('EXCHANGE32N_PENDING_INVALID');}
   if(!exact(e,recordFields)||!Buffer.from(JSON.stringify(e)).equals(bytes)||
    e.schema!==OFFLINE_CONFLICT_EXCHANGE_JOURNAL_SCHEMA||
    e.index!==approval.postHead.count||e.sequence!==e.index||
    e.previousRecordDigest!==approval.preHead.headDigest||
    e.recordDigest!==approval.pendingRecordDigest||
    digest('TJ-32M-RECORD',JSON.stringify(Object.fromEntries(recordFields.filter(k=>k!=='recordDigest').map(k=>[k,e[k]]))))!==e.recordDigest||
    sha(bytes)!==approval.pendingBytesDigest)fail('EXCHANGE32N_PENDING_INVALID');
   const ps=await lstat(pending),recordPath=join(dir,filename(e.index));
   let rs;try{rs=await lstat(recordPath);}catch(err){if(err.code!=='ENOENT')throw err;}
   if(approval.action==='abort'){
    if(rs||ps.nlink!==1)fail('EXCHANGE32N_FORK_OR_LINK_CONFLICT');
    const s=await state({allowPending:true});pinned(s,approval.preHead);
    if(e.previousExchangeDigest!==s.lastExchangeDigest)fail('EXCHANGE32N_PREDECESSOR_INVALID');
   }else{
    if(!rs||ps.nlink!==2||rs.nlink!==2||ps.ino!==rs.ino||ps.dev!==rs.dev)
     fail('EXCHANGE32N_FORK_OR_LINK_CONFLICT');
    const s=await state({allowPending:true,allowLinkedIndex:e.index});pinned(s,approval.postHead);
    const predecessor=s.entries.length>1?s.entries.at(-2).exchangeDigest:genesisExchangeDigest;
    if(e.previousExchangeDigest!==predecessor)fail('EXCHANGE32N_PREDECESSOR_INVALID');
   }
   await check();if(injectFault)await injectFault('before-recovery-unlink');
   let receiptHead;
   if(expectedReceiptHead!==undefined){
    receiptHead=await receipts.recordAttempt({decision,reviewers,expectedReviewerPolicyDigest,expectedHead:expectedReceiptHead,nowMs});
    if(injectFault)await injectFault('after-recovery-receipt-sync');
   }
   await unlink(pending);await syncDir();
   if(injectFault)await injectFault('after-recovery-sync');
   const completed=await state();pinned(completed,pinnedHead);
   return Object.freeze({...result(completed),recoveryAction:approval.action,
    recoveryReviewerCount:approval.reviewerCount,independentlyPublished:false,
    ...(receiptHead?{recoveryAttemptReceiptHead:{count:receiptHead.count,headDigest:receiptHead.headDigest},
     recoveryReceiptCompletionProven:false}: {})});
  });
 }
 async function inspectRecoveryReceipts({expectedReceiptHead}={}){
  return withLock(()=>receipts.inspect({expectedHead:expectedReceiptHead}));
 }
 async function inspectRecoveryPolicyEpochHistory(args={}){
  if(args?.genesisExchangeDigest!==genesisExchangeDigest)fail('EXCHANGE32P_GENESIS_MISMATCH');
  return withLock(async()=>{
   const verified=verifyOfflineConflictRecoveryPolicyEpochHistory(args);
   await receipts.inspect({expectedHead:args.expectedFinalReceiptHead});
   return Object.freeze({...verified,localReceiptInventoryMatchesPin:true});
  });
 }
 async function activateRecoveryPolicyCutover({history,expectedPriorPolicyDigest,expectedCutoverDigest,expectedExchangeJournalHead}={}){
  if(!history||history.genesisExchangeDigest!==genesisExchangeDigest||!HEX.test(expectedPriorPolicyDigest||'')||
   !Array.isArray(history.transitions)||history.transitions.length!==1||
   !Array.isArray(history.segments)||history.segments.length!==2||history.segments[1].length!==0||
   !Array.isArray(history.reviewerPolicies)||history.reviewerPolicies.length!==2)
   fail('EXCHANGE32Q_HISTORY_REQUIRED');
  return withLock(async check=>{
   const names=await readdir(dir);if(names.includes('.recovery-policy-cutover.json'))fail('EXCHANGE32Q_ALREADY_OR_UNCERTAIN');
   await cutover.inspect({allowAbsent:true}); // reject interrupted cutover before any new write
   const exchangeState=await state();pinned(exchangeState,expectedExchangeJournalHead);
   const verified=verifyOfflineConflictRecoveryPolicyEpochHistory(history);
   await receipts.inspect({expectedHead:history.expectedFinalReceiptHead});
   if(offlineConflictExchangeRecoveryReviewerPolicyDigest(history.reviewerPolicies[0])!==expectedPriorPolicyDigest||
    history.transitions[0].body.receiptHead.count!==history.expectedFinalReceiptHead.count||
    history.transitions[0].body.receiptHead.headDigest!==history.expectedFinalReceiptHead.headDigest||
    history.nowMs>history.transitions[0].body.expiresAt)fail('EXCHANGE32Q_CUTOVER_PRECONDITION');
   const body={schema:OFFLINE_CONFLICT_RECOVERY_CUTOVER_SCHEMA,genesisExchangeDigest,
    previousPolicyDigest:expectedPriorPolicyDigest,activePolicyDigest:verified.activeReviewerPolicyDigest,
    transitionHead:history.expectedTransitionHead,receiptHead:history.expectedFinalReceiptHead,activatedAt:history.nowMs};
   await check();return cutover.commit({body,expectedCutoverDigest});
  });
 }
 async function adjudicateInterruptedRecoveryPolicyCutover({decision,history,expectedDecisionDigest,
  expectedCutoverDigest,expectedPendingBytesDigest,expectedResolutionDigest,expectedExchangeJournalHead,nowMs}={}){
  if(!history||history.genesisExchangeDigest!==genesisExchangeDigest||!Array.isArray(history.transitions)||
   history.transitions.length!==1||!Array.isArray(history.reviewerPolicies)||history.reviewerPolicies.length!==2||
   !Array.isArray(history.segments)||history.segments.length!==2||history.segments[1].length!==0)
   fail('EXCHANGE32R_HISTORY_REQUIRED');
  return withLock(async check=>{
   const verified=verifyOfflineConflictRecoveryPolicyEpochHistory(history);
   await receipts.inspect({expectedHead:history.expectedFinalReceiptHead});
   const s=await state({allowPending:true});pinned(s,expectedExchangeJournalHead);
   const approved=verifyOfflineConflictCutoverAdjudication({decision,
    previousReviewers:history.reviewerPolicies[0],activeReviewers:history.reviewerPolicies[1],
    expectedDecisionDigest,expectedCutoverDigest,expectedGenesisExchangeDigest:genesisExchangeDigest,nowMs});
   const b=approved;
   if(b.previousPolicyDigest!==offlineConflictExchangeRecoveryReviewerPolicyDigest(history.reviewerPolicies[0])||
    b.activePolicyDigest!==verified.activeReviewerPolicyDigest||
    b.exchangeJournalHead.count!==s.head.count||b.exchangeJournalHead.headDigest!==s.head.headDigest||
    b.receiptHead.count!==history.expectedFinalReceiptHead.count||
    b.receiptHead.headDigest!==history.expectedFinalReceiptHead.headDigest||
    b.pendingBytesDigest!==expectedPendingBytesDigest||
    b.cutoverDigest!==expectedCutoverDigest)fail('EXCHANGE32R_STATE_PIN_MISMATCH');
   const body={schema:OFFLINE_CONFLICT_RECOVERY_CUTOVER_SCHEMA,genesisExchangeDigest,
    previousPolicyDigest:b.previousPolicyDigest,activePolicyDigest:b.activePolicyDigest,
    transitionHead:history.expectedTransitionHead,receiptHead:history.expectedFinalReceiptHead,activatedAt:history.nowMs};
   if(offlineConflictRecoveryCutoverDigest(body)!==expectedCutoverDigest)
    fail('EXCHANGE32R_CUTOVER_HISTORY_MISMATCH');
   await check();return cutover.adjudicate({action:b.action,expectedCutoverDigest,
    expectedPendingBytesDigest,expectedDecisionDigest,expectedResolutionDigest,nowMs});
  });
 }
 async function inspectRecoveryPolicyCutoverResolution({expectedResolutionDigest}={}){
  return withLock(()=>cutover.inspectResolution({expectedResolutionDigest}));
 }
 // Read-only, fail-closed 32S inspection of an uncertain or locally completed receipt.
 // Never removes pending, retries a decision, or infers independent publication.
 async function inspectRecoveryPolicyCutoverResolutionEvidence({expectedResolutionDigest}={}){
  return withLock(()=>cutover.inspectResolution({expectedResolutionDigest,allowUncertain:true}));
 }
 async function inspectActiveRecoveryPolicy({expectedCutoverDigest}={}){
  return withLock(()=>cutover.inspect({expectedCutoverDigest}));
 }
 return Object.freeze({inspect,claim,adjudicatePending,inspectRecoveryReceipts,inspectRecoveryPolicyEpochHistory,
  activateRecoveryPolicyCutover,inspectActiveRecoveryPolicy,adjudicateInterruptedRecoveryPolicyCutover,inspectRecoveryPolicyCutoverResolution,inspectRecoveryPolicyCutoverResolutionEvidence,
  recoveryReceiptGenesisHead:receipts.genesisHead,genesisHead:genesis});
}
