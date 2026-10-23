/**
 * Objective 32W: opt-in, single-Linux-host acceptance ledger for fully verified
 * 32V signed evidence transports. It persists only manifest/session/digest pins.
 * No independent monotonic anchor, remote consensus, hosted auth, or Shopify IO.
 * An interrupted append is deliberately NOT auto-repaired or retried.
 */
import {createHash} from 'node:crypto';
import {constants as F} from 'node:fs';
import {mkdir,open,lstat,realpath,readdir,link,unlink} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {resolve,join} from 'node:path';
import {verifyOfflineConflictResolutionChunks} from './offline-conflict-resolution-chunks.mjs';
import {verifyOfflineConflictManifestClaimDecision} from './offline-conflict-manifest-claim-adjudication.mjs';
import {encodeOfflineConflictManifestClaimTranscript} from './offline-conflict-manifest-claim-transcript.mjs';

export const OFFLINE_CONFLICT_MANIFEST_JOURNAL_SCHEMA='TJ-OFFLINE-CONFLICT-MANIFEST-JOURNAL-1';
export const OFFLINE_CONFLICT_MANIFEST_JOURNAL_MAX_RECORDS=4096;
const HEX=/^[0-9a-f]{64}$/;
const SESSION=/^[A-Za-z0-9_-]{16,96}$/;
const fields=['schema','index','previousRecordDigest','manifestDigest','transportDigest','sessionId','chunkCount','recordDigest'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const digest=(domain,payload)=>createHash('sha256').update(domain+'\0').update(payload).digest('hex');
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value' in d&&d.enumerable;})&&
 Object.keys(o).every(k=>keys.includes(k));
const recordName=n=>String(n).padStart(4,'0')+'.json';
const recordDigest=r=>digest('TJ-32W-RECORD',Buffer.from(JSON.stringify(r)));
const validHead=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&
 h.count<=OFFLINE_CONFLICT_MANIFEST_JOURNAL_MAX_RECORDS&&HEX.test(h.headDigest);
const genesis=Object.freeze({count:0,headDigest:digest('TJ-32W-GENESIS',Buffer.from(OFFLINE_CONFLICT_MANIFEST_JOURNAL_SCHEMA))});
export function offlineConflictManifestJournalGenesisHead(){return {...genesis};}
export function createOfflineConflictManifestJournal({directory,lockTimeoutMs=3000,injectFault}={}){
 if(process.platform!=='linux'||!F.O_NOFOLLOW||typeof directory!=='string'||!directory.trim()||
 !Number.isSafeInteger(lockTimeoutMs)||lockTimeoutMs<0||lockTimeoutMs>10000||
 (injectFault!==undefined&&typeof injectFault!=='function'))fail('EXCHANGE32W_CONFIGURATION');
 const dir=resolve(directory),lockPath=join(dir,'.manifest-lock'),pending=join(dir,'.pending.json');
 async function safeDir(readOnly=false){
  if(!readOnly)await mkdir(dir,{recursive:true,mode:0o700});
  const [s,r]=await Promise.all([lstat(dir),realpath(dir)]);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0||r!==dir)
   fail('EXCHANGE32W_DIRECTORY_UNSAFE');
  return s;
 }
 async function withLock(fn,{readOnly=false}={}){
  const ds=await safeDir(readOnly);let h;
  try{
   h=await open(lockPath,F.O_RDWR|(readOnly?0:F.O_CREAT)|F.O_NOFOLLOW,0o600);
   const [s,p]=await Promise.all([h.stat(),lstat(lockPath)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev)
    fail('EXCHANGE32W_LOCK_UNSAFE');
   await new Promise((ok,no)=>{
    const c=spawn('/usr/bin/flock',['-x','-w',(lockTimeoutMs/1000).toFixed(3),'3'],
     {stdio:['ignore','ignore','ignore',h.fd]});
    c.once('error',()=>no(Object.assign(new Error('EXCHANGE32W_LOCK_UNAVAILABLE'),{code:'EXCHANGE32W_LOCK_UNAVAILABLE'})));
    c.once('close',code=>code===0?ok():no(Object.assign(new Error('EXCHANGE32W_LOCK_UNAVAILABLE'),{code:'EXCHANGE32W_LOCK_UNAVAILABLE'})));
   });
   const check=async()=>{
    const [a,b]=await Promise.all([lstat(dir),lstat(lockPath)]);
    if(!a.isDirectory()||a.ino!==ds.ino||a.dev!==ds.dev||!b.isFile()||b.nlink!==1||
     b.ino!==s.ino||b.dev!==s.dev)fail('EXCHANGE32W_LOCK_UNSAFE');
   };
   await check();return await fn(check);
  }finally{if(h)await h.close();}
 }
 async function readSafe(path,allowLinked=false){
  let h;
  try{
   h=await open(path,F.O_RDONLY|F.O_NOFOLLOW);
   const [s,p]=await Promise.all([h.stat(),lstat(path)]);
   if(!s.isFile()||s.nlink!==(allowLinked?2:1)||s.uid!==process.getuid()||(s.mode&0o077)!==0||
    s.ino!==p.ino||s.dev!==p.dev||s.size<2||s.size>2048)fail('EXCHANGE32W_RECORD_UNSAFE');
   return await h.readFile();
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e?.code))fail('EXCHANGE32W_RECORD_UNSAFE');throw e;}
  finally{if(h)await h.close();}
 }
 async function state({allowPending=false}={}){
  const names=await readdir(dir);
  const hasPending=names.includes('.pending.json');
  if(hasPending&&!allowPending)fail('EXCHANGE32W_UNCERTAIN_COMMIT');
  const records=names.filter(n=>n!=='.manifest-lock'&&n!=='.pending.json');
  if(records.length>OFFLINE_CONFLICT_MANIFEST_JOURNAL_MAX_RECORDS||records.some(n=>!/^\d{4}\.json$/.test(n)))
   fail('EXCHANGE32W_HISTORY_INVALID');
  let head=genesis.headDigest;const seen=new Set(),sessions=new Set(),transports=new Set(),entries=[];
  for(let i=1;i<=records.length;i++){
   if(!names.includes(recordName(i)))fail('EXCHANGE32W_HISTORY_INVALID');
   const path=join(dir,recordName(i));
   const stat=await lstat(path);
   const allowLinked=allowPending&&hasPending&&i===records.length&&stat.nlink===2;
   const bytes=await readSafe(path,allowLinked);let e;
   try{e=JSON.parse(bytes.toString('utf8'));}catch{fail('EXCHANGE32W_HISTORY_INVALID');}
   if(!exact(e,fields)||!Buffer.from(JSON.stringify(e)).equals(bytes)||
    e.schema!==OFFLINE_CONFLICT_MANIFEST_JOURNAL_SCHEMA||e.index!==i||
    e.previousRecordDigest!==head||!HEX.test(e.manifestDigest)||!HEX.test(e.transportDigest)||
    !SESSION.test(e.sessionId)||!Number.isSafeInteger(e.chunkCount)||e.chunkCount<1||e.chunkCount>128||
    !HEX.test(e.recordDigest)||seen.has(e.manifestDigest)||sessions.has(e.sessionId)||transports.has(e.transportDigest))
    fail('EXCHANGE32W_HISTORY_INVALID');
   const {recordDigest:claimed,...body}=e;
   if(recordDigest(body)!==claimed)fail('EXCHANGE32W_HISTORY_INVALID');
   seen.add(e.manifestDigest);sessions.add(e.sessionId);transports.add(e.transportDigest);head=claimed;entries.push(e);
  }
  return {head:{count:records.length,headDigest:head},seen,sessions,transports,entries};
 }
 async function syncDir(){const h=await open(dir,F.O_RDONLY|F.O_DIRECTORY|F.O_NOFOLLOW);try{await h.sync();}finally{await h.close();}}
 function pinned(s,expectedHead){
  if(!validHead(expectedHead))fail('EXCHANGE32W_EXTERNAL_HEAD_REQUIRED');
  if(s.head.count!==expectedHead.count||s.head.headDigest!==expectedHead.headDigest)
   fail('EXCHANGE32W_STALE_OR_ROLLED_BACK_HEAD');
 }
 /** 32X: cryptographically authorized inspection, never cleanup/retry/finalize. */
 async function adjudicateInterruptedClaimReadOnly({decision,reviewerGroupA,reviewerGroupB,
  expectedDecisionDigest,expectedReviewerGroupADigest,expectedReviewerGroupBDigest,
  expectedHead,expectedPendingBytesDigest,nowMs}={}){
  // Authenticate before touching the filesystem. All pins originate outside this journal.
  const authorization=verifyOfflineConflictManifestClaimDecision({decision,reviewerGroupA,reviewerGroupB,
   expectedDecisionDigest,expectedReviewerGroupADigest,expectedReviewerGroupBDigest,
   expectedHead,expectedPendingBytesDigest,nowMs});
  return withLock(async check=>{
   const names=await readdir(dir);
   if(!names.includes('.pending.json'))fail('EXCHANGE32X_PENDING_REQUIRED');
   const pendingStat=await lstat(pending);
   if(!pendingStat.isFile()||pendingStat.isSymbolicLink()||![1,2].includes(pendingStat.nlink))
    fail('EXCHANGE32X_PENDING_UNSAFE');
   const bytes=await readSafe(pending,pendingStat.nlink===2);
   const bytesDigest=createHash('sha256').update(bytes).digest('hex');
   if(bytesDigest!==expectedPendingBytesDigest)fail('EXCHANGE32X_PENDING_PIN_MISMATCH');
   const linked=pendingStat.nlink===2;
   if(linked){
    const target=join(dir,recordName(expectedHead.count+1));let targetStat;
    try{targetStat=await lstat(target);}catch{fail('EXCHANGE32X_LINK_MISMATCH');}
    if(!targetStat.isFile()||targetStat.isSymbolicLink()||targetStat.nlink!==2||
     targetStat.ino!==pendingStat.ino||targetStat.dev!==pendingStat.dev)
     fail('EXCHANGE32X_LINK_MISMATCH');
   }
   const s=await state({allowPending:true});
   const preHead=linked?{count:s.head.count-1,headDigest:s.entries.at(-1)?.previousRecordDigest}:s.head;
   if(preHead.count!==expectedHead.count||preHead.headDigest!==expectedHead.headDigest)
    fail('EXCHANGE32X_HISTORY_PIN_MISMATCH');
   let e;try{e=JSON.parse(bytes.toString('utf8'));}catch{fail('EXCHANGE32X_PENDING_INVALID');}
   if(!exact(e,fields)||!Buffer.from(JSON.stringify(e)).equals(bytes)||
    e.schema!==OFFLINE_CONFLICT_MANIFEST_JOURNAL_SCHEMA||e.index!==preHead.count+1||
    e.previousRecordDigest!==preHead.headDigest||!HEX.test(e.manifestDigest)||
    !HEX.test(e.transportDigest)||!SESSION.test(e.sessionId)||
    !Number.isSafeInteger(e.chunkCount)||e.chunkCount<1||e.chunkCount>128||
    !HEX.test(e.recordDigest)||
    recordDigest(Object.fromEntries(fields.filter(k=>k!=='recordDigest').map(k=>[k,e[k]])))!==e.recordDigest)
    fail('EXCHANGE32X_PENDING_INVALID');
   if(linked){
    const last=s.entries.at(-1),target=join(dir,recordName(e.index));
    const targetStat=await lstat(target);
    if(s.head.count!==e.index||s.head.headDigest!==e.recordDigest||
     !last||JSON.stringify(last)!==JSON.stringify(e)||
     targetStat.ino!==pendingStat.ino||targetStat.dev!==pendingStat.dev||targetStat.nlink!==2)
     fail('EXCHANGE32X_LINK_MISMATCH');
   }else{
    if(s.head.count!==preHead.count||s.seen.has(e.manifestDigest)||
     s.sessions.has(e.sessionId)||s.transports.has(e.transportDigest))
     fail('EXCHANGE32X_PENDING_INVALID');
   }
   const observedState=linked?'linked-pending':'pending-only';
   if(authorization.expectedPendingState!==observedState||authorization.pendingIndex!==e.index||
    authorization.pendingRecordDigest!==e.recordDigest)fail('EXCHANGE32X_DECISION_STATE_MISMATCH');
   await check();
   // Read-only evidence only. A receipt of inspection does not resolve the pending claim.
   return Object.freeze({verified:true,readOnly:true,observedState,priorHead:Object.freeze({...preHead}),
    pendingIndex:e.index,pendingRecordDigest:e.recordDigest,pendingBytesDigest:bytesDigest,
    decisionDigest:expectedDecisionDigest,requiresIndependentResolution:true,
    authorizesRepair:false,authorizesProduction:false,independentlyWitnessed:false});
  },{readOnly:true});
 }
 /** 32Y: canonical bytes from one completed 32X locked inspection; no second
  * filesystem scan, mutation, or assumed remote witness. */
 async function exportInterruptedClaimTranscriptReadOnly(args={}){
  const inspection=await adjudicateInterruptedClaimReadOnly(args);
  return encodeOfflineConflictManifestClaimTranscript({inspection,decision:args.decision,observedAt:args.nowMs});
 }
 function result(s){return Object.freeze({...s.head,acceptedManifestCount:s.head.count,
  durableSingleHostReplayProtection:true,independentlyAnchored:false,hostedAuthentication:false,
  authorizesProduction:false,authorizesCheckout:false});}
 async function inspect({expectedHead}={}){
  return withLock(async()=>{const s=await state();pinned(s,expectedHead);return result(s);});
 }
 async function claim({verificationArgs,expectedHead}={}){
  if(!verificationArgs||typeof verificationArgs!=='object'||Array.isArray(verificationArgs)||!validHead(expectedHead))
   fail('EXCHANGE32W_REQUEST_INVALID');
  return withLock(async check=>{
   const s=await state();pinned(s,expectedHead);
   if(s.head.count>=OFFLINE_CONFLICT_MANIFEST_JOURNAL_MAX_RECORDS)fail('EXCHANGE32W_HISTORY_FULL');
   // The local durable inventory, not the caller's replay Set, is authoritative.
   if(s.seen.has(verificationArgs.expectedManifestDigest)||s.sessions.has(verificationArgs.expectedSessionId)||
    s.transports.has(verificationArgs.expectedTransportDigest))
    fail('EXCHANGE32W_REPLAY');
   const verified=verifyOfflineConflictResolutionChunks({...verificationArgs,
    previouslyAcceptedManifestDigests:s.seen});
   if(verified.verified!==true||verified.chunkManifestVerified!==true)
    fail('EXCHANGE32W_VERIFICATION_REQUIRED');
   const body={schema:OFFLINE_CONFLICT_MANIFEST_JOURNAL_SCHEMA,index:s.head.count+1,
    previousRecordDigest:s.head.headDigest,manifestDigest:verified.chunkManifestDigest,
    transportDigest:verificationArgs.expectedTransportDigest,sessionId:verified.sessionId,
    chunkCount:verified.chunkCount};
   const e={...body,recordDigest:recordDigest(body)},bytes=Buffer.from(JSON.stringify(e));
   if(bytes.length>2048)fail('EXCHANGE32W_RECORD_TOO_LARGE');
   await check();let h;
   try{
    h=await open(pending,F.O_WRONLY|F.O_CREAT|F.O_EXCL|F.O_NOFOLLOW,0o600);
    await h.writeFile(bytes);await h.sync();
   }catch(err){if(err.code==='EEXIST')fail('EXCHANGE32W_UNCERTAIN_COMMIT');throw err;}
   finally{if(h)await h.close();}
   await syncDir();if(injectFault)await injectFault('after-pending-sync');
   await check();
   try{await link(pending,join(dir,recordName(e.index)));}
   catch(err){if(err.code==='EEXIST')fail('EXCHANGE32W_UNCERTAIN_COMMIT');throw err;}
   await syncDir();if(injectFault)await injectFault('after-link-sync');
   await unlink(pending);await syncDir();
   if(injectFault)await injectFault('after-commit-sync');
   const committed=await state();
   if(committed.head.count!==e.index||committed.head.headDigest!==e.recordDigest)
    fail('EXCHANGE32W_UNCERTAIN_COMMIT');
   return result(committed);
  });
 }
 return Object.freeze({inspect,claim,adjudicateInterruptedClaimReadOnly,exportInterruptedClaimTranscriptReadOnly});
}
