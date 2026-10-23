/**
 * Objective 32O: local, append-only, independently pinned recovery ATTEMPT
 * receipts. A receipt is durably committed BEFORE pending unlink. It proves
 * authorization was attempted, NOT that the unlink completed. A crash between
 * these events deliberately requires independent manual adjudication.
 * No external anchor, distributed atomicity, or production authorization.
 */
import {createHash} from 'node:crypto';
import {constants as F} from 'node:fs';
import {mkdir,open,lstat,realpath,readdir} from 'node:fs/promises';
import {join} from 'node:path';
import {offlineConflictExchangeRecoveryDecisionBytes,verifyOfflineConflictExchangeRecoveryDecision} from './offline-conflict-exchange-recovery.mjs';

export const OFFLINE_CONFLICT_RECOVERY_RECEIPT_SCHEMA='TJ-OFFLINE-CONFLICT-RECOVERY-ATTEMPT-1';
const HEX=/^[0-9a-f]{64}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const sha=b=>createHash('sha256').update(b).digest('hex');
const hash=(domain,bytes)=>sha(Buffer.concat([Buffer.from(domain+'\0'),Buffer.isBuffer(bytes)?bytes:Buffer.from(bytes)]));
const exact=(o,fields)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Object.keys(o).length===fields.length&&
 fields.every(k=>Object.getOwnPropertyDescriptor(o,k)?.value!==undefined&&Object.getOwnPropertyDescriptor(o,k)?.enumerable)&&
 Object.keys(o).every(k=>fields.includes(k));
const HEAD=['count','headDigest'];
const bodyFields=['schema','index','previousReceiptDigest','decisionDigest','reviewerPolicyDigest',
 'nonce','action','genesisExchangeDigest','preHead','postHead','pendingRecordDigest',
 'pendingBytesDigest','attemptAt'];
const fields=[...bodyFields,'receiptDigest'];
const headValid=h=>exact(h,HEAD)&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=4096&&HEX.test(h.headDigest);
const journalHeadValid=h=>headValid(h);
const fileName=i=>String(i).padStart(4,'0')+'.json';
export function offlineConflictRecoveryReceiptGenesisHead(genesisExchangeDigest){
 if(!HEX.test(genesisExchangeDigest||''))fail('EXCHANGE32O_GENESIS_INVALID');
 return Object.freeze({count:0,headDigest:hash('TJ-32O-RECEIPT-GENESIS',genesisExchangeDigest)});
}
export function offlineConflictRecoveryDecisionDigest(decision){
 // Caller MUST first verify the decision's signatures against an external policy pin.
 if(!exact(decision,['body','signatures'])||!Array.isArray(decision.signatures))fail('EXCHANGE32O_DECISION_INVALID');
 const bytes=offlineConflictExchangeRecoveryDecisionBytes(decision.body);
 if(!decision.signatures.every(s=>exact(s,['reviewerId','signature'])&&typeof s.reviewerId==='string'&&typeof s.signature==='string'))
  fail('EXCHANGE32O_DECISION_INVALID');
 return hash('TJ-32O-SIGNED-DECISION',Buffer.concat([bytes,Buffer.from('\0'+JSON.stringify(decision.signatures))]));
}
function validateRecord(e){
 if(!exact(e,fields)||e.schema!==OFFLINE_CONFLICT_RECOVERY_RECEIPT_SCHEMA||
 !Number.isSafeInteger(e.index)||e.index<1||e.index>4096||
 ![e.previousReceiptDigest,e.decisionDigest,e.reviewerPolicyDigest,e.genesisExchangeDigest,
 e.pendingRecordDigest,e.pendingBytesDigest,e.receiptDigest].every(x=>HEX.test(x||''))||
 typeof e.nonce!=='string'||!/^[a-zA-Z0-9_-]{8,80}$/.test(e.nonce)||
 !['abort','finalize'].includes(e.action)||!journalHeadValid(e.preHead)||!journalHeadValid(e.postHead)||
 e.postHead.count!==e.preHead.count+1||e.postHead.headDigest!==e.pendingRecordDigest||
 !Number.isSafeInteger(e.attemptAt)||e.attemptAt<0)fail('EXCHANGE32O_RECEIPT_INVALID');
 const {receiptDigest,...body}=e;
 if(hash('TJ-32O-RECEIPT',JSON.stringify(body))!==receiptDigest)fail('EXCHANGE32O_RECEIPT_INVALID');
}
export function createOfflineConflictRecoveryReceiptStore({directory,genesisExchangeDigest}={}){
 if(process.platform!=='linux'||!F.O_NOFOLLOW||typeof directory!=='string'||!directory||!HEX.test(genesisExchangeDigest||''))
  fail('EXCHANGE32O_CONFIGURATION');
 const root=directory,genesis=offlineConflictRecoveryReceiptGenesisHead(genesisExchangeDigest);
 async function ensureDir(){
  await mkdir(root,{recursive:true,mode:0o700});
  const [s,p]=await Promise.all([lstat(root),realpath(root)]);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0||p!==root)
   fail('EXCHANGE32O_DIRECTORY_UNSAFE');
 }
 async function readSafe(path){
  let h;try{
   h=await open(path,F.O_RDONLY|F.O_NOFOLLOW);
   const [s,p]=await Promise.all([h.stat(),lstat(path)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev||s.size<2||s.size>4096)
    fail('EXCHANGE32O_FILE_UNSAFE');
   return await h.readFile();
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e?.code))fail('EXCHANGE32O_FILE_UNSAFE');throw e;}
  finally{if(h)await h.close();}
 }
 async function state(){
  await ensureDir();const names=await readdir(root);
  if(names.length>4096||names.some(n=>!/^[0-9]{4}\.json$/.test(n)))fail('EXCHANGE32O_INVENTORY_INVALID');
  let previous=genesis.headDigest;const nonces=new Set(),pendingDigests=new Set(),entries=[];
  for(let i=1;i<=names.length;i++){
   if(!names.includes(fileName(i)))fail('EXCHANGE32O_INVENTORY_INVALID');
   const bytes=await readSafe(join(root,fileName(i)));let e;
   try{e=JSON.parse(bytes.toString('utf8'));}catch{fail('EXCHANGE32O_RECEIPT_INVALID');}
   if(!Buffer.from(JSON.stringify(e)).equals(bytes))fail('EXCHANGE32O_RECEIPT_INVALID');
   validateRecord(e);
   if(e.index!==i||e.previousReceiptDigest!==previous||e.genesisExchangeDigest!==genesisExchangeDigest||
    nonces.has(e.nonce)||pendingDigests.has(e.pendingBytesDigest))fail('EXCHANGE32O_REPLAY_OR_FORK');
   nonces.add(e.nonce);pendingDigests.add(e.pendingBytesDigest);entries.push(e);previous=e.receiptDigest;
  }
  return {head:{count:entries.length,headDigest:previous},nonces,pendingDigests,entries};
 }
 function pin(s,expectedHead){
  if(!headValid(expectedHead))fail('EXCHANGE32O_EXTERNAL_PIN_REQUIRED');
  if(s.head.count!==expectedHead.count||s.head.headDigest!==expectedHead.headDigest)
   fail('EXCHANGE32O_ROLLBACK_OR_FORK');
 }
 async function inspect({expectedHead}={}){const s=await state();pin(s,expectedHead);return Object.freeze({...s.head,
  localOnly:true,externallyPublished:false,completionProven:false});}
 // The caller MUST hold the parent journal's cross-process lock for the entire call.
 async function recordAttempt({decision,reviewers,expectedReviewerPolicyDigest,expectedHead,nowMs}={}){
  const approval=verifyOfflineConflictExchangeRecoveryDecision({decision,reviewers,expectedReviewerPolicyDigest,nowMs});
  const s=await state();pin(s,expectedHead);
  if(s.head.count>=4096)fail('EXCHANGE32O_INVENTORY_FULL');
  if(s.nonces.has(approval.nonce)||s.pendingDigests.has(approval.pendingBytesDigest))
   fail('EXCHANGE32O_REPLAY_OR_FORK');
  const body={schema:OFFLINE_CONFLICT_RECOVERY_RECEIPT_SCHEMA,index:s.head.count+1,
   previousReceiptDigest:s.head.headDigest,decisionDigest:offlineConflictRecoveryDecisionDigest(decision),
   reviewerPolicyDigest:approval.reviewerPolicyDigest,nonce:approval.nonce,action:approval.action,
   genesisExchangeDigest:approval.genesisExchangeDigest,preHead:approval.preHead,postHead:approval.postHead,
   pendingRecordDigest:approval.pendingRecordDigest,pendingBytesDigest:approval.pendingBytesDigest,attemptAt:nowMs};
  const receipt={...body,receiptDigest:hash('TJ-32O-RECEIPT',JSON.stringify(body))};
  const raw=Buffer.from(JSON.stringify(receipt));if(raw.length>4096)fail('EXCHANGE32O_RECEIPT_INVALID');
  const path=join(root,fileName(receipt.index));let h;
  try{
   h=await open(path,F.O_WRONLY|F.O_CREAT|F.O_EXCL|F.O_NOFOLLOW,0o600);
   await h.writeFile(raw);await h.sync();
  }catch(e){if(e?.code==='EEXIST')fail('EXCHANGE32O_INVENTORY_INVALID');throw e;}
  finally{if(h)await h.close();}
  const d=await open(root,F.O_RDONLY|F.O_DIRECTORY|F.O_NOFOLLOW);
  try{await d.sync();}finally{await d.close();}
  return Object.freeze({count:receipt.index,headDigest:receipt.receiptDigest,receiptDigest:receipt.receiptDigest,
   decisionAttemptOnly:true,completionProven:false,externallyPublished:false});
 }
 return Object.freeze({inspect,recordAttempt,genesisHead:genesis});
}
