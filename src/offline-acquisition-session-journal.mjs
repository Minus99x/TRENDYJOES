/**
 * Objective 31M — single-host, opt-in, durable forensic acquisition session.
 * A session directory is single-use. An interrupted or uncertain session is
 * permanently read-only; no resume, rollback, ACK, deletion or recovery grant.
 * External retention pins and trust keys are never derived from local files.
 * Linux-only prototype; not an independently retained witness service.
 */
import {createHash} from 'node:crypto';
import {constants as F} from 'node:fs';
import {mkdir,open,lstat,readdir,rename} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {resolve,join} from 'node:path';
import {verifyOfflineForensicAcquisitionManifest} from './offline-forensic-acquisition-provenance.mjs';

export const OFFLINE_ACQUISITION_SESSION_SCHEMA='TJ-OFFLINE-ACQUISITION-SESSION-1';
const ROOT='0'.repeat(64),HEX=/^[0-9a-f]{64}$/,ID=/^[A-Za-z0-9_-]{12,80}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,fields)=>obj(x)&&Object.keys(x).sort().join('|')===fields.slice().sort().join('|');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const sha=b=>createHash('sha256').update(b).digest('hex');
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=2000&&HEX.test(h.headDigest)&&(h.count===0)===(h.headDigest===ROOT);
const heads=h=>exact(h,['forensic','publication','outbox'])&&Object.values(h).every(head);
const file=i=>String(i).padStart(4,'0')+'.json';
const digest=b=>sha(Buffer.from(`${OFFLINE_ACQUISITION_SESSION_SCHEMA}\0${JSON.stringify(b)}`));

/** The journal itself carries no keys or authority to retry an interrupted acquisition. */
export function createOfflineAcquisitionSessionJournal({directory,lockTimeoutMs=5000,injectFault}={}){
 if(process.platform!=='linux'||!F.O_NOFOLLOW||typeof directory!=='string'||!directory.trim()||!Number.isSafeInteger(lockTimeoutMs)||lockTimeoutMs<0||lockTimeoutMs>10000||(injectFault!==undefined&&typeof injectFault!=='function'))fail('ACQUISITION_SESSION_CONFIGURATION');
 const dir=resolve(directory),lock=join(dir,'.session-lock'),pending=join(dir,'.pending.json');
 async function safeDir(){
  await mkdir(dir,{recursive:true,mode:0o700});const s=await lstat(dir);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0)fail('ACQUISITION_SESSION_DIRECTORY_UNSAFE');return s;
 }
 async function withLock(fn){
  const d=await safeDir();let h;
  try{
   h=await open(lock,F.O_RDWR|F.O_CREAT|F.O_NOFOLLOW,0o600);
   const [s,p]=await Promise.all([h.stat(),lstat(lock)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev)fail('ACQUISITION_SESSION_LOCK_UNSAFE');
   await new Promise((ok,no)=>{const c=spawn('/usr/bin/flock',['-x','-w',(lockTimeoutMs/1000).toFixed(3),'3'],{stdio:['ignore','ignore','ignore',h.fd]});c.once('error',()=>no(Object.assign(Error('ACQUISITION_SESSION_LOCK_UNAVAILABLE'),{code:'ACQUISITION_SESSION_LOCK_UNAVAILABLE'})));c.once('close',code=>code===0?ok():no(Object.assign(Error('ACQUISITION_SESSION_LOCK_UNAVAILABLE'),{code:'ACQUISITION_SESSION_LOCK_UNAVAILABLE'})));});
   const check=async()=>{const [a,b]=await Promise.all([lstat(dir),lstat(lock)]);if(!a.isDirectory()||a.ino!==d.ino||a.dev!==d.dev||!b.isFile()||b.ino!==s.ino||b.dev!==s.dev||b.nlink!==1)fail('ACQUISITION_SESSION_LOCK_UNSAFE');};
   await check();return await fn(check);
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('ACQUISITION_SESSION_LOCK_UNSAFE');throw e;}finally{if(h)await h.close();}
 }
 async function readSafe(path){
  let h;try{
   h=await open(path,F.O_RDONLY|F.O_NOFOLLOW);const [s,p]=await Promise.all([h.stat(),lstat(path)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev||s.size<2||s.size>12*1024*1024)fail('ACQUISITION_SESSION_FILE_UNSAFE');
   return await h.readFile();
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('ACQUISITION_SESSION_FILE_UNSAFE');throw e;}finally{if(h)await h.close();}
 }
 async function state(){
  const names=await readdir(dir);
  if(names.includes('.pending.json'))fail('ACQUISITION_SESSION_UNCERTAIN_COMMIT');
  const files=names.filter(n=>n!=='.session-lock');
  if(files.length>3||files.some((n,i)=>!/^\d{4}\.json$/.test(n)))fail('ACQUISITION_SESSION_HISTORY_INVALID');
  const events=[];for(let i=1;i<=files.length;i++){
   if(!files.includes(file(i)))fail('ACQUISITION_SESSION_HISTORY_INVALID');
   const raw=(await readSafe(join(dir,file(i)))).toString('utf8');let e;
   try{e=JSON.parse(raw);}catch{fail('ACQUISITION_SESSION_HISTORY_INVALID');}
   if(raw!==JSON.stringify(e)||!exact(e,['schema','index','previousDigest','action','payload','digest'])||e.schema!==OFFLINE_ACQUISITION_SESSION_SCHEMA||e.index!==i||e.previousDigest!==(events.at(-1)?.digest??ROOT)||!HEX.test(e.digest))fail('ACQUISITION_SESSION_HISTORY_INVALID');
   const {digest:recorded,...body}=e;if(digest(body)!==recorded)fail('ACQUISITION_SESSION_HISTORY_INVALID');
   if(e.action!==['BEGIN','PRE','POST'][i-1])fail('ACQUISITION_SESSION_SEQUENCE_INVALID');
   events.push(e);
  }
  if(events[0]){
   const p=events[0].payload;
   if(!exact(p,['acquisitionId','independentPins','priorRetentionHead'])||!ID.test(p.acquisitionId||'')||!heads(p.independentPins)||!head(p.priorRetentionHead)||p.priorRetentionHead.count%2!==0)fail('ACQUISITION_SESSION_HISTORY_INVALID');
   if(events[1]){
    const r=events[1].payload;
    if(!obj(r)||r.phase!=='PRE'||r.acquisitionId!==p.acquisitionId||r.index!==p.priorRetentionHead.count+1||r.previousDigest!==p.priorRetentionHead.headDigest||!same(r.heads,p.independentPins))fail('ACQUISITION_SESSION_PRE_MISMATCH');
   }
   if(events[2]){
    const m=events[2].payload;
    if(!obj(m)||m.acquisitionId!==p.acquisitionId||!Array.isArray(m.receiptHistory)||!same(m.receiptHistory.at(-2),events[1].payload)||!same(m.receiptHistory.at(-1)?.heads,p.independentPins))fail('ACQUISITION_SESSION_POST_MISMATCH');
   }
  }
  return {events,head:{count:events.length,headDigest:events.at(-1)?.digest??ROOT},status:['EMPTY','BEGIN_REVIEW_REQUIRED','PRE_REVIEW_REQUIRED','COMPLETE_DIAGNOSTIC_ONLY'][events.length]};
 }
 async function syncDir(){const h=await open(dir,'r');try{await h.sync();}finally{await h.close();}}
 async function append(s,check,action,payload){
  const body={schema:OFFLINE_ACQUISITION_SESSION_SCHEMA,index:s.events.length+1,previousDigest:s.head.headDigest,action,payload};
  const e={...body,digest:digest(body)},raw=Buffer.from(JSON.stringify(e));
  if(raw.length>12*1024*1024)fail('ACQUISITION_SESSION_SIZE_INVALID');
  await check();let h;
  try{h=await open(pending,F.O_WRONLY|F.O_CREAT|F.O_EXCL|F.O_NOFOLLOW,0o600);await h.writeFile(raw);await h.sync();}
  catch(e){if(['EEXIST','ELOOP'].includes(e.code))fail('ACQUISITION_SESSION_UNCERTAIN_COMMIT');throw e;}finally{if(h)await h.close();}
  await syncDir();if(injectFault)await injectFault(`after-${action.toLowerCase()}-pending-sync`);
  await check();await rename(pending,join(dir,file(e.index)));await syncDir();
  if(injectFault)await injectFault(`after-${action.toLowerCase()}-commit-sync`);
  const next=await state();if(next.head.headDigest!==e.digest)fail('ACQUISITION_SESSION_UNCERTAIN_COMMIT');return next;
 }
 async function begin({acquisitionId,independentPins,priorRetentionHead,expectedSessionHead}={}){
  if(!ID.test(acquisitionId||'')||!heads(independentPins)||!head(priorRetentionHead)||priorRetentionHead.count%2!==0||!head(expectedSessionHead))fail('ACQUISITION_SESSION_REQUEST_INVALID');
  return withLock(async check=>{
   const s=await state();if(!same(s.head,expectedSessionHead))fail('ACQUISITION_SESSION_STALE_PIN');if(s.events.length)fail('ACQUISITION_SESSION_SINGLE_USE');
   const n=await append(s,check,'BEGIN',structuredClone({acquisitionId,independentPins,priorRetentionHead}));
   return Object.freeze({...n.head,status:n.status,readOnly:true,productionApproved:false});
  });
 }
 /** Verify the signed complete acquisition before writing PRE then POST. */
 async function record({manifest,independentPins,forensicTrust,retentionTrust,independentRetentionHead,expectedSessionHead}={}){
  if(!obj(manifest)||!heads(independentPins)||!head(independentRetentionHead)||!head(expectedSessionHead))fail('ACQUISITION_SESSION_REQUEST_INVALID');
  return withLock(async check=>{
   const s=await state();if(!same(s.head,expectedSessionHead))fail('ACQUISITION_SESSION_STALE_PIN');
   if(s.events.length!==1)fail('ACQUISITION_SESSION_REVIEW_REQUIRED');
   const p=s.events[0].payload,history=manifest.receiptHistory;
   if(manifest.acquisitionId!==p.acquisitionId||!same(independentPins,p.independentPins)||!Array.isArray(history)||history.length!==p.priorRetentionHead.count+2||history.at(-2)?.previousDigest!==p.priorRetentionHead.headDigest||independentRetentionHead.count!==history.length)fail('ACQUISITION_SESSION_BINDING_INVALID');
   // No signed PRE/POST or embedded manifest can replace external trust/pins.
   verifyOfflineForensicAcquisitionManifest({manifest,independentPins,forensicTrust,retentionTrust,independentRetentionHead});
   let n=await append(s,check,'PRE',structuredClone(history.at(-2)));
   n=await append(n,check,'POST',structuredClone(manifest));
   return Object.freeze({...n.head,status:n.status,readOnly:true,mayRetry:false,productionApproved:false});
  });
 }
 async function inspect({expectedSessionHead}={}){return withLock(async()=>{
  if(!head(expectedSessionHead))fail('ACQUISITION_SESSION_EXTERNAL_PIN_REQUIRED');
  const s=await state();if(!same(s.head,expectedSessionHead))fail('ACQUISITION_SESSION_PIN_MISMATCH');
  return Object.freeze({...s.head,status:s.status,readOnly:true,mayRetry:false,mayAcknowledge:false,mayDeletePending:false,productionApproved:false});
 });}
 async function verify({expectedSessionHead,independentPins,forensicTrust,retentionTrust,independentRetentionHead}={}){return withLock(async()=>{
  if(!head(expectedSessionHead)||!head(independentRetentionHead)||!heads(independentPins))fail('ACQUISITION_SESSION_EXTERNAL_PIN_REQUIRED');
  const s=await state();if(!same(s.head,expectedSessionHead))fail('ACQUISITION_SESSION_PIN_MISMATCH');
  if(s.events.length!==3)fail('ACQUISITION_SESSION_REVIEW_REQUIRED');
  const p=s.events[0].payload;if(!same(independentPins,p.independentPins))fail('ACQUISITION_SESSION_BINDING_INVALID');
  const m=s.events[2].payload;
  if(m.receiptHistory.length!==p.priorRetentionHead.count+2||m.receiptHistory.at(-2)?.previousDigest!==p.priorRetentionHead.headDigest)fail('ACQUISITION_SESSION_BINDING_INVALID');
  const v=verifyOfflineForensicAcquisitionManifest({manifest:m,independentPins,forensicTrust,retentionTrust,independentRetentionHead});
  return Object.freeze({...s.head,status:s.status,classification:v.classification,readOnly:true,mayRetry:false,mayAcknowledge:false,mayDeletePending:false,productionApproved:false});
 });}
 return Object.freeze({begin,record,inspect,verify});
}
