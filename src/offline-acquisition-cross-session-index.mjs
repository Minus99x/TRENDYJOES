/**
 * Objective 31N — externally pinned, append-only cross-session acquisition index.
 * Local diagnostics only. The caller independently retains index/session/retention
 * heads and trust keys; no local index record grants recovery or retry authority.
 * Linux flock + fsync prototype; not a remote immutable witness.
 */
import {createHash} from 'node:crypto';
import {constants as F} from 'node:fs';
import {mkdir,open,lstat,readdir,rename} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {join,resolve} from 'node:path';
import {createOfflineAcquisitionSessionJournal} from './offline-acquisition-session-journal.mjs';
import {verifyOfflineForensicAcquisitionManifest} from './offline-forensic-acquisition-provenance.mjs';

export const OFFLINE_ACQUISITION_INDEX_SCHEMA='TJ-OFFLINE-ACQUISITION-CROSS-SESSION-1';
const ROOT='0'.repeat(64), HEX=/^[0-9a-f]{64}$/, ID=/^[A-Za-z0-9_-]{12,80}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,fields)=>obj(x)&&Object.keys(x).sort().join('|')===fields.slice().sort().join('|');
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const sha=b=>createHash('sha256').update(b).digest('hex');
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=2000&&HEX.test(h.headDigest)&&(h.count===0)===(h.headDigest===ROOT);
const heads=h=>exact(h,['forensic','publication','outbox'])&&Object.values(h).every(head);
const name=i=>String(i).padStart(4,'0')+'.json';
const hashRecord=b=>sha(Buffer.from(`${OFFLINE_ACQUISITION_INDEX_SCHEMA}\0${JSON.stringify(b)}`));
const manifestHash=m=>sha(Buffer.from(`TJ-OFFLINE-ACQUISITION-MANIFEST-SNAPSHOT-1\0${JSON.stringify(m)}`));
function validPayload(p){
 return exact(p,['acquisitionId','sessionHead','previousRetentionHead','retentionHead','forensicHeads','manifestDigest'])&&ID.test(p.acquisitionId||'')&&head(p.sessionHead)&&p.sessionHead.count===3&&head(p.previousRetentionHead)&&head(p.retentionHead)&&p.retentionHead.count===p.previousRetentionHead.count+2&&p.retentionHead.count%2===0&&heads(p.forensicHeads)&&HEX.test(p.manifestDigest);
}
function checkContinuity(p,prior,seen){
 if(seen.has(p.acquisitionId))fail('ACQUISITION_INDEX_REPLAY');
 if(!equal(p.previousRetentionHead,prior?.retentionHead??{count:0,headDigest:ROOT}))fail('ACQUISITION_INDEX_RETENTION_GAP');
 if(prior)for(const k of ['forensic','publication','outbox']){
  const old=prior.forensicHeads[k],next=p.forensicHeads[k];
  if(next.count<old.count||(next.count===old.count&&next.headDigest!==old.headDigest))fail('ACQUISITION_INDEX_HEAD_ROLLBACK');
 }
 seen.add(p.acquisitionId);
}
export function createOfflineAcquisitionCrossSessionIndex({directory,lockTimeoutMs=5000,injectFault}={}){
 if(process.platform!=='linux'||!F.O_NOFOLLOW||typeof directory!=='string'||!directory.trim()||!Number.isSafeInteger(lockTimeoutMs)||lockTimeoutMs<0||lockTimeoutMs>10000||(injectFault!==undefined&&typeof injectFault!=='function'))fail('ACQUISITION_INDEX_CONFIGURATION');
 const dir=resolve(directory),lock=join(dir,'.index-lock'),pending=join(dir,'.pending.json');
 async function safeDir(){
  await mkdir(dir,{recursive:true,mode:0o700});const s=await lstat(dir);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0)fail('ACQUISITION_INDEX_DIRECTORY_UNSAFE');return s;
 }
 async function withLock(fn){
  const d=await safeDir();let h;
  try{
   h=await open(lock,F.O_RDWR|F.O_CREAT|F.O_NOFOLLOW,0o600);
   const [s,p]=await Promise.all([h.stat(),lstat(lock)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev)fail('ACQUISITION_INDEX_LOCK_UNSAFE');
   await new Promise((ok,no)=>{const c=spawn('/usr/bin/flock',['-x','-w',(lockTimeoutMs/1000).toFixed(3),'3'],{stdio:['ignore','ignore','ignore',h.fd]});c.once('error',()=>no(Object.assign(Error('ACQUISITION_INDEX_LOCK_UNAVAILABLE'),{code:'ACQUISITION_INDEX_LOCK_UNAVAILABLE'})));c.once('close',code=>code===0?ok():no(Object.assign(Error('ACQUISITION_INDEX_LOCK_UNAVAILABLE'),{code:'ACQUISITION_INDEX_LOCK_UNAVAILABLE'})));});
   const check=async()=>{const [a,b]=await Promise.all([lstat(dir),lstat(lock)]);if(!a.isDirectory()||a.ino!==d.ino||a.dev!==d.dev||!b.isFile()||b.ino!==s.ino||b.dev!==s.dev||b.nlink!==1)fail('ACQUISITION_INDEX_LOCK_UNSAFE');};
   await check();return await fn(check);
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('ACQUISITION_INDEX_LOCK_UNSAFE');throw e;}finally{if(h)await h.close();}
 }
 async function readSafe(path){let h;try{
  h=await open(path,F.O_RDONLY|F.O_NOFOLLOW);const [s,p]=await Promise.all([h.stat(),lstat(path)]);
  if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev||s.size<2||s.size>64*1024)fail('ACQUISITION_INDEX_FILE_UNSAFE');return await h.readFile();
 }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('ACQUISITION_INDEX_FILE_UNSAFE');throw e;}finally{if(h)await h.close();}}
 async function state(){
  const names=await readdir(dir);if(names.includes('.pending.json'))fail('ACQUISITION_INDEX_UNCERTAIN_COMMIT');
  const files=names.filter(n=>n!=='.index-lock');if(files.length>2000||files.some(n=>!/^\d{4}\.json$/.test(n)))fail('ACQUISITION_INDEX_HISTORY_INVALID');
  const entries=[],seen=new Set();let previous=ROOT,prior=null;
  for(let i=1;i<=files.length;i++){
   if(!files.includes(name(i)))fail('ACQUISITION_INDEX_HISTORY_INVALID');let e;const raw=(await readSafe(join(dir,name(i)))).toString('utf8');
   try{e=JSON.parse(raw);}catch{fail('ACQUISITION_INDEX_HISTORY_INVALID');}
   if(raw!==JSON.stringify(e)||!exact(e,['schema','index','previousDigest','payload','digest'])||e.schema!==OFFLINE_ACQUISITION_INDEX_SCHEMA||e.index!==i||e.previousDigest!==previous||!HEX.test(e.digest)||!validPayload(e.payload))fail('ACQUISITION_INDEX_HISTORY_INVALID');
   const {digest,...body}=e;if(hashRecord(body)!==digest)fail('ACQUISITION_INDEX_HISTORY_INVALID');
   checkContinuity(e.payload,prior,seen);entries.push(e);prior=e.payload;previous=digest;
  }
  return {entries,head:{count:entries.length,headDigest:previous}};
 }
 async function syncDir(){const h=await open(dir,'r');try{await h.sync();}finally{await h.close();}}
 async function checkProof({acquisitionId,sessionDirectory,sessionHead,manifest,independentPins,independentRetentionHead,forensicTrust,retentionTrust},previousRetentionHead){
  if(!ID.test(acquisitionId||'')||!head(sessionHead)||sessionHead.count!==3||!head(independentRetentionHead)||!heads(independentPins)||!obj(manifest)||typeof sessionDirectory!=='string'||!sessionDirectory.trim())fail('ACQUISITION_INDEX_PROOF_INVALID');
  if(manifest.acquisitionId!==acquisitionId||!Array.isArray(manifest.receiptHistory)||manifest.receiptHistory.length!==previousRetentionHead.count+2||manifest.receiptHistory.at(-2)?.previousDigest!==previousRetentionHead.headDigest)fail('ACQUISITION_INDEX_RETENTION_GAP');
  const v=verifyOfflineForensicAcquisitionManifest({manifest,independentPins,independentRetentionHead,forensicTrust,retentionTrust});
  const s=await createOfflineAcquisitionSessionJournal({directory:sessionDirectory}).verify({expectedSessionHead:sessionHead,independentPins,independentRetentionHead,forensicTrust,retentionTrust});
  if(!v.verified||!equal({count:s.count,headDigest:s.headDigest},sessionHead))fail('ACQUISITION_INDEX_PROOF_INVALID');
  return {acquisitionId,sessionHead:structuredClone(sessionHead),previousRetentionHead:structuredClone(previousRetentionHead),retentionHead:structuredClone(independentRetentionHead),forensicHeads:structuredClone(independentPins),manifestDigest:manifestHash(manifest)};
 }
 async function append({expectedIndexHead,...proof}={}){
  if(!head(expectedIndexHead))fail('ACQUISITION_INDEX_EXTERNAL_PIN_REQUIRED');
  return withLock(async check=>{
   const s=await state();if(!equal(s.head,expectedIndexHead))fail('ACQUISITION_INDEX_STALE_PIN');
   const previous=s.entries.at(-1)?.payload?.retentionHead??{count:0,headDigest:ROOT};
   const p=await checkProof(proof,previous);
   checkContinuity(p,s.entries.at(-1)?.payload,new Set(s.entries.map(e=>e.payload.acquisitionId)));
   const body={schema:OFFLINE_ACQUISITION_INDEX_SCHEMA,index:s.entries.length+1,previousDigest:s.head.headDigest,payload:p};
   const e={...body,digest:hashRecord(body)},raw=Buffer.from(JSON.stringify(e));await check();let h;
   try{h=await open(pending,F.O_WRONLY|F.O_CREAT|F.O_EXCL|F.O_NOFOLLOW,0o600);await h.writeFile(raw);await h.sync();}
   catch(error){if(['EEXIST','ELOOP'].includes(error.code))fail('ACQUISITION_INDEX_UNCERTAIN_COMMIT');throw error;}finally{if(h)await h.close();}
   await syncDir();if(injectFault)await injectFault('after-index-pending-sync');await check();await rename(pending,join(dir,name(e.index)));await syncDir();
   if(injectFault)await injectFault('after-index-commit-sync');const n=await state();if(n.head.headDigest!==e.digest)fail('ACQUISITION_INDEX_UNCERTAIN_COMMIT');
   return Object.freeze({...n.head,status:'RECORDED_DIAGNOSTIC_ONLY',readOnly:true,mayRetry:false,productionApproved:false});
  });
 }
 async function inspect({expectedIndexHead}={}){if(!head(expectedIndexHead))fail('ACQUISITION_INDEX_EXTERNAL_PIN_REQUIRED');return withLock(async()=>{
  const s=await state();if(!equal(s.head,expectedIndexHead))fail('ACQUISITION_INDEX_PIN_MISMATCH');
  return Object.freeze({...s.head,status:'STRUCTURAL_ONLY',readOnly:true,mayRetry:false,productionApproved:false});
 });}
 async function verify({expectedIndexHead,evidence,forensicTrust,retentionTrust}={}){
  if(!head(expectedIndexHead)||!Array.isArray(evidence))fail('ACQUISITION_INDEX_EXTERNAL_PIN_REQUIRED');
  return withLock(async()=>{
   const s=await state();if(!equal(s.head,expectedIndexHead))fail('ACQUISITION_INDEX_PIN_MISMATCH');
   if(evidence.length!==s.entries.length)fail('ACQUISITION_INDEX_EVIDENCE_INCOMPLETE');
   let prior={count:0,headDigest:ROOT};
   for(let i=0;i<evidence.length;i++){
    const proof={...evidence[i],forensicTrust,retentionTrust};const p=await checkProof(proof,prior);
    if(!equal(p,s.entries[i].payload))fail('ACQUISITION_INDEX_EVIDENCE_MISMATCH');prior=p.retentionHead;
   }
   return Object.freeze({...s.head,verified:true,classification:'INDEPENDENT_EVIDENCE_CHECKED_DIAGNOSTIC_ONLY',readOnly:true,mayRetry:false,mayAcknowledge:false,productionApproved:false});
  });
 }
 return Object.freeze({append,inspect,verify});
}
