/**
 * Objective 31A — independently anchored, append-only OFFLINE audit observations.
 * This is an opt-in fail-closed history of authenticated registry snapshots.
 * A bootstrap DOES NOT establish earlier history; only sequential observations
 * can be proved, and unobserved same-state writes cannot be inferred.
 * Single-host Linux cooperative locking only; no Shopify/network writes.
 */
import {createHash, verify as verifySignature} from 'node:crypto';
import {constants as C} from 'node:fs';
import {mkdir,open,lstat,readdir} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {resolve,join} from 'node:path';

const fail=code=>{throw Object.assign(new Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>obj(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const hex=/^[0-9a-f]{64}$/;
const authId=/^[a-zA-Z0-9_-]{12,80}$/;
const schema='TJ-OFFLINE-AUDIT-JOURNAL-EVENT-1';
const permitSchema='TJ-OFFLINE-AUDIT-JOURNAL-RECOVERY-1';
const auditSchema='TJ-OFFLINE-PRIVATE-REGISTRY-AUDIT-SNAPSHOT-1';
const snapshotFields=['schema','registryId','anchor','previousMac','stateSha256','revisionSha256','artworkSha256','revocationSha256','operationSha256','revisionCount','artworkCount','revocationCount','operationCount','historicalCoverage','productionApproved'];
const eventFields=['schema','index','previousDigest','registryAnchor','registryPreviousMac','stateSha256','revisionSha256','artworkSha256','revocationSha256','operationSha256','revisionCount','artworkCount','revocationCount','operationCount','coverage','digest'];
const permitFields=['schema','registryId','authorizationId','issuedAt','expiresAt','expectedJournalAnchor','targetJournalAnchor','reason'];
const rootDigest='0'.repeat(64);
const hash=x=>createHash('sha256').update(x).digest('hex');
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const nowValid=(issued,expires,now)=>Number.isSafeInteger(issued)&&Number.isSafeInteger(expires)&&issued<=now&&expires>now&&expires>issued&&expires-issued<=900000;
const indexFile=index=>String(index).padStart(10,'0')+'.json';
function registryAnchor(a){return exact(a,['sequence','mac'])&&Number.isSafeInteger(a.sequence)&&a.sequence>=1&&hex.test(a.mac);}
function journalAnchor(a){return exact(a,['index','digest'])&&Number.isSafeInteger(a.index)&&a.index>=1&&a.index<=10000&&hex.test(a.digest);}
function snapshot(s,registryId){
 if(!exact(s,snapshotFields)||s.schema!==auditSchema||s.registryId!==registryId||!registryAnchor(s.anchor)||
    !(s.previousMac===null||hex.test(s.previousMac))||
    !['stateSha256','revisionSha256','artworkSha256','revocationSha256','operationSha256'].every(k=>hex.test(s[k]))||
    !['revisionCount','artworkCount','revocationCount','operationCount'].every(k=>Number.isSafeInteger(s[k])&&s[k]>=0)||
    s.historicalCoverage!=='CURRENT_SNAPSHOT_ONLY'||s.productionApproved!==false)fail('AUDIT_SNAPSHOT_INVALID');
}
function validEvent(e){
 if(!exact(e,eventFields)||e.schema!==schema||!Number.isSafeInteger(e.index)||e.index<1||e.index>10000||
    !hex.test(e.previousDigest)||!registryAnchor(e.registryAnchor)||
    !(e.registryPreviousMac===null||hex.test(e.registryPreviousMac))||
    !['stateSha256','revisionSha256','artworkSha256','revocationSha256','operationSha256'].every(k=>hex.test(e[k]))||
    !['revisionCount','artworkCount','revocationCount','operationCount'].every(k=>Number.isSafeInteger(e[k])&&e[k]>=0)||
    !['BOOTSTRAP_UNPROVEN_PRIOR_HISTORY','CONTIGUOUS_OBSERVATION'].includes(e.coverage)||!hex.test(e.digest))fail('AUDIT_EVENT_INVALID');
 const {digest,...body}=e;
 if(digest!==hash(Buffer.from(`${schema}\0${JSON.stringify(body)}`)))fail('AUDIT_EVENT_TAMPERED');
}
function recoveryPermit(p,conf){
 if(!exact(p,[...permitFields,'signature'])||p.schema!==permitSchema||p.registryId!==conf.registryId||
    !authId.test(p.authorizationId||'')||!nowValid(p.issuedAt,p.expiresAt,Date.now())||
    !(p.expectedJournalAnchor===null||journalAnchor(p.expectedJournalAnchor))||
    !journalAnchor(p.targetJournalAnchor)||
    typeof p.reason!=='string'||p.reason.length<12||p.reason.length>200||p.reason!==p.reason.trim()||/[\x00-\x1f\x7f]/.test(p.reason)||
    typeof p.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(p.signature))fail('AUDIT_RECOVERY_DENIED');
 const body=Object.fromEntries(permitFields.map(k=>[k,p[k]]));
 const sig=Buffer.from(p.signature,'base64url');
 if(sig.length!==64||sig.toString('base64url')!==p.signature||
    !verifySignature(null,Buffer.from(`${permitSchema}\0${JSON.stringify(body)}`),conf.publicKey,sig))fail('AUDIT_RECOVERY_DENIED');
}

export function createOfflineAnchoredAuditJournal({directory,registry,registryId,readJournalAnchor,compareAndSetJournalAnchor,readRegistryAnchor,recovery,lockTimeoutMs=1500,injectFault}={}){
 if(process.platform!=='linux'||!C.O_NOFOLLOW||typeof directory!=='string'||!directory.trim()||
    !authId.test(registryId||'')||typeof registry?.exportAuthenticatedAudit!=='function'||
    typeof readJournalAnchor!=='function'||typeof compareAndSetJournalAnchor!=='function'||typeof readRegistryAnchor!=='function'||
    !Number.isInteger(lockTimeoutMs)||lockTimeoutMs<0||lockTimeoutMs>10000||
    (injectFault!==undefined&&typeof injectFault!=='function')||
    (recovery!==undefined&&(!exact(recovery,['registryId','publicKey'])||recovery.registryId!==registryId||
    recovery.publicKey?.type!=='public'||recovery.publicKey?.asymmetricKeyType!=='ed25519')))
    fail('AUDIT_CONFIGURATION');
 const dir=resolve(directory),lock=join(dir,'.audit-journal-lock');
 async function ensureDir(){await mkdir(dir,{recursive:true,mode:0o700});const s=await lstat(dir);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0)fail('AUDIT_DIRECTORY_UNSAFE');return s;}
 async function readExternal(){let a;try{a=await readJournalAnchor();}catch{fail('AUDIT_ANCHOR_UNAVAILABLE');}if(!(a===null||journalAnchor(a)))fail('AUDIT_ANCHOR_UNAVAILABLE');return a;}
 async function readRegistry(){let a;try{a=await readRegistryAnchor();}catch{fail('AUDIT_REGISTRY_ANCHOR_UNAVAILABLE');}if(!registryAnchor(a))fail('AUDIT_REGISTRY_ANCHOR_UNAVAILABLE');return a;}
 async function withLock(fn){
  const before=await ensureDir();let h;
  try{
   h=await open(lock,C.O_RDWR|C.O_CREAT|C.O_NOFOLLOW,0o600);const st=await h.stat(),ps=await lstat(lock);
   if(!st.isFile()||st.nlink!==1||(st.mode&0o077)!==0||st.ino!==ps.ino||st.dev!==ps.dev)fail('AUDIT_LOCK_UNSAFE');
   await new Promise((ok,no)=>{const child=spawn('/usr/bin/flock',['-x','-w',(lockTimeoutMs/1000).toFixed(3),'3'],{stdio:['ignore','ignore','ignore',h.fd]});child.once('error',()=>no(Object.assign(Error('AUDIT_LOCK_UNAVAILABLE'),{code:'AUDIT_LOCK_UNAVAILABLE'})));child.once('close',code=>code===0?ok():no(Object.assign(Error('AUDIT_LOCK_UNAVAILABLE'),{code:'AUDIT_LOCK_UNAVAILABLE'})));});
   const verify=async()=>{const [d,l]=await Promise.all([lstat(dir),lstat(lock)]);if(!d.isDirectory()||d.ino!==before.ino||d.dev!==before.dev||!l.isFile()||l.ino!==st.ino||l.dev!==st.dev||l.nlink!==1)fail('AUDIT_LOCK_UNSAFE');};
   await verify();return await fn(verify);
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('AUDIT_LOCK_UNSAFE');throw e;}
  finally{if(h)await h.close();}
 }
 async function readEvents(){
  const names=(await readdir(dir)).filter(x=>x.endsWith('.json'));
  if(names.length>10000)fail('AUDIT_CAPACITY');
  const events=[];
  for(let i=1;i<=names.length;i++){
   const name=indexFile(i);if(!names.includes(name))fail('AUDIT_MISSING_EVENT');
   let h;try{
    h=await open(join(dir,name),C.O_RDONLY|C.O_NOFOLLOW);
    const s=await h.stat(),p=await lstat(join(dir,name));
    if(!s.isFile()||s.nlink!==1||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev||s.size>4096)fail('AUDIT_FILE_UNSAFE');
    const bytes=await h.readFile();let e;try{e=JSON.parse(bytes.toString('utf8'));}catch{fail('AUDIT_EVENT_INVALID');}
    validEvent(e);
    if(e.index!==i||e.previousDigest!==(i===1?rootDigest:events.at(-1).digest)||
       (i===1?e.coverage!=='BOOTSTRAP_UNPROVEN_PRIOR_HISTORY':e.coverage!=='CONTIGUOUS_OBSERVATION'||
        e.registryAnchor.sequence!==events.at(-1).registryAnchor.sequence+1||e.registryPreviousMac!==events.at(-1).registryAnchor.mac))fail('AUDIT_CHAIN_INVALID');
    events.push(e);
   }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('AUDIT_FILE_UNSAFE');throw e;}
   finally{if(h)await h.close();}
  }
  return events;
 }
 function assertHead(events,observed){
  const local=events.length?{index:events.length,digest:events.at(-1).digest}:null;
  if(!equal(local,observed))fail('AUDIT_ANCHOR_MISMATCH');
 }
 async function verify(){return withLock(async()=>{
  const events=await readEvents(),observed=await readExternal();assertHead(events,observed);
  return Object.freeze({anchor:observed,eventCount:events.length,firstObservedRegistrySequence:events[0]?.registryAnchor.sequence??null,
   lastObservedRegistryAnchor:events.at(-1)?.registryAnchor??null,historyBeforeBootstrapProven:false,productionApproved:false});
 });}
 async function appendAuthenticatedSnapshot(envelope){
  return withLock(async filesystemCheck=>{
   const observed=await readExternal(),events=await readEvents();assertHead(events,observed);
   if(events.length>=10000)fail('AUDIT_CAPACITY');
   // The configured registry verifies the operator's Ed25519 permit and anchor.
   const s=await registry.exportAuthenticatedAudit(envelope);snapshot(s,registryId);
   const current=await readRegistry();if(!equal(current,s.anchor))fail('AUDIT_REGISTRY_CHANGED');
   const prior=events.at(-1);
   if(prior&&(s.anchor.sequence!==prior.registryAnchor.sequence+1||s.previousMac!==prior.registryAnchor.mac))fail('AUDIT_HISTORY_GAP');
   if(!prior&&s.anchor.sequence===1&&s.previousMac!==rootDigest)fail('AUDIT_SNAPSHOT_INVALID');
   const body={schema,index:events.length+1,previousDigest:prior?.digest??rootDigest,
    registryAnchor:s.anchor,registryPreviousMac:s.previousMac,
    stateSha256:s.stateSha256,revisionSha256:s.revisionSha256,artworkSha256:s.artworkSha256,
    revocationSha256:s.revocationSha256,operationSha256:s.operationSha256,
    revisionCount:s.revisionCount,artworkCount:s.artworkCount,revocationCount:s.revocationCount,operationCount:s.operationCount,
    coverage:prior?'CONTIGUOUS_OBSERVATION':'BOOTSTRAP_UNPROVEN_PRIOR_HISTORY'};
   const event={...body,digest:hash(Buffer.from(`${schema}\0${JSON.stringify(body)}`))};
   const target={index:event.index,digest:event.digest};
   // Fail closed on partial writes, conflicts, crashes, or offsite anchor outages.
   await filesystemCheck();
   const path=join(dir,indexFile(event.index));let h;
   try{
    h=await open(path,C.O_WRONLY|C.O_CREAT|C.O_EXCL|C.O_NOFOLLOW,0o600);
    await h.writeFile(Buffer.from(JSON.stringify(event)));await h.sync();
   }catch(e){if(e.code==='EEXIST'||e.code==='ELOOP')fail('AUDIT_FILE_UNSAFE');throw e;}
   finally{if(h)await h.close();}
   const dh=await open(dir,'r');try{await dh.sync();}finally{await dh.close();}
   if(injectFault)await injectFault('after-event-file');
   await filesystemCheck();
   if(!equal(await readRegistry(),s.anchor))fail('AUDIT_REGISTRY_CHANGED');
   let cas;try{cas=await compareAndSetJournalAnchor(observed,target);}catch{fail('AUDIT_ANCHOR_UNAVAILABLE');}
   if(cas!==true||!equal(await readExternal(),target))fail('AUDIT_ANCHOR_CONFLICT');
   return Object.freeze({journalAnchor:target,registryAnchor:s.anchor,coverage:event.coverage,productionApproved:false});
  });
 }
 async function recoverInterruptedAppend({authorization}={}){
  if(!recovery)fail('AUDIT_RECOVERY_UNAVAILABLE');recoveryPermit(authorization,recovery);
  return withLock(async filesystemCheck=>{
   const events=await readEvents(),observed=await readExternal();
   const expected=authorization.expectedJournalAnchor,target=authorization.targetJournalAnchor;
   if(!equal(expected,observed))fail('AUDIT_RECOVERY_ANCHOR_MISMATCH');
   if(events.length!==target.index||target.index!==(observed?.index??0)+1||
      !equal({index:events.length,digest:events.at(-1)?.digest},target)||
      (observed!==null&&events.at(-2)?.digest!==observed.digest))fail('AUDIT_RECOVERY_CHAIN');
   if(!equal(await readRegistry(),events.at(-1).registryAnchor))fail('AUDIT_REGISTRY_CHANGED');
   await filesystemCheck();
   let cas;try{cas=await compareAndSetJournalAnchor(expected,target);}catch{fail('AUDIT_ANCHOR_UNAVAILABLE');}
   if(cas!==true||!equal(await readExternal(),target))fail('AUDIT_ANCHOR_CONFLICT');
   return 'recovered';
  });
 }
 return Object.freeze({verify,appendAuthenticatedSnapshot,recoverInterruptedAppend});
}
