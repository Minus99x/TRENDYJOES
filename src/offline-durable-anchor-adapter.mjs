/**
 * Objective 31D: opt-in OFFLINE append-only, crash-recoverable anchor adapter.
 * This is a single-host file-system fixture/adapter, NOT an offsite witness,
 * anti-rollback hardware, or a hosted durable service. Every public method
 * re-verifies its entire local history under a cooperative cross-process lock.
 * Crash during a prepared append fails closed until independently signed repair.
 */
import {createHash,verify as verifySignature} from 'node:crypto';
import {constants as C} from 'node:fs';
import {mkdir,open,lstat,readdir,rename,unlink} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {resolve,join} from 'node:path';

const SCHEMA='TJ-OFFLINE-DURABLE-ANCHOR-EVENT-1';
const RECOVERY='TJ-OFFLINE-DURABLE-ANCHOR-RECOVERY-1';
const ROOT='0'.repeat(64);
const ID=/^[A-Za-z0-9_-]{12,80}$/;
const HEX=/^[0-9a-f]{64}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>object(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const sha=b=>createHash('sha256').update(b).digest('hex');
const file=i=>String(i).padStart(10,'0')+'.json';
const fields=['schema','registryId','anchorType','index','previousDigest','previousAnchor','anchor','digest'];
const permitFields=['schema','registryId','anchorType','action','authorizationId','issuedAt','expiresAt','expectedAnchor','targetAnchor','pendingDigest','reason'];
function validAnchor(type,a){
 return a===null||(type==='registry'?exact(a,['sequence','mac'])&&Number.isSafeInteger(a.sequence)&&a.sequence>=1&&HEX.test(a.mac):
 exact(a,['index','digest'])&&Number.isSafeInteger(a.index)&&a.index>=1&&a.index<=10000&&HEX.test(a.digest));
}
function nextAnchor(type,old,next){
 const field=type==='registry'?'sequence':'index';
 return next!==null&&next[field]===(old?.[field]??0)+1;
}
function eventValid(e,conf){
 if(!exact(e,fields)||e.schema!==SCHEMA||e.registryId!==conf.registryId||e.anchorType!==conf.anchorType||
    !Number.isSafeInteger(e.index)||e.index<1||e.index>10000||!HEX.test(e.previousDigest)||
    !validAnchor(conf.anchorType,e.previousAnchor)||!validAnchor(conf.anchorType,e.anchor)||
    !nextAnchor(conf.anchorType,e.previousAnchor,e.anchor)||!HEX.test(e.digest))fail('DURABLE_ANCHOR_EVENT_INVALID');
 const {digest,...body}=e;
 if(digest!==sha(Buffer.from(`${SCHEMA}\0${JSON.stringify(body)}`)))fail('DURABLE_ANCHOR_EVENT_TAMPERED');
}
function permitValid(p,conf){
 const now=Date.now();
 if(!exact(p,[...permitFields,'signature'])||p.schema!==RECOVERY||p.registryId!==conf.registryId||p.anchorType!==conf.anchorType||
    !['commit-pending','abort-pending'].includes(p.action)||!ID.test(p.authorizationId||'')||
    !Number.isSafeInteger(p.issuedAt)||!Number.isSafeInteger(p.expiresAt)||p.issuedAt>now||p.expiresAt<=now||
    p.expiresAt<=p.issuedAt||p.expiresAt-p.issuedAt>900000||
    !validAnchor(conf.anchorType,p.expectedAnchor)||!validAnchor(conf.anchorType,p.targetAnchor)||
    !HEX.test(p.pendingDigest)||typeof p.reason!=='string'||p.reason!==p.reason.trim()||p.reason.length<12||p.reason.length>200||
    /[\x00-\x1f\x7f]/.test(p.reason)||typeof p.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(p.signature))fail('DURABLE_ANCHOR_RECOVERY_DENIED');
 const body=Object.fromEntries(permitFields.map(k=>[k,p[k]]));
 const sig=Buffer.from(p.signature,'base64url');
 if(sig.length!==64||sig.toString('base64url')!==p.signature||
    !verifySignature(null,Buffer.from(`${RECOVERY}\0${JSON.stringify(body)}`),conf.publicKey,sig))fail('DURABLE_ANCHOR_RECOVERY_DENIED');
}
export function createOfflineDurableAnchorAdapter({directory,registryId,anchorType,recovery,lockTimeoutMs=1500,injectFault}={}){
 if(process.platform!=='linux'||!C.O_NOFOLLOW||typeof directory!=='string'||!directory.trim()||
    !ID.test(registryId||'')||!['registry','journal'].includes(anchorType)||
    !exact(recovery,['publicKey'])||recovery.publicKey?.type!=='public'||recovery.publicKey?.asymmetricKeyType!=='ed25519'||
    !Number.isInteger(lockTimeoutMs)||lockTimeoutMs<0||lockTimeoutMs>10000||
    (injectFault!==undefined&&typeof injectFault!=='function'))fail('DURABLE_ANCHOR_CONFIGURATION');
 const dir=resolve(directory),lock=join(dir,'.anchor-lock'),pending=join(dir,'.pending.json');
 const conf={registryId,anchorType,publicKey:recovery.publicKey};
 async function directorySafe(){
  await mkdir(dir,{recursive:true,mode:0o700});const s=await lstat(dir);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0)fail('DURABLE_ANCHOR_DIRECTORY_UNSAFE');
  return s;
 }
 async function withLock(fn){
  const before=await directorySafe();let h;
  try{
   h=await open(lock,C.O_RDWR|C.O_CREAT|C.O_NOFOLLOW,0o600);
   const s=await h.stat(),p=await lstat(lock);
   if(!s.isFile()||s.nlink!==1||(s.mode&0o077)!==0||s.uid!==process.getuid()||s.ino!==p.ino||s.dev!==p.dev)fail('DURABLE_ANCHOR_LOCK_UNSAFE');
   await new Promise((ok,no)=>{
    const child=spawn('/usr/bin/flock',['-x','-w',(lockTimeoutMs/1000).toFixed(3),'3'],{stdio:['ignore','ignore','ignore',h.fd]});
    child.once('error',()=>no(Object.assign(Error('DURABLE_ANCHOR_LOCK_UNAVAILABLE'),{code:'DURABLE_ANCHOR_LOCK_UNAVAILABLE'})));
    child.once('close',code=>code===0?ok():no(Object.assign(Error('DURABLE_ANCHOR_LOCK_UNAVAILABLE'),{code:'DURABLE_ANCHOR_LOCK_UNAVAILABLE'})));
   });
   const check=async()=>{
    let d,l;try{[d,l]=await Promise.all([lstat(dir),lstat(lock)]);}catch{fail('DURABLE_ANCHOR_LOCK_UNSAFE');}
    if(!d.isDirectory()||d.ino!==before.ino||d.dev!==before.dev||!l.isFile()||l.ino!==s.ino||l.dev!==s.dev||l.nlink!==1)fail('DURABLE_ANCHOR_LOCK_UNSAFE');
   };
   await check();return await fn(check);
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('DURABLE_ANCHOR_LOCK_UNSAFE');throw e;}
  finally{if(h)await h.close();}
 }
 async function safeBytes(path,{allowEmpty=false,maxBytes=2048}={}){
  let h;
  try{
   h=await open(path,C.O_RDONLY|C.O_NOFOLLOW);
   const [s,p]=await Promise.all([h.stat(),lstat(path)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev||(!allowEmpty&&s.size<1)||s.size>maxBytes)fail('DURABLE_ANCHOR_FILE_UNSAFE');
   return await h.readFile();
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('DURABLE_ANCHOR_FILE_UNSAFE');throw e;}
  finally{if(h)await h.close();}
 }
 async function committed({allowPending=false}={}){
  const names=await readdir(dir);
  const hasPending=names.includes('.pending.json');
  if(hasPending&&!allowPending)fail('DURABLE_ANCHOR_PENDING_RECOVERY_REQUIRED');
  const committedNames=names.filter(x=>x!=='.anchor-lock'&&x!=='.pending.json');
  if(committedNames.length>10000)fail('DURABLE_ANCHOR_CAPACITY');
  const events=[];
  for(let i=1;i<=committedNames.length;i++){
   const name=file(i);if(!committedNames.includes(name))fail('DURABLE_ANCHOR_HISTORY_GAP');
   const bytes=await safeBytes(join(dir,name));let e;
   try{e=JSON.parse(bytes.toString('utf8'));}catch{fail('DURABLE_ANCHOR_EVENT_INVALID');}
   eventValid(e,conf);
   if(bytes.toString('utf8')!==JSON.stringify(e)||e.index!==i||e.previousDigest!==(events.at(-1)?.digest??ROOT)||
      !same(e.previousAnchor,events.at(-1)?.anchor??null))fail('DURABLE_ANCHOR_CHAIN_INVALID');
   events.push(e);
  }
  return {events,hasPending,head:events.at(-1)?.anchor??null,digest:events.at(-1)?.digest??ROOT};
 }
 async function syncDir(){const h=await open(dir,'r');try{await h.sync();}finally{await h.close();}}
 async function append(next,old,state,check){
  const body={schema:SCHEMA,registryId,anchorType,index:state.events.length+1,previousDigest:state.digest,previousAnchor:old,anchor:next};
  const e={...body,digest:sha(Buffer.from(`${SCHEMA}\0${JSON.stringify(body)}`))};
  await check();let h;
  try{
   h=await open(pending,C.O_WRONLY|C.O_CREAT|C.O_EXCL|C.O_NOFOLLOW,0o600);
   await h.writeFile(JSON.stringify(e));await h.sync();
  }catch(e){if(['EEXIST','ELOOP'].includes(e.code))fail('DURABLE_ANCHOR_PENDING_RECOVERY_REQUIRED');throw e;}
  finally{if(h)await h.close();}
  await syncDir();
  if(injectFault)await injectFault('after-pending-sync');
  await check();await rename(pending,join(dir,file(e.index)));await syncDir();
  if(injectFault)await injectFault('after-commit-sync');
  const final=await committed();
  if(!same(final.head,next)||final.digest!==e.digest)fail('DURABLE_ANCHOR_COMMIT_UNCERTAIN');
 }
 async function inspectRecoveryState(){
  // For an independently authorized recovery workflow only. Ordinary reads
  // still reject pending writes; this method does NOT approve recovery.
  return withLock(async()=>{
   const s=await committed({allowPending:true});
   const pendingDigest=s.hasPending?sha(await safeBytes(pending,{allowEmpty:true,maxBytes:8192})):null;
   return Object.freeze({anchor:structuredClone(s.head),eventCount:s.events.length,
    historyDigest:s.digest,pending:s.hasPending,pendingDigest,productionApproved:false});
  });
 }
 function validateRecoveryAuthorization(authorization){permitValid(authorization,conf);return true;}
 async function read(){return withLock(async()=>structuredClone((await committed()).head));}
 async function inspect(){return withLock(async()=>{const s=await committed();return Object.freeze({anchor:structuredClone(s.head),eventCount:s.events.length,historyDigest:s.digest,productionApproved:false});});}
 async function readPinned(expected){
  if(!validAnchor(anchorType,expected))fail('DURABLE_ANCHOR_PIN_INVALID');
  return withLock(async()=>{const s=await committed();if(!same(s.head,expected))fail('DURABLE_ANCHOR_STALE_READ');return structuredClone(s.head);});
 }
 async function compareAndSet(expected,next){
  if(!validAnchor(anchorType,expected)||!validAnchor(anchorType,next)||!nextAnchor(anchorType,expected,next))fail('DURABLE_ANCHOR_CAS_INVALID');
  return withLock(async check=>{
   const s=await committed();if(!same(s.head,expected))return false;
   if(s.events.length>=10000)fail('DURABLE_ANCHOR_CAPACITY');
   await append(next,expected,s,check);return true;
  });
 }
 async function recoverInterruptedCommit({authorization}={}){
  permitValid(authorization,conf);
  return withLock(async check=>{
   const s=await committed({allowPending:true});
   if(!s.hasPending||!same(s.head,authorization.expectedAnchor))fail('DURABLE_ANCHOR_RECOVERY_STATE_MISMATCH');
   const bytes=await safeBytes(pending,{allowEmpty:true,maxBytes:8192});
   if(sha(bytes)!==authorization.pendingDigest)fail('DURABLE_ANCHOR_RECOVERY_STATE_MISMATCH');
   if(authorization.action==='commit-pending'){
    let e;try{e=JSON.parse(bytes.toString('utf8'));}catch{fail('DURABLE_ANCHOR_RECOVERY_INVALID_PENDING');}
    try{eventValid(e,conf);}catch{fail('DURABLE_ANCHOR_RECOVERY_INVALID_PENDING');}
    if(bytes.toString('utf8')!==JSON.stringify(e)||e.index!==s.events.length+1||e.previousDigest!==s.digest||
       !same(e.previousAnchor,s.head)||!same(e.anchor,authorization.targetAnchor))fail('DURABLE_ANCHOR_RECOVERY_INVALID_PENDING');
    await check();await rename(pending,join(dir,file(e.index)));await syncDir();
    const after=await committed();if(!same(after.head,e.anchor))fail('DURABLE_ANCHOR_COMMIT_UNCERTAIN');
    return Object.freeze({recovered:true,action:'commit-pending',anchor:structuredClone(after.head),productionApproved:false});
   }
   // Aborting a torn, uncommitted proposal does not assert that the registry
   // state was rolled back; registry/journal consistency must be rechecked.
   if(authorization.targetAnchor!==null)fail('DURABLE_ANCHOR_RECOVERY_STATE_MISMATCH');
   await check();await unlink(pending);await syncDir();
   return Object.freeze({recovered:true,action:'abort-pending',anchor:structuredClone(s.head),productionApproved:false});
  });
 }
 return Object.freeze({read,readPinned,inspect,inspectRecoveryState,validateRecoveryAuthorization,compareAndSet,recoverInterruptedCommit});
}
