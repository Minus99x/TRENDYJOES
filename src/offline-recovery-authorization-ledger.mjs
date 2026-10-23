/**
 * Objective 31E: fail-closed single-host reservation ledger for signed recovery
 * authorization IDs. A reservation is burned BEFORE attempting recovery, so
 * ambiguous crashes never automatically retry a possibly-used permit.
 * NOT an offsite/WORM store or a defense against a privileged full rollback.
 */
import {createHash} from 'node:crypto';
import {constants as C} from 'node:fs';
import {mkdir,open,lstat,readdir,rename} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {resolve,join} from 'node:path';

const SCHEMA='TJ-OFFLINE-RECOVERY-RESERVATION-1';
const ROOT='0'.repeat(64);
const ID=/^[A-Za-z0-9_-]{12,80}$/;
const HEX=/^[0-9a-f]{64}$/;
const fields=['schema','registryId','anchorType','index','previousDigest','authorizationId','permitDigest','pendingDigest','digest'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>object(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const sha=x=>createHash('sha256').update(x).digest('hex');
const file=i=>String(i).padStart(10,'0')+'.json';

export function createOfflineRecoveryAuthorizationLedger({directory,registryId,anchorType,lockTimeoutMs=5000,injectFault}={}){
 if(process.platform!=='linux'||!C.O_NOFOLLOW||typeof directory!=='string'||!directory.trim()||
   !ID.test(registryId||'')||!['registry','journal'].includes(anchorType)||
   !Number.isInteger(lockTimeoutMs)||lockTimeoutMs<0||lockTimeoutMs>10000||
   (injectFault!==undefined&&typeof injectFault!=='function'))fail('RECOVERY_LEDGER_CONFIGURATION');
 const dir=resolve(directory),lock=join(dir,'.reservation-lock'),pending=join(dir,'.pending.json');
 async function safeDirectory(){
  await mkdir(dir,{recursive:true,mode:0o700});const s=await lstat(dir);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0)fail('RECOVERY_LEDGER_DIRECTORY_UNSAFE');
  return s;
 }
 async function withLock(fn){
  const d=await safeDirectory();let h;
  try{
   h=await open(lock,C.O_RDWR|C.O_CREAT|C.O_NOFOLLOW,0o600);
   const s=await h.stat(),p=await lstat(lock);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev)fail('RECOVERY_LEDGER_LOCK_UNSAFE');
   await new Promise((ok,no)=>{
    const child=spawn('/usr/bin/flock',['-x','-w',(lockTimeoutMs/1000).toFixed(3),'3'],{stdio:['ignore','ignore','ignore',h.fd]});
    child.once('error',()=>no(Object.assign(Error('RECOVERY_LEDGER_LOCK_UNAVAILABLE'),{code:'RECOVERY_LEDGER_LOCK_UNAVAILABLE'})));
    child.once('close',code=>code===0?ok():no(Object.assign(Error('RECOVERY_LEDGER_LOCK_UNAVAILABLE'),{code:'RECOVERY_LEDGER_LOCK_UNAVAILABLE'})));
   });
   const verify=async()=>{
    const [a,b]=await Promise.all([lstat(dir),lstat(lock)]);
    if(!a.isDirectory()||a.ino!==d.ino||a.dev!==d.dev||!b.isFile()||b.ino!==s.ino||b.dev!==s.dev||b.nlink!==1)fail('RECOVERY_LEDGER_LOCK_UNSAFE');
   };
   await verify();return await fn(verify);
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('RECOVERY_LEDGER_LOCK_UNSAFE');throw e;}
  finally{if(h)await h.close();}
 }
 async function safeBytes(path,{allowEmpty=false}={}){
  let h;
  try{
   h=await open(path,C.O_RDONLY|C.O_NOFOLLOW);
   const [s,p]=await Promise.all([h.stat(),lstat(path)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev||(!allowEmpty&&s.size===0)||s.size>2048)fail('RECOVERY_LEDGER_FILE_UNSAFE');
   return await h.readFile();
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('RECOVERY_LEDGER_FILE_UNSAFE');throw e;}
  finally{if(h)await h.close();}
 }
 async function state(){
  const names=await readdir(dir);
  if(names.includes('.pending.json'))fail('RECOVERY_LEDGER_PENDING_REVIEW_REQUIRED');
  const events=names.filter(x=>x!=='.reservation-lock');
  if(events.length>10000)fail('RECOVERY_LEDGER_CAPACITY');
  let previous=ROOT;const ids=new Set(),permits=new Set(),history=[];
  for(let i=1;i<=events.length;i++){
   const name=file(i);if(!events.includes(name))fail('RECOVERY_LEDGER_HISTORY_GAP');
   const raw=(await safeBytes(join(dir,name))).toString('utf8');let e;
   try{e=JSON.parse(raw);}catch{fail('RECOVERY_LEDGER_EVENT_INVALID');}
   if(!exact(e,fields)||raw!==JSON.stringify(e)||e.schema!==SCHEMA||e.registryId!==registryId||e.anchorType!==anchorType||
     e.index!==i||e.previousDigest!==previous||!ID.test(e.authorizationId||'')||
     !HEX.test(e.permitDigest)||!HEX.test(e.pendingDigest)||!HEX.test(e.digest))fail('RECOVERY_LEDGER_EVENT_INVALID');
   const {digest,...body}=e;
   if(digest!==sha(Buffer.from(`${SCHEMA}\0${JSON.stringify(body)}`)))fail('RECOVERY_LEDGER_TAMPERED');
   if(ids.has(e.authorizationId)||permits.has(e.permitDigest))fail('RECOVERY_LEDGER_DUPLICATE_HISTORY');
   ids.add(e.authorizationId);permits.add(e.permitDigest);previous=digest;history.push(e);
  }
  return {count:events.length,headDigest:previous,ids,permits,history};
 }
 async function syncDir(){const h=await open(dir,'r');try{await h.sync();}finally{await h.close();}}
 async function inspect(){return withLock(async()=>{const s=await state();return Object.freeze({count:s.count,headDigest:s.headDigest,productionApproved:false});});}
 async function inspectHistory(){return withLock(async()=>{const s=await state();return structuredClone({count:s.count,headDigest:s.headDigest,events:s.history});});}
 async function inspectPinned(expected){
  if(!exact(expected,['count','headDigest'])||!Number.isSafeInteger(expected.count)||
     expected.count<0||expected.count>10000||!HEX.test(expected.headDigest))fail('RECOVERY_LEDGER_PIN_INVALID');
  return withLock(async()=>{
   const s=await state();
   if(s.count!==expected.count||s.headDigest!==expected.headDigest)fail('RECOVERY_LEDGER_STALE_PIN');
   return Object.freeze({count:s.count,headDigest:s.headDigest,productionApproved:false});
  });
 }
 async function reserve({authorizationId,permitDigest,pendingDigest,expectedHead}={}){
  if(!ID.test(authorizationId||'')||!HEX.test(permitDigest)||!HEX.test(pendingDigest)||
    (expectedHead!==undefined&&(!exact(expectedHead,['count','headDigest'])||!Number.isSafeInteger(expectedHead.count)||expectedHead.count<0||expectedHead.count>10000||!HEX.test(expectedHead.headDigest))))fail('RECOVERY_LEDGER_RESERVATION_INVALID');
  return withLock(async check=>{
   const s=await state();
   if(expectedHead!==undefined&&(s.count!==expectedHead.count||s.headDigest!==expectedHead.headDigest))fail('RECOVERY_LEDGER_STALE_PIN');
   if(s.ids.has(authorizationId)||s.permits.has(permitDigest))fail('RECOVERY_LEDGER_REPLAY');
   if(s.count>=10000)fail('RECOVERY_LEDGER_CAPACITY');
   const body={schema:SCHEMA,registryId,anchorType,index:s.count+1,previousDigest:s.headDigest,authorizationId,permitDigest,pendingDigest};
   const e={...body,digest:sha(Buffer.from(`${SCHEMA}\0${JSON.stringify(body)}`))};
   await check();let h;
   try{
    h=await open(pending,C.O_WRONLY|C.O_CREAT|C.O_EXCL|C.O_NOFOLLOW,0o600);
    await h.writeFile(JSON.stringify(e));await h.sync();
   }catch(err){if(['EEXIST','ELOOP'].includes(err.code))fail('RECOVERY_LEDGER_PENDING_REVIEW_REQUIRED');throw err;}
   finally{if(h)await h.close();}
   await syncDir();if(injectFault)await injectFault('after-pending-sync');
   await check();await rename(pending,join(dir,file(e.index)));await syncDir();
   if(injectFault)await injectFault('after-commit-sync');
   const final=await state();
   if(final.headDigest!==e.digest||final.count!==e.index)fail('RECOVERY_LEDGER_COMMIT_UNCERTAIN');
   return Object.freeze({reserved:true,index:e.index,headDigest:e.digest,productionApproved:false});
  });
 }
 return Object.freeze({inspect,inspectHistory,inspectPinned,reserve});
}
