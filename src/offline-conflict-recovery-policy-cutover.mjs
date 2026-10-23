/**
 * Objective 32Q: opt-in, single-cutover, Linux-local durable activation marker.
 * Caller MUST hold the parent exchange journal's cross-process flock lock.
 * The marker is NOT an independent anchor; callers must supply its SHA-256 pin.
 * Interrupted writes deliberately require external adjudication, not cleanup.
 */
import {createHash} from 'node:crypto';
import {constants as F} from 'node:fs';
import {open,lstat,link,unlink,readdir} from 'node:fs/promises';
import {join} from 'node:path';

export const OFFLINE_CONFLICT_RECOVERY_CUTOVER_SCHEMA='TJ-OFFLINE-CONFLICT-RECOVERY-CUTOVER-1';
const HEX=/^[a-f0-9]{64}$/;
const fields=['schema','genesisExchangeDigest','previousPolicyDigest','activePolicyDigest','transitionHead','receiptHead','activatedAt','cutoverDigest'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Object.keys(o).length===keys.length&&
 keys.every(k=>Object.getOwnPropertyDescriptor(o,k)?.value!==undefined&&Object.getOwnPropertyDescriptor(o,k)?.enumerable)&&
 Object.keys(o).every(k=>keys.includes(k));
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=4096&&HEX.test(h.headDigest);
const digest=b=>createHash('sha256').update('TJ-32Q-CUTOVER\0').update(JSON.stringify(b)).digest('hex');
export function offlineConflictRecoveryCutoverDigest(body){
 if(!exact(body,fields.slice(0,-1))||body.schema!==OFFLINE_CONFLICT_RECOVERY_CUTOVER_SCHEMA||
 ![body.genesisExchangeDigest,body.previousPolicyDigest,body.activePolicyDigest].every(x=>HEX.test(x||''))||
 body.previousPolicyDigest===body.activePolicyDigest||!head(body.transitionHead)||body.transitionHead.count!==1||
 !head(body.receiptHead)||!Number.isSafeInteger(body.activatedAt)||body.activatedAt<0)
 fail('EXCHANGE32Q_CUTOVER_INVALID');
 return digest(body);
}
export function createOfflineConflictRecoveryPolicyCutover({directory,genesisExchangeDigest,injectFault}={}){
 if(typeof directory!=='string'||!HEX.test(genesisExchangeDigest||''))fail('EXCHANGE32Q_CONFIGURATION');
 const active=join(directory,'.recovery-policy-cutover.json'),pending=join(directory,'.recovery-policy-cutover.pending');
 const resolution=join(directory,'.recovery-policy-cutover-resolution.json');
 async function syncDir(){const h=await open(directory,F.O_RDONLY|F.O_DIRECTORY|F.O_NOFOLLOW);try{await h.sync();}finally{await h.close();}}
 async function safeRead(){
  let h;try{
   h=await open(active,F.O_RDONLY|F.O_NOFOLLOW);
   const [s,p]=await Promise.all([h.stat(),lstat(active)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||
    s.ino!==p.ino||s.dev!==p.dev||s.size<2||s.size>2048)fail('EXCHANGE32Q_FILE_UNSAFE');
   const bytes=await h.readFile();let e;try{e=JSON.parse(bytes.toString('utf8'));}catch{fail('EXCHANGE32Q_CUTOVER_INVALID');}
   if(!exact(e,fields)||!Buffer.from(JSON.stringify(e)).equals(bytes)||
    e.genesisExchangeDigest!==genesisExchangeDigest||
    offlineConflictRecoveryCutoverDigest(Object.fromEntries(fields.slice(0,-1).map(k=>[k,e[k]])))!==e.cutoverDigest)
    fail('EXCHANGE32Q_CUTOVER_INVALID');
   return e;
  }finally{if(h)await h.close();}
 }
 async function assertNoPending(){
  if((await readdir(directory)).includes('.recovery-policy-cutover.pending'))fail('EXCHANGE32Q_UNCERTAIN_CUTOVER');
 }
 async function inspect({expectedCutoverDigest,allowAbsent=false}={}){
  const names=await readdir(directory);
  if(names.includes('.recovery-policy-cutover.pending'))fail('EXCHANGE32Q_UNCERTAIN_CUTOVER');
  if(!names.includes('.recovery-policy-cutover.json')){
   if(allowAbsent&&expectedCutoverDigest===undefined){
    if(names.includes('.recovery-policy-cutover-resolution.json'))fail('EXCHANGE32R_RESOLVED_CUTOVER');
    return null;
   }
   fail('EXCHANGE32Q_NOT_ACTIVE');
  }
  if(!HEX.test(expectedCutoverDigest||''))fail('EXCHANGE32Q_EXTERNAL_PIN_REQUIRED');
  const e=await safeRead();if(e.cutoverDigest!==expectedCutoverDigest)fail('EXCHANGE32Q_FORK_OR_ROLLBACK');
  return Object.freeze({...e,localOnly:true,independentlyPublished:false,authorizesProduction:false});
 }
 async function commit({body,expectedCutoverDigest}={}){
  const calculated=offlineConflictRecoveryCutoverDigest(body);
  if(calculated!==expectedCutoverDigest)fail('EXCHANGE32Q_EXTERNAL_PIN_MISMATCH');
  if((await readdir(directory)).some(n=>n==='.recovery-policy-cutover.pending'||n==='.recovery-policy-cutover.json'||n==='.recovery-policy-cutover-resolution.json'))
   fail('EXCHANGE32Q_ALREADY_OR_UNCERTAIN');
  const raw=Buffer.from(JSON.stringify({...body,cutoverDigest:calculated}));let h;
  try{
   h=await open(pending,F.O_WRONLY|F.O_CREAT|F.O_EXCL|F.O_NOFOLLOW,0o600);
   await h.writeFile(raw);await h.sync();
  }catch(e){if(e?.code==='EEXIST')fail('EXCHANGE32Q_ALREADY_OR_UNCERTAIN');throw e;}
  finally{if(h)await h.close();}
  await syncDir();if(injectFault)await injectFault('after-cutover-pending-sync');
  try{await link(pending,active);}catch(e){if(e?.code==='EEXIST')fail('EXCHANGE32Q_ALREADY_OR_UNCERTAIN');throw e;}
  await syncDir();if(injectFault)await injectFault('after-cutover-link-sync');
  await unlink(pending);await syncDir();
  if(injectFault)await injectFault('after-cutover-commit-sync');
  return inspect({expectedCutoverDigest:calculated});
 }
 async function adjudicate({action,expectedCutoverDigest,expectedPendingBytesDigest,expectedDecisionDigest,
 expectedResolutionDigest,nowMs}={}){
  if(!['abort','finalize'].includes(action)||![expectedCutoverDigest,expectedPendingBytesDigest,expectedDecisionDigest,expectedResolutionDigest].every(x=>HEX.test(x||''))||
   !Number.isSafeInteger(nowMs)||nowMs<0)fail('EXCHANGE32R_EXTERNAL_PINS_REQUIRED');
  const names=await readdir(directory);
  if(names.includes('.recovery-policy-cutover-resolution.json'))fail('EXCHANGE32R_ALREADY_ADJUDICATED');
  if(!names.includes('.recovery-policy-cutover.pending'))fail('EXCHANGE32R_PENDING_REQUIRED');
  let h;let bytes;try{
   h=await open(pending,F.O_RDONLY|F.O_NOFOLLOW);
   const [s,p]=await Promise.all([h.stat(),lstat(pending)]);
   if(!s.isFile()||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev||
    s.size<2||s.size>2048||!([1,2].includes(s.nlink)))fail('EXCHANGE32R_PENDING_UNSAFE');
   bytes=await h.readFile();
   const linked=names.includes('.recovery-policy-cutover.json');
   if(action==='abort'&&(linked||s.nlink!==1))fail('EXCHANGE32R_UNSAFE_ABORT');
   if(action==='finalize'){
    if(!linked||s.nlink!==2)fail('EXCHANGE32R_UNSAFE_FINALIZE');
    const a=await lstat(active);
    if(!a.isFile()||a.ino!==s.ino||a.dev!==s.dev||a.nlink!==2)fail('EXCHANGE32R_UNSAFE_FINALIZE');
   }
  }finally{if(h)await h.close();}
  const bytesDigest=createHash('sha256').update(bytes).digest('hex');
  if(bytesDigest!==expectedPendingBytesDigest)fail('EXCHANGE32R_PENDING_PIN_MISMATCH');
  let e;try{e=JSON.parse(bytes.toString('utf8'));}catch{fail('EXCHANGE32R_PENDING_INVALID');}
  if(!exact(e,fields)||!Buffer.from(JSON.stringify(e)).equals(bytes)||
   e.genesisExchangeDigest!==genesisExchangeDigest||
   offlineConflictRecoveryCutoverDigest(Object.fromEntries(fields.slice(0,-1).map(k=>[k,e[k]])))!==e.cutoverDigest||
   e.cutoverDigest!==expectedCutoverDigest)fail('EXCHANGE32R_PENDING_INVALID');
  const body={schema:'TJ-OFFLINE-CONFLICT-CUTOVER-RESOLUTION-1',action,genesisExchangeDigest,
   cutoverDigest:expectedCutoverDigest,pendingBytesDigest:bytesDigest,decisionDigest:expectedDecisionDigest,resolvedAt:nowMs};
  const receiptDigest=createHash('sha256').update('TJ-32R-RESOLUTION-RECEIPT\0'+JSON.stringify(body)).digest('hex');
  if(receiptDigest!==expectedResolutionDigest)fail('EXCHANGE32R_RESOLUTION_PIN_MISMATCH');
  const raw=Buffer.from(JSON.stringify({...body,receiptDigest}));let rh;
  try{
   rh=await open(resolution,F.O_WRONLY|F.O_CREAT|F.O_EXCL|F.O_NOFOLLOW,0o600);
   await rh.writeFile(raw);await rh.sync();
  }catch(err){if(err.code==='EEXIST')fail('EXCHANGE32R_ALREADY_ADJUDICATED');throw err;}
  finally{if(rh)await rh.close();}
  await syncDir();if(injectFault)await injectFault('after-cutover-resolution-receipt-sync');
  await unlink(pending);await syncDir();
  if(injectFault)await injectFault('after-cutover-resolution-unlink-sync');
  return Object.freeze({...body,receiptDigest,localOnly:true,completionProvenLocally:true,
   independentlyPublished:false,authorizesProduction:false});
 }
 async function inspectResolution({expectedResolutionDigest,allowUncertain=false}={}){
  if(!HEX.test(expectedResolutionDigest||''))fail('EXCHANGE32R_EXTERNAL_PINS_REQUIRED');
  let h;try{
   h=await open(resolution,F.O_RDONLY|F.O_NOFOLLOW);
   const [s,p]=await Promise.all([h.stat(),lstat(resolution)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev||s.size<2||s.size>2048)
    fail('EXCHANGE32R_RECEIPT_UNSAFE');
   const bytes=await h.readFile();let e;try{e=JSON.parse(bytes.toString('utf8'));}catch{fail('EXCHANGE32R_RECEIPT_INVALID');}
   const keys=['schema','action','genesisExchangeDigest','cutoverDigest','pendingBytesDigest','decisionDigest','resolvedAt','receiptDigest'];
   if(!exact(e,keys)||!Buffer.from(JSON.stringify(e)).equals(bytes)||e.schema!=='TJ-OFFLINE-CONFLICT-CUTOVER-RESOLUTION-1'||
    !['abort','finalize'].includes(e.action)||e.genesisExchangeDigest!==genesisExchangeDigest||
    ![e.cutoverDigest,e.pendingBytesDigest,e.decisionDigest].every(x=>HEX.test(x||''))||
    !Number.isSafeInteger(e.resolvedAt)||e.resolvedAt<0||
    createHash('sha256').update('TJ-32R-RESOLUTION-RECEIPT\0'+JSON.stringify(Object.fromEntries(keys.slice(0,-1).map(k=>[k,e[k]])))).digest('hex')!==e.receiptDigest)
    fail('EXCHANGE32R_RECEIPT_INVALID');
   if(e.receiptDigest!==expectedResolutionDigest)fail('EXCHANGE32R_RESOLUTION_PIN_MISMATCH');
   const names=await readdir(directory);
   if(names.includes('.recovery-policy-cutover.pending')){
    if(!allowUncertain)fail('EXCHANGE32R_UNCERTAIN_RESOLUTION');
    let ph;try{
     ph=await open(pending,F.O_RDONLY|F.O_NOFOLLOW);
     const [ps,lp]=await Promise.all([ph.stat(),lstat(pending)]);
     if(!ps.isFile()||ps.uid!==process.getuid()||(ps.mode&0o077)!==0||
      ps.ino!==lp.ino||ps.dev!==lp.dev||ps.size<2||ps.size>2048||
      ![1,2].includes(ps.nlink))fail('EXCHANGE32S_PENDING_UNSAFE');
     const pb=await ph.readFile();
     if(createHash('sha256').update(pb).digest('hex')!==e.pendingBytesDigest)
      fail('EXCHANGE32S_PENDING_PIN_MISMATCH');
     let marker;try{marker=JSON.parse(pb.toString('utf8'));}catch{fail('EXCHANGE32S_PENDING_INVALID');}
     if(!exact(marker,fields)||!Buffer.from(JSON.stringify(marker)).equals(pb)||
      marker.cutoverDigest!==e.cutoverDigest||marker.genesisExchangeDigest!==genesisExchangeDigest||
      offlineConflictRecoveryCutoverDigest(Object.fromEntries(fields.slice(0,-1).map(k=>[k,marker[k]])))!==marker.cutoverDigest)
      fail('EXCHANGE32S_PENDING_INVALID');
     const linked=names.includes('.recovery-policy-cutover.json');
     if((e.action==='abort'&&(linked||ps.nlink!==1))||
      (e.action==='finalize'&&(!linked||ps.nlink!==2)))fail('EXCHANGE32S_UNCERTAIN_STATE_CONFLICT');
     if(linked){const a=await lstat(active);
      if(!a.isFile()||a.ino!==ps.ino||a.dev!==ps.dev||a.nlink!==2)
       fail('EXCHANGE32S_UNCERTAIN_STATE_CONFLICT');}
    }finally{if(ph)await ph.close();}
    return Object.freeze({...e,status:'uncertain-pending',completionProvenLocally:false,
     localOnly:true,independentlyPublished:false,authorizesProduction:false});
   }
   if(e.action==='abort'&&names.includes('.recovery-policy-cutover.json'))fail('EXCHANGE32R_RESOLUTION_STATE_CONFLICT');
   if(e.action==='finalize'){
    if(!names.includes('.recovery-policy-cutover.json'))fail('EXCHANGE32R_RESOLUTION_STATE_CONFLICT');
    const activeMarker=await safeRead();
    if(activeMarker.cutoverDigest!==e.cutoverDigest)fail('EXCHANGE32R_RESOLUTION_STATE_CONFLICT');
   }
   return Object.freeze({...e,status:'locally-completed',completionProvenLocally:true,
    localOnly:true,independentlyPublished:false,authorizesProduction:false});
  }finally{if(h)await h.close();}
 }
 return Object.freeze({inspect,commit,assertNoPending,adjudicate,inspectResolution});
}
