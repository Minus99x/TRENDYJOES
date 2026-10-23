/**
 * Objective 31B — opt-in OFFLINE fail-closed coordinator for authenticated
 * registry mutations and independently anchored audit observations.
 *
 * There is NO atomic commit spanning two independent anchors. After a crash,
 * a signed, independently inspected recovery is mandatory. Direct registry
 * callers can bypass this coordinator; they cannot be prevented by this module.
 * Linux cooperative locking is single-host only. No Shopify/network writes.
 */
import {verify as verifySignature} from 'node:crypto';
import {constants as C} from 'node:fs';
import {mkdir,open,lstat} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {join,resolve} from 'node:path';

const fail=code=>{throw Object.assign(new Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>obj(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const hex=/^[0-9a-f]{64}$/;
const identifier=/^[A-Za-z0-9_-]{12,80}$/;
const schema='TJ-OFFLINE-AUDITED-REGISTRY-COORDINATOR-RECOVERY-1';
const permitFields=['schema','registryId','action','authorizationId','issuedAt','expiresAt','expectedJournalAnchor','expectedRegistryAnchor','targetRegistryAnchor','reason'];
const readActions=Object.freeze(['readAuthenticatedArtwork','exportAuthenticatedBackup']);
const mutationActions=Object.freeze([
 'commitAuthenticatedRevision','revokeAuthenticatedArtwork','revokeAuthenticatedRevision',
 'migrateAuthenticatedArtwork','rotateAuthenticatedArtworkKey','restoreAuthenticatedBackup',
 'recoverInterruptedRegistry'
]);
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const validRegistry=a=>a===null||(exact(a,['sequence','mac'])&&Number.isSafeInteger(a.sequence)&&a.sequence>=1&&hex.test(a.mac));
const validJournal=a=>a===null||(exact(a,['index','digest'])&&Number.isSafeInteger(a.index)&&a.index>=1&&a.index<=10000&&hex.test(a.digest));
function verifyPermit(p,config,action){
 const now=Date.now();
 if(!exact(p,[...permitFields,'signature'])||p.schema!==schema||p.registryId!==config.registryId||p.action!==action||
    !identifier.test(p.authorizationId||'')||!Number.isSafeInteger(p.issuedAt)||!Number.isSafeInteger(p.expiresAt)||
    p.issuedAt>now||p.expiresAt<=now||p.expiresAt<=p.issuedAt||p.expiresAt-p.issuedAt>900000||
    !validJournal(p.expectedJournalAnchor)||!validRegistry(p.expectedRegistryAnchor)||
    !validRegistry(p.targetRegistryAnchor)||p.targetRegistryAnchor===null||
    typeof p.reason!=='string'||p.reason.length<12||p.reason.length>200||p.reason!==p.reason.trim()||
    /[\x00-\x1f\x7f]/.test(p.reason)||typeof p.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(p.signature))
   fail('COORDINATOR_RECOVERY_DENIED');
 const body=Object.fromEntries(permitFields.map(k=>[k,p[k]]));
 const sig=Buffer.from(p.signature,'base64url');
 if(sig.length!==64||sig.toString('base64url')!==p.signature||
    !verifySignature(null,Buffer.from(`${schema}\0${JSON.stringify(body)}`),config.publicKey,sig))
   fail('COORDINATOR_RECOVERY_DENIED');
}

export function createOfflineAuditedRegistryCoordinator({directory,registry,journal,registryId,
 readRegistryAnchor,readJournalAnchor,recovery,lockTimeoutMs=1500,injectFault}={}){
 if(process.platform!=='linux'||!C.O_NOFOLLOW||typeof directory!=='string'||!directory.trim()||
    !identifier.test(registryId||'')||!registry||!journal||
    mutationActions.some(a=>typeof registry[a]!=='function')||readActions.some(a=>typeof registry[a]!=='function')||
    typeof journal.verify!=='function'||typeof journal.appendAuthenticatedSnapshot!=='function'||
    typeof journal.recoverInterruptedAppend!=='function'||
    typeof readRegistryAnchor!=='function'||typeof readJournalAnchor!=='function'||
    !exact(recovery,['publicKey'])||recovery.publicKey?.type!=='public'||
    recovery.publicKey?.asymmetricKeyType!=='ed25519'||
    !Number.isInteger(lockTimeoutMs)||lockTimeoutMs<0||lockTimeoutMs>10000||
    (injectFault!==undefined&&typeof injectFault!=='function'))fail('COORDINATOR_CONFIGURATION');
 const dir=resolve(directory),lock=join(dir,'.audited-registry-coordinator-lock');
 const config={registryId,publicKey:recovery.publicKey};
 async function withLock(fn){
  await mkdir(dir,{recursive:true,mode:0o700});
  const before=await lstat(dir);
  if(!before.isDirectory()||before.isSymbolicLink()||before.uid!==process.getuid()||(before.mode&0o077)!==0)
   fail('COORDINATOR_DIRECTORY_UNSAFE');
  let h;
  try{
   h=await open(lock,C.O_RDWR|C.O_CREAT|C.O_NOFOLLOW,0o600);
   const st=await h.stat(),p=await lstat(lock);
   if(!st.isFile()||st.nlink!==1||(st.mode&0o077)!==0||st.ino!==p.ino||st.dev!==p.dev)
    fail('COORDINATOR_LOCK_UNSAFE');
   await new Promise((ok,no)=>{
    const child=spawn('/usr/bin/flock',['-x','-w',(lockTimeoutMs/1000).toFixed(3),'3'],
     {stdio:['ignore','ignore','ignore',h.fd]});
    child.once('error',()=>no(Object.assign(Error('COORDINATOR_LOCK_UNAVAILABLE'),{code:'COORDINATOR_LOCK_UNAVAILABLE'})));
    child.once('close',code=>code===0?ok():no(Object.assign(Error('COORDINATOR_LOCK_UNAVAILABLE'),{code:'COORDINATOR_LOCK_UNAVAILABLE'})));
   });
   const check=async()=>{
    let d,l;try{[d,l]=await Promise.all([lstat(dir),lstat(lock)]);}catch{fail('COORDINATOR_LOCK_UNSAFE');}
    if(!d.isDirectory()||d.ino!==before.ino||d.dev!==before.dev||
       !l.isFile()||l.ino!==st.ino||l.dev!==st.dev||l.nlink!==1)fail('COORDINATOR_LOCK_UNSAFE');
   };
   await check();return await fn(check);
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('COORDINATOR_LOCK_UNSAFE');throw e;}
  finally{if(h)await h.close();}
 }
 async function registryAnchor(){
  let a;try{a=await readRegistryAnchor();}catch{fail('COORDINATOR_REGISTRY_ANCHOR_UNAVAILABLE');}
  if(!validRegistry(a))fail('COORDINATOR_REGISTRY_ANCHOR_UNAVAILABLE');return a;
 }
 async function journalAnchor(){
  let a;try{a=await readJournalAnchor();}catch{fail('COORDINATOR_JOURNAL_ANCHOR_UNAVAILABLE');}
  if(!validJournal(a))fail('COORDINATOR_JOURNAL_ANCHOR_UNAVAILABLE');return a;
 }
 async function inspect(){
  const j=await journal.verify(); // verifies local event bytes against independent anchor
  const [r,a]=await Promise.all([registryAnchor(),journalAnchor()]);
  if(!same(a,j.anchor))fail('COORDINATOR_JOURNAL_CHANGED');
  if(j.eventCount===0){if(r!==null)fail('COORDINATOR_BOOTSTRAP_REQUIRED');}
  else if(!same(r,j.lastObservedRegistryAnchor))fail('COORDINATOR_REGISTRY_GAP');
  return Object.freeze({registryAnchor:r,journalAnchor:a,eventCount:j.eventCount,
   historicalCoverage:j.historyBeforeBootstrapProven,productionApproved:false});
 }
 async function signedAudit(envelopeProvider,target){
  if(typeof envelopeProvider!=='function')fail('COORDINATOR_AUDIT_AUTH_REQUIRED');
  const envelope=await envelopeProvider(structuredClone(target));
  if(!obj(envelope))fail('COORDINATOR_AUDIT_AUTH_REQUIRED');
  return envelope;
 }
 async function execute({action,envelope,auditEnvelope}={}){
  if(!mutationActions.includes(action)||!obj(envelope)||typeof auditEnvelope!=='function')
   fail('COORDINATOR_ACTION_DENIED');
  return withLock(async check=>{
   const prior=await inspect();await check();
   // Authenticated mutation, restore, or independently signed registry recovery.
   const result=await registry[action](envelope);
   const after=await registryAnchor();
   if(after===null||same(after,prior.registryAnchor)||
      after.sequence!==(prior.registryAnchor?.sequence??0)+1)
    fail('COORDINATOR_REGISTRY_UNEXPECTED');
   if(injectFault)await injectFault('after-registry-commit');
   await check();
   const audit=await signedAudit(auditEnvelope,after);
   const appended=await journal.appendAuthenticatedSnapshot(audit);
   if(!same(appended.registryAnchor,after))fail('COORDINATOR_AUDIT_MISMATCH');
   const synced=await inspect();
   if(!same(synced.registryAnchor,after))fail('COORDINATOR_REGISTRY_CHANGED');
   if(injectFault)await injectFault('after-journal-append');
   return Object.freeze({result,registryAnchor:after,journalAnchor:synced.journalAnchor,productionApproved:false});
  });
 }
 /** Read only through the same coordinator lock and both independent heads.
  * A read cannot observe a known unjournaled transition through this facade.
  * Only authenticated artwork and operator-signed encrypted backup reads exist.
  */
 async function read({action,envelope}={}){
  if(!readActions.includes(action)||!obj(envelope))fail('COORDINATOR_READ_DENIED');
  return withLock(async check=>{
   const prior=await inspect();await check();
   const result=await registry[action](envelope);
   await check();const after=await inspect();
   if(!same(prior.registryAnchor,after.registryAnchor)||
      !same(prior.journalAnchor,after.journalAnchor))fail('COORDINATOR_READ_CHANGED');
   return result;
  });
 }
 async function reconcile({authorization,auditEnvelope}={}){
  // Signed, exact one-step reconciliation after registry commit but before audit append.
  verifyPermit(authorization,config,'reconcile-registry-gap');
  return withLock(async check=>{
   const j=await journal.verify();
   const [r,a]=await Promise.all([registryAnchor(),journalAnchor()]);
   if(!same(j.anchor,a)||!same(a,authorization.expectedJournalAnchor)||
      !same(j.lastObservedRegistryAnchor??null,authorization.expectedRegistryAnchor)||
      !same(r,authorization.targetRegistryAnchor)||
      r.sequence!==(authorization.expectedRegistryAnchor?.sequence??0)+1)
    fail('COORDINATOR_RECOVERY_STATE_MISMATCH');
   await check();
   const audit=await signedAudit(auditEnvelope,r);
   const appended=await journal.appendAuthenticatedSnapshot(audit);
   if(!same(appended.registryAnchor,r))fail('COORDINATOR_AUDIT_MISMATCH');
   await inspect();return Object.freeze({reconciled:true,registryAnchor:r,journalAnchor:appended.journalAnchor,productionApproved:false});
  });
 }
 async function bootstrap({authorization,auditEnvelope}={}){
  // Existing legacy history is explicitly NOT proven by first observation.
  verifyPermit(authorization,config,'bootstrap-unproven-history');
  return withLock(async check=>{
   const j=await journal.verify();
   const [r,a]=await Promise.all([registryAnchor(),journalAnchor()]);
   if(j.eventCount!==0||a!==null||authorization.expectedJournalAnchor!==null||
      authorization.expectedRegistryAnchor!==null||!same(r,authorization.targetRegistryAnchor))
    fail('COORDINATOR_BOOTSTRAP_DENIED');
   await check();
   const appended=await journal.appendAuthenticatedSnapshot(await signedAudit(auditEnvelope,r));
   if(appended.coverage!=='BOOTSTRAP_UNPROVEN_PRIOR_HISTORY')fail('COORDINATOR_BOOTSTRAP_DENIED');
   await inspect();return Object.freeze({bootstrap:true,historyBeforeBootstrapProven:false,productionApproved:false});
  });
 }
 async function recoverJournal({authorization}={}){
  return withLock(async()=>{
   const result=await journal.recoverInterruptedAppend({authorization});
   const synced=await inspect();return Object.freeze({result,registryAnchor:synced.registryAnchor,
    journalAnchor:synced.journalAnchor,productionApproved:false});
  });
 }
 return Object.freeze({inspect:()=>withLock(inspect),execute,read,reconcile,bootstrap,recoverJournal});
}
