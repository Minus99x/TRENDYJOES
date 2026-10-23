/**
 * Objective 31V: one durable, fail-closed OFFLINE export-receipt witness cutover.
 * Operates on Objective 31S's on-disk receipt records, sharing its flock lock.
 * A trusted caller MUST retain both the receipt-head and transition-digest pins
 * outside this directory. Crash uncertainty is never silently repaired.
 * Linux-only local prototype; no keys, network or production authority stored.
 */
import {createHash,verify as cryptoVerify} from 'node:crypto';
import {constants as F} from 'node:fs';
import {mkdir,open,lstat,readdir,realpath,link,unlink} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {join,resolve} from 'node:path';
import {verifyOfflineAcquisitionEvidenceExport} from './offline-acquisition-evidence-export.mjs';
import {OFFLINE_EXPORT_REGISTRY_SCHEMA,offlineExportReceiptPolicyDigest,verifyHistoricalOfflineExportReceipt,verifyOfflineExportReceipt} from './offline-acquisition-export-receipt-registry.mjs';
import {offlineExportWitnessTransitionSigningBytes,offlineExportWitnessTransitionPossessionBytes,offlineExportWitnessTransitionChainDigest} from './offline-export-receipt-witness-rotation.mjs';

const ROOT='0'.repeat(64),HEX=/^[0-9a-f]{64}$/,ID=/^[A-Za-z0-9_-]{12,80}$/;
const CUTOVER_SCHEMA='TJ-OFFLINE-EXPORT-RECEIPT-DURABLE-CUTOVER-1';
const fail=code=>{throw Object.assign(new Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>obj(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const sha=b=>createHash('sha256').update(b).digest('hex');
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=2000&&HEX.test(h.headDigest)&&(h.count===0)===(h.headDigest===ROOT);
const fname=i=>`${String(i).padStart(4,'0')}.json`;
const recHash=b=>sha(Buffer.from(`${OFFLINE_EXPORT_REGISTRY_SCHEMA}\0${JSON.stringify(b)}`));
const signed=s=>typeof s==='string'&&/^[A-Za-z0-9_-]{86}$/.test(s)&&Buffer.from(s,'base64url').length===64&&Buffer.from(s,'base64url').toString('base64url')===s;
const readonly=(s,status)=>Object.freeze({head:Object.freeze({...s.head}),epoch:s.cutover?1:0,transitionDigest:s.cutover?.transitionDigest??null,status,readOnly:true,mayManufacture:false,mayAcknowledge:false,productionApproved:false});

function checkSignatures(signatures,policy,minimum,bytes){
 if(!Array.isArray(signatures)||signatures.length<minimum||signatures.length>policy.witnesses.length)fail('CUTOVER_SIGNATURE_INVALID');
 const members=new Map(policy.witnesses.map(w=>[w.id,w.publicKey]));let prev='';
 for(const item of signatures){
  if(!exact(item,['witnessId','signature'])||typeof item.witnessId!=='string'||item.witnessId<=prev||!members.has(item.witnessId)||!signed(item.signature)||
    !cryptoVerify(null,bytes(item.witnessId),members.get(item.witnessId),Buffer.from(item.signature,'base64url')))fail('CUTOVER_SIGNATURE_INVALID');
  prev=item.witnessId;
 }
}
function checkTransition(transition,oldPolicy,newPolicy,registryId,expectedHead,nowMs,historical=false){
 if(!exact(transition,['body','outgoingSignatures','incomingProofs']))fail('CUTOVER_CERTIFICATE_INVALID');
 const b=transition.body,bytes=offlineExportWitnessTransitionSigningBytes(b);
 if(b.registryId!==registryId||b.fromEpoch!==0||b.toEpoch!==1||b.fromPolicyDigest!==offlineExportReceiptPolicyDigest(oldPolicy)||
    b.toPolicyDigest!==offlineExportReceiptPolicyDigest(newPolicy)||!same(b.anchorHead,expectedHead)||expectedHead.count<1)fail('CUTOVER_ANCHOR_OR_POLICY_INVALID');
 if(b.issuedAt>nowMs||(!historical&&nowMs>=b.expiresAt))fail('CUTOVER_EXPIRED_OR_FUTURE');
 const oldIds=new Set(oldPolicy.witnesses.map(w=>w.id)),oldKeys=new Set(oldPolicy.witnesses.map(w=>sha(w.publicKey.export({format:'der',type:'spki'}))));
 for(const w of newPolicy.witnesses)if(oldIds.has(w.id)||oldKeys.has(sha(w.publicKey.export({format:'der',type:'spki'}))))fail('CUTOVER_RETIRED_KEY_REUSE');
 checkSignatures(transition.outgoingSignatures,oldPolicy,oldPolicy.quorum,()=>bytes);
 if(transition.incomingProofs?.length!==newPolicy.witnesses.length)fail('CUTOVER_PROOF_INVALID');
 checkSignatures(transition.incomingProofs,newPolicy,newPolicy.witnesses.length,id=>offlineExportWitnessTransitionPossessionBytes(b,id));
 return offlineExportWitnessTransitionChainDigest({transitions:[transition]});
}
export function createOfflineExportReceiptCutoverRegistry({directory,registryId,oldPolicy,newPolicy,lockTimeoutMs=5000,injectFault}={}){
 if(process.platform!=='linux'||!F.O_NOFOLLOW||typeof directory!=='string'||!directory.trim()||!ID.test(registryId||'')||
  !Number.isSafeInteger(lockTimeoutMs)||lockTimeoutMs<0||lockTimeoutMs>10000||(injectFault!==undefined&&typeof injectFault!=='function'))fail('CUTOVER_CONFIGURATION');
 if(!exact(oldPolicy,['witnesses','quorum'])||!exact(newPolicy,['witnesses','quorum']))fail('CUTOVER_CONFIGURATION');
 const oldDigest=offlineExportReceiptPolicyDigest(oldPolicy),newDigest=offlineExportReceiptPolicyDigest(newPolicy);
 if(oldDigest===newDigest)fail('CUTOVER_CONFIGURATION');
 const retiredIds=new Set(oldPolicy.witnesses.map(w=>w.id));
 const retiredKeys=new Set(oldPolicy.witnesses.map(w=>sha(w.publicKey.export({format:'der',type:'spki'}))));
 if(newPolicy.witnesses.some(w=>retiredIds.has(w.id)||retiredKeys.has(sha(w.publicKey.export({format:'der',type:'spki'})))))fail('CUTOVER_CONFIGURATION');
 const dir=resolve(directory),lock=join(dir,'.export-registry-lock'),pending=join(dir,'.pending-cutover.json'),committed=join(dir,'.witness-cutover.json');
 async function safeDir(){
  await mkdir(dir,{recursive:true,mode:0o700});const s=await lstat(dir);
  if(!s.isDirectory()||s.isSymbolicLink()||(await realpath(dir))!==dir||s.uid!==process.getuid()||(s.mode&0o077)!==0)fail('CUTOVER_DIRECTORY_UNSAFE');
  return s;
 }
 async function withLock(fn){
  const d=await safeDir();let h,child;
  try{
   h=await open(lock,F.O_RDWR|F.O_CREAT|F.O_NOFOLLOW,0o600);
   const [s,ps]=await Promise.all([h.stat(),lstat(lock)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==ps.ino||s.dev!==ps.dev)fail('CUTOVER_LOCK_UNSAFE');
   child=spawn('/usr/bin/flock',['-x','-w',(lockTimeoutMs/1000).toFixed(3),'/proc/self/fd/3','/bin/sh','-c','printf "READY\\n"; IFS= read -r _ || :'],{stdio:['pipe','pipe','pipe',h.fd]});
   child.stdin?.on('error',()=>{});
   await new Promise((ok,no)=>{let settled=false,data='';const err=()=>{if(!settled){settled=true;no(Object.assign(Error('CUTOVER_LOCK_UNAVAILABLE'),{code:'CUTOVER_LOCK_UNAVAILABLE'}));}};
    child.once('error',err);child.once('close',err);child.stdout.on('data',b=>{data+=b.toString();if(data.length>32)return err();if(data.includes('READY\n')&&!settled){settled=true;ok();}});});
   const check=async()=>{const [a,b]=await Promise.all([lstat(dir),lstat(lock)]);if(!a.isDirectory()||a.ino!==d.ino||a.dev!==d.dev||!b.isFile()||b.ino!==s.ino||b.dev!==s.dev||b.nlink!==1||(b.mode&0o077)!==0)fail('CUTOVER_LOCK_UNSAFE');};
   await check();return await fn(check);
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('CUTOVER_LOCK_UNSAFE');throw e;}
  finally{if(child){child.stdin?.end('\n');await new Promise(ok=>{if(child.exitCode!==null||child.signalCode!==null)return ok();child.once('close',ok);setTimeout(()=>{child.kill('SIGKILL');ok();},1000).unref();});}if(h)await h.close();}
 }
 async function readSafe(path,max=16384,allowedLinks=1){let h;try{
  h=await open(path,F.O_RDONLY|F.O_NOFOLLOW|F.O_NONBLOCK);const [s,ps]=await Promise.all([h.stat(),lstat(path)]);
  if(!s.isFile()||s.nlink!==allowedLinks||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==ps.ino||s.dev!==ps.dev||s.size<2||s.size>max)fail('CUTOVER_FILE_UNSAFE');
  const bytes=await h.readFile(),after=await h.stat(),p2=await lstat(path);
  if(bytes.length!==s.size||after.size!==s.size||after.mtimeMs!==s.mtimeMs||after.ctimeMs!==s.ctimeMs||p2.ino!==s.ino||p2.dev!==s.dev)fail('CUTOVER_FILE_CHANGED');
  const raw=bytes.toString('utf8');if(!Buffer.from(raw).equals(bytes))fail('CUTOVER_HISTORY_INVALID');
  let data;try{data=JSON.parse(raw);}catch{fail('CUTOVER_HISTORY_INVALID');}
  if(JSON.stringify(data)!==raw)fail('CUTOVER_HISTORY_INVALID');return data;
 }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('CUTOVER_FILE_UNSAFE');throw e;}finally{if(h)await h.close();}}
 async function syncDir(){const h=await open(dir,'r');try{await h.sync();}finally{await h.close();}}
 async function state({expectedTransitionDigest,nowMs,allowPending=null,linkedPath=null}={}){
  const names=await readdir(dir);
  if((names.includes('.pending.json')&&allowPending!=='.pending.json')||(names.includes('.pending-cutover.json')&&allowPending!=='.pending-cutover.json'))fail('CUTOVER_UNCERTAIN_COMMIT');
  const permitted=new Set(['.export-registry-lock','.witness-cutover.json']);
  if(allowPending)permitted.add(allowPending);const files=names.filter(n=>!permitted.has(n));
  if(files.length>2000||files.some(n=>!/^[0-9]{4}\.json$/.test(n)))fail('CUTOVER_HISTORY_INVALID');
  const hasCutover=names.includes('.witness-cutover.json');let cutover=null;
  if(hasCutover){
   if(!HEX.test(expectedTransitionDigest||''))fail('CUTOVER_EXTERNAL_TRANSITION_PIN_REQUIRED');
   const c=await readSafe(committed,16384,linkedPath===committed?2:1);
   if(!exact(c,['schema','registryId','transition','transitionDigest'])||c.schema!==CUTOVER_SCHEMA||c.registryId!==registryId||c.transitionDigest!==expectedTransitionDigest)fail('CUTOVER_TRANSITION_PIN_MISMATCH');
   const digest=checkTransition(c.transition,oldPolicy,newPolicy,registryId,c.transition.body.anchorHead,nowMs,true);
   if(digest!==expectedTransitionDigest)fail('CUTOVER_TRANSITION_PIN_MISMATCH');cutover=c;
  }else if(expectedTransitionDigest!==undefined&&expectedTransitionDigest!==null)fail('CUTOVER_MISSING_PINNED_TRANSITION');
  let previous=ROOT,previousTime=-1;const entries=[],exports=new Set(),acquisitions=new Set(),digests=new Set(),nonces=new Set();
  for(let i=1;i<=files.length;i++){
   if(!files.includes(fname(i)))fail('CUTOVER_HISTORY_INVALID');
   const path=join(dir,fname(i));const e=await readSafe(path,16384,linkedPath===path?2:1);
   if(!exact(e,['schema','index','previousDigest','receipt','digest'])||e.schema!==OFFLINE_EXPORT_REGISTRY_SCHEMA||e.index!==i||e.previousDigest!==previous||!HEX.test(e.digest||''))fail('CUTOVER_HISTORY_INVALID');
   const policy=cutover&&i>cutover.transition.body.anchorHead.count?newPolicy:oldPolicy;
   const b=verifyHistoricalOfflineExportReceipt({receipt:e.receipt,...policy,registryId}).body;
   if(b.sequence!==i||b.previousDigest!==previous||b.issuedAt<previousTime||
     (cutover&&((i<=cutover.transition.body.anchorHead.count&&b.issuedAt>cutover.transition.body.issuedAt)||
       (i>cutover.transition.body.anchorHead.count&&b.issuedAt<cutover.transition.body.issuedAt))))fail('CUTOVER_HISTORY_INVALID');
   if(exports.has(b.exportId)||acquisitions.has(b.acquisitionId)||digests.has(b.archiveDigest)||nonces.has(b.nonce))fail('CUTOVER_REPLAY');
   const {digest,...record}=e;if(recHash(record)!==digest)fail('CUTOVER_HISTORY_INVALID');
   exports.add(b.exportId);acquisitions.add(b.acquisitionId);digests.add(b.archiveDigest);nonces.add(b.nonce);entries.push(e);previous=e.digest;previousTime=b.issuedAt;
   if(cutover&&i===cutover.transition.body.anchorHead.count&&previous!==cutover.transition.body.anchorHead.headDigest)fail('CUTOVER_ANCHOR_MISMATCH');
  }
  if(cutover&&files.length<cutover.transition.body.anchorHead.count)fail('CUTOVER_ANCHOR_MISMATCH');
  return {entries,head:{count:entries.length,headDigest:previous},cutover,exports,acquisitions,digests,nonces,previousTime};
 }
 function checkPin(expectedHead){if(!head(expectedHead))fail('CUTOVER_EXTERNAL_HEAD_REQUIRED');}
 async function cutover({transition,expectedHead,expectedTransitionDigest,nowMs}={}){
  checkPin(expectedHead);if(!HEX.test(expectedTransitionDigest||'')||!Number.isSafeInteger(nowMs)||nowMs<0)fail('CUTOVER_EXTERNAL_TRANSITION_PIN_REQUIRED');
  return withLock(async check=>{
   const s=await state({nowMs});if(s.cutover)fail('CUTOVER_ALREADY_APPLIED');
   if(!same(s.head,expectedHead))fail('CUTOVER_STALE_HEAD');
   const digest=checkTransition(transition,oldPolicy,newPolicy,registryId,expectedHead,nowMs);
   if(digest!==expectedTransitionDigest)fail('CUTOVER_TRANSITION_PIN_MISMATCH');
   if(s.entries.at(-1).receipt.body.issuedAt>transition.body.issuedAt)fail('CUTOVER_TIME_ORDER_INVALID');
   const c={schema:CUTOVER_SCHEMA,registryId,transition,transitionDigest:digest},bytes=Buffer.from(JSON.stringify(c));
   if(bytes.length>16384)fail('CUTOVER_RECORD_TOO_LARGE');
   await check();let h;
   try{h=await open(pending,F.O_WRONLY|F.O_CREAT|F.O_EXCL|F.O_NOFOLLOW,0o600);await h.writeFile(bytes);await h.sync();}
   catch(e){if(['EEXIST','ELOOP'].includes(e.code))fail('CUTOVER_UNCERTAIN_COMMIT');throw e;}finally{if(h)await h.close();}
   await syncDir();if(injectFault)await injectFault('after-cutover-pending-sync');await check();
   try{await link(pending,committed);}catch(e){if(e.code==='EEXIST')fail('CUTOVER_UNCERTAIN_COMMIT');throw e;}
   await syncDir();if(injectFault)await injectFault('after-cutover-link-sync');await unlink(pending);await syncDir();if(injectFault)await injectFault('after-cutover-commit-sync');
   const n=await state({expectedTransitionDigest,nowMs});if(!same(n.head,expectedHead))fail('CUTOVER_UNCERTAIN_COMMIT');
   return readonly(n,'PINNED_WITNESS_CUTOVER_OFFLINE_ONLY');
  });
 }
 async function inspect({expectedHead,expectedTransitionDigest,nowMs}={}){
  checkPin(expectedHead);if(!Number.isSafeInteger(nowMs)||nowMs<0)fail('CUTOVER_CLOCK_REQUIRED');
  return withLock(async()=>{const s=await state({expectedTransitionDigest,nowMs});if(!same(s.head,expectedHead))fail('CUTOVER_STALE_HEAD');return readonly(s,'PINNED_ROTATED_RECEIPT_HISTORY');});
 }
 async function append({receipt,archiveBytes,expectedHead,expectedTransitionDigest,nowMs}={}){
  checkPin(expectedHead);if(!HEX.test(expectedTransitionDigest||'')||!Number.isSafeInteger(nowMs)||nowMs<0)fail('CUTOVER_EXTERNAL_TRANSITION_PIN_REQUIRED');
  return withLock(async check=>{
   const s=await state({expectedTransitionDigest,nowMs});if(!s.cutover)fail('CUTOVER_NOT_COMMITTED');if(!same(s.head,expectedHead))fail('CUTOVER_STALE_HEAD');
   const b=verifyOfflineExportReceipt({receipt,...newPolicy,registryId,nowMs});const body=receipt.body;
   if(body.sequence!==s.head.count+1||body.previousDigest!==s.head.headDigest||body.issuedAt<s.previousTime||body.issuedAt<s.cutover.transition.body.issuedAt)fail('CUTOVER_SEQUENCE_OR_EPOCH_INVALID');
   if(s.exports.has(body.exportId)||s.acquisitions.has(body.acquisitionId)||s.digests.has(body.archiveDigest)||s.nonces.has(body.nonce))fail('CUTOVER_REPLAY');
   if(!Buffer.isBuffer(archiveBytes)||archiveBytes.length!==b.archiveBytes)fail('CUTOVER_ARCHIVE_SIZE_MISMATCH');
   verifyOfflineAcquisitionEvidenceExport({bytes:archiveBytes,expectedDigest:b.archiveDigest,expectedAcquisitionId:b.acquisitionId});
   const record={schema:OFFLINE_EXPORT_REGISTRY_SCHEMA,index:body.sequence,previousDigest:s.head.headDigest,receipt};const entry={...record,digest:recHash(record)};
   const bytes=Buffer.from(JSON.stringify(entry));if(bytes.length>16384)fail('CUTOVER_RECORD_TOO_LARGE');
   const path=join(dir,fname(entry.index)),temp=join(dir,'.pending.json');await check();let h;
   try{h=await open(temp,F.O_WRONLY|F.O_CREAT|F.O_EXCL|F.O_NOFOLLOW,0o600);await h.writeFile(bytes);await h.sync();}
   catch(e){if(['EEXIST','ELOOP'].includes(e.code))fail('CUTOVER_UNCERTAIN_COMMIT');throw e;}finally{if(h)await h.close();}
   await syncDir();if(injectFault)await injectFault('after-rotated-append-pending-sync');await check();
   try{await link(temp,path);}catch(e){if(e.code==='EEXIST')fail('CUTOVER_UNCERTAIN_COMMIT');throw e;}
   await syncDir();if(injectFault)await injectFault('after-rotated-append-link-sync');await unlink(temp);await syncDir();if(injectFault)await injectFault('after-rotated-append-commit-sync');
   const n=await state({expectedTransitionDigest,nowMs});if(n.head.headDigest!==entry.digest)fail('CUTOVER_UNCERTAIN_COMMIT');
   return readonly(n,'ROTATED_RECEIPT_PIN_RECORDED_OFFLINE_ONLY');
  });
 }

 /**
  * Objective 31W: explicit, externally pinned reconciliation of an uncertain
  * pending commit. Never infer trusted pins from local state or auto-recover.
  * Caller must independently persist the intended before/after pins BEFORE
  * invoking this operation. Abort is permitted only before the hardlink exists.
  */
 async function reconcilePending({kind,decision,expectedBeforeHead,expectedAfterHead,expectedTransitionDigest,expectedPendingDigest,nowMs}={}){
  checkPin(expectedBeforeHead);
  if(!['cutover','append'].includes(kind)||!['abort-unlinked','finalize-linked'].includes(decision)||
    !HEX.test(expectedTransitionDigest||'')||!HEX.test(expectedPendingDigest||'')||
    !Number.isSafeInteger(nowMs)||nowMs<0)fail('CUTOVER_RECOVERY_EXTERNAL_PINS_REQUIRED');
  if(decision==='finalize-linked')checkPin(expectedAfterHead);
  return withLock(async check=>{
   const marker=kind==='cutover'?'.pending-cutover.json':'.pending.json';
   const path=kind==='cutover'?committed:null;
   const names=await readdir(dir);
   if(!names.includes(marker)||names.includes(kind==='cutover'?'.pending.json':'.pending-cutover.json'))fail('CUTOVER_RECOVERY_MARKER_MISMATCH');
   const pendingPath=join(dir,marker);
   // Determine the only permissible destination from the pinned pending body.
   // The pending bytes are canonical, owner-only, and independently SHA-pinned.
   const pendingData=await readSafe(pendingPath,16384,decision==='finalize-linked'?2:1);
   const pendingBytes=Buffer.from(JSON.stringify(pendingData));
   if(sha(pendingBytes)!==expectedPendingDigest)fail('CUTOVER_RECOVERY_PENDING_PIN_MISMATCH');
   let destination=path;
   if(kind==='cutover'){
    if(!exact(pendingData,['schema','registryId','transition','transitionDigest'])||pendingData.schema!==CUTOVER_SCHEMA||
      pendingData.registryId!==registryId||pendingData.transitionDigest!==expectedTransitionDigest)fail('CUTOVER_RECOVERY_RECORD_INVALID');
    if(!same(pendingData.transition?.body?.anchorHead,expectedBeforeHead)||
      checkTransition(pendingData.transition,oldPolicy,newPolicy,registryId,expectedBeforeHead,nowMs,true)!==expectedTransitionDigest)
      fail('CUTOVER_RECOVERY_RECORD_INVALID');
   }else{
    const e=pendingData;
    if(!exact(e,['schema','index','previousDigest','receipt','digest'])||e.schema!==OFFLINE_EXPORT_REGISTRY_SCHEMA||
      !Number.isSafeInteger(e.index)||e.index<2||e.index>2000||
      e.index!==expectedBeforeHead.count+1||e.previousDigest!==expectedBeforeHead.headDigest||
      !HEX.test(e.digest||''))fail('CUTOVER_RECOVERY_RECORD_INVALID');
    const {digest,...record}=e;
    if(recHash(record)!==digest)fail('CUTOVER_RECOVERY_RECORD_INVALID');
    const b=verifyHistoricalOfflineExportReceipt({receipt:e.receipt,...newPolicy,registryId}).body;
    if(b.sequence!==e.index||b.previousDigest!==e.previousDigest)fail('CUTOVER_RECOVERY_RECORD_INVALID');
    destination=join(dir,fname(e.index));
   }
   if(decision==='abort-unlinked'){
    if(names.includes(kind==='cutover'?'.witness-cutover.json':fname(pendingData.index)))fail('CUTOVER_RECOVERY_LINK_EXISTS');
    const s=await state({expectedTransitionDigest:kind==='append'?expectedTransitionDigest:undefined,nowMs,allowPending:marker});
    if(!same(s.head,expectedBeforeHead)|| (kind==='cutover'&&s.cutover) || (kind==='append'&&!s.cutover))fail('CUTOVER_RECOVERY_STALE_PIN');
   }else{
    if(!names.includes(kind==='cutover'?'.witness-cutover.json':fname(pendingData.index)))fail('CUTOVER_RECOVERY_LINK_MISSING');
    const [a,b]=await Promise.all([lstat(pendingPath),lstat(destination)]);
    if(!a.isFile()||!b.isFile()||a.isSymbolicLink()||b.isSymbolicLink()||a.nlink!==2||b.nlink!==2||
      a.ino!==b.ino||a.dev!==b.dev||a.uid!==process.getuid()||(a.mode&0o077)!==0)fail('CUTOVER_RECOVERY_LINK_UNSAFE');
    if(kind==='cutover'&&!same(expectedAfterHead,expectedBeforeHead))fail('CUTOVER_RECOVERY_STALE_PIN');
    if(kind==='append'&&(!same(expectedAfterHead,{count:pendingData.index,headDigest:pendingData.digest})||
      expectedAfterHead.count!==expectedBeforeHead.count+1))fail('CUTOVER_RECOVERY_STALE_PIN');
    const s=await state({expectedTransitionDigest,nowMs,allowPending:marker,linkedPath:destination});
    if(!same(s.head,expectedAfterHead)||!s.cutover)fail('CUTOVER_RECOVERY_STALE_PIN');
   }
   await check();
   // The only mutation is removing the verified marker; no receipt/certificate
   // is overwritten, and no missing commit is ever synthesized.
   await unlink(pendingPath);await syncDir();
   if(injectFault)await injectFault('after-recovery-marker-sync');
   const after=await state({expectedTransitionDigest:kind==='cutover'&&decision==='abort-unlinked'?undefined:expectedTransitionDigest,nowMs});
   const pinned=decision==='abort-unlinked'?expectedBeforeHead:expectedAfterHead;
   if(!same(after.head,pinned))fail('CUTOVER_RECOVERY_STALE_PIN');
   return readonly(after,decision==='abort-unlinked'?'EXTERNALLY_PINNED_ABORT_OFFLINE_ONLY':'EXTERNALLY_PINNED_FINALIZATION_OFFLINE_ONLY');
  });
 }

 return Object.freeze({cutover,append,inspect,reconcilePending,registryId,oldPolicyDigest:oldDigest,newPolicyDigest:newDigest});
}
