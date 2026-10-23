/**
 * Objective 31Z — OFFLINE, fail-closed archive/receipt cross-resource handoff.
 * Archives and signed receipts are separate durable resources. This is NOT an
 * atomic distributed transaction. Every uncertain state requires independent
 * supervisor pins; no implicit recovery or manufacturing authorization.
 * Linux owner-only local filesystem; no Shopify/network access.
 */
import {createHash} from 'node:crypto';
import {constants as F} from 'node:fs';
import {mkdir,open,lstat,readdir,realpath,link,unlink} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {join,resolve} from 'node:path';
import {verifyOfflineAcquisitionEvidenceExport} from './offline-acquisition-evidence-export.mjs';
import {OFFLINE_EXPORT_REGISTRY_SCHEMA,verifyOfflineExportReceipt,verifyHistoricalOfflineExportReceipt} from './offline-acquisition-export-receipt-registry.mjs';

export const OFFLINE_ARCHIVE_RECEIPT_COORDINATION_SCHEMA='TJ-OFFLINE-ARCHIVE-RECEIPT-COORDINATION-1';
const HEX=/^[0-9a-f]{64}$/,ROOT='0'.repeat(64),ID=/^[A-Za-z0-9_-]{12,80}$/;
const sha=b=>createHash('sha256').update(b).digest('hex');
const fail=code=>{throw Object.assign(new Error(code),{code});};
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>object(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<2000&&HEX.test(h.headDigest)&&(h.count===0)===(h.headDigest===ROOT);
const recHash=record=>sha(Buffer.from(`${OFFLINE_EXPORT_REGISTRY_SCHEMA}\0${JSON.stringify(record)}`));
const name=d=>`${d}.tjexport`;
const MAX_ARCHIVE=32*1024*1024+32768;

export function createOfflineArchiveReceiptCoordinator({archiveDirectory,registryDirectory,registry,registryId,witnesses,quorum,injectFault,lockTimeoutMs=5000}={}){
 if(process.platform!=='linux'||!F.O_NOFOLLOW||typeof archiveDirectory!=='string'||!archiveDirectory.trim()||
  typeof registryDirectory!=='string'||!registryDirectory.trim()||!ID.test(registryId||'')||
  typeof registry?.inspect!=='function'||typeof registry?.append!=='function'||
  !Array.isArray(witnesses)||!Number.isSafeInteger(quorum)||
  !Number.isSafeInteger(lockTimeoutMs)||lockTimeoutMs<0||lockTimeoutMs>10000||
  (injectFault!==undefined&&typeof injectFault!=='function'))fail('CROSS_RESOURCE_CONFIGURATION');
 const dir=resolve(archiveDirectory),receiptDir=resolve(registryDirectory),pending=join(dir,'.pending-coordination.json'),lock=join(dir,'.coordination-lock');
 if(dir===receiptDir||dir.startsWith(receiptDir+'/')||receiptDir.startsWith(dir+'/'))fail('CROSS_RESOURCE_SEPARATION_REQUIRED');
 async function safeDir(path,create=false){
  if(create)await mkdir(path,{recursive:true,mode:0o700});
  let s;try{s=await lstat(path);if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o077)!==0||s.uid!==process.getuid()||(await realpath(path))!==path)fail('CROSS_RESOURCE_DIRECTORY_UNSAFE');}
  catch(e){if(e.code==='CROSS_RESOURCE_DIRECTORY_UNSAFE')throw e;fail('CROSS_RESOURCE_DIRECTORY_UNSAFE');}
  return s;
 }
 async function readSafe(path,limit,links=1){let h;try{
  h=await open(path,F.O_RDONLY|F.O_NOFOLLOW|F.O_NONBLOCK);
  const [a,b]=await Promise.all([h.stat(),lstat(path)]);
  if(!a.isFile()||a.isSymbolicLink()||a.nlink!==links||a.uid!==process.getuid()||(a.mode&0o077)!==0||a.size<2||a.size>limit||a.dev!==b.dev||a.ino!==b.ino)fail('CROSS_RESOURCE_FILE_UNSAFE');
  const bytes=await h.readFile(),c=await h.stat(),d=await lstat(path);
  if(bytes.length!==a.size||c.size!==a.size||c.mtimeMs!==a.mtimeMs||c.ctimeMs!==a.ctimeMs||d.dev!==a.dev||d.ino!==a.ino)fail('CROSS_RESOURCE_FILE_CHANGED');
  return bytes;
 }catch(e){if(['ENOENT','ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('CROSS_RESOURCE_FILE_UNSAFE');throw e;}finally{if(h)await h.close();}}
 async function syncDir(){const h=await open(dir,'r');try{await h.sync();}finally{await h.close();}}
 async function exclusiveWrite(path,bytes){let h;try{
  h=await open(path,F.O_WRONLY|F.O_CREAT|F.O_EXCL|F.O_NOFOLLOW,0o600);await h.writeFile(bytes);await h.sync();
 }catch(e){if(['EEXIST','ELOOP'].includes(e.code))fail('CROSS_RESOURCE_UNCERTAIN_COMMIT');throw e;}finally{if(h)await h.close();}await syncDir();}
 async function withLock(fn){const d=await safeDir(dir,true);let h,child;
  try{
   h=await open(lock,F.O_RDWR|F.O_CREAT|F.O_NOFOLLOW,0o600);const [a,b]=await Promise.all([h.stat(),lstat(lock)]);
   if(!a.isFile()||a.nlink!==1||a.uid!==process.getuid()||(a.mode&0o077)!==0||a.dev!==b.dev||a.ino!==b.ino)fail('CROSS_RESOURCE_LOCK_UNSAFE');
   child=spawn('/usr/bin/flock',['-x','-w',(lockTimeoutMs/1000).toFixed(3),'/proc/self/fd/3','/bin/sh','-c','printf "READY\\n"; IFS= read -r _ || :'],{stdio:['pipe','pipe','pipe',h.fd]});child.stdin?.on('error',()=>{});
   await new Promise((ok,no)=>{let settled=false,out='';const bad=()=>{if(!settled){settled=true;no(Object.assign(Error('CROSS_RESOURCE_LOCK_UNAVAILABLE'),{code:'CROSS_RESOURCE_LOCK_UNAVAILABLE'}));}};child.once('error',bad);child.once('close',bad);child.stdout.on('data',b=>{out+=b.toString();if(out.length>32)return bad();if(out.includes('READY\n')&&!settled){settled=true;ok();}});});
   const check=async()=>{const [x,y]=await Promise.all([lstat(dir),lstat(lock)]);if(x.dev!==d.dev||x.ino!==d.ino||!y.isFile()||y.dev!==a.dev||y.ino!==a.ino||y.nlink!==1||(y.mode&0o077)!==0)fail('CROSS_RESOURCE_LOCK_UNSAFE');};
   await check();return await fn(check);
  }finally{if(child){child.stdin?.end('\n');await new Promise(ok=>{if(child.exitCode!==null||child.signalCode!==null)return ok();child.once('close',ok);setTimeout(()=>{child.kill('SIGKILL');ok();},1000).unref();});}if(h)await h.close();}
 }
 async function enumeration({allowPending=false,expectedArchive=null}={}){
  const names=await readdir(dir),allowed=new Set(['.coordination-lock']);
  if(allowPending)allowed.add('.pending-coordination.json');if(expectedArchive)allowed.add(name(expectedArchive));
  // A prior finalized archive may coexist, but every archive must be explicitly
  // supplied in a trusted inventory: do not silently treat it as legitimate.
  const extras=names.filter(n=>!allowed.has(n));if(extras.length)fail('CROSS_RESOURCE_ORPHAN_OR_UNTRACKED_FILE');
  if(!allowPending&&names.includes('.pending-coordination.json'))fail('CROSS_RESOURCE_UNCERTAIN_COMMIT');
 }
 function pins({expectedBeforeHead,expectedAfterHead,expectedTransitionDigest,expectedEpoch,nowMs}){
  if(!head(expectedBeforeHead)||!head(expectedAfterHead)||expectedAfterHead.count!==expectedBeforeHead.count+1||
   !HEX.test(expectedTransitionDigest||'')||!Number.isSafeInteger(expectedEpoch)||expectedEpoch<0||!Number.isSafeInteger(nowMs)||nowMs<0)fail('CROSS_RESOURCE_EXTERNAL_PINS_REQUIRED');
 }
 function verifyReceiptAndPins(receipt,archiveBytes,args){
  pins(args);const b=verifyOfflineExportReceipt({receipt,witnesses,quorum,registryId,nowMs:args.nowMs});
  if(receipt.body.sequence!==args.expectedAfterHead.count||receipt.body.previousDigest!==args.expectedBeforeHead.headDigest||
   b.archiveBytes!==archiveBytes.length||sha(archiveBytes)!==b.archiveDigest)fail('CROSS_RESOURCE_RECEIPT_BINDING');
  verifyOfflineAcquisitionEvidenceExport({bytes:archiveBytes,expectedDigest:b.archiveDigest,expectedAcquisitionId:b.acquisitionId});
  const body={schema:OFFLINE_EXPORT_REGISTRY_SCHEMA,index:receipt.body.sequence,previousDigest:receipt.body.previousDigest,receipt};
  if(recHash(body)!==args.expectedAfterHead.headDigest)fail('CROSS_RESOURCE_AFTER_HEAD_PIN_MISMATCH');
  return b;
 }
 function mark(receipt,args){return {schema:OFFLINE_ARCHIVE_RECEIPT_COORDINATION_SCHEMA,registryId,receipt,expectedBeforeHead:args.expectedBeforeHead,expectedAfterHead:args.expectedAfterHead,expectedTransitionDigest:args.expectedTransitionDigest,expectedEpoch:args.expectedEpoch};}
 async function verifyPending(args){
  if(!HEX.test(args.expectedMarkerDigest||'')||!HEX.test(args.expectedArchiveDigest||''))fail('CROSS_RESOURCE_EXTERNAL_PINS_REQUIRED');
  const bytes=await readSafe(pending,16384);if(sha(bytes)!==args.expectedMarkerDigest)fail('CROSS_RESOURCE_MARKER_PIN_MISMATCH');
  let marker;try{marker=JSON.parse(bytes.toString('utf8'));}catch{fail('CROSS_RESOURCE_MARKER_INVALID');}
  if(JSON.stringify(marker)!==bytes.toString('utf8')||!exact(marker,['schema','registryId','receipt','expectedBeforeHead','expectedAfterHead','expectedTransitionDigest','expectedEpoch'])||marker.schema!==OFFLINE_ARCHIVE_RECEIPT_COORDINATION_SCHEMA||marker.registryId!==registryId||
   !equal(marker.expectedBeforeHead,args.expectedBeforeHead)||!equal(marker.expectedAfterHead,args.expectedAfterHead)||marker.expectedTransitionDigest!==args.expectedTransitionDigest||marker.expectedEpoch!==args.expectedEpoch||marker.receipt?.body?.archiveDigest!==args.expectedArchiveDigest)fail('CROSS_RESOURCE_MARKER_INVALID');
  const archive=await readSafe(join(dir,name(args.expectedArchiveDigest)),MAX_ARCHIVE);
  if(sha(archive)!==args.expectedArchiveDigest||archive.length!==marker.receipt.body.archiveBytes)fail('CROSS_RESOURCE_ARCHIVE_TAMPERED');
  verifyOfflineAcquisitionEvidenceExport({bytes:archive,expectedDigest:args.expectedArchiveDigest,expectedAcquisitionId:marker.receipt.body.acquisitionId});
  verifyHistoricalOfflineExportReceipt({receipt:marker.receipt,witnesses,quorum,registryId});
  const body={schema:OFFLINE_EXPORT_REGISTRY_SCHEMA,index:marker.receipt.body.sequence,previousDigest:marker.receipt.body.previousDigest,receipt:marker.receipt};
  if(!equal(args.expectedBeforeHead,marker.expectedBeforeHead)||recHash(body)!==args.expectedAfterHead.headDigest)fail('CROSS_RESOURCE_MARKER_INVALID');
  return {marker,archive};
 }
 async function checkRegistry(args,committed){
  const target=committed?args.expectedAfterHead:args.expectedBeforeHead;
  await registry.inspect({expectedHead:target,expectedTransitionDigest:args.expectedTransitionDigest,expectedEpoch:args.expectedEpoch,nowMs:args.nowMs});
  const slot=join(receiptDir,`${String(args.expectedAfterHead.count).padStart(4,'0')}.json`);
  if(committed){const bytes=await readSafe(slot,16384),s=bytes.toString('utf8');let r;try{r=JSON.parse(s);}catch{fail('CROSS_RESOURCE_RECEIPT_RECORD_INVALID');}
   if(s!==JSON.stringify(r)||!exact(r,['schema','index','previousDigest','receipt','digest'])||r.schema!==OFFLINE_EXPORT_REGISTRY_SCHEMA||r.index!==args.expectedAfterHead.count||r.previousDigest!==args.expectedBeforeHead.headDigest||r.digest!==args.expectedAfterHead.headDigest||!equal(r.receipt,args.receipt))fail('CROSS_RESOURCE_RECEIPT_RECORD_INVALID');
  }else{const names=await readdir(receiptDir);if(names.includes(`${String(args.expectedAfterHead.count).padStart(4,'0')}.json`))fail('CROSS_RESOURCE_AMBIGUOUS_RECEIPT');}
 }
 /** Stage archive and a durable, independently pinnable intent BEFORE registry append. */
 async function stage({receipt,archiveBytes,...args}={}){return withLock(async check=>{
  if(!Buffer.isBuffer(archiveBytes)||archiveBytes.length<2||archiveBytes.length>MAX_ARCHIVE)fail('CROSS_RESOURCE_ARCHIVE_SIZE');
  const b=verifyReceiptAndPins(receipt,archiveBytes,args);await safeDir(receiptDir);await enumeration();
  await registry.inspect({expectedHead:args.expectedBeforeHead,expectedTransitionDigest:args.expectedTransitionDigest,expectedEpoch:args.expectedEpoch,nowMs:args.nowMs});
  const bytes=Buffer.from(JSON.stringify(mark(receipt,args)));if(bytes.length>16384)fail('CROSS_RESOURCE_MARKER_SIZE');
  const archivePath=join(dir,name(b.archiveDigest)),tmp=join(dir,'.pending-archive');
  await exclusiveWrite(tmp,archiveBytes);if(injectFault)await injectFault('after-archive-temp-sync');await check();
  try{await link(tmp,archivePath);}catch(e){if(e.code==='EEXIST')fail('CROSS_RESOURCE_UNCERTAIN_COMMIT');throw e;}
  await syncDir();if(injectFault)await injectFault('after-archive-link-sync');await unlink(tmp);await syncDir();
  await exclusiveWrite(pending,bytes);if(injectFault)await injectFault('after-coordination-marker-sync');
  return Object.freeze({expectedMarkerDigest:sha(bytes),expectedArchiveDigest:b.archiveDigest,expectedAfterHead:args.expectedAfterHead,status:'STAGED_NOT_COMMITTED',productionApproved:false});
 });}
 /** Commit is never retried after uncertainty; external recovery must adjudicate. */
 async function commit(args={}){return withLock(async check=>{
  pins(args);await safeDir(receiptDir);await enumeration({allowPending:true,expectedArchive:args.expectedArchiveDigest});
  const {marker,archive}=await verifyPending(args);
  await checkRegistry({...args,receipt:marker.receipt},false);await check();
  if(injectFault)await injectFault('before-receipt-append');
  const result=await registry.append({receipt:marker.receipt,archiveBytes:archive,expectedHead:args.expectedBeforeHead,expectedTransitionDigest:args.expectedTransitionDigest,expectedEpoch:args.expectedEpoch,nowMs:args.nowMs});
  if(!equal(result.head,args.expectedAfterHead))fail('CROSS_RESOURCE_AFTER_HEAD_PIN_MISMATCH');
  if(injectFault)await injectFault('after-receipt-append');
  return Object.freeze({head:result.head,status:'COMMITTED_REQUIRES_SUPERVISED_FINALIZATION',productionApproved:false});
 });}
 /** Supervisor supplies pins and a decision; never infer which resource won. */
 async function reconcile({decision,...args}={}){return withLock(async check=>{
  pins(args);await safeDir(receiptDir);await enumeration({allowPending:true,expectedArchive:args.expectedArchiveDigest});
  const {marker}=await verifyPending(args);if(!['finalize-committed','quarantine-uncommitted'].includes(decision))fail('CROSS_RESOURCE_DECISION_REQUIRED');
  const committed=decision==='finalize-committed';await checkRegistry({...args,receipt:marker.receipt},committed);
  const before=await lstat(pending);await check();if(injectFault)await injectFault('before-coordination-reconcile');
  const after=await lstat(pending);if(after.ino!==before.ino||after.dev!==before.dev||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs)fail('CROSS_RESOURCE_MARKER_CHANGED');
  if(committed){await unlink(pending);await syncDir();}
  else{
   // Preserve orphan archive and pinned intent as forensic evidence. Refuse
   // further staging until an independent custodian removes this quarantine.
   const quarantine=join(dir,`.orphan-${args.expectedArchiveDigest}.json`);
   try{await link(pending,quarantine);}catch(e){if(e.code==='EEXIST')fail('CROSS_RESOURCE_UNCERTAIN_COMMIT');throw e;}
   await syncDir();await unlink(pending);await syncDir();
  }
  if(injectFault)await injectFault('after-coordination-reconcile');
  return Object.freeze({status:committed?'EXTERNALLY_PINNED_FINALIZED':'EXTERNALLY_PINNED_ORPHAN_QUARANTINED',head:committed?args.expectedAfterHead:args.expectedBeforeHead,productionApproved:false});
 });}
 return Object.freeze({stage,commit,reconcile});
}
