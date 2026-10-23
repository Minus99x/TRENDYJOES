/** Objective 33Q — offline verification of actual supplied 33O registry record
 * bytes against independently pinned 33P signed head assertions, with optional
 * Linux-local read-only file-descriptor acquisition. No remote disk proof.
 */
import {createHash,KeyObject} from 'node:crypto';
import {constants as F} from 'node:fs';
import {open,lstat,realpath,readdir} from 'node:fs/promises';
import {resolve} from 'node:path';
import {offlineConflictAcquisitionRegistryGenesisHead,OFFLINE_CONFLICT_ACQUISITION_REGISTRY_SCHEMA} from './offline-conflict-inventory-acquisition-registry.mjs';
import {verifyOfflineConflictInventoryAcquisitionReceipt} from './offline-conflict-inventory-filesystem-acquisition.mjs';
import {reconcileOfflineConflictAcquisitionHeadPublications} from './offline-conflict-acquisition-head-publications.mjs';
export const OFFLINE_CONFLICT_ACQUISITION_RECORD_EVIDENCE_SCHEMA='TJ-OFFLINE-33Q-ACQUISITION-RECORD-EVIDENCE-1';
const HEX=/^[0-9a-f]{64}$/;
const KEYS=['schema','index','namespaceId','journalScopeDigest','hostId','observerId','previousRecordDigest','entry','receiptDigest','nonce','recordDigest'];
const ENTRY=['receipt','records','recordPins','directoryPin','fromHead','toHead','admittedAtMs'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hash=(domain,bytes)=>createHash('sha256').update(domain+'\0').update(bytes).digest('hex');
const exact=(x,keys)=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype&&
 Reflect.ownKeys(x).length===keys.length&&Object.keys(x).join('|')===keys.join('|')&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(x,k);return d&&d.enumerable&&'value'in d;});
const dense=(x,min,max)=>Array.isArray(x)&&Object.getPrototypeOf(x)===Array.prototype&&x.length>=min&&x.length<=max&&
 Reflect.ownKeys(x).length===x.length+1&&Array.from({length:x.length},(_,i)=>{const d=Object.getOwnPropertyDescriptor(x,String(i));return d&&d.enumerable&&'value'in d;}).every(Boolean);
const head=x=>x&&typeof x==='object'&&Number.isSafeInteger(x.count)&&x.count>=0&&x.count<=256&&typeof x.headDigest==='string'&&HEX.test(x.headDigest)&&Object.keys(x).join('|')==='count|headDigest';
const same=(a,b)=>a.count===b.count&&a.headDigest===b.headDigest;
const pin=p=>p&&typeof p==='object'&&Object.keys(p).join('|')==='dev|ino'&&['dev','ino'].every(k=>typeof p[k]==='string'&&/^(0|[1-9][0-9]*)$/.test(p[k]))&&p.ino!=='0';
const samePin=(a,b)=>a.dev===b.dev&&a.ino===b.ino;
const decode=s=>{if(typeof s!=='string'||s.length<1||s.length>100000||!/^[A-Za-z0-9_-]+$/.test(s))fail('EXCHANGE33Q_RECORD_INVALID');
 const b=Buffer.from(s,'base64url');if(b.toString('base64url')!==s)fail('EXCHANGE33Q_RECORD_INVALID');return b;};
const parse=bytes=>{let r;try{r=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{fail('EXCHANGE33Q_RECORD_INVALID');}
 if(!Buffer.from(JSON.stringify(r)).equals(bytes))fail('EXCHANGE33Q_RECORD_INVALID');return r;};
const filename=i=>String(i).padStart(4,'0')+'.json';
const statsEqual=(a,b)=>a.dev===b.dev&&a.ino===b.ino&&a.size===b.size&&a.mtimeNs===b.mtimeNs&&a.ctimeNs===b.ctimeNs;
const safeDir=s=>s.isDirectory()&&!s.isSymbolicLink()&&s.uid===BigInt(process.getuid())&&(s.mode&0o077n)===0n;
const safeFile=s=>s.isFile()&&s.nlink===1n&&s.uid===BigInt(process.getuid())&&(s.mode&0o077n)===0n&&s.size>=100n&&s.size<=3_000_000n;
/** Independent pins are caller-supplied. Full history from genesis is required:
 * no suffix-only or count-only assertion can establish a complete prefix.
 */
export function verifyOfflineConflictAcquisitionRegistryRecordEvidence({recordBytes,expectedRecordBytesDigests,
 publicationVerification,namespaceId,journalScopeDigest,hostId,observerId,
 expectedObserverPublicKey,initialInventoryHead,expectedRegistryDirectoryPin}={}){
 if(!dense(recordBytes,0,64)||!dense(expectedRecordBytesDigests,0,64)||recordBytes.length!==expectedRecordBytesDigests.length||
  !expectedRecordBytesDigests.every(x=>typeof x==='string'&&HEX.test(x))||
  !(expectedObserverPublicKey instanceof KeyObject)||expectedObserverPublicKey.type!=='public'||expectedObserverPublicKey.asymmetricKeyType!=='ed25519'||
  !head(initialInventoryHead)||!pin(expectedRegistryDirectoryPin)||!publicationVerification||typeof publicationVerification!=='object')
  fail('EXCHANGE33Q_EXTERNAL_PINS_REQUIRED');
 const genesis=offlineConflictAcquisitionRegistryGenesisHead({namespaceId,journalScopeDigest,hostId,observerId,expectedObserverPublicKey,initialInventoryHead});
 const p=publicationVerification;
 if(p.expectedNamespaceId!==namespaceId||p.expectedJournalScopeDigest!==journalScopeDigest||
  p.expectedTargetHostId!==hostId||!same(p.expectedRegistryGenesisHead??{},genesis)||
  !pin(p.expectedRegistryDirectoryPin)||!samePin(p.expectedRegistryDirectoryPin,expectedRegistryDirectoryPin))
  fail('EXCHANGE33Q_SCOPE_OR_GENESIS_MISMATCH');
 const signed=reconcileOfflineConflictAcquisitionHeadPublications(p);
 if(signed.status!=='consistent-head')fail('EXCHANGE33Q_UNRESOLVED_PUBLICATIONS');
 const published=signed.registryHeads[0],inventoryClaim=signed.inventoryHeads[0];
 if(recordBytes.length!==published.count)fail('EXCHANGE33Q_RECORD_OMISSION_OR_ROLLBACK');
 let previous=genesis.headDigest,inventory=initialInventoryHead,total=0;
 const seenNonces=[],seenDigests=[];
 for(let i=0;i<recordBytes.length;i++){
  const bytes=recordBytes[i];if(!Buffer.isBuffer(bytes)||bytes.length<100||bytes.length>3_000_000)fail('EXCHANGE33Q_RECORD_INVALID');
  total+=bytes.length;if(total>16_000_000)fail('EXCHANGE33Q_HISTORY_TOO_LARGE');
  if(hash('TJ-33Q-PINNED-33O-RECORD-BYTES',bytes)!==expectedRecordBytesDigests[i])fail('EXCHANGE33Q_RECORD_BYTE_PIN_MISMATCH');
  const r=parse(bytes);
  if(!exact(r,KEYS)||r.schema!==OFFLINE_CONFLICT_ACQUISITION_REGISTRY_SCHEMA||r.index!==i+1||
   r.namespaceId!==namespaceId||r.journalScopeDigest!==journalScopeDigest||r.hostId!==hostId||r.observerId!==observerId||
   r.previousRecordDigest!==previous||typeof r.recordDigest!=='string'||!HEX.test(r.recordDigest)||
   !exact(r.entry,ENTRY)||!head(r.entry.fromHead)||!head(r.entry.toHead)||!same(r.entry.fromHead,inventory)||
   !pin(r.entry.directoryPin)||!Number.isSafeInteger(r.entry.admittedAtMs)||
   !dense(r.entry.records,1,32)||!dense(r.entry.recordPins,1,32)||r.entry.records.length!==r.entry.recordPins.length||
   typeof r.receiptDigest!=='string'||!HEX.test(r.receiptDigest)||typeof r.nonce!=='string')fail('EXCHANGE33Q_RECORD_INVALID');
  const {recordDigest,...body}=r;
  if(hash('TJ-33O-ACQUISITION-REGISTRY-RECORD',Buffer.from(JSON.stringify(body)))!==recordDigest)
   fail('EXCHANGE33Q_RECORD_HASH_MISMATCH');
  const receiptBytes=decode(r.entry.receipt),records=r.entry.records.map(decode);
  let result;try{result=verifyOfflineConflictInventoryAcquisitionReceipt({receiptBytes,records,
   expectedObserverPublicKey,expectedObserverId:observerId,expectedHostId:hostId,
   expectedDirectoryPin:r.entry.directoryPin,recordPins:r.entry.recordPins,
   expectedFromHead:r.entry.fromHead,expectedToHead:r.entry.toHead,
   expectedNamespaceId:namespaceId,expectedJournalScopeDigest:journalScopeDigest,
   nowMs:r.entry.admittedAtMs,seenNonces,seenDigests});}
  catch(e){fail(e?.code==='EXCHANGE33N_REPLAY'?'EXCHANGE33Q_REPLAY':'EXCHANGE33Q_EMBEDDED_EVIDENCE_INVALID');}
  const receipt=parse(receiptBytes);
  if(result.receiptDigest!==r.receiptDigest||receipt.body.nonce!==r.nonce)fail('EXCHANGE33Q_EMBEDDED_EVIDENCE_INVALID');
  seenNonces.push(r.nonce);seenDigests.push(r.receiptDigest);previous=recordDigest;inventory=r.entry.toHead;
 }
 if(published.headDigest!==previous||!same(inventory,inventoryClaim))fail('EXCHANGE33Q_PUBLISHED_HEAD_MISMATCH');
 return Object.freeze({verifiedSuppliedRegistryRecordBytes:true,verifiedEmbeddedWitnessSignatures:true,
  verifiedSignedPublisherClaims:true,recordCount:recordBytes.length,registryHead:Object.freeze({count:recordBytes.length,headDigest:previous}),
  inventoryHead:Object.freeze({...inventory}),provesRemoteFilesystemState:false,provesActualPublication:false,
  provesTrustedTime:false,provesGlobalConsistency:false,authorizesRecovery:false,authorizesCheckout:false,authorizesProduction:false});
}
/** Linux-local read-only acquisition, anchored to a directory descriptor and
 * external inode pin. All contents must be the complete numbered prefix.
 */
export async function acquireOfflineConflictAcquisitionRegistryRecordsReadOnly({directory,checkpoint,...verification}={}){
 if(process.platform!=='linux'||!F.O_NOFOLLOW||!F.O_DIRECTORY||typeof directory!=='string'||!directory.trim()||
  (checkpoint!==undefined&&typeof checkpoint!=='function')||!pin(verification.expectedRegistryDirectoryPin))
  fail('EXCHANGE33Q_ACQUISITION_ARGUMENTS');
 const dir=resolve(directory),count=verification.expectedRecordBytesDigests?.length;
 if(!Number.isInteger(count)||count<0||count>64)fail('EXCHANGE33Q_ACQUISITION_ARGUMENTS');
 let dh;
 try{
  const initial=await lstat(dir,{bigint:true});
  if(!safeDir(initial)||!samePin({dev:String(initial.dev),ino:String(initial.ino)},verification.expectedRegistryDirectoryPin)||await realpath(dir)!==dir)
   fail('EXCHANGE33Q_DIRECTORY_UNSAFE');
  dh=await open(dir,F.O_RDONLY|F.O_DIRECTORY|F.O_NOFOLLOW);
  const fdStat=await dh.stat({bigint:true});if(!safeDir(fdStat)||!statsEqual(initial,fdStat))fail('EXCHANGE33Q_DIRECTORY_UNSAFE');
  const list=async()=>{
   const names=await readdir(`/proc/self/fd/${dh.fd}`);
   if(names.length!==count||!Array.from({length:count},(_,i)=>filename(i+1)).every(x=>names.includes(x)))
    fail('EXCHANGE33Q_DIRECTORY_CONTENTS_UNSAFE');
   return names.sort();
  };
  const before=await list(),records=[];
  for(let i=1;i<=count;i++){
   const path=`/proc/self/fd/${dh.fd}/${filename(i)}`;let fh;
   try{
    fh=await open(path,F.O_RDONLY|F.O_NOFOLLOW|F.O_NONBLOCK);
    const [s,e]=await Promise.all([fh.stat({bigint:true}),lstat(path,{bigint:true})]);
    if(!safeFile(s)||!safeFile(e)||!statsEqual(s,e))fail('EXCHANGE33Q_RECORD_UNSAFE');
    if(checkpoint)await checkpoint('after-open',i);
    const bytes=await fh.readFile();if(checkpoint)await checkpoint('after-read',i);
    const [end,entryEnd]=await Promise.all([fh.stat({bigint:true}),lstat(path,{bigint:true})]);
    if(!safeFile(end)||!safeFile(entryEnd)||!statsEqual(s,end)||!statsEqual(s,entryEnd)||bytes.length!==Number(s.size))
     fail('EXCHANGE33Q_TOCTOU_DETECTED');
    records.push(bytes);
   }catch(e){if(['ELOOP','EISDIR','ENOTDIR','ENOENT'].includes(e?.code))fail('EXCHANGE33Q_RECORD_UNSAFE');throw e;}
   finally{if(fh)await fh.close();}
  }
  const [end,endFd]=await Promise.all([lstat(dir,{bigint:true}),dh.stat({bigint:true})]);
  if(!safeDir(end)||!statsEqual(initial,end)||!statsEqual(initial,endFd)||await realpath(dir)!==dir||
   JSON.stringify(before)!==JSON.stringify(await list()))fail('EXCHANGE33Q_DIRECTORY_CHANGED');
  const verified=verifyOfflineConflictAcquisitionRegistryRecordEvidence({...verification,recordBytes:records});
  return Object.freeze({records:records.map(x=>Buffer.from(x)),verification:verified,
   locallyReadPinnedBytes:true,provesRemoteFilesystemState:false,provesActualPublication:false,authorizesProduction:false});
 }catch(e){if(['ELOOP','ENOTDIR','ENOENT'].includes(e?.code))fail('EXCHANGE33Q_DIRECTORY_UNSAFE');throw e;}
 finally{if(dh)await dh.close();}
}
export const offlineConflictAcquisitionRegistryRecordBytesDigest=bytes=>{
 if(!Buffer.isBuffer(bytes)||bytes.length<100||bytes.length>3_000_000)fail('EXCHANGE33Q_RECORD_INVALID');
 return hash('TJ-33Q-PINNED-33O-RECORD-BYTES',bytes);
};
