/** Objective 33N: Linux-local, read-only acquisition of actual 33J record bytes.
 * Independent pins and a separately pinned witness key are mandatory. A signed
 * receipt records a caller-supplied observation, NOT remote disk truth, trusted
 * time, immutable storage, or production/checkout authorization.
 */
import {constants as F} from 'node:fs';
import {open,lstat,realpath,readdir} from 'node:fs/promises';
import {resolve} from 'node:path';
import {createHash,sign,verify,KeyObject} from 'node:crypto';
import {OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA} from './offline-conflict-adjudication-transcript-inventory.mjs';
import {offlineConflictInventoryRecordBytesDigest} from './offline-conflict-adjudication-inventory-record-evidence.mjs';

export const OFFLINE_CONFLICT_FILESYSTEM_ACQUISITION_SCHEMA='TJ-OFFLINE-33N-FILESYSTEM-ACQUISITION-1';
const HEX=/^[a-f0-9]{64}$/,ID=/^[A-Za-z0-9_-]{8,64}$/,DEC=/^(0|[1-9][0-9]*)$/;
const RECORD_KEYS=['schema','index','namespaceId','journalScopeDigest','previousRecordDigest','pair','recordDigest'];
const BODY_KEYS=['schema','hostId','observerId','namespaceId','journalScopeDigest','directoryPin','fromHead','toHead','recordPinsDigest','observations','observedAt','expiresAt','nonce'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const digest=(domain,bytes)=>createHash('sha256').update(domain+'\0').update(bytes).digest('hex');
const exact=(x,keys)=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(x))&&Reflect.ownKeys(x).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(x,k);return d&&d.enumerable&&'value' in d;})&&
 Object.keys(x).every(k=>keys.includes(k));
const dense=(a,max=32)=>Array.isArray(a)&&Object.getPrototypeOf(a)===Array.prototype&&a.length>0&&a.length<=max&&
 Reflect.ownKeys(a).length===a.length+1&&Array.from({length:a.length},(_,i)=>
 {const d=Object.getOwnPropertyDescriptor(a,String(i));return d&&d.enumerable&&'value' in d;}).every(Boolean);
const head=x=>exact(x,['count','headDigest'])&&Number.isSafeInteger(x.count)&&x.count>=0&&x.count<=256&&typeof x.headDigest==='string'&&HEX.test(x.headDigest);
const same=(a,b)=>a.count===b.count&&a.headDigest===b.headDigest;
const pin=x=>exact(x,['dev','ino'])&&typeof x.dev==='string'&&typeof x.ino==='string'&&DEC.test(x.dev)&&DEC.test(x.ino);
const statPin=s=>({dev:String(s.dev),ino:String(s.ino)});
const samePin=(a,b)=>a.dev===b.dev&&a.ino===b.ino;
const filename=i=>String(i).padStart(4,'0')+'.json';
const pinsHash=p=>digest('TJ-33N-EXTERNAL-RECORD-PINS',Buffer.from(JSON.stringify(p)));
const recordHash=b=>digest('TJ-33J-INVENTORY-RECORD',Buffer.from(JSON.stringify(b)));
const statsEqual=(a,b)=>a.dev===b.dev&&a.ino===b.ino&&a.size===b.size&&a.mtimeNs===b.mtimeNs&&a.ctimeNs===b.ctimeNs;
const metadata=s=>({index:0,recordBytesDigest:'',recordDigest:'',dev:String(s.dev),ino:String(s.ino),size:Number(s.size),mtimeNs:String(s.mtimeNs),ctimeNs:String(s.ctimeNs)});
const safeDirectory=s=>s.isDirectory()&&!s.isSymbolicLink()&&s.uid===BigInt(process.getuid())&&(s.mode&0o077n)===0n;
const safeRecord=s=>s.isFile()&&s.nlink===1n&&s.uid===BigInt(process.getuid())&&(s.mode&0o077n)===0n&&s.size>=50n&&s.size<=65536n;
function checkPins(p,from,to){
 if(!head(from)||!head(to)||!dense(p)||to.count-from.count!==p.length)fail('EXCHANGE33N_EXTERNAL_PINS_INVALID');
 let current=from;
 for(const x of p){
  if(!exact(x,['expectedRecordBytesDigest','expectedFromHead','expectedToHead'])||
   typeof x.expectedRecordBytesDigest!=='string'||!HEX.test(x.expectedRecordBytesDigest)||!head(x.expectedFromHead)||!head(x.expectedToHead)||
   !same(current,x.expectedFromHead)||x.expectedToHead.count!==current.count+1)
   fail('EXCHANGE33N_EXTERNAL_PINS_INVALID');
  current=x.expectedToHead;
 }
 if(!same(current,to))fail('EXCHANGE33N_EXTERNAL_PINS_INVALID');
}
function checkRecord(bytes,index,previous,namespaceId,journalScopeDigest){
 let r;
 try{r=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
 catch{fail('EXCHANGE33N_RECORD_INVALID');}
 if(!exact(r,RECORD_KEYS)||Object.keys(r).join('|')!==RECORD_KEYS.join('|')||
  !Buffer.from(JSON.stringify(r)).equals(bytes)||r.schema!==OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA||
  r.index!==index||r.previousRecordDigest!==previous||r.namespaceId!==namespaceId||
  r.journalScopeDigest!==journalScopeDigest||typeof r.recordDigest!=='string'||!HEX.test(r.recordDigest)||
  !Array.isArray(r.pair)||r.pair.length!==2||
  recordHash(Object.fromEntries(RECORD_KEYS.slice(0,-1).map(k=>[k,r[k]])))!==r.recordDigest)
  fail('EXCHANGE33N_RECORD_INVALID');
 return r;
}
function checkCommon({expectedDirectoryPin,recordPins,expectedFromHead,expectedToHead,expectedNamespaceId,expectedJournalScopeDigest}){
 if(!pin(expectedDirectoryPin)||typeof expectedNamespaceId!=='string'||!ID.test(expectedNamespaceId)||typeof expectedJournalScopeDigest!=='string'||!HEX.test(expectedJournalScopeDigest))fail('EXCHANGE33N_ARGUMENTS_INVALID');
 checkPins(recordPins,expectedFromHead,expectedToHead);
}
const fileList=async(dirFd,count)=>{
 const names=await readdir(`/proc/self/fd/${dirFd}`);
 if(names.length!==count||names.some((x,i)=>!(/^\d{4}\.json$/).test(x))||
  !Array.from({length:count},(_,i)=>filename(i+1)).every(x=>names.includes(x)))
  fail('EXCHANGE33N_DIRECTORY_CONTENTS_UNSAFE');
 return names.sort();
};
const readOnlyFlags=F.O_RDONLY|F.O_NOFOLLOW|F.O_NONBLOCK;
export function offlineConflictFilesystemAcquisitionBodyBytes(body){
 if(!exact(body,BODY_KEYS))fail('EXCHANGE33N_RECEIPT_INVALID');
 return Buffer.from(JSON.stringify(body));
}
export async function acquireOfflineConflictInventoryRecordsReadOnly(args={}){
 if(!exact(args,['directory','expectedDirectoryPin','recordPins','expectedFromHead','expectedToHead',
  'expectedNamespaceId','expectedJournalScopeDigest','hostId','observerId','observerPrivateKey',
  'observedAt','expiresAt','nonce','checkpoint']))fail('EXCHANGE33N_ARGUMENTS_INVALID');
 const {directory,expectedDirectoryPin,recordPins,expectedFromHead,expectedToHead,
  expectedNamespaceId,expectedJournalScopeDigest,hostId,observerId,observerPrivateKey,
  observedAt,expiresAt,nonce,checkpoint}=args;
 checkCommon(args);
 if(process.platform!=='linux'||!F.O_NOFOLLOW||!F.O_DIRECTORY||typeof directory!=='string'||!directory.trim()||
  typeof hostId!=='string'||!ID.test(hostId)||typeof observerId!=='string'||!ID.test(observerId)||typeof nonce!=='string'||!ID.test(nonce)||
  !(observerPrivateKey instanceof KeyObject)||observerPrivateKey.type!=='private'||observerPrivateKey.asymmetricKeyType!=='ed25519'||
  !Number.isSafeInteger(observedAt)||observedAt<0||!Number.isSafeInteger(expiresAt)||expiresAt<=observedAt||
  expiresAt-observedAt>3600000||(checkpoint!==undefined&&typeof checkpoint!=='function'))
  fail('EXCHANGE33N_ARGUMENTS_INVALID');
 const dir=resolve(directory);
 let dh;
 try{
  const original=await lstat(dir,{bigint:true});
  if(!safeDirectory(original)||!samePin(statPin(original),expectedDirectoryPin)||await realpath(dir)!==dir)
   fail('EXCHANGE33N_DIRECTORY_UNSAFE');
  dh=await open(dir,F.O_RDONLY|F.O_DIRECTORY|F.O_NOFOLLOW);
  const fdStat=await dh.stat({bigint:true});
  if(!safeDirectory(fdStat)||!samePin(statPin(fdStat),expectedDirectoryPin)||!statsEqual(original,fdStat))
   fail('EXCHANGE33N_DIRECTORY_UNSAFE');
  const beforeNames=await fileList(dh.fd,expectedToHead.count);
  const records=[],observations=[];
  for(let i=0;i<recordPins.length;i++){
   const p=recordPins[i],index=p.expectedToHead.count,path=`/proc/self/fd/${dh.fd}/${filename(index)}`;
   let fh;
   try{
    fh=await open(path,readOnlyFlags);
    const [s,entry]=await Promise.all([fh.stat({bigint:true}),lstat(path,{bigint:true})]);
    if(!safeRecord(s)||!safeRecord(entry)||!statsEqual(s,entry))fail('EXCHANGE33N_RECORD_UNSAFE');
    if(checkpoint)await checkpoint('after-open',index);
    const bytes=await fh.readFile();
    if(checkpoint)await checkpoint('after-read',index);
    const [end,entryEnd]=await Promise.all([fh.stat({bigint:true}),lstat(path,{bigint:true})]);
    if(!safeRecord(end)||!safeRecord(entryEnd)||!statsEqual(s,end)||!statsEqual(s,entryEnd)||bytes.length!==Number(s.size))
     fail('EXCHANGE33N_TOCTOU_DETECTED');
    const r=checkRecord(bytes,index,p.expectedFromHead.headDigest,expectedNamespaceId,expectedJournalScopeDigest);
    const bd=offlineConflictInventoryRecordBytesDigest(bytes);
    if(bd!==p.expectedRecordBytesDigest||r.recordDigest!==p.expectedToHead.headDigest)
     fail('EXCHANGE33N_RECORD_PIN_MISMATCH');
    records.push(Buffer.from(bytes));
    observations.push({...metadata(s),index,recordBytesDigest:bd,recordDigest:r.recordDigest});
   }catch(e){if(['ELOOP','EISDIR','ENOTDIR','ENOENT'].includes(e?.code))fail('EXCHANGE33N_RECORD_UNSAFE');throw e;}
   finally{if(fh)await fh.close();}
  }
  const [final,finalFd]=await Promise.all([lstat(dir,{bigint:true}),dh.stat({bigint:true})]);
  if(!safeDirectory(final)||!statsEqual(original,final)||!statsEqual(original,finalFd)||
   !samePin(statPin(final),expectedDirectoryPin)||await realpath(dir)!==dir)
   fail('EXCHANGE33N_DIRECTORY_CHANGED');
  const afterNames=await fileList(dh.fd,expectedToHead.count);
  if(JSON.stringify(beforeNames)!==JSON.stringify(afterNames))fail('EXCHANGE33N_DIRECTORY_CHANGED');
  const body={schema:OFFLINE_CONFLICT_FILESYSTEM_ACQUISITION_SCHEMA,hostId,observerId,
   namespaceId:expectedNamespaceId,journalScopeDigest:expectedJournalScopeDigest,
   directoryPin:expectedDirectoryPin,fromHead:expectedFromHead,toHead:expectedToHead,
   recordPinsDigest:pinsHash(recordPins),observations,observedAt,expiresAt,nonce};
  const signature=sign(null,offlineConflictFilesystemAcquisitionBodyBytes(body),observerPrivateKey).toString('base64url');
  const receiptBytes=Buffer.from(JSON.stringify({body,signature}));
  return Object.freeze({receiptBytes,records,locallyReadPinnedBytes:true,
   independentlyWitnessed:false,provesRemoteDiskState:false,provesHistoricalPrefix:false,
   trustedTimestamp:false,authorizesCheckout:false,authorizesProduction:false});
 }catch(e){if(['ELOOP','ENOTDIR','ENOENT'].includes(e?.code))fail('EXCHANGE33N_DIRECTORY_UNSAFE');throw e;}
 finally{if(dh)await dh.close();}
}
export function verifyOfflineConflictInventoryAcquisitionReceipt(args={}){
 if(!exact(args,['receiptBytes','records','expectedObserverPublicKey','expectedObserverId',
  'expectedHostId','expectedDirectoryPin','recordPins','expectedFromHead','expectedToHead',
  'expectedNamespaceId','expectedJournalScopeDigest','nowMs','seenNonces','seenDigests']))
  fail('EXCHANGE33N_ARGUMENTS_INVALID');
 const {receiptBytes,records,expectedObserverPublicKey,expectedObserverId,expectedHostId,
  expectedDirectoryPin,recordPins,expectedFromHead,expectedToHead,expectedNamespaceId,
  expectedJournalScopeDigest,nowMs,seenNonces,seenDigests}=args;
 checkCommon(args);
 if(!Buffer.isBuffer(receiptBytes)||receiptBytes.length<100||receiptBytes.length>20000||
  !Array.isArray(records)||records.length!==recordPins.length||
  !(expectedObserverPublicKey instanceof KeyObject)||expectedObserverPublicKey.type!=='public'||
  expectedObserverPublicKey.asymmetricKeyType!=='ed25519'||typeof expectedObserverId!=='string'||!ID.test(expectedObserverId)||typeof expectedHostId!=='string'||!ID.test(expectedHostId)||
  !Number.isSafeInteger(nowMs)||!Array.isArray(seenNonces)||!Array.isArray(seenDigests))
  fail('EXCHANGE33N_ARGUMENTS_INVALID');
 let receipt;
 try{receipt=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(receiptBytes));}
 catch{fail('EXCHANGE33N_RECEIPT_INVALID');}
 if(!exact(receipt,['body','signature'])||!Buffer.from(JSON.stringify(receipt)).equals(receiptBytes)||
  !exact(receipt.body,BODY_KEYS)||typeof receipt.signature!=='string'||!/^[-_A-Za-z0-9]{86}$/.test(receipt.signature)||
  Buffer.from(receipt.signature,'base64url').length!==64||
  Buffer.from(receipt.signature,'base64url').toString('base64url')!==receipt.signature||
  !Array.isArray(receipt.body.observations)||receipt.body.observations.length!==recordPins.length)
  fail('EXCHANGE33N_RECEIPT_INVALID');
 const b=receipt.body;
 if(b.schema!==OFFLINE_CONFLICT_FILESYSTEM_ACQUISITION_SCHEMA||b.hostId!==expectedHostId||
  b.observerId!==expectedObserverId||b.namespaceId!==expectedNamespaceId||
  b.journalScopeDigest!==expectedJournalScopeDigest||!pin(b.directoryPin)||
  !samePin(b.directoryPin,expectedDirectoryPin)||!head(b.fromHead)||!head(b.toHead)||
  !same(b.fromHead,expectedFromHead)||!same(b.toHead,expectedToHead)||
  b.recordPinsDigest!==pinsHash(recordPins)||typeof b.nonce!=='string'||!ID.test(b.nonce)||
  !Number.isSafeInteger(b.observedAt)||!Number.isSafeInteger(b.expiresAt)||
  b.observedAt>nowMs||nowMs>=b.expiresAt||b.expiresAt-b.observedAt>3600000)
  fail('EXCHANGE33N_RECEIPT_SCOPE_OR_TIME_INVALID');
 if(!verify(null,offlineConflictFilesystemAcquisitionBodyBytes(b),expectedObserverPublicKey,
  Buffer.from(receipt.signature,'base64url')))fail('EXCHANGE33N_SIGNATURE_INVALID');
 const receiptDigest=digest('TJ-33N-SIGNED-ACQUISITION-RECEIPT',receiptBytes);
 if(seenNonces.includes(b.nonce)||seenDigests.includes(receiptDigest))fail('EXCHANGE33N_REPLAY');
 for(let i=0;i<records.length;i++){
  const o=b.observations[i],p=recordPins[i];
  if(!exact(o,['index','recordBytesDigest','recordDigest','dev','ino','size','mtimeNs','ctimeNs'])||
   o.index!==p.expectedToHead.count||!DEC.test(o.dev)||!DEC.test(o.ino)||
   typeof o.dev!=='string'||typeof o.ino!=='string'||
   typeof o.mtimeNs!=='string'||typeof o.ctimeNs!=='string'||
   !DEC.test(o.mtimeNs)||!DEC.test(o.ctimeNs)||!Number.isSafeInteger(o.size)||o.size<50||o.size>65536||
   !Buffer.isBuffer(records[i])||records[i].length!==o.size)
   fail('EXCHANGE33N_OBSERVATION_INVALID');
  const r=checkRecord(records[i],o.index,p.expectedFromHead.headDigest,expectedNamespaceId,expectedJournalScopeDigest);
  if(o.recordBytesDigest!==offlineConflictInventoryRecordBytesDigest(records[i])||
   o.recordBytesDigest!==p.expectedRecordBytesDigest||o.recordDigest!==r.recordDigest||
   o.recordDigest!==p.expectedToHead.headDigest)fail('EXCHANGE33N_RECORD_PIN_MISMATCH');
 }
 return Object.freeze({verifiedWitnessSignature:true,verifiedSuppliedRecordBytes:true,
  receiptDigest,provesRemoteDiskState:false,provesHistoricalPrefix:false,
  independentlyWitnessed:false,trustedTimestamp:false,durableReplayProtection:false,
  authorizesCheckout:false,authorizesProduction:false});
}
