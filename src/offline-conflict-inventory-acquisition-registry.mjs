/** Objective 33O — fail-closed, single-Linux-host, append-only admission of
 * independently pinned 33N acquisition receipts across local sessions.
 * The caller MUST retain the registry head and directory inode pin externally.
 * Stored witness claims do not establish remote filesystem truth or trusted time.
 */
import {createHash,KeyObject} from 'node:crypto';
import {constants as F} from 'node:fs';
import {lstat,realpath,readdir,open,mkdir,rmdir,link,unlink} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {verifyOfflineConflictInventoryAcquisitionReceipt} from './offline-conflict-inventory-filesystem-acquisition.mjs';
export const OFFLINE_CONFLICT_ACQUISITION_REGISTRY_SCHEMA='TJ-OFFLINE-33O-ACQUISITION-REGISTRY-1';
const HEX=/^[0-9a-f]{64}$/,ID=/^[A-Za-z0-9_-]{8,64}$/,DEC=/^(0|[1-9][0-9]*)$/;
const MAX_ENTRIES=64,MAX_BYTES=3_000_000;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hash=(domain,bytes)=>createHash('sha256').update(domain+'\0').update(bytes).digest('hex');
const exact=(x,keys)=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype&&Reflect.ownKeys(x).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(x,k);return d&&d.enumerable&&'value'in d;})&&
 Object.keys(x).every(k=>keys.includes(k));
const head=x=>exact(x,['count','headDigest'])&&Number.isSafeInteger(x.count)&&x.count>=0&&x.count<=256&&HEX.test(x.headDigest);
const eq=(a,b)=>a.count===b.count&&a.headDigest===b.headDigest;
const pin=x=>exact(x,['dev','ino'])&&typeof x.dev==='string'&&typeof x.ino==='string'&&DEC.test(x.dev)&&DEC.test(x.ino);
const eqPin=(a,b)=>a.dev===b.dev&&a.ino===b.ino;
const statPin=s=>({dev:String(s.dev),ino:String(s.ino)});
const fileName=i=>String(i).padStart(4,'0')+'.json';
const recordHash=b=>hash('TJ-33O-ACQUISITION-REGISTRY-RECORD',Buffer.from(JSON.stringify(b)));
const BASE_KEYS=['receipt','records','recordPins','directoryPin','fromHead','toHead','admittedAtMs'];
const RECORD_KEYS=['schema','index','namespaceId','journalScopeDigest','hostId','observerId','previousRecordDigest','entry','receiptDigest','nonce','recordDigest'];
const safeDir=s=>s.isDirectory()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&(s.mode&0o077)===0;
const safeFile=s=>s.isFile()&&s.nlink===1n&&s.uid===BigInt(process.getuid())&&(s.mode&0o077n)===0n&&s.size>=100n&&s.size<=BigInt(MAX_BYTES);
const decode=s=>{if(typeof s!=='string'||!/^[A-Za-z0-9_-]+$/.test(s))fail('EXCHANGE33O_HISTORY_INVALID');
 const b=Buffer.from(s,'base64url');if(b.toString('base64url')!==s)fail('EXCHANGE33O_HISTORY_INVALID');return b;};
const parse=bytes=>{let value;try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
 catch{fail('EXCHANGE33O_HISTORY_INVALID');}
 if(!bytes.equals(Buffer.from(JSON.stringify(value))))fail('EXCHANGE33O_HISTORY_INVALID');return value;};
function snapshot({receiptBytes,records,recordPins,expectedDirectoryPin,expectedFromHead,expectedToHead,nowMs}){
 if(!Buffer.isBuffer(receiptBytes)||receiptBytes.length>20000||!Array.isArray(records)||records.length<1||records.length>32||
  !records.every(x=>Buffer.isBuffer(x)&&x.length<=65536)||!pin(expectedDirectoryPin)||
  !head(expectedFromHead)||!head(expectedToHead)||!Number.isSafeInteger(nowMs))fail('EXCHANGE33O_ARGUMENTS_INVALID');
 let s;try{s=JSON.stringify({receipt:receiptBytes.toString('base64url'),records:records.map(x=>x.toString('base64url')),
  recordPins,directoryPin:expectedDirectoryPin,fromHead:expectedFromHead,toHead:expectedToHead,admittedAtMs:nowMs});}
 catch{fail('EXCHANGE33O_ARGUMENTS_INVALID');}
 if(!s||s.length>MAX_BYTES-1024)fail('EXCHANGE33O_ARGUMENTS_INVALID');
 const entry=JSON.parse(s);if(!exact(entry,BASE_KEYS))fail('EXCHANGE33O_ARGUMENTS_INVALID');return entry;
}
export function offlineConflictAcquisitionRegistryGenesisHead({namespaceId,journalScopeDigest,hostId,observerId,
 expectedObserverPublicKey,initialInventoryHead}={}){
 if(![namespaceId,hostId,observerId].every(x=>typeof x==='string'&&ID.test(x))||
  typeof journalScopeDigest!=='string'||!HEX.test(journalScopeDigest)||!head(initialInventoryHead)||
  !(expectedObserverPublicKey instanceof KeyObject)||expectedObserverPublicKey.type!=='public'||
  expectedObserverPublicKey.asymmetricKeyType!=='ed25519')fail('EXCHANGE33O_CONFIGURATION');
 const keyDigest=hash('TJ-33O-PINNED-WITNESS-KEY',expectedObserverPublicKey.export({format:'der',type:'spki'}));
 return Object.freeze({count:0,headDigest:hash('TJ-33O-REGISTRY-GENESIS',Buffer.from(JSON.stringify([
  namespaceId,journalScopeDigest,hostId,observerId,keyDigest,initialInventoryHead])))});
}
export function createOfflineConflictInventoryAcquisitionRegistry(config={}){
 const {directory,namespaceId,journalScopeDigest,hostId,observerId,expectedObserverPublicKey,
  initialInventoryHead,injectFault}=config;
 const genesis=offlineConflictAcquisitionRegistryGenesisHead(config);
 if(process.platform!=='linux'||!F.O_NOFOLLOW||!F.O_DIRECTORY||typeof directory!=='string'||!directory.trim()||
  (injectFault!==undefined&&typeof injectFault!=='function'))fail('EXCHANGE33O_CONFIGURATION');
 const dir=resolve(directory),lock=join(dir,'.registry-lock'),pending=join(dir,'.pending.json');
 async function safeDirectory(expectedRegistryDirectoryPin){
  if(!pin(expectedRegistryDirectoryPin))fail('EXCHANGE33O_EXTERNAL_DIRECTORY_PIN_REQUIRED');
  const [s,r]=await Promise.all([lstat(dir),realpath(dir)]);
  if(!safeDir(s)||r!==dir||!eqPin(statPin(s),expectedRegistryDirectoryPin))fail('EXCHANGE33O_DIRECTORY_UNSAFE');
  return s;
 }
 async function syncDir(){const h=await open(dir,F.O_RDONLY|F.O_DIRECTORY|F.O_NOFOLLOW);
  try{await h.sync();}finally{await h.close();}}
 async function withLock(expectedRegistryDirectoryPin,fn){
  const original=await safeDirectory(expectedRegistryDirectoryPin);let locked=false;
  try{
   try{await mkdir(lock,{mode:0o700});locked=true;}
   catch(e){if(e?.code==='EEXIST')fail('EXCHANGE33O_LOCKED');throw e;}
   const ls=await lstat(lock);if(!safeDir(ls))fail('EXCHANGE33O_LOCK_UNSAFE');
   const current=await safeDirectory(expectedRegistryDirectoryPin);
   if(current.ino!==original.ino||current.dev!==original.dev)fail('EXCHANGE33O_DIRECTORY_UNSAFE');
   const result=await fn();
   const final=await safeDirectory(expectedRegistryDirectoryPin);
   if(final.ino!==original.ino||final.dev!==original.dev)fail('EXCHANGE33O_DIRECTORY_UNSAFE');
   return result;
  }finally{if(locked)await rmdir(lock);}
 }
 async function readSafe(path){let h;
  try{h=await open(path,F.O_RDONLY|F.O_NOFOLLOW|F.O_NONBLOCK);
   const [s,e]=await Promise.all([h.stat({bigint:true}),lstat(path,{bigint:true})]);
   if(!safeFile(s)||!safeFile(e)||s.ino!==e.ino||s.dev!==e.dev||s.size!==e.size||s.mtimeNs!==e.mtimeNs||s.ctimeNs!==e.ctimeNs)fail('EXCHANGE33O_RECORD_UNSAFE');
   const bytes=await h.readFile();const [end,entryEnd]=await Promise.all([h.stat({bigint:true}),lstat(path,{bigint:true})]);
   if(!safeFile(end)||!safeFile(entryEnd)||s.ino!==end.ino||s.ino!==entryEnd.ino||
    s.dev!==end.dev||s.dev!==entryEnd.dev||s.size!==end.size||s.size!==entryEnd.size||
    s.mtimeNs!==end.mtimeNs||s.ctimeNs!==end.ctimeNs||s.mtimeNs!==entryEnd.mtimeNs||s.ctimeNs!==entryEnd.ctimeNs||BigInt(bytes.length)!==s.size)fail('EXCHANGE33O_RECORD_UNSAFE');
   return bytes;
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e?.code))fail('EXCHANGE33O_RECORD_UNSAFE');throw e;}
  finally{if(h)await h.close();}
 }
 function verifyEntry(entry,seenNonces,seenDigests){
  if(!exact(entry,BASE_KEYS)||!Array.isArray(entry.records)||entry.records.length<1||entry.records.length>32||
   !head(entry.fromHead)||!head(entry.toHead)||!pin(entry.directoryPin)||
   !Number.isSafeInteger(entry.admittedAtMs))fail('EXCHANGE33O_HISTORY_INVALID');
  const receiptBytes=decode(entry.receipt),records=entry.records.map(decode);
  const result=verifyOfflineConflictInventoryAcquisitionReceipt({receiptBytes,records,
   expectedObserverPublicKey,expectedObserverId:observerId,expectedHostId:hostId,
   expectedDirectoryPin:entry.directoryPin,recordPins:entry.recordPins,
   expectedFromHead:entry.fromHead,expectedToHead:entry.toHead,
   expectedNamespaceId:namespaceId,expectedJournalScopeDigest:journalScopeDigest,
   nowMs:entry.admittedAtMs,seenNonces,seenDigests});
  const receipt=parse(receiptBytes);return {digest:result.receiptDigest,nonce:receipt.body.nonce};
 }
 async function state(){
  const names=await readdir(dir);
  if(names.includes('.pending.json'))fail('EXCHANGE33O_UNCERTAIN_COMMIT');
  const files=names.filter(x=>x!=='.registry-lock');
  if(files.length>MAX_ENTRIES||files.some(x=>!/^[0-9]{4}\.json$/.test(x)))fail('EXCHANGE33O_HISTORY_INVALID');
  let previous=genesis.headDigest,inventory=initialInventoryHead;
  const nonces=[],digests=[];
  for(let i=1;i<=files.length;i++){
   if(!files.includes(fileName(i)))fail('EXCHANGE33O_HISTORY_INVALID');
   const bytes=await readSafe(join(dir,fileName(i))),r=parse(bytes);
   if(!exact(r,RECORD_KEYS)||r.schema!==OFFLINE_CONFLICT_ACQUISITION_REGISTRY_SCHEMA||
    r.index!==i||r.namespaceId!==namespaceId||r.journalScopeDigest!==journalScopeDigest||
    r.hostId!==hostId||r.observerId!==observerId||r.previousRecordDigest!==previous||
    typeof r.recordDigest!=='string'||!HEX.test(r.recordDigest))fail('EXCHANGE33O_HISTORY_INVALID');
   const {recordDigest,...body}=r;
   if(recordHash(body)!==recordDigest||!eq(r.entry.fromHead,inventory))fail('EXCHANGE33O_HISTORY_INVALID');
   let v;try{v=verifyEntry(r.entry,nonces,digests);}catch{fail('EXCHANGE33O_HISTORY_INVALID');}
   if(v.digest!==r.receiptDigest||v.nonce!==r.nonce)fail('EXCHANGE33O_HISTORY_INVALID');
   digests.push(v.digest);nonces.push(v.nonce);previous=recordDigest;inventory=r.entry.toHead;
  }
  return {head:{count:files.length,headDigest:previous},inventory,nonces,digests};
 }
 function pinned(s,expectedHead){if(!head(expectedHead))fail('EXCHANGE33O_EXTERNAL_HEAD_REQUIRED');
  if(!eq(s.head,expectedHead))fail('EXCHANGE33O_STALE_OR_ROLLED_BACK_HEAD');}
 const view=s=>Object.freeze({...s.head,inventoryHead:Object.freeze({...s.inventory}),
  durableLocalReplay:true,independentHeadPublication:false,independentlyWitnessed:false,
  trustedTimestamp:false,provesRemoteDiskState:false,authorizesCheckout:false,authorizesProduction:false});
 async function inspect({expectedHead,expectedRegistryDirectoryPin}={}){
  return withLock(expectedRegistryDirectoryPin,async()=>{const s=await state();pinned(s,expectedHead);return view(s);});
 }
 async function accept({receiptBytes,records,recordPins,expectedDirectoryPin,expectedFromHead,expectedToHead,
  nowMs,expectedHead,expectedRegistryDirectoryPin}={}){
  if(!head(expectedHead))fail('EXCHANGE33O_EXTERNAL_HEAD_REQUIRED');
  const entry=snapshot({receiptBytes,records,recordPins,expectedDirectoryPin,expectedFromHead,expectedToHead,nowMs});
  return withLock(expectedRegistryDirectoryPin,async()=>{
   const s=await state();pinned(s,expectedHead);
   if(s.head.count>=MAX_ENTRIES)fail('EXCHANGE33O_HISTORY_FULL');
   if(!eq(s.inventory,entry.fromHead))fail('EXCHANGE33O_NONCONTIGUOUS_SESSION');
   let v;try{v=verifyEntry(entry,s.nonces,s.digests);}catch(e){if(e?.code==='EXCHANGE33N_REPLAY')fail('EXCHANGE33O_REPLAY');throw e;}
   const body={schema:OFFLINE_CONFLICT_ACQUISITION_REGISTRY_SCHEMA,index:s.head.count+1,
    namespaceId,journalScopeDigest,hostId,observerId,previousRecordDigest:s.head.headDigest,
    entry,receiptDigest:v.digest,nonce:v.nonce};
   const r={...body,recordDigest:recordHash(body)},bytes=Buffer.from(JSON.stringify(r));
   if(bytes.length>MAX_BYTES)fail('EXCHANGE33O_RECORD_TOO_LARGE');
   let h;try{h=await open(pending,F.O_WRONLY|F.O_CREAT|F.O_EXCL|F.O_NOFOLLOW,0o600);
    await h.writeFile(bytes);await h.sync();}
   catch(e){if(e?.code==='EEXIST')fail('EXCHANGE33O_UNCERTAIN_COMMIT');throw e;}
   finally{if(h)await h.close();}
   await syncDir();if(injectFault)await injectFault('after-pending-sync');
   await link(pending,join(dir,fileName(r.index)));
   await syncDir();if(injectFault)await injectFault('after-link-sync');
   await unlink(pending);await syncDir();if(injectFault)await injectFault('after-commit-sync');
   const committed=await state();
   if(committed.head.count!==r.index||committed.head.headDigest!==r.recordDigest)fail('EXCHANGE33O_UNCERTAIN_COMMIT');
   return view(committed);
  });
 }
 return Object.freeze({genesisHead:genesis,inspect,accept});
}
