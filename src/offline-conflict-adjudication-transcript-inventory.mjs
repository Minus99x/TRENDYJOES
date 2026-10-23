/** Objective 33J — single-Linux-host, fail-closed, append-only admission of
 * two independently signed 33I pending-adjudication transcripts. Caller must
 * retain head pins outside this directory. No independent timestamp, global
 * consensus, disk-state proof, recovery, production or Shopify authority.
 */
import {createHash} from 'node:crypto';
import {constants as F} from 'node:fs';
import {mkdir,rmdir,lstat,realpath,readdir,open,link,unlink} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {reconcileOfflineConflictPendingAdjudicationTranscripts,
 verifyOfflineConflictPendingAdjudicationTranscript} from './offline-conflict-pending-adjudication-transcript.mjs';

export const OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA='TJ-OFFLINE-PENDING-ADJUDICATION-INVENTORY-1';
const HEX=/^[0-9a-f]{64}$/, ID=/^[A-Za-z0-9_-]{8,64}$/;
const MAX_RECORDS=256, MAX_BYTES=65536;
const PIN_KEYS=['expectedTranscriptDigest','expectedNamespaceId','expectedJournalScopeDigest',
 'expectedDecisionDigest','expectedReviewerGroupADigest','expectedReviewerGroupBDigest',
 'expectedPendingBytesDigest','expectedPreHead','expectedObservedHead',
 'expectedObserverId','expectedObserverPublicKey'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hash=(domain,value)=>createHash('sha256').update(domain+'\0').update(value).digest('hex');
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 Object.getPrototypeOf(o)===Object.prototype&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value' in d&&d.enumerable;})&&
 Object.keys(o).every(k=>keys.includes(k));
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=MAX_RECORDS&&HEX.test(h.headDigest);
const eqHead=(a,b)=>a.count===b.count&&a.headDigest===b.headDigest;
const fileName=i=>String(i).padStart(4,'0')+'.json';
const recordHash=b=>hash('TJ-33J-INVENTORY-RECORD',Buffer.from(JSON.stringify(b)));
export function offlineConflictAdjudicationInventoryGenesisHead(namespaceId,journalScopeDigest){
 if(!ID.test(namespaceId)||!HEX.test(journalScopeDigest))fail('EXCHANGE33J_SCOPE_INVALID');
 return Object.freeze({count:0,headDigest:hash('TJ-33J-INVENTORY-GENESIS',Buffer.from(JSON.stringify([namespaceId,journalScopeDigest])))});
}
function normalizeArgs(a){
 if(!exact(a,['bytes','nowMs',...PIN_KEYS])||!Buffer.isBuffer(a.bytes)||
  a.bytes.length<10||a.bytes.length>16384||!Number.isSafeInteger(a.nowMs)||
  !head(a.expectedPreHead)||!head(a.expectedObservedHead))
  fail('EXCHANGE33J_ARGUMENTS_INVALID');
 const pins=Object.fromEntries(PIN_KEYS.map(k=>[k,a[k]]));
 // Freeze the exact snapshot before entering the critical section. This also
 // excludes getters, prototype pollution, and noncanonical objects.
 let canonical;
 try{canonical=JSON.stringify({bytes:a.bytes.toString('base64url'),nowMs:a.nowMs,pins});
  if(!canonical||canonical.length>25000)throw Error();}
 catch{fail('EXCHANGE33J_ARGUMENTS_INVALID');}
 const value=JSON.parse(canonical);
 if(!exact(value,['bytes','nowMs','pins'])||!exact(value.pins,PIN_KEYS)||
  !head(value.pins.expectedPreHead)||!head(value.pins.expectedObservedHead)||
  !HEX.test(value.pins.expectedTranscriptDigest))fail('EXCHANGE33J_ARGUMENTS_INVALID');
 return value;
}
function rehydrate(v){
 if(!exact(v,['bytes','nowMs','pins'])||!exact(v.pins,PIN_KEYS)||
  typeof v.bytes!=='string'||!(/^[A-Za-z0-9_-]+$/).test(v.bytes)||
  Buffer.from(v.bytes,'base64url').toString('base64url')!==v.bytes||
  !Number.isSafeInteger(v.nowMs))fail('EXCHANGE33J_HISTORY_INVALID');
 return {bytes:Buffer.from(v.bytes,'base64url'),nowMs:v.nowMs,...v.pins};
}
function verifyPair(pair,namespaceId,journalScopeDigest){
 if(!Array.isArray(pair)||pair.length!==2||Reflect.ownKeys(pair).length!==3)
  fail('EXCHANGE33J_PAIR_INVALID');
 const [left,right]=pair.map(rehydrate);
 const a=verifyOfflineConflictPendingAdjudicationTranscript(left);
 const b=verifyOfflineConflictPendingAdjudicationTranscript(right);
 const c=reconcileOfflineConflictPendingAdjudicationTranscripts({left,right});
 if(a.namespaceId!==namespaceId||b.namespaceId!==namespaceId||
  a.journalScopeDigest!==journalScopeDigest||b.journalScopeDigest!==journalScopeDigest)
  fail('EXCHANGE33J_SCOPE_MISMATCH');
 return {a,b,c};
}
export function createOfflineConflictAdjudicationTranscriptInventory({directory,namespaceId,
 journalScopeDigest,injectFault}={}){
 const genesis=offlineConflictAdjudicationInventoryGenesisHead(namespaceId,journalScopeDigest);
 if(process.platform!=='linux'||!F.O_NOFOLLOW||typeof directory!=='string'||!directory.trim()||
  (injectFault!==undefined&&typeof injectFault!=='function'))fail('EXCHANGE33J_CONFIGURATION');
 const dir=resolve(directory),lockDir=join(dir,'.inventory-lock'),pending=join(dir,'.pending.json');
 async function safeDir(){
  await mkdir(dir,{recursive:true,mode:0o700});
  const [s,r]=await Promise.all([lstat(dir),realpath(dir)]);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||
   (s.mode&0o077)!==0||r!==dir)fail('EXCHANGE33J_DIRECTORY_UNSAFE');
  return s;
 }
 async function syncDir(){const h=await open(dir,F.O_RDONLY|F.O_DIRECTORY|F.O_NOFOLLOW);
  try{await h.sync();}finally{await h.close();}}
 async function withLock(fn){
  const ds=await safeDir();let locked=false;
  try{
   try{await mkdir(lockDir,{mode:0o700});locked=true;}
   catch(e){if(e?.code==='EEXIST')fail('EXCHANGE33J_LOCKED');throw e;}
   const ls=await lstat(lockDir);
   if(!ls.isDirectory()||ls.isSymbolicLink()||ls.uid!==process.getuid()||
    (ls.mode&0o077)!==0)fail('EXCHANGE33J_LOCK_UNSAFE');
   const [current,real]=await Promise.all([lstat(dir),realpath(dir)]);
   if(current.ino!==ds.ino||current.dev!==ds.dev||real!==dir)
    fail('EXCHANGE33J_DIRECTORY_UNSAFE');
   return await fn();
  }finally{if(locked)await rmdir(lockDir);}
 }
 async function readSafe(path){let h;
  try{
   h=await open(path,F.O_RDONLY|F.O_NOFOLLOW);
   const [s,p]=await Promise.all([h.stat(),lstat(path)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||
    (s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev||
    s.size<2||s.size>MAX_BYTES)fail('EXCHANGE33J_RECORD_UNSAFE');
   return await h.readFile();
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e?.code))fail('EXCHANGE33J_RECORD_UNSAFE');throw e;}
  finally{if(h)await h.close();}
 }
 async function state(){
  const names=await readdir(dir);
  if(names.includes('.pending.json'))fail('EXCHANGE33J_UNCERTAIN_COMMIT');
  const files=names.filter(x=>x!=='.inventory-lock');
  if(files.length>MAX_RECORDS||files.some(x=>!/^[0-9]{4}\.json$/.test(x)))
   fail('EXCHANGE33J_HISTORY_INVALID');
  const digests=new Set(),nonces=new Set();let previous=genesis.headDigest;
  for(let i=1;i<=files.length;i++){
   if(!files.includes(fileName(i)))fail('EXCHANGE33J_HISTORY_INVALID');
   const bytes=await readSafe(join(dir,fileName(i)));let r;
   try{r=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
   catch{fail('EXCHANGE33J_HISTORY_INVALID');}
   if(!exact(r,['schema','index','namespaceId','journalScopeDigest','previousRecordDigest','pair','recordDigest'])||
    !bytes.equals(Buffer.from(JSON.stringify(r)))||r.schema!==OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA||
    r.index!==i||r.namespaceId!==namespaceId||r.journalScopeDigest!==journalScopeDigest||
    r.previousRecordDigest!==previous||!HEX.test(r.recordDigest))fail('EXCHANGE33J_HISTORY_INVALID');
   const {recordDigest,...body}=r;
   if(recordHash(body)!==recordDigest)fail('EXCHANGE33J_HISTORY_INVALID');
   let v;try{v=verifyPair(r.pair,namespaceId,journalScopeDigest);}
   catch{fail('EXCHANGE33J_HISTORY_INVALID');}
   for(const x of [v.a,v.b]){
    if(digests.has(x.digest)||nonces.has(x.nonce))fail('EXCHANGE33J_HISTORY_REPLAY');
    digests.add(x.digest);nonces.add(x.nonce);
   }
   previous=recordDigest;
  }
  return {head:{count:files.length,headDigest:previous},digests,nonces};
 }
 function pinned(s,expectedHead){
  if(!head(expectedHead))fail('EXCHANGE33J_EXTERNAL_HEAD_REQUIRED');
  if(!eqHead(s.head,expectedHead))fail('EXCHANGE33J_STALE_OR_ROLLED_BACK_HEAD');
 }
 const view=s=>Object.freeze({...s.head,singleHostDurableReplay:true,independentlyPublished:false,
  trustedTimestamp:false,independentlyWitnessed:false,authorizesRepair:false,
  authorizesRecovery:false,authorizesCheckout:false,authorizesProduction:false});
 async function inspect({expectedHead}={}){
  return withLock(async()=>{const s=await state();pinned(s,expectedHead);return view(s);});
 }
 async function accept({left,right,expectedHead}={}){
  if(!head(expectedHead))fail('EXCHANGE33J_EXTERNAL_HEAD_REQUIRED');
  const pair=[normalizeArgs(left),normalizeArgs(right)];
  return withLock(async()=>{
   const s=await state();pinned(s,expectedHead);
   if(s.head.count>=MAX_RECORDS)fail('EXCHANGE33J_HISTORY_FULL');
   const v=verifyPair(pair,namespaceId,journalScopeDigest);
   for(const x of [v.a,v.b])if(s.digests.has(x.digest)||s.nonces.has(x.nonce))fail('EXCHANGE33J_REPLAY');
   const body={schema:OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA,index:s.head.count+1,
    namespaceId,journalScopeDigest,previousRecordDigest:s.head.headDigest,pair};
   const r={...body,recordDigest:recordHash(body)},bytes=Buffer.from(JSON.stringify(r));
   if(bytes.length>MAX_BYTES)fail('EXCHANGE33J_RECORD_TOO_LARGE');
   let h;
   try{h=await open(pending,F.O_WRONLY|F.O_CREAT|F.O_EXCL|F.O_NOFOLLOW,0o600);
    await h.writeFile(bytes);await h.sync();}
   catch(e){if(e?.code==='EEXIST')fail('EXCHANGE33J_UNCERTAIN_COMMIT');throw e;}
   finally{if(h)await h.close();}
   await syncDir();if(injectFault)await injectFault('after-pending-sync');
   await link(pending,join(dir,fileName(r.index)));
   await syncDir();if(injectFault)await injectFault('after-link-sync');
   await unlink(pending);await syncDir();
   if(injectFault)await injectFault('after-commit-sync');
   const committed=await state();
   if(committed.head.count!==r.index||committed.head.headDigest!==r.recordDigest)
    fail('EXCHANGE33J_UNCERTAIN_COMMIT');
   return view(committed);
  });
 }
 return Object.freeze({inspect,accept,genesisHead:genesis});
}
