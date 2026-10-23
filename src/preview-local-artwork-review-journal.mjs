/** Objective 35Z — opt-in LOCAL append-only operator-review evidence transcript.
 * All admissions reverify 35Y signed evidence and current local artwork state.
 * History inspection reauthenticates historical signatures, not live snapshots.
 * Caller MUST preserve the returned head OUTSIDE this directory. No deletion,
 * quarantine, repair, Shopify writes, production authority, or global witness.
 */
import {createHash} from 'node:crypto';
import {constants as F} from 'node:fs';
import {mkdir,lstat,realpath,open,readdir,link,unlink} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {resolve,join,sep} from 'node:path';
import {verifyLocalArtworkReviewEvidence,verifyHistoricalLocalArtworkReviewSignature} from './preview-local-artwork-review-evidence.mjs';

export const LOCAL_REVIEW_JOURNAL_SCHEMA='TJ-LOCAL-ARTWORK-REVIEW-JOURNAL-35Z-1';
export const LOCAL_REVIEW_JOURNAL_MAX_RECORDS=256;
const HEX=/^[a-f0-9]{64}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hash=(domain,payload)=>createHash('sha256').update(domain+'\n').update(payload).digest('hex');
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value' in d&&d.enumerable;})&&
 Object.keys(o).every(k=>keys.includes(k));
const fields=['schema','index','previousRecordDigest','evidenceDigest','evidence','recordDigest'];
const name=n=>String(n).padStart(4,'0')+'.json';
const recordDigest=body=>hash('TJ-35Z-RECORD',Buffer.from(JSON.stringify(body)));
const genesis=Object.freeze({count:0,headDigest:hash('TJ-35Z-GENESIS',LOCAL_REVIEW_JOURNAL_SCHEMA)});
const validHead=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&
 h.count>=0&&h.count<=LOCAL_REVIEW_JOURNAL_MAX_RECORDS&&typeof h.headDigest==='string'&&HEX.test(h.headDigest);
export function localArtworkReviewJournalGenesisHead(){return {...genesis};}

export function createLocalArtworkReviewJournal({directory,root,lockTimeoutMs=3000,injectFault}={}){
 if(process.platform!=='linux'||!F.O_NOFOLLOW||!F.O_DIRECTORY||
  typeof directory!=='string'||!directory.trim()||typeof root!=='string'||!root.trim()||
  !Number.isSafeInteger(lockTimeoutMs)||lockTimeoutMs<0||lockTimeoutMs>10000||
  (injectFault!==undefined&&typeof injectFault!=='function'))fail('LOCAL_REVIEW_JOURNAL_CONFIGURATION');
 const dir=resolve(directory),artRoot=resolve(root),rootPin=createHash('sha256').update(artRoot).digest('hex');
 if(dir===artRoot||dir.startsWith(artRoot+sep))fail('LOCAL_REVIEW_JOURNAL_CONFIGURATION');
 const lockPath=join(dir,'.review-lock'),pending=join(dir,'.pending.json');
 async function safeDir(readOnly){
  if(!readOnly)await mkdir(dir,{recursive:true,mode:0o700});
  let s,r;
  try{[s,r]=await Promise.all([lstat(dir),realpath(dir)]);}catch{fail('LOCAL_REVIEW_JOURNAL_DIRECTORY_UNSAFE');}
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||
   (s.mode&0o077)!==0||r!==dir)fail('LOCAL_REVIEW_JOURNAL_DIRECTORY_UNSAFE');
  return s;
 }
 async function withLock(fn,{readOnly=false}={}){
  const ds=await safeDir(readOnly);let h;
  try{
   h=await open(lockPath,F.O_RDWR|(readOnly?0:F.O_CREAT)|F.O_NOFOLLOW,0o600);
   const [s,p]=await Promise.all([h.stat(),lstat(lockPath)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||
    s.ino!==p.ino||s.dev!==p.dev)fail('LOCAL_REVIEW_JOURNAL_LOCK_UNSAFE');
   await new Promise((ok,no)=>{
    const c=spawn('/usr/bin/flock',['-x','-w',(lockTimeoutMs/1000).toFixed(3),'3'],
     {stdio:['ignore','ignore','ignore',h.fd]});
    c.once('error',()=>no(Object.assign(new Error('LOCAL_REVIEW_JOURNAL_LOCK_UNAVAILABLE'),{code:'LOCAL_REVIEW_JOURNAL_LOCK_UNAVAILABLE'})));
    c.once('close',code=>code===0?ok():no(Object.assign(new Error('LOCAL_REVIEW_JOURNAL_LOCK_UNAVAILABLE'),{code:'LOCAL_REVIEW_JOURNAL_LOCK_UNAVAILABLE'})));
   });
   const check=async()=>{
    const [a,b]=await Promise.all([lstat(dir),lstat(lockPath)]);
    if(!a.isDirectory()||a.ino!==ds.ino||a.dev!==ds.dev||!b.isFile()||b.nlink!==1||
     b.ino!==s.ino||b.dev!==s.dev)fail('LOCAL_REVIEW_JOURNAL_LOCK_UNSAFE');
   };
   await check();return await fn(check);
  }finally{if(h)await h.close();}
 }
 async function readSafe(path){
  let h;
  try{
   h=await open(path,F.O_RDONLY|F.O_NOFOLLOW);
   const [s,p]=await Promise.all([h.stat(),lstat(path)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||
    s.ino!==p.ino||s.dev!==p.dev||s.size<2||s.size>131072)
    fail('LOCAL_REVIEW_JOURNAL_RECORD_UNSAFE');
   return await h.readFile();
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e?.code))fail('LOCAL_REVIEW_JOURNAL_RECORD_UNSAFE');throw e;}
  finally{if(h)await h.close();}
 }
 async function state(resolvePublicKey){
  const names=await readdir(dir);
  if(names.includes('.pending.json'))fail('LOCAL_REVIEW_JOURNAL_UNCERTAIN_COMMIT');
  const records=names.filter(n=>n!=='.review-lock');
  if(records.length>LOCAL_REVIEW_JOURNAL_MAX_RECORDS||records.some(n=>!/^[0-9]{4}\.json$/.test(n)))
   fail('LOCAL_REVIEW_JOURNAL_HISTORY_INVALID');
  let head=genesis.headDigest;const seenEvidence=new Set(),seenTickets=new Set(),seenChallenges=new Set(),entries=[];
  for(let i=1;i<=records.length;i++){
   if(!names.includes(name(i)))fail('LOCAL_REVIEW_JOURNAL_HISTORY_INVALID');
   const bytes=await readSafe(join(dir,name(i)));let e;
   try{e=JSON.parse(bytes.toString('utf8'));}catch{fail('LOCAL_REVIEW_JOURNAL_HISTORY_INVALID');}
   if(!exact(e,fields)||!Buffer.from(JSON.stringify(e)).equals(bytes)||
    e.schema!==LOCAL_REVIEW_JOURNAL_SCHEMA||e.index!==i||e.previousRecordDigest!==head||
    typeof e.evidenceDigest!=='string'||!HEX.test(e.evidenceDigest)||
    typeof e.recordDigest!=='string'||!HEX.test(e.recordDigest))fail('LOCAL_REVIEW_JOURNAL_HISTORY_INVALID');
   const {recordDigest:claimed,...body}=e;
   if(recordDigest(body)!==claimed)fail('LOCAL_REVIEW_JOURNAL_HISTORY_INVALID');
   let verified;
   try{verified=await verifyHistoricalLocalArtworkReviewSignature(e.evidence,{resolvePublicKey});}
   catch{fail('LOCAL_REVIEW_JOURNAL_HISTORY_INVALID');}
   if(verified.rootPin!==rootPin||verified.evidenceDigest!==e.evidenceDigest||
    seenEvidence.has(verified.evidenceDigest)||seenTickets.has(verified.ticketDigest)||
    seenChallenges.has(verified.challenge))fail('LOCAL_REVIEW_JOURNAL_HISTORY_INVALID');
   seenEvidence.add(verified.evidenceDigest);seenTickets.add(verified.ticketDigest);
   seenChallenges.add(verified.challenge);head=claimed;
   entries.push(Object.freeze({index:i,recordDigest:claimed,evidenceDigest:verified.evidenceDigest,
    rootPin:verified.rootPin,referencePin:verified.referencePin,ticketDigest:verified.ticketDigest,
    keyId:verified.keyId,challenge:verified.challenge,observedAt:verified.observedAt,
    expiresAt:verified.expiresAt,authority:'NONE',liveSnapshotVerified:false}));
  }
  return {head:{count:records.length,headDigest:head},seenEvidence,seenTickets,seenChallenges,entries};
 }
 function pinned(actual,expected){
  if(!validHead(expected))fail('LOCAL_REVIEW_JOURNAL_EXTERNAL_HEAD_REQUIRED');
  if(actual.count!==expected.count||actual.headDigest!==expected.headDigest)
   fail('LOCAL_REVIEW_JOURNAL_STALE_OR_ROLLED_BACK_HEAD');
 }
 async function syncDir(){const h=await open(dir,F.O_RDONLY|F.O_DIRECTORY|F.O_NOFOLLOW);
  try{await h.sync();}finally{await h.close();}}
 function report(s){return Object.freeze({schema:LOCAL_REVIEW_JOURNAL_SCHEMA,
  head:Object.freeze({...s.head}),entries:Object.freeze([...s.entries]),
  durableLocalTranscript:true,historySignaturesVerified:true,independentlyWitnessed:false,
  trustedTime:false,liveSnapshotVerified:false,authorizesDeletion:false,
  authorizesQuarantine:false,shopifyWritesAllowed:false,authorizesProduction:false});}
 async function inspect({expectedHead,resolvePublicKey}={}){
  if(typeof resolvePublicKey!=='function')fail('LOCAL_REVIEW_JOURNAL_INVALID_REQUEST');
  return withLock(async()=>{const s=await state(resolvePublicKey);pinned(s.head,expectedHead);return report(s);},{readOnly:true});
 }
 async function admit({evidence,ticket,reviewKey,resolvePublicKey,expectedChallenge,expectedHead,
  now=Date.now(),io}={}){
  if(typeof resolvePublicKey!=='function'||typeof expectedChallenge!=='string'||
   !/^[a-f0-9]{32}$/.test(expectedChallenge)||!validHead(expectedHead))
   fail('LOCAL_REVIEW_JOURNAL_INVALID_REQUEST');
  return withLock(async check=>{
   const s=await state(resolvePublicKey);pinned(s.head,expectedHead);
   if(s.head.count>=LOCAL_REVIEW_JOURNAL_MAX_RECORDS)fail('LOCAL_REVIEW_JOURNAL_FULL');
   const verified=await verifyLocalArtworkReviewEvidence(artRoot,evidence,ticket,
    {reviewKey,resolvePublicKey,expectedChallenge,now,io});
   if(verified.verifiedReadOnly!==true||verified.safeToAutoDelete!==false||
    verified.safeToQuarantine!==false||verified.shopifyWritesAllowed!==false||
    evidence.rootPin!==rootPin)fail('LOCAL_REVIEW_JOURNAL_VERIFICATION_REQUIRED');
   if(s.seenEvidence.has(verified.evidenceDigest)||s.seenTickets.has(evidence.ticketDigest)||
    s.seenChallenges.has(evidence.challenge))fail('LOCAL_REVIEW_JOURNAL_REPLAY');
   const body={schema:LOCAL_REVIEW_JOURNAL_SCHEMA,index:s.head.count+1,
    previousRecordDigest:s.head.headDigest,evidenceDigest:verified.evidenceDigest,evidence};
   const e={...body,recordDigest:recordDigest(body)},bytes=Buffer.from(JSON.stringify(e));
   if(bytes.length>131072)fail('LOCAL_REVIEW_JOURNAL_RECORD_TOO_LARGE');
   await check();let h;
   try{h=await open(pending,F.O_WRONLY|F.O_CREAT|F.O_EXCL|F.O_NOFOLLOW,0o600);
    await h.writeFile(bytes);await h.sync();}
   catch(error){if(error?.code==='EEXIST')fail('LOCAL_REVIEW_JOURNAL_UNCERTAIN_COMMIT');throw error;}
   finally{if(h)await h.close();}
   await syncDir();if(injectFault)await injectFault('after-pending-sync');
   await check();
   try{await link(pending,join(dir,name(e.index)));}
   catch(error){if(error?.code==='EEXIST')fail('LOCAL_REVIEW_JOURNAL_UNCERTAIN_COMMIT');throw error;}
   await syncDir();if(injectFault)await injectFault('after-link-sync');
   await unlink(pending);await syncDir();
   if(injectFault)await injectFault('after-commit-sync');
   const committed=await state(resolvePublicKey);
   if(committed.head.count!==e.index||committed.head.headDigest!==e.recordDigest)
    fail('LOCAL_REVIEW_JOURNAL_UNCERTAIN_COMMIT');
   return report(committed);
  });
 }
 return Object.freeze({inspect,admit});
}
