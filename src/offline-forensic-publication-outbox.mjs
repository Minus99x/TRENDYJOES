/**
 * Objective 31J: opt-in, single-host durable publication outbox and signed
 * witness acknowledgements. Two separate stores are NOT atomic; ambiguous
 * prepare/publish/ack windows fail closed until independently reviewed.
 * A signature is NOT evidence of actual remote/WORM retention.
 */
import {createHash,verify as verifySignature} from 'node:crypto';
import {constants as C} from 'node:fs';
import {mkdir,open,lstat,readdir,rename} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {resolve,join} from 'node:path';
import {verifyOfflineForensicPublicationHistory} from './offline-forensic-head-publication.mjs';
import {recoveryReviewKeyDigest} from './offline-recovery-adjudication.mjs';

export const OFFLINE_FORENSIC_OUTBOX_SCHEMA='TJ-OFFLINE-FORENSIC-OUTBOX-1';
export const OFFLINE_FORENSIC_ACK_SCHEMA='TJ-OFFLINE-FORENSIC-PUBLICATION-ACK-1';
const ROOT='0'.repeat(64),HEX=/^[0-9a-f]{64}$/,ID=/^[A-Za-z0-9_-]{12,80}$/;
const ACK=['schema','registryId','anchorType','publicationIndex','publicationDigest','publicationHeadDigest','acknowledgedAt'];
const fail=code=>{throw Object.assign(Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>obj(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const sha=x=>createHash('sha256').update(x).digest('hex');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const filename=i=>String(i).padStart(10,'0')+'.json';
const validHead=x=>exact(x,['count','headDigest'])&&Number.isSafeInteger(x.count)&&x.count>=0&&x.count<=2000&&HEX.test(x.headDigest)&&(x.count===0)===(x.headDigest===ROOT);
const canonicalSig=s=>typeof s==='string'&&/^[A-Za-z0-9_-]{86}$/.test(s)&&Buffer.from(s,'base64url').length===64&&Buffer.from(s,'base64url').toString('base64url')===s;
export function forensicPublicationAcknowledgementBytes(body){
 if(!exact(body,ACK)||body.schema!==OFFLINE_FORENSIC_ACK_SCHEMA||!ID.test(body.registryId||'')||!['registry','journal'].includes(body.anchorType)||!Number.isSafeInteger(body.publicationIndex)||body.publicationIndex<1||body.publicationIndex>1000||!HEX.test(body.publicationDigest)||body.publicationHeadDigest!==body.publicationDigest||!Number.isSafeInteger(body.acknowledgedAt)||body.acknowledgedAt<0)fail('FORENSIC_OUTBOX_ACK_BODY_INVALID');
 return Buffer.from(`${OFFLINE_FORENSIC_ACK_SCHEMA}\0${JSON.stringify(body)}`);
}
export function verifyOfflineForensicPublicationAcknowledgement({acknowledgement,registryId,anchorType,record,witnesses,witnessQuorum}={}){
 if(!exact(acknowledgement,['body','witnessSignatures'])||!obj(record)||!Array.isArray(witnesses)||witnesses.length<2||witnesses.length>10||!Number.isSafeInteger(witnessQuorum)||witnessQuorum<=witnesses.length/2||witnessQuorum>witnesses.length)fail('FORENSIC_OUTBOX_ACK_REQUEST_INVALID');
 const body=acknowledgement.body,bytes=forensicPublicationAcknowledgementBytes(body);
 if(body.registryId!==registryId||body.anchorType!==anchorType||body.publicationIndex!==record.index||body.publicationDigest!==record.digest||body.acknowledgedAt<record.publishedAt)fail('FORENSIC_OUTBOX_ACK_BINDING_INVALID');
 const byId=new Map(),keys=new Set();
 for(const w of witnesses){
  if(!exact(w,['id','publicKey'])||!ID.test(w.id||'')||byId.has(w.id)||w.publicKey?.type!=='public'||w.publicKey?.asymmetricKeyType!=='ed25519')fail('FORENSIC_OUTBOX_ACK_CONFIGURATION');
  const digest=recoveryReviewKeyDigest(w.publicKey);
  if(keys.has(digest))fail('FORENSIC_OUTBOX_ACK_CONFIGURATION');
  keys.add(digest);byId.set(w.id,w.publicKey);
 }
 const sigs=acknowledgement.witnessSignatures,seen=new Set();
 if(!Array.isArray(sigs)||sigs.length<witnessQuorum||sigs.length>byId.size)fail('FORENSIC_OUTBOX_ACK_SIGNATURE_INVALID');
 for(const s of sigs){
  if(!exact(s,['witnessId','signature'])||!byId.has(s.witnessId)||seen.has(s.witnessId)||!canonicalSig(s.signature)||!verifySignature(null,bytes,byId.get(s.witnessId),Buffer.from(s.signature,'base64url')))fail('FORENSIC_OUTBOX_ACK_SIGNATURE_INVALID');
  seen.add(s.witnessId);
 }
 return Object.freeze({verified:true,publicationIndex:record.index,productionApproved:false});
}
export function verifyOfflineForensicOutboxHistory({events,expectedHead,registryId,anchorType,witnesses,witnessQuorum}={}){
  if(!Array.isArray(events)||events.length>2000||!validHead(expectedHead)||events.length!==expectedHead.count)fail('FORENSIC_OUTBOX_PIN_MISMATCH');
  let previous=ROOT,openPrepare=null,completed=0;
  for(let i=0;i<events.length;i++){
   const e=events[i];
   if(!exact(e,['schema','index','previousDigest','action','publicationIndex','publicationDigest','publishedAt','acknowledgement','digest'])||e.schema!==OFFLINE_FORENSIC_OUTBOX_SCHEMA||e.index!==i+1||e.previousDigest!==previous||!HEX.test(e.digest)||!Number.isSafeInteger(e.publicationIndex)||e.publicationIndex<1||e.publicationIndex>1000||!HEX.test(e.publicationDigest)||!Number.isSafeInteger(e.publishedAt)||e.publishedAt<0)fail('FORENSIC_OUTBOX_EVENT_INVALID');
   const {digest,...body}=e;
   if(digest!==sha(Buffer.from(`${OFFLINE_FORENSIC_OUTBOX_SCHEMA}\0${JSON.stringify(body)}`)))fail('FORENSIC_OUTBOX_DIGEST_INVALID');
   if(e.action==='PREPARE'){
    if(openPrepare||e.acknowledgement!==null||e.publicationIndex!==completed+1)fail('FORENSIC_OUTBOX_SEQUENCE_INVALID');
    openPrepare=e;
   }else if(e.action==='ACK'){
    if(!openPrepare||e.publicationIndex!==openPrepare.publicationIndex||e.publicationDigest!==openPrepare.publicationDigest||e.publishedAt!==openPrepare.publishedAt||!exact(e.acknowledgement,['body','witnessSignatures']))fail('FORENSIC_OUTBOX_SEQUENCE_INVALID');
    verifyOfflineForensicPublicationAcknowledgement({acknowledgement:e.acknowledgement,registryId,anchorType,record:{index:e.publicationIndex,digest:e.publicationDigest,publishedAt:e.publishedAt},witnesses,witnessQuorum});
    completed++;openPrepare=null;
   }else fail('FORENSIC_OUTBOX_SEQUENCE_INVALID');
   previous=e.digest;
  }
  if(previous!==expectedHead.headDigest)fail('FORENSIC_OUTBOX_PIN_MISMATCH');
  return Object.freeze({verified:true,openPrepare:openPrepare?structuredClone(openPrepare):null,completed,head:{count:events.length,headDigest:previous},productionApproved:false});
 }

export function createOfflineForensicPublicationOutbox({directory,registryId,anchorType,witnesses,witnessQuorum,reviewerPolicies,publicationStore,lockTimeoutMs=5000,injectFault}={}){
 if(process.platform!=='linux'||!C.O_NOFOLLOW||typeof directory!=='string'||!directory.trim()||!ID.test(registryId||'')||!['registry','journal'].includes(anchorType)||!publicationStore||typeof publicationStore.inspectHistory!=='function'||!Number.isSafeInteger(lockTimeoutMs)||lockTimeoutMs<0||lockTimeoutMs>10000||(injectFault!==undefined&&typeof injectFault!=='function'))fail('FORENSIC_OUTBOX_CONFIGURATION');
 verifyOfflineForensicPublicationHistory({registryId,anchorType,witnesses,witnessQuorum,reviewerPolicies,publications:[],expectedHead:{count:0,headDigest:ROOT}});
 const dir=resolve(directory),lock=join(dir,'.outbox-lock'),pending=join(dir,'.pending.json');
 async function safeDir(){
  await mkdir(dir,{recursive:true,mode:0o700});const s=await lstat(dir);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0)fail('FORENSIC_OUTBOX_DIRECTORY_UNSAFE');return s;
 }
 async function withLock(fn){
  const d=await safeDir();let h;
  try{
   h=await open(lock,C.O_RDWR|C.O_CREAT|C.O_NOFOLLOW,0o600);
   const [s,p]=await Promise.all([h.stat(),lstat(lock)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev)fail('FORENSIC_OUTBOX_LOCK_UNSAFE');
   await new Promise((ok,no)=>{const c=spawn('/usr/bin/flock',['-x','-w',(lockTimeoutMs/1000).toFixed(3),'3'],{stdio:['ignore','ignore','ignore',h.fd]});c.once('error',()=>no(Object.assign(Error('FORENSIC_OUTBOX_LOCK_UNAVAILABLE'),{code:'FORENSIC_OUTBOX_LOCK_UNAVAILABLE'})));c.once('close',code=>code===0?ok():no(Object.assign(Error('FORENSIC_OUTBOX_LOCK_UNAVAILABLE'),{code:'FORENSIC_OUTBOX_LOCK_UNAVAILABLE'})));});
   const check=async()=>{const [a,b]=await Promise.all([lstat(dir),lstat(lock)]);if(!a.isDirectory()||a.ino!==d.ino||a.dev!==d.dev||!b.isFile()||b.ino!==s.ino||b.dev!==s.dev||b.nlink!==1)fail('FORENSIC_OUTBOX_LOCK_UNSAFE');};
   await check();return await fn(check);
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('FORENSIC_OUTBOX_LOCK_UNSAFE');throw e;}finally{if(h)await h.close();}
 }
 async function readSafe(path){
  let h;try{
   h=await open(path,C.O_RDONLY|C.O_NOFOLLOW);const [s,p]=await Promise.all([h.stat(),lstat(path)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev||s.size<2||s.size>65536)fail('FORENSIC_OUTBOX_FILE_UNSAFE');
   return await h.readFile();
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('FORENSIC_OUTBOX_FILE_UNSAFE');throw e;}finally{if(h)await h.close();}
 }
 async function state(){
  const names=await readdir(dir);if(names.includes('.pending.json'))fail('FORENSIC_OUTBOX_PENDING_REVIEW_REQUIRED');
  const files=names.filter(n=>n!=='.outbox-lock');if(files.length>2000)fail('FORENSIC_OUTBOX_CAPACITY');
  const events=[];
  for(let i=1;i<=files.length;i++){
   if(!files.includes(filename(i)))fail('FORENSIC_OUTBOX_HISTORY_GAP');
   const raw=(await readSafe(join(dir,filename(i)))).toString('utf8');let e;
   try{e=JSON.parse(raw);}catch{fail('FORENSIC_OUTBOX_EVENT_INVALID');}
   if(raw!==JSON.stringify(e))fail('FORENSIC_OUTBOX_NONCANONICAL');
   events.push(e);
  }
  const expectedHead={count:events.length,headDigest:events.at(-1)?.digest??ROOT};
  return {...verifyOfflineForensicOutboxHistory({events,expectedHead,registryId,anchorType,witnesses,witnessQuorum}),events};
 }
 async function syncDir(){const h=await open(dir,'r');try{await h.sync();}finally{await h.close();}}
 async function appendEvent(s,check,action,publicationIndex,publicationDigest,publishedAt,acknowledgement=null){
  if(s.events.length>=2000)fail('FORENSIC_OUTBOX_CAPACITY');
  const body={schema:OFFLINE_FORENSIC_OUTBOX_SCHEMA,index:s.events.length+1,previousDigest:s.head.headDigest,action,publicationIndex,publicationDigest,publishedAt,acknowledgement};
  const event={...body,digest:sha(Buffer.from(`${OFFLINE_FORENSIC_OUTBOX_SCHEMA}\0${JSON.stringify(body)}`))};
  const raw=Buffer.from(JSON.stringify(event));if(raw.length>65536)fail('FORENSIC_OUTBOX_FILE_UNSAFE');
  await check();let h;
  try{h=await open(pending,C.O_WRONLY|C.O_CREAT|C.O_EXCL|C.O_NOFOLLOW,0o600);await h.writeFile(raw);await h.sync();}
  catch(e){if(['EEXIST','ELOOP'].includes(e.code))fail('FORENSIC_OUTBOX_PENDING_REVIEW_REQUIRED');throw e;}finally{if(h)await h.close();}
  await syncDir();if(injectFault)await injectFault('after-pending-sync');
  await check();await rename(pending,join(dir,filename(event.index)));await syncDir();
  if(injectFault)await injectFault('after-commit-sync');
  const next=await state();if(next.head.headDigest!==event.digest)fail('FORENSIC_OUTBOX_COMMIT_UNCERTAIN');
  return Object.freeze({...next.head,recorded:true,productionApproved:false});
 }
 async function inspect({expectedOutboxHead}={}){return withLock(async()=>{
  const s=await state();if(expectedOutboxHead&&!same(s.head,expectedOutboxHead))fail('FORENSIC_OUTBOX_PIN_MISMATCH');
  return structuredClone({...s.head,completed:s.completed,pendingPublicationIndex:s.openPrepare?.publicationIndex??null,productionApproved:false});
 });}
 async function inspectHistory({expectedOutboxHead}={}){return withLock(async()=>{
  const s=await state();if(expectedOutboxHead&&!same(s.head,expectedOutboxHead))fail('FORENSIC_OUTBOX_PIN_MISMATCH');
  return structuredClone({count:s.head.count,headDigest:s.head.headDigest,events:s.events,productionApproved:false});
 });}
 async function prepare({record,expectedOutboxHead,expectedPublicationHead}={}){
  if(!obj(record)||!validHead(expectedOutboxHead)||!validHead(expectedPublicationHead))fail('FORENSIC_OUTBOX_REQUEST_INVALID');
  return withLock(async check=>{
   const s=await state();if(!same(s.head,expectedOutboxHead))fail('FORENSIC_OUTBOX_STALE_PIN');
   if(s.openPrepare)fail('FORENSIC_OUTBOX_UNACKNOWLEDGED');
   const history=await publicationStore.inspectHistory({expectedHead:expectedPublicationHead});
   if(history.count!==s.completed||record.index!==history.count+1)fail('FORENSIC_OUTBOX_ORPHAN_PUBLICATION');
   const next={count:record.index,headDigest:record.digest};
   verifyOfflineForensicPublicationHistory({registryId,anchorType,witnesses,witnessQuorum,reviewerPolicies,publications:[...history.publications,record],expectedHead:next});
   return appendEvent(s,check,'PREPARE',record.index,record.digest,record.publishedAt);
  });
 }
 async function acknowledge({acknowledgement,expectedOutboxHead,expectedPublicationHead}={}){
  if(!obj(acknowledgement)||!validHead(expectedOutboxHead)||!validHead(expectedPublicationHead))fail('FORENSIC_OUTBOX_REQUEST_INVALID');
  return withLock(async check=>{
   const s=await state();if(!same(s.head,expectedOutboxHead))fail('FORENSIC_OUTBOX_STALE_PIN');
   if(!s.openPrepare)fail('FORENSIC_OUTBOX_NO_PREPARE');
   const history=await publicationStore.inspectHistory({expectedHead:expectedPublicationHead});
   const r=history.publications.at(-1);
   if(history.count!==s.openPrepare.publicationIndex||r?.digest!==s.openPrepare.publicationDigest)fail('FORENSIC_OUTBOX_PUBLICATION_MISMATCH');
   verifyOfflineForensicPublicationAcknowledgement({acknowledgement,registryId,anchorType,record:r,witnesses,witnessQuorum});
   return appendEvent(s,check,'ACK',r.index,r.digest,r.publishedAt,acknowledgement);
  });
 }
 async function reconcile({expectedOutboxHead,expectedPublicationHead}={}){
  if(!validHead(expectedOutboxHead)||!validHead(expectedPublicationHead))fail('FORENSIC_OUTBOX_REQUEST_INVALID');
  return withLock(async()=>{
   const s=await state();if(!same(s.head,expectedOutboxHead))fail('FORENSIC_OUTBOX_PIN_MISMATCH');
   const history=await publicationStore.inspectHistory({expectedHead:expectedPublicationHead});
   const prepared=s.events.filter(e=>e.action==='PREPARE');
   if(history.count>prepared.length)fail('FORENSIC_OUTBOX_ORPHAN_PUBLICATION');
   for(let i=0;i<history.count;i++)if((prepared[i]?.publicationDigest!==history.publications[i].digest||prepared[i]?.publishedAt!==history.publications[i].publishedAt))fail('FORENSIC_OUTBOX_PUBLICATION_MISMATCH');
   if(s.openPrepare){
    if(history.count<prepared.length)fail('FORENSIC_OUTBOX_UNCERTAIN_PREPARE');
    fail('FORENSIC_OUTBOX_UNACKNOWLEDGED');
   }
   if(history.count!==s.completed)fail('FORENSIC_OUTBOX_ORPHAN_PUBLICATION');
   return Object.freeze({verified:true,publicationCount:history.count,outboxHead:{...s.head},productionApproved:false});
  });
 }
 return Object.freeze({inspect,inspectHistory,prepare,acknowledge,reconcile});
}
