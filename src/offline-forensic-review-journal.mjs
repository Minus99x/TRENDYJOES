/**
 * Objective 31H: opt-in, single-host, append-only forensic review evidence.
 * Not WORM/offsite storage or proof that a signed forensic assertion is true.
 * A separately operated witness must retain an independently monotonic head.
 */
import {createHash,randomBytes,verify as verifySignature} from 'node:crypto';
import {constants as C} from 'node:fs';
import {mkdir,open,lstat,readdir,rename} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {resolve,join} from 'node:path';
import {verifyOfflineRecoveryAdjudicationQuorum,validateOfflineRecoveryReviewers,recoveryReviewKeyDigest} from './offline-recovery-adjudication.mjs';

export const OFFLINE_FORENSIC_JOURNAL_WITNESS_SCHEMA='TJ-OFFLINE-FORENSIC-JOURNAL-WITNESS-1';
const SCHEMA='TJ-OFFLINE-FORENSIC-JOURNAL-EVENT-1';
const ROOT='0'.repeat(64);
const HEX=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9_-]{12,80}$/;
const FIELDS=['schema','witnessId','registryId','anchorType','count','headDigest','challenge','issuedAt','expiresAt'];
const EVENT_FIELDS=['schema','registryId','anchorType','index','previousDigest','observedAt','review','evidence','digest'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>obj(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const sha=x=>createHash('sha256').update(x).digest('hex');
const challengeValid=x=>typeof x==='string'&&/^[A-Za-z0-9_-]{43}$/.test(x)&&Buffer.from(x,'base64url').toString('base64url')===x;
const file=i=>String(i).padStart(10,'0')+'.json';
const head=s=>({count:s.count,headDigest:s.headDigest});
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
function validateWitnesses(witnesses,quorum,excludedKeys=[]){
 if(!Array.isArray(witnesses)||witnesses.length<2||witnesses.length>10||!Number.isSafeInteger(quorum)||quorum<=witnesses.length/2||quorum>witnesses.length)fail('FORENSIC_WITNESS_CONFIGURATION');
 const ids=new Set(),keys=new Set(excludedKeys);
 for(const w of witnesses){
  if(!exact(w,['id','publicKey','readLatest'])||!ID.test(w.id||'')||ids.has(w.id)||w.publicKey?.type!=='public'||w.publicKey?.asymmetricKeyType!=='ed25519'||typeof w.readLatest!=='function')fail('FORENSIC_WITNESS_CONFIGURATION');
  const k=recoveryReviewKeyDigest(w.publicKey);if(keys.has(k))fail('FORENSIC_WITNESS_SHARED_KEY');ids.add(w.id);keys.add(k);
 }
}
export function verifyOfflineForensicJournalWitnessQuorum({registryId,anchorType,witnesses,quorum,receipts,snapshot,challenge,now=Date.now(),excludedKeys=[]}={}){
 validateWitnesses(witnesses,quorum,excludedKeys);
 if(!ID.test(registryId||'')||!['registry','journal'].includes(anchorType)||!exact(snapshot,['count','headDigest'])||!Number.isSafeInteger(snapshot.count)||snapshot.count<0||snapshot.count>1000||!HEX.test(snapshot.headDigest)||(snapshot.count===0)!==(snapshot.headDigest===ROOT)||!challengeValid(challenge)||!Number.isSafeInteger(now)||!Array.isArray(receipts)||receipts.length<quorum||receipts.length>witnesses.length)fail('FORENSIC_WITNESS_REQUEST_INVALID');
 const byId=new Map(witnesses.map(w=>[w.id,w]));const seen=new Set();
 for(const r of receipts){
  if(!exact(r,[...FIELDS,'signature'])||r.schema!==OFFLINE_FORENSIC_JOURNAL_WITNESS_SCHEMA||r.registryId!==registryId||r.anchorType!==anchorType||!byId.has(r.witnessId)||seen.has(r.witnessId)||r.count!==snapshot.count||r.headDigest!==snapshot.headDigest||r.challenge!==challenge||!Number.isSafeInteger(r.issuedAt)||!Number.isSafeInteger(r.expiresAt)||r.issuedAt>now||r.expiresAt<=now||r.expiresAt<=r.issuedAt||r.expiresAt-r.issuedAt>300000||typeof r.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(r.signature))fail('FORENSIC_WITNESS_RECEIPT_INVALID');
  const sig=Buffer.from(r.signature,'base64url'),body=Object.fromEntries(FIELDS.map(k=>[k,r[k]]));
  if(sig.length!==64||sig.toString('base64url')!==r.signature||!verifySignature(null,Buffer.from(`${OFFLINE_FORENSIC_JOURNAL_WITNESS_SCHEMA}\0${JSON.stringify(body)}`),byId.get(r.witnessId).publicKey,sig))fail('FORENSIC_WITNESS_SIGNATURE_INVALID');
  seen.add(r.witnessId);
 }
 return Object.freeze({verified:true,count:seen.size,required:quorum,productionApproved:false});
}
/** Caller-pinned historical reviewer policy. Epochs are NOT trusted merely
 * because they appear in a local file; preserve the policy independently. */
function validateReviewerEpochs(epochs,excludedKeys=[]){
 if(!Array.isArray(epochs)||epochs.length<1||epochs.length>20)fail('FORENSIC_REVIEWER_EPOCH_CONFIGURATION');
 const ids=new Map(),keys=new Map(),retiredKeys=new Set();let lastStart=0;
 const out=[];
 for(const e of epochs){
  if(!exact(e,['startIndex','reviewers','quorum'])||!Number.isSafeInteger(e.startIndex)||e.startIndex<=lastStart||e.startIndex>1000||(lastStart===0&&e.startIndex!==1))fail('FORENSIC_REVIEWER_EPOCH_CONFIGURATION');
  validateOfflineRecoveryReviewers(e.reviewers,e.quorum,excludedKeys);
  for(const r of e.reviewers){
   const k=recoveryReviewKeyDigest(r.publicKey);
   if(keys.has(k)&&keys.get(k)!==r.id)fail('FORENSIC_REVIEWER_KEY_REASSIGNED');
   if(retiredKeys.has(k))fail('FORENSIC_REVIEWER_KEY_ROLLBACK');
   if(ids.has(r.id)&&ids.get(r.id)!==k)retiredKeys.add(ids.get(r.id));
   keys.set(k,r.id);
   // A reviewer ID can rotate to a new key, but a retired key may not
   // be reassigned to a different identity in a later epoch.
   ids.set(r.id,k);
  }
  out.push(Object.freeze({startIndex:e.startIndex,reviewers:Object.freeze(e.reviewers.map(r=>Object.freeze({...r}))),quorum:e.quorum}));
  lastStart=e.startIndex;
 }
 return Object.freeze(out);
}
function epochAt(epochs,index){
 let selected=epochs[0];for(const e of epochs){if(e.startIndex>index)break;selected=e;}return selected;
}
function sameReviewers(a,b){
 return a.length===b.length&&a.every(r=>b.some(x=>x.id===r.id&&recoveryReviewKeyDigest(x.publicKey)===recoveryReviewKeyDigest(r.publicKey)));
}
/** Portable, pure verification against a separately pinned head and trust
 * epochs. Never infer trusted policy or head from the supplied event bundle. */
export function verifyOfflineForensicEvidenceBundle({registryId,anchorType,events,reviewerEpochs,expectedHead,excludedKeys=[]}={}){
 if(!ID.test(registryId||'')||!['registry','journal'].includes(anchorType)||!Array.isArray(events)||events.length>1000||!exact(expectedHead,['count','headDigest'])||!Number.isSafeInteger(expectedHead.count)||expectedHead.count<0||expectedHead.count>1000||!HEX.test(expectedHead.headDigest)||!Array.isArray(excludedKeys))fail('FORENSIC_PORTABLE_BUNDLE_INVALID');
 const epochs=validateReviewerEpochs(reviewerEpochs,excludedKeys);
 if(expectedHead.count!==events.length)fail('FORENSIC_PORTABLE_HEAD_MISMATCH');
 let previous=ROOT,lastObservedAt=0;const seenPermits=new Set(),seenChallenges=new Set();
 for(let i=0;i<events.length;i++){
  const e=events[i],index=i+1,epoch=epochAt(epochs,index);
  if(!obj(e)||e.index!==index||e.previousDigest!==previous)fail('FORENSIC_JOURNAL_HISTORY_GAP');
  verifyEvent(e,registryId,anchorType,epoch.reviewers,epoch.quorum,excludedKeys);
  if(e.observedAt<lastObservedAt)fail('FORENSIC_JOURNAL_CLOCK_ROLLBACK');lastObservedAt=e.observedAt;
  if(seenPermits.has(e.review.authorizationDigest)||seenChallenges.has(e.review.challenge))fail('FORENSIC_JOURNAL_REPLAY');
  seenPermits.add(e.review.authorizationDigest);seenChallenges.add(e.review.challenge);previous=e.digest;
 }
 if(previous!==expectedHead.headDigest)fail('FORENSIC_PORTABLE_HEAD_MISMATCH');
 return Object.freeze({verified:true,count:events.length,headDigest:previous,productionApproved:false});
}
function bytes(value){
 if(!Buffer.isBuffer(value)&&!(value instanceof Uint8Array))fail('FORENSIC_EVIDENCE_INVALID');
 const b=Buffer.from(value);if(!b.length||b.length>131072)fail('FORENSIC_EVIDENCE_INVALID');return b;
}
function encoded(value){
 if(typeof value!=='string'||!value||value.length>175000||!/^[A-Za-z0-9_-]+$/.test(value))fail('FORENSIC_EVIDENCE_INVALID');
 const b=Buffer.from(value,'base64url');if(!b.length||b.length>131072||b.toString('base64url')!==value)fail('FORENSIC_EVIDENCE_INVALID');return b;
}
function verifyEvidence(review,evidence){
 if(!exact(evidence,['caseEvidence','outcomeEvidence'])||!Array.isArray(evidence.outcomeEvidence)||!Array.isArray(review?.outcomes)||evidence.outcomeEvidence.length!==review.outcomes.length)fail('FORENSIC_EVIDENCE_INVALID');
 if(sha(encoded(evidence.caseEvidence))!==review.caseDigest)fail('FORENSIC_EVIDENCE_DIGEST_MISMATCH');
 for(let i=0;i<review.outcomes.length;i++)if(sha(encoded(evidence.outcomeEvidence[i]))!==review.outcomes[i]?.evidenceDigest)fail('FORENSIC_EVIDENCE_DIGEST_MISMATCH');
}
function verifyEvent(e,registryId,anchorType,reviewers,reviewQuorum,excludedKeys){
 if(!exact(e,EVENT_FIELDS)||e.schema!==SCHEMA||e.registryId!==registryId||e.anchorType!==anchorType||!Number.isSafeInteger(e.observedAt)||!exact(e.review,['history','anchor','caseDigest','outcomes','authorizationDigest','challenge','receipts'])||!HEX.test(e.digest))fail('FORENSIC_JOURNAL_EVENT_INVALID');
 verifyEvidence(e.review,e.evidence);
 verifyOfflineRecoveryAdjudicationQuorum({registryId,anchorType,reviewers,quorum:reviewQuorum,...e.review,now:e.observedAt,excludedKeys});
 const {digest,...body}=e;if(sha(Buffer.from(`${SCHEMA}\0${JSON.stringify(body)}`))!==digest)fail('FORENSIC_JOURNAL_TAMPERED');
}
export function createOfflineForensicReviewJournal({directory,registryId,anchorType,reviewers,reviewQuorum,reviewerEpochs,excludedKeys=[],lockTimeoutMs=5000,injectFault}={}){
 if(process.platform!=='linux'||!C.O_NOFOLLOW||typeof directory!=='string'||!directory.trim()||!ID.test(registryId||'')||!['registry','journal'].includes(anchorType)||!Array.isArray(excludedKeys)||!Number.isInteger(lockTimeoutMs)||lockTimeoutMs<0||lockTimeoutMs>10000||(injectFault!==undefined&&typeof injectFault!=='function'))fail('FORENSIC_JOURNAL_CONFIGURATION');
 validateOfflineRecoveryReviewers(reviewers,reviewQuorum,excludedKeys);
 const epochs=validateReviewerEpochs(reviewerEpochs??[{startIndex:1,reviewers,quorum:reviewQuorum}],excludedKeys);
 const latest=epochs.at(-1);
 if(latest.quorum!==reviewQuorum||!sameReviewers(latest.reviewers,reviewers))fail('FORENSIC_REVIEWER_EPOCH_CURRENT_MISMATCH');
 const reviewerKeys=[...new Set(epochs.flatMap(e=>e.reviewers.map(r=>recoveryReviewKeyDigest(r.publicKey))))];
 const dir=resolve(directory),lock=join(dir,'.forensic-lock'),pending=join(dir,'.pending.json');
 async function safeDir(){
  await mkdir(dir,{recursive:true,mode:0o700});const s=await lstat(dir);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0)fail('FORENSIC_JOURNAL_DIRECTORY_UNSAFE');return s;
 }
 async function withLock(fn){
  const d=await safeDir();let h;
  try{
   h=await open(lock,C.O_RDWR|C.O_CREAT|C.O_NOFOLLOW,0o600);
   const [s,p]=await Promise.all([h.stat(),lstat(lock)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev)fail('FORENSIC_JOURNAL_LOCK_UNSAFE');
   await new Promise((ok,no)=>{const child=spawn('/usr/bin/flock',['-x','-w',(lockTimeoutMs/1000).toFixed(3),'3'],{stdio:['ignore','ignore','ignore',h.fd]});child.once('error',()=>no(Object.assign(Error('FORENSIC_JOURNAL_LOCK_UNAVAILABLE'),{code:'FORENSIC_JOURNAL_LOCK_UNAVAILABLE'})));child.once('close',code=>code===0?ok():no(Object.assign(Error('FORENSIC_JOURNAL_LOCK_UNAVAILABLE'),{code:'FORENSIC_JOURNAL_LOCK_UNAVAILABLE'})));});
   const check=async()=>{const [a,b]=await Promise.all([lstat(dir),lstat(lock)]);if(!a.isDirectory()||a.ino!==d.ino||a.dev!==d.dev||!b.isFile()||b.ino!==s.ino||b.dev!==s.dev||b.nlink!==1)fail('FORENSIC_JOURNAL_LOCK_UNSAFE');};
   await check();return await fn(check);
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('FORENSIC_JOURNAL_LOCK_UNSAFE');throw e;}
  finally{if(h)await h.close();}
 }
 async function readSafe(path){
  let h;try{
   h=await open(path,C.O_RDONLY|C.O_NOFOLLOW);const [s,p]=await Promise.all([h.stat(),lstat(path)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev||s.size===0||s.size>1048576)fail('FORENSIC_JOURNAL_FILE_UNSAFE');return await h.readFile();
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('FORENSIC_JOURNAL_FILE_UNSAFE');throw e;}finally{if(h)await h.close();}
 }
 async function state(){
  const names=await readdir(dir);if(names.includes('.pending.json'))fail('FORENSIC_JOURNAL_PENDING_REVIEW_REQUIRED');
  const events=names.filter(n=>n!=='.forensic-lock');if(events.length>1000)fail('FORENSIC_JOURNAL_CAPACITY');
  let previous=ROOT,lastObservedAt=0;const seenPermits=new Set(),seenChallenges=new Set();const history=[];
  for(let i=1;i<=events.length;i++){
   const name=file(i);if(!events.includes(name))fail('FORENSIC_JOURNAL_HISTORY_GAP');
   const raw=(await readSafe(join(dir,name))).toString('utf8');let e;
   try{e=JSON.parse(raw);}catch{fail('FORENSIC_JOURNAL_EVENT_INVALID');}
   if(raw!==JSON.stringify(e)||e.index!==i||e.previousDigest!==previous)fail('FORENSIC_JOURNAL_EVENT_INVALID');
   const epoch=epochAt(epochs,i);verifyEvent(e,registryId,anchorType,epoch.reviewers,epoch.quorum,excludedKeys);
   if(e.observedAt<lastObservedAt)fail('FORENSIC_JOURNAL_CLOCK_ROLLBACK');lastObservedAt=e.observedAt;
   if(seenPermits.has(e.review.authorizationDigest)||seenChallenges.has(e.review.challenge))fail('FORENSIC_JOURNAL_REPLAY');
   seenPermits.add(e.review.authorizationDigest);seenChallenges.add(e.review.challenge);previous=e.digest;history.push(e);
  }
  return {count:history.length,headDigest:previous,history,seenPermits,seenChallenges};
 }
 async function syncDir(){const h=await open(dir,'r');try{await h.sync();}finally{await h.close();}}
 async function inspect(){return withLock(async()=>Object.freeze({...head(await state()),productionApproved:false}));}
 async function inspectHistory(){return withLock(async()=>{const s=await state();return structuredClone({count:s.count,headDigest:s.headDigest,events:s.history});});}
 async function append({review,caseEvidence,outcomeEvidence,expectedHead}={}){
  if(!exact(review,['history','anchor','caseDigest','outcomes','authorizationDigest','challenge','receipts'])||!exact(expectedHead,['count','headDigest'])||!Number.isSafeInteger(expectedHead.count)||expectedHead.count<0||expectedHead.count>1000||!HEX.test(expectedHead.headDigest)||!Array.isArray(outcomeEvidence)||outcomeEvidence.length>512||outcomeEvidence.length!==review.outcomes?.length)fail('FORENSIC_JOURNAL_APPEND_INVALID');
  const caseBytes=bytes(caseEvidence),outcomeBytes=outcomeEvidence.map(bytes);
  if(caseBytes.length+outcomeBytes.reduce((n,b)=>n+b.length,0)>524288)fail('FORENSIC_JOURNAL_EVENT_TOO_LARGE');
  const evidence={caseEvidence:caseBytes.toString('base64url'),outcomeEvidence:outcomeBytes.map(x=>x.toString('base64url'))};
  verifyEvidence(review,evidence);
  return withLock(async check=>{
   const s=await state();if(!same(head(s),expectedHead))fail('FORENSIC_JOURNAL_STALE_PIN');
   if(s.seenPermits.has(review.authorizationDigest)||s.seenChallenges.has(review.challenge))fail('FORENSIC_JOURNAL_REPLAY');
   if(s.count>=1000)fail('FORENSIC_JOURNAL_CAPACITY');
   const observedAt=Date.now();
   if(s.history.length&&observedAt<s.history.at(-1).observedAt)fail('FORENSIC_JOURNAL_CLOCK_ROLLBACK');
   const epoch=epochAt(epochs,s.count+1);verifyOfflineRecoveryAdjudicationQuorum({registryId,anchorType,reviewers:epoch.reviewers,quorum:epoch.quorum,...review,now:observedAt,excludedKeys});
   const body={schema:SCHEMA,registryId,anchorType,index:s.count+1,previousDigest:s.headDigest,observedAt,review:structuredClone(review),evidence};
   const event={...body,digest:sha(Buffer.from(`${SCHEMA}\0${JSON.stringify(body)}`))};
   const raw=Buffer.from(JSON.stringify(event));if(raw.length>1048576)fail('FORENSIC_JOURNAL_EVENT_TOO_LARGE');
   await check();let h;
   try{h=await open(pending,C.O_WRONLY|C.O_CREAT|C.O_EXCL|C.O_NOFOLLOW,0o600);await h.writeFile(raw);await h.sync();}
   catch(e){if(['EEXIST','ELOOP'].includes(e.code))fail('FORENSIC_JOURNAL_PENDING_REVIEW_REQUIRED');throw e;}finally{if(h)await h.close();}
   await syncDir();if(injectFault)await injectFault('after-pending-sync');
   await check();await rename(pending,join(dir,file(event.index)));await syncDir();
   if(injectFault)await injectFault('after-commit-sync');
   const after=await state();if(after.count!==event.index||after.headDigest!==event.digest)fail('FORENSIC_JOURNAL_COMMIT_UNCERTAIN');
   return Object.freeze({recorded:true,index:event.index,headDigest:event.digest,productionApproved:false});
  });
 }
 async function inspectWitnessed({witnesses,quorum}={}){
  validateWitnesses(witnesses,quorum,[...excludedKeys,...reviewerKeys]);
  const before=await inspect(),challenge=randomBytes(32).toString('base64url');
  const receipts=await Promise.all(witnesses.map(w=>w.readLatest({registryId,anchorType,challenge})));
  verifyOfflineForensicJournalWitnessQuorum({registryId,anchorType,witnesses,quorum,receipts,snapshot:{count:before.count,headDigest:before.headDigest},challenge,excludedKeys:[...excludedKeys,...reviewerKeys]});
  const after=await inspect();if(!same(before,after))fail('FORENSIC_JOURNAL_CONCURRENT_CHANGE');
  return Object.freeze({...before,independentlyWitnessed:true,productionApproved:false});
 }
 return Object.freeze({inspect,inspectHistory,append,inspectWitnessed});
}
