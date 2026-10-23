/**
 * Objective 31I-B: offline, independently signed forensic-head publication
 * contract and single-host append-only retention. No network service, trusted
 * timestamp, offsite/WORM storage, production key custody or global rollback
 * protection is provided. Witness signatures are supplied by callers; this
 * module never handles private keys.
 */
import {createHash,verify as verifySignature} from 'node:crypto';
import {constants as C} from 'node:fs';
import {mkdir,open,lstat,readdir,rename} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {resolve,join} from 'node:path';
import {validateOfflineRecoveryReviewers,recoveryReviewKeyDigest} from './offline-recovery-adjudication.mjs';
import {verifyOfflineForensicEvidenceBundle} from './offline-forensic-review-journal.mjs';

export const OFFLINE_FORENSIC_PUBLICATION_SCHEMA='TJ-OFFLINE-FORENSIC-PUBLICATION-1';
export const OFFLINE_FORENSIC_ROTATION_SCHEMA='TJ-OFFLINE-FORENSIC-POLICY-ROTATION-1';
const ROOT='0'.repeat(64),HEX=/^[0-9a-f]{64}$/,ID=/^[A-Za-z0-9_-]{12,80}$/;
const BODY=['schema','registryId','anchorType','index','previousDigest','forensicCount','forensicHeadDigest','policyIndex','policyDigest','publishedAt'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>obj(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const sha=x=>createHash('sha256').update(x).digest('hex');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const head=x=>({count:x.count,headDigest:x.headDigest});
const name=i=>String(i).padStart(10,'0')+'.json';
const bodyOf=r=>Object.fromEntries(BODY.map(k=>[k,r[k]]));
const canonicalSig=s=>typeof s==='string'&&/^[A-Za-z0-9_-]{86}$/.test(s)&&Buffer.from(s,'base64url').length===64&&Buffer.from(s,'base64url').toString('base64url')===s;
const validHead=x=>exact(x,['count','headDigest'])&&Number.isSafeInteger(x.count)&&x.count>=0&&x.count<=1000&&HEX.test(x.headDigest)&&(x.count===0)===(x.headDigest===ROOT);
const signature=(key,bytes,s)=>canonicalSig(s)&&verifySignature(null,bytes,key,Buffer.from(s,'base64url'));
function checkBody(b){
 if(!exact(b,BODY)||b.schema!==OFFLINE_FORENSIC_PUBLICATION_SCHEMA||!ID.test(b.registryId||'')||!['registry','journal'].includes(b.anchorType)||!Number.isSafeInteger(b.index)||b.index<1||b.index>1000||!HEX.test(b.previousDigest)||!Number.isSafeInteger(b.forensicCount)||b.forensicCount<0||b.forensicCount>1000||!HEX.test(b.forensicHeadDigest)||(b.forensicCount===0)!==(b.forensicHeadDigest===ROOT)||!Number.isSafeInteger(b.policyIndex)||b.policyIndex<0||b.policyIndex>19||!HEX.test(b.policyDigest)||!Number.isSafeInteger(b.publishedAt)||b.publishedAt<0)fail('FORENSIC_PUBLICATION_BODY_INVALID');
}
export function forensicPublicationRotationBytes(body){checkBody(body);return Buffer.from(`${OFFLINE_FORENSIC_ROTATION_SCHEMA}\0${JSON.stringify(body)}`);}
export function forensicPublicationSigningBytes(body,rotationApprovals){
 checkBody(body);if(!Array.isArray(rotationApprovals))fail('FORENSIC_PUBLICATION_APPROVAL_INVALID');
 return Buffer.from(`${OFFLINE_FORENSIC_PUBLICATION_SCHEMA}\0${JSON.stringify({...body,rotationApprovals})}`);
}
export function forensicPublicationPolicyDigest({reviewers,quorum}={}){
 validateOfflineRecoveryReviewers(reviewers,quorum);
 return sha(Buffer.from(JSON.stringify({schema:'TJ-FORENSIC-REVIEWER-POLICY-1',quorum,reviewers:reviewers.map(r=>({id:r.id,keyDigest:recoveryReviewKeyDigest(r.publicKey)})).sort((a,b)=>a.id.localeCompare(b.id,'en'))})));
}
function configuration({registryId,anchorType,witnesses,witnessQuorum,reviewerPolicies}){
 if(!ID.test(registryId||'')||!['registry','journal'].includes(anchorType)||!Array.isArray(reviewerPolicies)||reviewerPolicies.length<1||reviewerPolicies.length>20||!Array.isArray(witnesses)||witnesses.length<2||witnesses.length>10||!Number.isSafeInteger(witnessQuorum)||witnessQuorum<=witnesses.length/2||witnessQuorum>witnesses.length)fail('FORENSIC_PUBLICATION_CONFIGURATION');
 const ids=new Set(),keys=new Set();
 for(const w of witnesses){
  if(!exact(w,['id','publicKey'])||!ID.test(w.id||'')||ids.has(w.id)||w.publicKey?.type!=='public'||w.publicKey?.asymmetricKeyType!=='ed25519')fail('FORENSIC_PUBLICATION_CONFIGURATION');
  const k=recoveryReviewKeyDigest(w.publicKey);if(keys.has(k))fail('FORENSIC_PUBLICATION_DUPLICATE_KEY');ids.add(w.id);keys.add(k);
 }
 const policies=[],ever=new Map(),retired=new Set(),active=new Map();
 for(const p of reviewerPolicies){
  if(!exact(p,['reviewers','quorum']))fail('FORENSIC_PUBLICATION_CONFIGURATION');
  validateOfflineRecoveryReviewers(p.reviewers,p.quorum,[...keys]);
  const current=new Map();
  for(const r of p.reviewers){
   const k=recoveryReviewKeyDigest(r.publicKey);
   if(ever.has(k)&&ever.get(k)!==r.id)fail('FORENSIC_PUBLICATION_KEY_REASSIGNED');
   if(retired.has(k))fail('FORENSIC_PUBLICATION_KEY_REACTIVATED');
   ever.set(k,r.id);current.set(r.id,k);
  }
  for(const [id,k] of active)if(current.get(id)!==k)retired.add(k);
  active.clear();for(const [id,k] of current)active.set(id,k);
  policies.push({...p,digest:forensicPublicationPolicyDigest(p)});
 }
 return policies;
}
function verifySignatures(entries,members,quorum,bytes,idField,code){
 if(!Array.isArray(entries)||entries.length<quorum||entries.length>members.length)fail(code);
 const byId=new Map(members.map(m=>[m.id,m.publicKey])),seen=new Set();
 for(const entry of entries){
  if(!exact(entry,[idField,'signature'])||!byId.has(entry[idField])||seen.has(entry[idField])||!signature(byId.get(entry[idField]),bytes,entry.signature))fail(code);
  seen.add(entry[idField]);
 }
}
/** Pure verification: external caller must independently pin witness keys,
 * reviewer policies, and expected publication head. */
export function verifyOfflineForensicPublicationHistory({registryId,anchorType,witnesses,witnessQuorum,reviewerPolicies,publications,expectedHead,expectedForensicHead}={}){
 const policies=configuration({registryId,anchorType,witnesses,witnessQuorum,reviewerPolicies});
 if(!Array.isArray(publications)||publications.length>1000||!validHead(expectedHead)||(expectedForensicHead!==undefined&&!validHead(expectedForensicHead)))fail('FORENSIC_PUBLICATION_REQUEST_INVALID');
 if(publications.length!==expectedHead.count)fail('FORENSIC_PUBLICATION_PIN_MISMATCH');
 let previous=ROOT,prior=null;
 for(let i=0;i<publications.length;i++){
  const r=publications[i];
  if(!exact(r,[...BODY,'rotationApprovals','witnessSignatures','digest']))fail('FORENSIC_PUBLICATION_RECORD_INVALID');
  const b=bodyOf(r);
  checkBody(b);
  if(r.registryId!==registryId||r.anchorType!==anchorType||r.index!==i+1||r.previousDigest!==previous||r.policyIndex>=policies.length||r.policyDigest!==policies[r.policyIndex].digest||!HEX.test(r.digest))fail('FORENSIC_PUBLICATION_CHAIN_INVALID');
  if(prior){
   if(r.publishedAt<=prior.publishedAt||r.forensicCount<prior.forensicCount||(r.forensicCount===prior.forensicCount&&r.forensicHeadDigest!==prior.forensicHeadDigest)||r.policyIndex<prior.policyIndex||r.policyIndex>prior.policyIndex+1)fail('FORENSIC_PUBLICATION_ROLLBACK');
  }else if(r.policyIndex!==0)fail('FORENSIC_PUBLICATION_POLICY_SKIP');
  const changed=prior&&r.policyIndex===prior.policyIndex+1;
  if(changed)verifySignatures(r.rotationApprovals,policies[prior.policyIndex].reviewers,policies[prior.policyIndex].quorum,forensicPublicationRotationBytes(b),'reviewerId','FORENSIC_PUBLICATION_ROTATION_INVALID');
  else if(!Array.isArray(r.rotationApprovals)||r.rotationApprovals.length)fail('FORENSIC_PUBLICATION_ROTATION_INVALID');
  verifySignatures(r.witnessSignatures,witnesses,witnessQuorum,forensicPublicationSigningBytes(b,r.rotationApprovals),'witnessId','FORENSIC_PUBLICATION_WITNESS_INVALID');
  const {digest,...unsigned}=r;
  if(sha(Buffer.from(`${OFFLINE_FORENSIC_PUBLICATION_SCHEMA}\0${JSON.stringify(unsigned)}`))!==r.digest)fail('FORENSIC_PUBLICATION_DIGEST_INVALID');
  previous=r.digest;prior=r;
 }
 if(previous!==expectedHead.headDigest)fail('FORENSIC_PUBLICATION_PIN_MISMATCH');
 if(expectedForensicHead&&(!prior||prior.forensicCount!==expectedForensicHead.count||prior.forensicHeadDigest!==expectedForensicHead.headDigest))fail('FORENSIC_PUBLICATION_FORENSIC_PIN_MISMATCH');
 return Object.freeze({verified:true,count:publications.length,headDigest:previous,forensicHead:prior?{count:prior.forensicCount,headDigest:prior.forensicHeadDigest}:null,productionApproved:false});
}

/** Composite offline verifier: a signed, pinned publication must describe the
 * exact forensic evidence chain and the correct historical reviewer epoch at
 * each published count. The witness/publication pin must be independently held. */
export function verifyOfflinePublishedForensicEvidenceBundle({registryId,anchorType,events,reviewerEpochs,expectedForensicHead,publications,expectedPublicationHead,witnesses,witnessQuorum,reviewerPolicies}={}){
 const publication=verifyOfflineForensicPublicationHistory({registryId,anchorType,witnesses,witnessQuorum,reviewerPolicies,publications,expectedHead:expectedPublicationHead,expectedForensicHead});
 if(!Array.isArray(reviewerEpochs)||!reviewerEpochs.length)fail('FORENSIC_PUBLICATION_EPOCH_BINDING_INVALID');
 for(const r of publications){
  let epochIndex=0;
  for(let i=0;i<reviewerEpochs.length;i++)if(reviewerEpochs[i]?.startIndex<=(r.forensicCount||1))epochIndex=i;
  if(r.policyIndex!==epochIndex||!reviewerPolicies[epochIndex]||reviewerEpochs[epochIndex].quorum!==reviewerPolicies[epochIndex].quorum||forensicPublicationPolicyDigest(reviewerEpochs[epochIndex])!==r.policyDigest)fail('FORENSIC_PUBLICATION_EPOCH_BINDING_INVALID');
 }
 const evidence=verifyOfflineForensicEvidenceBundle({registryId,anchorType,events,reviewerEpochs,expectedHead:expectedForensicHead});
 if(!evidence.verified||!publication.verified)fail('FORENSIC_PUBLICATION_COMPOSITE_INVALID');
 return Object.freeze({verified:true,publicationHead:{count:publication.count,headDigest:publication.headDigest},forensicHead:{count:evidence.count,headDigest:evidence.headDigest},productionApproved:false});
}

/** Durable single-host store. Pending writes are never silently recovered. */
export function createOfflineForensicPublicationStore({directory,registryId,anchorType,witnesses,witnessQuorum,reviewerPolicies,lockTimeoutMs=5000,injectFault}={}){
 configuration({registryId,anchorType,witnesses,witnessQuorum,reviewerPolicies});
 if(process.platform!=='linux'||!C.O_NOFOLLOW||typeof directory!=='string'||!directory.trim()||!Number.isSafeInteger(lockTimeoutMs)||lockTimeoutMs<0||lockTimeoutMs>10000||(injectFault!==undefined&&typeof injectFault!=='function'))fail('FORENSIC_PUBLICATION_CONFIGURATION');
 const dir=resolve(directory),lock=join(dir,'.publication-lock'),pending=join(dir,'.pending.json');
 async function safeDir(){
  await mkdir(dir,{recursive:true,mode:0o700});const s=await lstat(dir);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0)fail('FORENSIC_PUBLICATION_DIRECTORY_UNSAFE');return s;
 }
 async function withLock(fn){
  const d=await safeDir();let h;
  try{
   h=await open(lock,C.O_RDWR|C.O_CREAT|C.O_NOFOLLOW,0o600);
   const [s,p]=await Promise.all([h.stat(),lstat(lock)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev)fail('FORENSIC_PUBLICATION_LOCK_UNSAFE');
   await new Promise((ok,no)=>{const child=spawn('/usr/bin/flock',['-x','-w',(lockTimeoutMs/1000).toFixed(3),'3'],{stdio:['ignore','ignore','ignore',h.fd]});child.once('error',()=>no(Object.assign(Error('FORENSIC_PUBLICATION_LOCK_UNAVAILABLE'),{code:'FORENSIC_PUBLICATION_LOCK_UNAVAILABLE'})));child.once('close',code=>code===0?ok():no(Object.assign(Error('FORENSIC_PUBLICATION_LOCK_UNAVAILABLE'),{code:'FORENSIC_PUBLICATION_LOCK_UNAVAILABLE'})));});
   const check=async()=>{const [a,b]=await Promise.all([lstat(dir),lstat(lock)]);if(!a.isDirectory()||a.ino!==d.ino||a.dev!==d.dev||!b.isFile()||b.ino!==s.ino||b.dev!==s.dev||b.nlink!==1)fail('FORENSIC_PUBLICATION_LOCK_UNSAFE');};
   await check();return await fn(check);
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('FORENSIC_PUBLICATION_LOCK_UNSAFE');throw e;}
  finally{if(h)await h.close();}
 }
 async function readSafe(path){
  let h;try{
   h=await open(path,C.O_RDONLY|C.O_NOFOLLOW);const [s,p]=await Promise.all([h.stat(),lstat(path)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev||s.size<2||s.size>65536)fail('FORENSIC_PUBLICATION_FILE_UNSAFE');return await h.readFile();
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('FORENSIC_PUBLICATION_FILE_UNSAFE');throw e;}finally{if(h)await h.close();}
 }
 async function state(){
  const names=await readdir(dir);if(names.includes('.pending.json'))fail('FORENSIC_PUBLICATION_PENDING_REVIEW_REQUIRED');
  const files=names.filter(n=>n!=='.publication-lock');if(files.length>1000)fail('FORENSIC_PUBLICATION_CAPACITY');
  const publications=[];
  for(let i=1;i<=files.length;i++){
   if(!files.includes(name(i)))fail('FORENSIC_PUBLICATION_HISTORY_GAP');
   const raw=(await readSafe(join(dir,name(i)))).toString('utf8');let r;
   try{r=JSON.parse(raw);}catch{fail('FORENSIC_PUBLICATION_RECORD_INVALID');}
   if(raw!==JSON.stringify(r))fail('FORENSIC_PUBLICATION_NONCANONICAL');publications.push(r);
  }
  // Derive the expected head from the complete on-disk chain; independent
  // callers must supply their own pinned head to reject valid-prefix rollback.
  const last=publications.at(-1),expectedHead={count:publications.length,headDigest:last?.digest??ROOT};
  verifyOfflineForensicPublicationHistory({registryId,anchorType,witnesses,witnessQuorum,reviewerPolicies,publications,expectedHead});
  return {publications,expectedHead};
 }
 async function syncDir(){const h=await open(dir,'r');try{await h.sync();}finally{await h.close();}}
 async function inspect({expectedHead}={}){return withLock(async()=>{
  const s=await state();if(expectedHead&&!same(expectedHead,s.expectedHead))fail('FORENSIC_PUBLICATION_PIN_MISMATCH');
  return structuredClone({...s.expectedHead,productionApproved:false});
 });}
 async function inspectHistory({expectedHead}={}){return withLock(async()=>{
  const s=await state();if(expectedHead&&!same(expectedHead,s.expectedHead))fail('FORENSIC_PUBLICATION_PIN_MISMATCH');
  return structuredClone({count:s.expectedHead.count,headDigest:s.expectedHead.headDigest,publications:s.publications});
 });}
 async function append({record,expectedHead}={}){
  if(!validHead(expectedHead)||!obj(record))fail('FORENSIC_PUBLICATION_APPEND_INVALID');
  return withLock(async check=>{
   const s=await state();if(!same(s.expectedHead,expectedHead))fail('FORENSIC_PUBLICATION_STALE_PIN');
   if(s.publications.length>=1000)fail('FORENSIC_PUBLICATION_CAPACITY');
   const publications=[...s.publications,record],next={count:publications.length,headDigest:record.digest};
   verifyOfflineForensicPublicationHistory({registryId,anchorType,witnesses,witnessQuorum,reviewerPolicies,publications,expectedHead:next});
   const raw=Buffer.from(JSON.stringify(record));if(raw.length>65536)fail('FORENSIC_PUBLICATION_FILE_UNSAFE');
   await check();let h;
   try{h=await open(pending,C.O_WRONLY|C.O_CREAT|C.O_EXCL|C.O_NOFOLLOW,0o600);await h.writeFile(raw);await h.sync();}
   catch(e){if(['EEXIST','ELOOP'].includes(e.code))fail('FORENSIC_PUBLICATION_PENDING_REVIEW_REQUIRED');throw e;}finally{if(h)await h.close();}
   await syncDir();if(injectFault)await injectFault('after-pending-sync');
   await check();await rename(pending,join(dir,name(record.index)));await syncDir();
   if(injectFault)await injectFault('after-commit-sync');
   const after=await state();if(!same(after.expectedHead,next))fail('FORENSIC_PUBLICATION_COMMIT_UNCERTAIN');
   return Object.freeze({...next,recorded:true,productionApproved:false});
  });
 }
 return Object.freeze({inspect,inspectHistory,append});
}
