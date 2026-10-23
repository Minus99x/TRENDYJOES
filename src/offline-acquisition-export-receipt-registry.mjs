/**
 * Objective 31S: durable, independently signed OFFLINE export-receipt registry.
 * The caller supplies an independently retained expected head, witness public
 * keys and trusted clock. No private keys, customer data or network I/O.
 * A receipt attests an archive digest, NOT the authenticity of its contents.
 */
import {createHash,verify as cryptoVerify} from 'node:crypto';
import {constants as F} from 'node:fs';
import {mkdir,open,lstat,readdir,realpath,rename} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {join,resolve} from 'node:path';
import {verifyOfflineAcquisitionEvidenceExport} from './offline-acquisition-evidence-export.mjs';

export const OFFLINE_EXPORT_RECEIPT_SCHEMA='TJ-OFFLINE-ACQUISITION-EXPORT-RECEIPT-1';
export const OFFLINE_EXPORT_REGISTRY_SCHEMA='TJ-OFFLINE-ACQUISITION-EXPORT-REGISTRY-1';
const ROOT='0'.repeat(64), HEX=/^[0-9a-f]{64}$/, ID=/^[A-Za-z0-9_-]{12,80}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>obj(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const sha=b=>createHash('sha256').update(b).digest('hex');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=2000&&HEX.test(h.headDigest)&&(h.count===0)===(h.headDigest===ROOT);
const sig=s=>typeof s==='string'&&/^[A-Za-z0-9_-]{86}$/.test(s)&&Buffer.from(s,'base64url').length===64&&Buffer.from(s,'base64url').toString('base64url')===s;
const recordDigest=body=>sha(Buffer.from(`${OFFLINE_EXPORT_REGISTRY_SCHEMA}\0${JSON.stringify(body)}`));
const fileName=i=>`${String(i).padStart(4,'0')}.json`;
const frozenState=(s,status)=>Object.freeze({head:Object.freeze({...s.head}),count:s.head.count,status,readOnly:true,mayRetry:false,mayAcknowledge:false,mayManufacture:false,productionApproved:false});

function trust(witnesses,quorum){
 if(!Array.isArray(witnesses)||witnesses.length<2||witnesses.length>12||!Number.isSafeInteger(quorum)||quorum<=witnesses.length/2||quorum>witnesses.length)fail('EXPORT_RECEIPT_POLICY_INVALID');
 const ids=new Set(),keys=new Set(),members=[];
 for(const w of witnesses){
  if(!exact(w,['id','publicKey'])||!ID.test(w.id||'')||ids.has(w.id)||w.publicKey?.type!=='public'||w.publicKey?.asymmetricKeyType!=='ed25519')fail('EXPORT_RECEIPT_POLICY_INVALID');
  const keyDigest=sha(w.publicKey.export({format:'der',type:'spki'}));
  if(keys.has(keyDigest))fail('EXPORT_RECEIPT_DUPLICATE_KEY');
  ids.add(w.id);keys.add(keyDigest);members.push({id:w.id,publicKey:w.publicKey,keyDigest});
 }
 const canonical=members.map(w=>({id:w.id,keyDigest:w.keyDigest})).sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);
 return {digest:sha(Buffer.from(`${OFFLINE_EXPORT_RECEIPT_SCHEMA}-POLICY\0${JSON.stringify({quorum,witnesses:canonical})}`)),quorum,members:new Map(members.map(w=>[w.id,w.publicKey]))};
}
export function offlineExportReceiptPolicyDigest({witnesses,quorum}={}){return trust(witnesses,quorum).digest;}
function checkBody(b){
 if(!exact(b,['schema','registryId','sequence','previousDigest','exportId','acquisitionId','archiveDigest','archiveBytes','issuedAt','expiresAt','nonce','policyDigest'])||b.schema!==OFFLINE_EXPORT_RECEIPT_SCHEMA||!ID.test(b.registryId||'')||!Number.isSafeInteger(b.sequence)||b.sequence<1||b.sequence>2000||!HEX.test(b.previousDigest||'')||!ID.test(b.exportId||'')||!ID.test(b.acquisitionId||'')||!HEX.test(b.archiveDigest||'')||!Number.isSafeInteger(b.archiveBytes)||b.archiveBytes<1||b.archiveBytes>32*1024*1024+32768||!Number.isSafeInteger(b.issuedAt)||b.issuedAt<0||!Number.isSafeInteger(b.expiresAt)||b.expiresAt<=b.issuedAt||b.expiresAt-b.issuedAt>7*24*3600*1000||!ID.test(b.nonce||'')||!HEX.test(b.policyDigest||''))fail('EXPORT_RECEIPT_BODY_INVALID');
}
export function offlineExportReceiptSigningBytes(body){checkBody(body);return Buffer.from(`${OFFLINE_EXPORT_RECEIPT_SCHEMA}\0${JSON.stringify(body)}`);}
function verifyReceipt(receipt,p,registryId){
 if(!exact(receipt,['body','signatures']))fail('EXPORT_RECEIPT_INVALID');
 const bytes=offlineExportReceiptSigningBytes(receipt.body),b=receipt.body;
 if(b.registryId!==registryId||b.policyDigest!==p.digest)fail('EXPORT_RECEIPT_POLICY_MISMATCH');
 if(!Array.isArray(receipt.signatures)||receipt.signatures.length<p.quorum||receipt.signatures.length>p.members.size)fail('EXPORT_RECEIPT_QUORUM_INVALID');
 let last='';
 for(const s of receipt.signatures){
  if(!exact(s,['witnessId','signature'])||typeof s.witnessId!=='string'||s.witnessId<=last||!p.members.has(s.witnessId)||!sig(s.signature)||!cryptoVerify(null,bytes,p.members.get(s.witnessId),Buffer.from(s.signature,'base64url')))fail('EXPORT_RECEIPT_SIGNATURE_INVALID');
  last=s.witnessId;
 }
 return b;
}
export function verifyHistoricalOfflineExportReceipt({receipt,witnesses,quorum,registryId}={}){
 if(!ID.test(registryId||''))fail('EXPORT_RECEIPT_REQUEST_INVALID');
 const b=verifyReceipt(receipt,trust(witnesses,quorum),registryId);
 return Object.freeze({verified:true,body:b,readOnly:true,productionApproved:false});
}

export function verifyOfflineExportReceipt({receipt,witnesses,quorum,registryId,nowMs}={}){
 if(!ID.test(registryId||'')||!Number.isSafeInteger(nowMs)||nowMs<0)fail('EXPORT_RECEIPT_REQUEST_INVALID');
 const b=verifyReceipt(receipt,trust(witnesses,quorum),registryId);
 if(nowMs<b.issuedAt||nowMs>=b.expiresAt)fail('EXPORT_RECEIPT_EXPIRED_OR_FUTURE');
 return Object.freeze({verified:true,archiveDigest:b.archiveDigest,archiveBytes:b.archiveBytes,acquisitionId:b.acquisitionId,readOnly:true,underlyingSignaturesVerified:false,productionApproved:false});
}

export function createOfflineExportReceiptRegistry({directory,registryId,witnesses,quorum,lockTimeoutMs=5000,injectFault}={}){
 if(process.platform!=='linux'||!F.O_NOFOLLOW||typeof directory!=='string'||!directory.trim()||!ID.test(registryId||'')||!Number.isSafeInteger(lockTimeoutMs)||lockTimeoutMs<0||lockTimeoutMs>10000||(injectFault!==undefined&&typeof injectFault!=='function'))fail('EXPORT_REGISTRY_CONFIGURATION');
 const p=trust(witnesses,quorum),dir=resolve(directory),lock=join(dir,'.export-registry-lock'),pending=join(dir,'.pending.json');
 async function safeDir(){
  await mkdir(dir,{recursive:true,mode:0o700});let s;
  try{s=await lstat(dir);if((await realpath(dir))!==dir||!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0)fail('EXPORT_REGISTRY_DIRECTORY_UNSAFE');}
  catch(e){if(e.code==='EXPORT_REGISTRY_DIRECTORY_UNSAFE')throw e;fail('EXPORT_REGISTRY_DIRECTORY_UNSAFE');}
  return s;
 }
 async function withLock(fn){
  const d=await safeDir();let h,child;
  try{
   h=await open(lock,F.O_RDWR|F.O_CREAT|F.O_NOFOLLOW,0o600);
   const [s,path]=await Promise.all([h.stat(),lstat(lock)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==path.ino||s.dev!==path.dev)fail('EXPORT_REGISTRY_LOCK_UNSAFE');
   // Unlike a one-shot `flock fd`, this child retains the lock for the WHOLE
   // parent critical section. A killed parent closes the pipe and frees it.
   child=spawn('/usr/bin/flock',['-x','-w',(lockTimeoutMs/1000).toFixed(3),'/proc/self/fd/3','/bin/sh','-c','printf "READY\\n"; IFS= read -r _ || :'],{stdio:['pipe','pipe','pipe',h.fd]});
   child.stdin?.on('error',()=>{}); // failed lock acquisition may close stdin before cleanup
   await new Promise((ok,no)=>{
    let settled=false,data='';
    const error=()=>{if(!settled){settled=true;no(Object.assign(Error('EXPORT_REGISTRY_LOCK_UNAVAILABLE'),{code:'EXPORT_REGISTRY_LOCK_UNAVAILABLE'}));}};
    child.once('error',error);child.once('close',error);
    child.stdout.on('data',chunk=>{data+=chunk.toString();if(data.length>32)return error();if(data.includes('READY\n')&&!settled){settled=true;ok();}});
   });
   const check=async()=>{
    const [a,b]=await Promise.all([lstat(dir),lstat(lock)]);
    if(!a.isDirectory()||a.ino!==d.ino||a.dev!==d.dev||!b.isFile()||b.ino!==s.ino||b.dev!==s.dev||b.nlink!==1||(b.mode&0o077)!==0)fail('EXPORT_REGISTRY_LOCK_UNSAFE');
   };
   await check();return await fn(check);
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('EXPORT_REGISTRY_LOCK_UNSAFE');throw e;}
  finally{
   if(child){child.stdin?.end('\n');await new Promise(ok=>{if(child.exitCode!==null||child.signalCode!==null)return ok();child.once('close',ok);setTimeout(()=>{child.kill('SIGKILL');ok();},1000).unref();});}
   if(h)await h.close();
  }
 }
 async function readSafe(path){let h;try{
  h=await open(path,F.O_RDONLY|F.O_NOFOLLOW|F.O_NONBLOCK);
  const [s,ps]=await Promise.all([h.stat(),lstat(path)]);
  if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==ps.ino||s.dev!==ps.dev||s.size<2||s.size>16*1024)fail('EXPORT_REGISTRY_FILE_UNSAFE');
  const bytes=await h.readFile(),after=await h.stat(),pathAfter=await lstat(path);
  if(bytes.length!==s.size||after.size!==s.size||after.mtimeMs!==s.mtimeMs||after.ctimeMs!==s.ctimeMs||pathAfter.ino!==s.ino||pathAfter.dev!==s.dev)fail('EXPORT_REGISTRY_FILE_CHANGED');
  const raw=bytes.toString('utf8');if(!Buffer.from(raw,'utf8').equals(bytes))fail('EXPORT_REGISTRY_HISTORY_INVALID');
  let parsed;try{parsed=JSON.parse(raw);}catch{fail('EXPORT_REGISTRY_HISTORY_INVALID');}
  if(JSON.stringify(parsed)!==raw)fail('EXPORT_REGISTRY_HISTORY_INVALID');return parsed;
 }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('EXPORT_REGISTRY_FILE_UNSAFE');throw e;}finally{if(h)await h.close();}}
 async function state(){
  const names=await readdir(dir);if(names.includes('.pending.json'))fail('EXPORT_REGISTRY_UNCERTAIN_COMMIT');
  const files=names.filter(n=>n!=='.export-registry-lock');
  if(files.length>2000||files.some(n=>!/^[0-9]{4}\.json$/.test(n)))fail('EXPORT_REGISTRY_HISTORY_INVALID');
  const entries=[],exports=new Set(),acquisitions=new Set(),digests=new Set(),nonces=new Set();let previous=ROOT,previousIssuedAt=-1;
  for(let i=1;i<=files.length;i++){
   if(!files.includes(fileName(i)))fail('EXPORT_REGISTRY_HISTORY_INVALID');
   const e=await readSafe(join(dir,fileName(i)));
   if(!exact(e,['schema','index','previousDigest','receipt','digest'])||e.schema!==OFFLINE_EXPORT_REGISTRY_SCHEMA||e.index!==i||e.previousDigest!==previous||!HEX.test(e.digest||''))fail('EXPORT_REGISTRY_HISTORY_INVALID');
   const b=verifyReceipt(e.receipt,p,registryId);
   if(b.sequence!==i||b.previousDigest!==previous||b.issuedAt<previousIssuedAt)fail('EXPORT_REGISTRY_HISTORY_INVALID');
   if(exports.has(b.exportId)||acquisitions.has(b.acquisitionId)||digests.has(b.archiveDigest)||nonces.has(b.nonce))fail('EXPORT_REGISTRY_REPLAY');
   const {digest,...body}=e;if(recordDigest(body)!==e.digest)fail('EXPORT_REGISTRY_HISTORY_INVALID');
   exports.add(b.exportId);acquisitions.add(b.acquisitionId);digests.add(b.archiveDigest);nonces.add(b.nonce);
   entries.push(e);previous=e.digest;previousIssuedAt=b.issuedAt;
  }
  return {entries,head:{count:entries.length,headDigest:previous},exports,acquisitions,digests,nonces,previousIssuedAt};
 }
 async function syncDir(){const h=await open(dir,'r');try{await h.sync();}finally{await h.close();}}
 async function append({receipt,archiveBytes,expectedHead,nowMs}={}){
  if(!head(expectedHead)||!Number.isSafeInteger(nowMs)||nowMs<0)fail('EXPORT_REGISTRY_EXTERNAL_PIN_REQUIRED');
  return withLock(async check=>{
   const s=await state();if(!same(s.head,expectedHead))fail('EXPORT_REGISTRY_STALE_PIN');
   const b=verifyReceipt(receipt,p,registryId);
   if(b.sequence!==s.head.count+1||b.previousDigest!==s.head.headDigest||b.issuedAt<s.previousIssuedAt)fail('EXPORT_REGISTRY_SEQUENCE_INVALID');
   if(nowMs<b.issuedAt||nowMs>=b.expiresAt)fail('EXPORT_RECEIPT_EXPIRED_OR_FUTURE');
   if(s.exports.has(b.exportId)||s.acquisitions.has(b.acquisitionId)||s.digests.has(b.archiveDigest)||s.nonces.has(b.nonce))fail('EXPORT_REGISTRY_REPLAY');
   if(!Buffer.isBuffer(archiveBytes)||archiveBytes.length!==b.archiveBytes)fail('EXPORT_REGISTRY_ARCHIVE_SIZE_MISMATCH');
   verifyOfflineAcquisitionEvidenceExport({bytes:archiveBytes,expectedDigest:b.archiveDigest,expectedAcquisitionId:b.acquisitionId});
   const body={schema:OFFLINE_EXPORT_REGISTRY_SCHEMA,index:b.sequence,previousDigest:s.head.headDigest,receipt};
   const entry={...body,digest:recordDigest(body)},bytes=Buffer.from(JSON.stringify(entry));
   if(bytes.length>16*1024)fail('EXPORT_REGISTRY_RECORD_TOO_LARGE');
   await check();let h;
   try{h=await open(pending,F.O_WRONLY|F.O_CREAT|F.O_EXCL|F.O_NOFOLLOW,0o600);await h.writeFile(bytes);await h.sync();}
   catch(e){if(['EEXIST','ELOOP'].includes(e.code))fail('EXPORT_REGISTRY_UNCERTAIN_COMMIT');throw e;}
   finally{if(h)await h.close();}
   await syncDir();if(injectFault)await injectFault('after-export-pending-sync');await check();
   await rename(pending,join(dir,fileName(entry.index)));await syncDir();
   if(injectFault)await injectFault('after-export-commit-sync');
   const n=await state();if(n.head.headDigest!==entry.digest)fail('EXPORT_REGISTRY_UNCERTAIN_COMMIT');
   return frozenState(n,'SIGNED_EXPORT_PIN_RECORDED_OFFLINE_ONLY');
  });
 }
 async function exportHistory({expectedHead}={}){
  if(!head(expectedHead))fail('EXPORT_REGISTRY_EXTERNAL_PIN_REQUIRED');
  return withLock(async()=>{
   const s=await state();if(!same(s.head,expectedHead))fail('EXPORT_REGISTRY_PIN_MISMATCH');
   const {encodeOfflineExportReceiptHistory}=await import('./offline-export-receipt-history.mjs');
   return encodeOfflineExportReceiptHistory({entries:s.entries,expectedHead,registryId,witnesses,quorum});
  });
 }
 async function inspect({expectedHead}={}){
  if(!head(expectedHead))fail('EXPORT_REGISTRY_EXTERNAL_PIN_REQUIRED');
  return withLock(async()=>{const s=await state();if(!same(s.head,expectedHead))fail('EXPORT_REGISTRY_PIN_MISMATCH');return frozenState(s,'INDEPENDENTLY_PINNED_SIGNED_HISTORY');});
 }
 return Object.freeze({append,inspect,exportHistory,policyDigest:p.digest,registryId});
}
