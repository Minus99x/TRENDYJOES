/**
 * Objective 31X: opt-in, OFFLINE migration of a 31V one-cutover registry to
 * durable multi-epoch witness policies. The legacy 31V records are unchanged.
 * All operations require caller-supplied external receipt-head AND policy-chain
 * pins. No recovery, trust anchor, signing key, or production authority is inferred.
 * Linux local filesystem only; not a Shopify integration.
 */
import {createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
import {constants as F} from 'node:fs';
import {mkdir,open,lstat,readdir,realpath,link,unlink} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {join,resolve} from 'node:path';
import {verifyOfflineAcquisitionEvidenceExport} from './offline-acquisition-evidence-export.mjs';
import {OFFLINE_EXPORT_REGISTRY_SCHEMA,offlineExportReceiptPolicyDigest,verifyHistoricalOfflineExportReceipt,verifyOfflineExportReceipt} from './offline-acquisition-export-receipt-registry.mjs';
import {offlineExportWitnessTransitionSigningBytes,offlineExportWitnessTransitionPossessionBytes,offlineExportWitnessTransitionChainDigest} from './offline-export-receipt-witness-rotation.mjs';

const ROOT='0'.repeat(64),HEX=/^[0-9a-f]{64}$/,ID=/^[A-Za-z0-9_-]{12,80}$/;
const LEGACY_SCHEMA='TJ-OFFLINE-EXPORT-RECEIPT-DURABLE-CUTOVER-1';
export const OFFLINE_MULTI_EPOCH_CUTOVER_SCHEMA='TJ-OFFLINE-EXPORT-RECEIPT-MULTI-CUTOVER-1';
const fail=code=>{throw Object.assign(new Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>obj(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const sha=b=>createHash('sha256').update(b).digest('hex');
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=2000&&HEX.test(h.headDigest)&&(h.count===0)===(h.headDigest===ROOT);
const fname=i=>`${String(i).padStart(4,'0')}.json`;
const certName=epoch=>epoch===1?'.witness-cutover.json':`.witness-cutover-${String(epoch).padStart(4,'0')}.json`;
const recHash=b=>sha(Buffer.from(`${OFFLINE_EXPORT_REGISTRY_SCHEMA}\0${JSON.stringify(b)}`));
const signed=s=>typeof s==='string'&&/^[A-Za-z0-9_-]{86}$/.test(s)&&Buffer.from(s,'base64url').length===64&&Buffer.from(s,'base64url').toString('base64url')===s;
const result=(s,status)=>Object.freeze({head:Object.freeze({...s.head}),epoch:s.transitions.length,transitionDigest:s.chainDigest,status,readOnly:true,mayManufacture:false,mayAcknowledge:false,productionApproved:false});
function signatures(items,policy,min,bytes){
 if(!Array.isArray(items)||items.length<min||items.length>policy.witnesses.length)fail('MULTI_EPOCH_SIGNATURE_INVALID');
 const members=new Map(policy.witnesses.map(w=>[w.id,w.publicKey]));let previous='';
 for(const item of items){
  if(!exact(item,['witnessId','signature'])||typeof item.witnessId!=='string'||item.witnessId<=previous||!members.has(item.witnessId)||!signed(item.signature)||
   !verifySignature(null,bytes(item.witnessId),members.get(item.witnessId),Buffer.from(item.signature,'base64url')))fail('MULTI_EPOCH_SIGNATURE_INVALID');
  previous=item.witnessId;
 }
}
export function createOfflineMultiEpochExportReceiptRegistry({directory,registryId,policies,lockTimeoutMs=5000,injectFault}={}){
 if(process.platform!=='linux'||!F.O_NOFOLLOW||typeof directory!=='string'||!directory.trim()||!ID.test(registryId||'')||
  !Array.isArray(policies)||policies.length<3||policies.length>20||!Number.isSafeInteger(lockTimeoutMs)||lockTimeoutMs<0||lockTimeoutMs>10000||
  (injectFault!==undefined&&typeof injectFault!=='function'))fail('MULTI_EPOCH_CONFIGURATION');
 const trustedPolicies=policies.map(p=>{
  if(!exact(p,['witnesses','quorum'])||!Array.isArray(p.witnesses))fail('MULTI_EPOCH_CONFIGURATION');
  // Snapshot keys and quorum: a caller must not silently replace the trust set
  // after this registry has pinned its policy digests.
  const witnesses=p.witnesses.map(w=>Object.freeze({id:w.id,publicKey:createPublicKey({key:w.publicKey.export({format:'der',type:'spki'}),format:'der',type:'spki'})}));
  return Object.freeze({quorum:p.quorum,witnesses:Object.freeze(witnesses)});
 });
 const digests=trustedPolicies.map(offlineExportReceiptPolicyDigest);
 const ids=new Set(),keys=new Set();
 for(const p of trustedPolicies)for(const w of p.witnesses){
  const kd=sha(w.publicKey.export({format:'der',type:'spki'}));
  if(ids.has(w.id)||keys.has(kd))fail('MULTI_EPOCH_RETIRED_KEY_REUSE');ids.add(w.id);keys.add(kd);
 }
 const dir=resolve(directory),lock=join(dir,'.export-registry-lock'),pending=join(dir,'.pending-multi-cutover.json'),appendPending=join(dir,'.pending.json');
 async function safeDir(){
  await mkdir(dir,{recursive:true,mode:0o700});const s=await lstat(dir);
  if(!s.isDirectory()||s.isSymbolicLink()||(await realpath(dir))!==dir||s.uid!==process.getuid()||(s.mode&0o077)!==0)fail('MULTI_EPOCH_DIRECTORY_UNSAFE');return s;
 }
 async function withLock(fn){
  const d=await safeDir();let h,child;
  try{
   h=await open(lock,F.O_RDWR|F.O_CREAT|F.O_NOFOLLOW,0o600);
   const [s,ps]=await Promise.all([h.stat(),lstat(lock)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==ps.ino||s.dev!==ps.dev)fail('MULTI_EPOCH_LOCK_UNSAFE');
   child=spawn('/usr/bin/flock',['-x','-w',(lockTimeoutMs/1000).toFixed(3),'/proc/self/fd/3','/bin/sh','-c','printf "READY\\n"; IFS= read -r _ || :'],{stdio:['pipe','pipe','pipe',h.fd]});
   child.stdin?.on('error',()=>{});
   await new Promise((ok,no)=>{let settled=false,data='';const err=()=>{if(!settled){settled=true;no(Object.assign(Error('MULTI_EPOCH_LOCK_UNAVAILABLE'),{code:'MULTI_EPOCH_LOCK_UNAVAILABLE'}));}};
    child.once('error',err);child.once('close',err);child.stdout.on('data',b=>{data+=b.toString();if(data.length>32)return err();if(data.includes('READY\n')&&!settled){settled=true;ok();}});});
   const check=async()=>{const [a,b]=await Promise.all([lstat(dir),lstat(lock)]);if(!a.isDirectory()||a.ino!==d.ino||a.dev!==d.dev||!b.isFile()||b.ino!==s.ino||b.dev!==s.dev||b.nlink!==1||(b.mode&0o077)!==0)fail('MULTI_EPOCH_LOCK_UNSAFE');};
   await check();return await fn(check);
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('MULTI_EPOCH_LOCK_UNSAFE');throw e;}
  finally{if(child){child.stdin?.end('\n');await new Promise(ok=>{if(child.exitCode!==null||child.signalCode!==null)return ok();child.once('close',ok);setTimeout(()=>{child.kill('SIGKILL');ok();},1000).unref();});}if(h)await h.close();}
 }
 async function readSafe(path,max=16384,allowedLinks=1){let h;try{
  h=await open(path,F.O_RDONLY|F.O_NOFOLLOW|F.O_NONBLOCK);const [s,ps]=await Promise.all([h.stat(),lstat(path)]);
  if(!s.isFile()||s.nlink!==allowedLinks||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==ps.ino||s.dev!==ps.dev||s.size<2||s.size>max)fail('MULTI_EPOCH_FILE_UNSAFE');
  const bytes=await h.readFile(),after=await h.stat(),p2=await lstat(path);
  if(bytes.length!==s.size||after.size!==s.size||after.mtimeMs!==s.mtimeMs||after.ctimeMs!==s.ctimeMs||p2.ino!==s.ino||p2.dev!==s.dev)fail('MULTI_EPOCH_FILE_CHANGED');
  const raw=bytes.toString('utf8');if(!Buffer.from(raw).equals(bytes))fail('MULTI_EPOCH_HISTORY_INVALID');
  let data;try{data=JSON.parse(raw);}catch{fail('MULTI_EPOCH_HISTORY_INVALID');}
  if(JSON.stringify(data)!==raw)fail('MULTI_EPOCH_HISTORY_INVALID');return data;
 }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('MULTI_EPOCH_FILE_UNSAFE');throw e;}finally{if(h)await h.close();}}
 async function syncDir(){const h=await open(dir,'r');try{await h.sync();}finally{await h.close();}}
 function checkHead(h){if(!head(h))fail('MULTI_EPOCH_EXTERNAL_HEAD_REQUIRED');}
 function checkPins({expectedHead,expectedTransitionDigest,expectedEpoch,nowMs}){
  checkHead(expectedHead);
  if(!HEX.test(expectedTransitionDigest||'')||!Number.isSafeInteger(expectedEpoch)||expectedEpoch<1||expectedEpoch>=policies.length||
   !Number.isSafeInteger(nowMs)||nowMs<0)fail('MULTI_EPOCH_EXTERNAL_PINS_REQUIRED');
 }
 function checkTransition(t,epoch,anchor,nowMs,historical=false){
  if(!exact(t,['body','outgoingSignatures','incomingProofs']))fail('MULTI_EPOCH_CERTIFICATE_INVALID');
  const b=t.body,bytes=offlineExportWitnessTransitionSigningBytes(b);
  if(b.registryId!==registryId||b.fromEpoch!==epoch-1||b.toEpoch!==epoch||b.fromPolicyDigest!==digests[epoch-1]||
   b.toPolicyDigest!==digests[epoch]||!same(b.anchorHead,anchor)||anchor.count<1||b.issuedAt>nowMs||(!historical&&nowMs>=b.expiresAt))fail('MULTI_EPOCH_TRANSITION_INVALID');
  signatures(t.outgoingSignatures,trustedPolicies[epoch-1],trustedPolicies[epoch-1].quorum,()=>bytes);
  if(t.incomingProofs?.length!==policies[epoch].witnesses.length)fail('MULTI_EPOCH_PROOF_INVALID');
  signatures(t.incomingProofs,trustedPolicies[epoch],trustedPolicies[epoch].witnesses.length,id=>offlineExportWitnessTransitionPossessionBytes(b,id));
 }
 async function state({expectedHead,expectedTransitionDigest,expectedEpoch,nowMs,allowPending=null,linkedPath=null}={}){
  checkPins({expectedHead,expectedTransitionDigest,expectedEpoch,nowMs});
  const names=await readdir(dir);
  for(const p of ['.pending.json','.pending-cutover.json','.pending-multi-cutover.json'])if(names.includes(p)&&p!==allowPending)fail('MULTI_EPOCH_UNCERTAIN_COMMIT');
  const permitted=new Set(['.export-registry-lock']);if(allowPending)permitted.add(allowPending);
  const transitions=[];let previousCount=0,previousTime=-1;
  for(let epoch=1;epoch<=expectedEpoch;epoch++){
   const path=join(dir,certName(epoch));if(!names.includes(certName(epoch)))fail('MULTI_EPOCH_MISSING_TRANSITION');
   permitted.add(certName(epoch));const c=await readSafe(path,16384,linkedPath===path?2:1);
   if(!exact(c,['schema','registryId','transition','transitionDigest'])||c.schema!==(epoch===1?LEGACY_SCHEMA:OFFLINE_MULTI_EPOCH_CUTOVER_SCHEMA)||c.registryId!==registryId)fail('MULTI_EPOCH_CERTIFICATE_INVALID');
   const b=c.transition?.body;
   if(!b||b.anchorHead.count<=previousCount||b.issuedAt<=previousTime)fail('MULTI_EPOCH_TRANSITION_ORDER');
   checkTransition(c.transition,epoch,b.anchorHead,nowMs,true);
   transitions.push(c.transition);
   if(c.transitionDigest!==offlineExportWitnessTransitionChainDigest({transitions}))fail('MULTI_EPOCH_CERTIFICATE_CHAIN_INVALID');
   previousCount=b.anchorHead.count;previousTime=b.issuedAt;
  }
  if(names.some(n=>/^\.witness-cutover(?:-\d{4})?\.json$/.test(n)&&!permitted.has(n)))fail('MULTI_EPOCH_UNPINNED_TRANSITION');
  const chainDigest=offlineExportWitnessTransitionChainDigest({transitions});
  if(chainDigest!==expectedTransitionDigest)fail('MULTI_EPOCH_TRANSITION_PIN_MISMATCH');
  const files=names.filter(n=>!permitted.has(n));
  if(files.length>2000||files.some(n=>!/^[0-9]{4}\.json$/.test(n)))fail('MULTI_EPOCH_HISTORY_INVALID');
  let previous=ROOT,previousReceiptTime=-1,epoch=0;
  const entries=[],exports=new Set(),acquisitions=new Set(),archiveDigests=new Set(),nonces=new Set();
  for(let i=1;i<=files.length;i++){
   if(!names.includes(fname(i)))fail('MULTI_EPOCH_HISTORY_INVALID');
   const path=join(dir,fname(i)),e=await readSafe(path,16384,linkedPath===path?2:1);
   if(!exact(e,['schema','index','previousDigest','receipt','digest'])||e.schema!==OFFLINE_EXPORT_REGISTRY_SCHEMA||e.index!==i||e.previousDigest!==previous||!HEX.test(e.digest||''))fail('MULTI_EPOCH_HISTORY_INVALID');
   while(epoch<transitions.length&&i>transitions[epoch].body.anchorHead.count){
    if(previous!==transitions[epoch].body.anchorHead.headDigest)fail('MULTI_EPOCH_ANCHOR_MISMATCH');epoch++;
   }
   const b=verifyHistoricalOfflineExportReceipt({receipt:e.receipt,...trustedPolicies[epoch],registryId}).body;
   const earliest=epoch?transitions[epoch-1].body.issuedAt:0,latest=transitions[epoch]?.body.issuedAt??Infinity;
   if(b.sequence!==i||b.previousDigest!==previous||b.issuedAt<previousReceiptTime||b.issuedAt<earliest||b.issuedAt>latest||b.issuedAt>nowMs)fail('MULTI_EPOCH_RECEIPT_EPOCH_INVALID');
   if(exports.has(b.exportId)||acquisitions.has(b.acquisitionId)||archiveDigests.has(b.archiveDigest)||nonces.has(b.nonce))fail('MULTI_EPOCH_REPLAY');
   const {digest,...record}=e;if(recHash(record)!==digest)fail('MULTI_EPOCH_HISTORY_INVALID');
   exports.add(b.exportId);acquisitions.add(b.acquisitionId);archiveDigests.add(b.archiveDigest);nonces.add(b.nonce);
   entries.push(e);previous=e.digest;previousReceiptTime=b.issuedAt;
   if(epoch<transitions.length&&i===transitions[epoch].body.anchorHead.count&&previous!==transitions[epoch].body.anchorHead.headDigest)fail('MULTI_EPOCH_ANCHOR_MISMATCH');
  }
  if(files.length<transitions.at(-1).body.anchorHead.count)fail('MULTI_EPOCH_ANCHOR_MISMATCH');
  const currentHead={count:entries.length,headDigest:previous};if(!same(currentHead,expectedHead))fail('MULTI_EPOCH_STALE_HEAD');
  return {head:currentHead,entries,transitions,chainDigest,exports,acquisitions,archiveDigests,nonces,previousReceiptTime};
 }
 async function inspect(args={}){return withLock(async()=>result(await state(args),'PINNED_MULTI_EPOCH_HISTORY_OFFLINE_ONLY'));}
 async function rotate({transition,expectedHead,expectedTransitionDigest,expectedEpoch,expectedNewTransitionDigest,nowMs}={}){
  checkPins({expectedHead,expectedTransitionDigest,expectedEpoch,nowMs});
  if(expectedEpoch>=policies.length-1||!HEX.test(expectedNewTransitionDigest||''))fail('MULTI_EPOCH_EXTERNAL_PINS_REQUIRED');
  return withLock(async check=>{
   const s=await state({expectedHead,expectedTransitionDigest,expectedEpoch,nowMs});
   const epoch=expectedEpoch+1;checkTransition(transition,epoch,expectedHead,nowMs);
   if(transition.body.anchorHead.count<=s.transitions.at(-1).body.anchorHead.count||transition.body.issuedAt<=s.transitions.at(-1).body.issuedAt||
    transition.body.issuedAt<s.previousReceiptTime||s.transitions.some(t=>t.body.nonce===transition.body.nonce))fail('MULTI_EPOCH_TRANSITION_ORDER');
   const chainDigest=offlineExportWitnessTransitionChainDigest({transitions:[...s.transitions,transition]});
   if(chainDigest!==expectedNewTransitionDigest)fail('MULTI_EPOCH_NEW_CHAIN_PIN_MISMATCH');
   const record={schema:OFFLINE_MULTI_EPOCH_CUTOVER_SCHEMA,registryId,transition,transitionDigest:chainDigest};
   const bytes=Buffer.from(JSON.stringify(record));if(bytes.length>16384)fail('MULTI_EPOCH_RECORD_TOO_LARGE');
   await check();let h;
   try{h=await open(pending,F.O_WRONLY|F.O_CREAT|F.O_EXCL|F.O_NOFOLLOW,0o600);await h.writeFile(bytes);await h.sync();}
   catch(e){if(['EEXIST','ELOOP'].includes(e.code))fail('MULTI_EPOCH_UNCERTAIN_COMMIT');throw e;}finally{if(h)await h.close();}
   await syncDir();if(injectFault)await injectFault('after-multi-pending-sync');await check();
   try{await link(pending,join(dir,certName(epoch)));}catch(e){if(e.code==='EEXIST')fail('MULTI_EPOCH_UNCERTAIN_COMMIT');throw e;}
   await syncDir();if(injectFault)await injectFault('after-multi-link-sync');await unlink(pending);await syncDir();
   if(injectFault)await injectFault('after-multi-commit-sync');
   return result(await state({expectedHead,expectedTransitionDigest:chainDigest,expectedEpoch:epoch,nowMs}),'PINNED_MULTI_EPOCH_CUTOVER_OFFLINE_ONLY');
  });
 }
 async function append({receipt,archiveBytes,expectedHead,expectedTransitionDigest,expectedEpoch,nowMs}={}){
  checkPins({expectedHead,expectedTransitionDigest,expectedEpoch,nowMs});
  return withLock(async check=>{
   const s=await state({expectedHead,expectedTransitionDigest,expectedEpoch,nowMs});
   const verified=verifyOfflineExportReceipt({receipt,...trustedPolicies[expectedEpoch],registryId,nowMs}),b=receipt.body;
   if(b.sequence!==s.head.count+1||b.previousDigest!==s.head.headDigest||b.issuedAt<s.previousReceiptTime||b.issuedAt<s.transitions.at(-1).body.issuedAt)fail('MULTI_EPOCH_RECEIPT_EPOCH_INVALID');
   if(s.exports.has(b.exportId)||s.acquisitions.has(b.acquisitionId)||s.archiveDigests.has(b.archiveDigest)||s.nonces.has(b.nonce))fail('MULTI_EPOCH_REPLAY');
   if(!Buffer.isBuffer(archiveBytes)||archiveBytes.length!==verified.archiveBytes)fail('MULTI_EPOCH_ARCHIVE_SIZE_MISMATCH');
   verifyOfflineAcquisitionEvidenceExport({bytes:archiveBytes,expectedDigest:b.archiveDigest,expectedAcquisitionId:b.acquisitionId});
   const record={schema:OFFLINE_EXPORT_REGISTRY_SCHEMA,index:b.sequence,previousDigest:s.head.headDigest,receipt};const e={...record,digest:recHash(record)};
   const bytes=Buffer.from(JSON.stringify(e));if(bytes.length>16384)fail('MULTI_EPOCH_RECORD_TOO_LARGE');
   await check();let h;
   try{h=await open(appendPending,F.O_WRONLY|F.O_CREAT|F.O_EXCL|F.O_NOFOLLOW,0o600);await h.writeFile(bytes);await h.sync();}
   catch(e){if(['EEXIST','ELOOP'].includes(e.code))fail('MULTI_EPOCH_UNCERTAIN_COMMIT');throw e;}finally{if(h)await h.close();}
   await syncDir();if(injectFault)await injectFault('after-multi-append-pending-sync');await check();
   try{await link(appendPending,join(dir,fname(e.index)));}catch(e){if(e.code==='EEXIST')fail('MULTI_EPOCH_UNCERTAIN_COMMIT');throw e;}
   await syncDir();if(injectFault)await injectFault('after-multi-append-link-sync');await unlink(appendPending);await syncDir();
   if(injectFault)await injectFault('after-multi-append-commit-sync');
   return result(await state({expectedHead:{count:e.index,headDigest:e.digest},expectedTransitionDigest,expectedEpoch,nowMs}),'PINNED_MULTI_EPOCH_APPEND_OFFLINE_ONLY');
  });
 }
 /**
  * Objective 31Y: externally supervised reconciliation of ONE uncertain durable
  * multi-epoch cutover or receipt append. Both the before and after pins must
  * come from an independent supervisor; local files never authorize recovery.
  * Only the pending hardlink is removed, never a committed record.
  */
 async function reconcilePending({kind,decision,expectedBeforeHead,expectedAfterHead,
   expectedBeforeTransitionDigest,expectedAfterTransitionDigest,expectedBeforeEpoch,
   expectedAfterEpoch,expectedPendingDigest,nowMs}={}){
  if(!['cutover','append'].includes(kind)||!['abort-unlinked','finalize-linked'].includes(decision)||
   !head(expectedBeforeHead)||!head(expectedAfterHead)||
   !HEX.test(expectedBeforeTransitionDigest||'')||!HEX.test(expectedAfterTransitionDigest||'')||
   !HEX.test(expectedPendingDigest||'')||!Number.isSafeInteger(expectedBeforeEpoch)||
   expectedBeforeEpoch<1||expectedBeforeEpoch>=policies.length||
   !Number.isSafeInteger(expectedAfterEpoch)||expectedAfterEpoch<1||expectedAfterEpoch>=policies.length||
   !Number.isSafeInteger(nowMs)||nowMs<0||
   expectedAfterEpoch!==expectedBeforeEpoch+(kind==='cutover'?1:0)||
   (kind==='append'&&expectedAfterTransitionDigest!==expectedBeforeTransitionDigest)||
   (kind==='cutover'&&!same(expectedBeforeHead,expectedAfterHead))||
   (kind==='append'&&expectedAfterHead.count!==expectedBeforeHead.count+1))
   fail('MULTI_EPOCH_RECOVERY_EXTERNAL_PINS_REQUIRED');
  return withLock(async check=>{
   const marker=kind==='cutover'?'.pending-multi-cutover.json':'.pending.json';
   const pendingPath=join(dir,marker),names=await readdir(dir);
   if(!names.includes(marker)||names.includes(kind==='cutover'?'.pending.json':'.pending-multi-cutover.json')||
     names.includes('.pending-cutover.json'))fail('MULTI_EPOCH_RECOVERY_MARKER_MISMATCH');
   const linked=decision==='finalize-linked';
   // The destination is determined solely from externally pinned epoch/index.
   // Check its presence before reading the pending file with a strict link
   // count, so a missing or already-linked destination fails explicitly.
   const pinnedDestinationName=kind==='cutover'?certName(expectedAfterEpoch):fname(expectedAfterHead.count);
   if(linked&&!names.includes(pinnedDestinationName))fail('MULTI_EPOCH_RECOVERY_LINK_MISSING');
   if(!linked&&names.includes(pinnedDestinationName))fail('MULTI_EPOCH_RECOVERY_LINK_EXISTS');
   const data=await readSafe(pendingPath,16384,linked?2:1);
   const pendingStat=await lstat(pendingPath);
   if(sha(Buffer.from(JSON.stringify(data)))!==expectedPendingDigest)fail('MULTI_EPOCH_RECOVERY_PENDING_PIN_MISMATCH');
   let destination;
   if(kind==='cutover'){
    const epoch=expectedAfterEpoch;
    if(!exact(data,['schema','registryId','transition','transitionDigest'])||
     data.schema!==OFFLINE_MULTI_EPOCH_CUTOVER_SCHEMA||data.registryId!==registryId||
     data.transitionDigest!==expectedAfterTransitionDigest||
     !same(data.transition?.body?.anchorHead,expectedBeforeHead))fail('MULTI_EPOCH_RECOVERY_RECORD_INVALID');
    checkTransition(data.transition,epoch,expectedBeforeHead,nowMs,true);
    destination=join(dir,certName(epoch));
   }else{
    if(!exact(data,['schema','index','previousDigest','receipt','digest'])||
     data.schema!==OFFLINE_EXPORT_REGISTRY_SCHEMA||data.index!==expectedAfterHead.count||
     data.previousDigest!==expectedBeforeHead.headDigest||data.digest!==expectedAfterHead.headDigest||
     !HEX.test(data.digest||''))fail('MULTI_EPOCH_RECOVERY_RECORD_INVALID');
    const {digest,...record}=data;
    if(recHash(record)!==digest)fail('MULTI_EPOCH_RECOVERY_RECORD_INVALID');
    const b=verifyHistoricalOfflineExportReceipt({receipt:data.receipt,...trustedPolicies[expectedBeforeEpoch],registryId}).body;
    if(b.sequence!==data.index||b.previousDigest!==data.previousDigest||b.issuedAt>nowMs)
     fail('MULTI_EPOCH_RECOVERY_RECORD_INVALID');
    destination=join(dir,fname(data.index));
   }
   const destinationName=kind==='cutover'?certName(expectedAfterEpoch):fname(data.index);
   if(linked){
    if(!names.includes(destinationName))fail('MULTI_EPOCH_RECOVERY_LINK_MISSING');
    const [a,b]=await Promise.all([lstat(pendingPath),lstat(destination)]);
    if(!a.isFile()||!b.isFile()||a.isSymbolicLink()||b.isSymbolicLink()||
     a.nlink!==2||b.nlink!==2||a.ino!==b.ino||a.dev!==b.dev||
     a.uid!==process.getuid()||(a.mode&0o077)!==0)
     fail('MULTI_EPOCH_RECOVERY_LINK_UNSAFE');
   }else if(names.includes(destinationName))fail('MULTI_EPOCH_RECOVERY_LINK_EXISTS');
   const pinnedHead=linked?expectedAfterHead:expectedBeforeHead;
   const pinnedEpoch=linked?expectedAfterEpoch:expectedBeforeEpoch;
   const pinnedChain=linked?expectedAfterTransitionDigest:expectedBeforeTransitionDigest;
   const s=await state({expectedHead:pinnedHead,expectedTransitionDigest:pinnedChain,
     expectedEpoch:pinnedEpoch,nowMs,allowPending:marker,linkedPath:linked?destination:null});
   if(kind==='cutover'){
    const beforeTransitions=linked?s.transitions.slice(0,-1):s.transitions;
    if(beforeTransitions.length!==expectedBeforeEpoch||
      offlineExportWitnessTransitionChainDigest({transitions:beforeTransitions})!==expectedBeforeTransitionDigest||
      offlineExportWitnessTransitionChainDigest({transitions:[...beforeTransitions,data.transition]})!==expectedAfterTransitionDigest||
      beforeTransitions.some(t=>t.body.nonce===data.transition.body.nonce)||
      data.transition.body.anchorHead.count<=beforeTransitions.at(-1).body.anchorHead.count||
      data.transition.body.issuedAt<=beforeTransitions.at(-1).body.issuedAt||
      data.transition.body.issuedAt<s.previousReceiptTime||
      (linked&&!same(s.transitions.at(-1),data.transition)))
      fail('MULTI_EPOCH_RECOVERY_STALE_PIN');
   }else{
    const beforeEntry=linked?s.entries.at(-2):s.entries.at(-1);
    const beforeDigest=beforeEntry?.digest??ROOT;
    if(beforeDigest!==expectedBeforeHead.headDigest||
      data.receipt.body.issuedAt<(beforeEntry?.receipt.body.issuedAt??0)||
      data.receipt.body.issuedAt<s.transitions.at(-1).body.issuedAt||
      (linked&&!same(s.entries.at(-1),data))||
      (!linked&&(s.exports.has(data.receipt.body.exportId)||s.acquisitions.has(data.receipt.body.acquisitionId)||
        s.archiveDigests.has(data.receipt.body.archiveDigest)||s.nonces.has(data.receipt.body.nonce))))
      fail('MULTI_EPOCH_RECOVERY_STALE_PIN');
   }
   await check();
   if(injectFault)await injectFault('before-multi-recovery-unlink');
   const finalPending=await lstat(pendingPath);
   if(finalPending.dev!==pendingStat.dev||finalPending.ino!==pendingStat.ino||
     finalPending.size!==pendingStat.size||finalPending.mtimeMs!==pendingStat.mtimeMs||
     finalPending.ctimeMs!==pendingStat.ctimeMs||finalPending.nlink!==(linked?2:1))
     fail('MULTI_EPOCH_RECOVERY_MARKER_CHANGED');
   if(linked){
    const finalDestination=await lstat(destination);
    if(finalDestination.dev!==finalPending.dev||finalDestination.ino!==finalPending.ino||
      finalDestination.nlink!==2)fail('MULTI_EPOCH_RECOVERY_LINK_UNSAFE');
   }
   // Removing the marker is safe only after the signed history, external pins,
   // and (for finalize) the exact same-inode hardlink have all been verified.
   await unlink(pendingPath);await syncDir();
   if(injectFault)await injectFault('after-multi-recovery-marker-sync');
   const after=await state({expectedHead:pinnedHead,expectedTransitionDigest:pinnedChain,
     expectedEpoch:pinnedEpoch,nowMs});
   return result(after,linked?'EXTERNALLY_PINNED_MULTI_FINALIZATION_OFFLINE_ONLY':'EXTERNALLY_PINNED_MULTI_ABORT_OFFLINE_ONLY');
  });
 }

 return Object.freeze({inspect,rotate,append,reconcilePending,registryId,genesisPolicyDigest:digests[0],configuredPolicyDigests:Object.freeze([...digests])});
}
