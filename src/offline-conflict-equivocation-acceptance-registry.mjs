/** Objective 33G — opt-in single-Linux-host durable acceptance of verified 33F
 * signed fork evidence. No global consensus, independent anchor, trusted clock,
 * automated resolution, hosted authentication, Shopify IO, or production grant.
 * Interrupted commits deliberately remain blocked pending independent adjudication.
 */
import {createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
import {constants as F} from 'node:fs';
import {mkdir,open,lstat,realpath,readdir,link,unlink} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {resolve,join} from 'node:path';
import {verifyOfflineConflictAuthorityEquivocationEnvelope} from './offline-conflict-authority-equivocation-envelope.mjs';

export const OFFLINE_CONFLICT_EQUIVOCATION_ACCEPTANCE_SCHEMA='TJ-OFFLINE-CONFLICT-EQUIVOCATION-ACCEPTANCE-1';
const HEX=/^[0-9a-f]{64}$/,ID=/^[A-Za-z0-9_-]{8,64}$/;
const MAX_RECORDS=4096,MAX_BYTES=2048;
export const OFFLINE_CONFLICT_EQUIVOCATION_PENDING_DECISION_SCHEMA='TJ-OFFLINE-CONFLICT-EQUIVOCATION-PENDING-DECISION-1';
const FIELDS=['schema','index','previousRecordDigest','previousEnvelopeDigest','envelopeDigest',
 'nonce','namespaceId','journalScopeDigest','observerIds','attestationDigests','chainHeads',
 'forkIndex','recordDigest'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hash=(domain,bytes)=>createHash('sha256').update(domain+'\0').update(bytes).digest('hex');
const exact=(x,fields)=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(x))&&Reflect.ownKeys(x).length===fields.length&&
 fields.every(k=>{const d=Object.getOwnPropertyDescriptor(x,k);return d&&'value' in d&&d.enumerable;})&&
 Object.keys(x).every(k=>fields.includes(k));
const sha=b=>createHash('sha256').update(b).digest('hex');
const b64=x=>typeof x==='string'&&/^[A-Za-z0-9_-]+$/.test(x)&&Buffer.from(x,'base64url').toString('base64url')===x;
const reviewerFields=['reviewerId','publicKey'];
const groupValid=g=>Array.isArray(g)&&g.length===3&&Object.getPrototypeOf(g)===Array.prototype&&
 Reflect.ownKeys(g).length===4&&g.every((x,i)=>exact(x,reviewerFields)&&ID.test(x.reviewerId)&&b64(x.publicKey)&&
 Buffer.from(x.publicKey,'base64url').length>=40&&(i===0||g[i-1].reviewerId<x.reviewerId))&&
 new Set(g.map(x=>x.publicKey)).size===3;
export function offlineConflictEquivocationPendingReviewerGroupDigest(group){
 if(!groupValid(group))fail('EXCHANGE33H_REVIEWER_GROUP_INVALID');
 return hash('TJ-33H-REVIEWER-GROUP',Buffer.from(JSON.stringify(group)));
}
const DECISION_FIELDS=['schema','action','namespaceId','journalScopeDigest','expectedPreHead',
 'pendingBytesDigest','pendingRecordDigest','pendingIndex','expectedPendingState',
 'reviewerGroupADigest','reviewerGroupBDigest','issuedAt','expiresAt','nonce'];
export function offlineConflictEquivocationPendingDecisionBytes(body){
 if(!exact(body,DECISION_FIELDS)||body.schema!==OFFLINE_CONFLICT_EQUIVOCATION_PENDING_DECISION_SCHEMA||
 body.action!=='inspect-only'||!ID.test(body.namespaceId)||!HEX.test(body.journalScopeDigest)||
 !validHead(body.expectedPreHead)||!HEX.test(body.pendingBytesDigest)||!HEX.test(body.pendingRecordDigest)||
 !Number.isSafeInteger(body.pendingIndex)||body.pendingIndex!==body.expectedPreHead.count+1||
 !['pending-only','pending-linked'].includes(body.expectedPendingState)||
 !HEX.test(body.reviewerGroupADigest)||!HEX.test(body.reviewerGroupBDigest)||
 body.reviewerGroupADigest===body.reviewerGroupBDigest||
 !Number.isSafeInteger(body.issuedAt)||!Number.isSafeInteger(body.expiresAt)||
 body.expiresAt<=body.issuedAt||body.expiresAt-body.issuedAt>600000||!ID.test(body.nonce))
 fail('EXCHANGE33H_DECISION_INVALID');
 return Buffer.from('TJ-33H-PENDING-DECISION\0'+JSON.stringify(body));
}
export function offlineConflictEquivocationPendingDecisionDigest(decision){
 if(!exact(decision,['body','groupASignatures','groupBSignatures']))fail('EXCHANGE33H_DECISION_INVALID');
 offlineConflictEquivocationPendingDecisionBytes(decision.body);
 return hash('TJ-33H-SIGNED-DECISION',Buffer.from(JSON.stringify(decision)));
}
const validHead=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=MAX_RECORDS&&HEX.test(h.headDigest);
const filename=n=>String(n).padStart(4,'0')+'.json';
const recordHash=x=>hash('TJ-33G-RECORD',Buffer.from(JSON.stringify(x)));
const pair=x=>Array.isArray(x)&&Object.getPrototypeOf(x)===Array.prototype&&x.length===2&&
 Reflect.ownKeys(x).length===3&&x.every(y=>typeof y==='string'&&HEX.test(y));
const ids=x=>Array.isArray(x)&&Object.getPrototypeOf(x)===Array.prototype&&x.length===2&&
 Reflect.ownKeys(x).length===3&&x.every(y=>typeof y==='string'&&ID.test(y))&&x[0]<x[1];
export function offlineConflictEquivocationAcceptanceGenesisHead(namespaceId,journalScopeDigest){
 if(typeof namespaceId!=='string'||!ID.test(namespaceId)||typeof journalScopeDigest!=='string'||!HEX.test(journalScopeDigest))
  fail('EXCHANGE33G_NAMESPACE_INVALID');
 return Object.freeze({count:0,headDigest:hash('TJ-33G-GENESIS',Buffer.from(JSON.stringify({
  schema:OFFLINE_CONFLICT_EQUIVOCATION_ACCEPTANCE_SCHEMA,namespaceId,journalScopeDigest})))});
}
export function verifyOfflineConflictEquivocationPendingDecisionApproval({decision,reviewerGroupA,reviewerGroupB,expectedReviewerGroupADigest,
  expectedReviewerGroupBDigest,expectedDecisionDigest,nowMs,expectedNamespaceId,expectedJournalScopeDigest}){
  if(!exact(decision,['body','groupASignatures','groupBSignatures'])||
   !groupValid(reviewerGroupA)||!groupValid(reviewerGroupB)||
   !HEX.test(expectedReviewerGroupADigest)||!HEX.test(expectedReviewerGroupBDigest)||
   !HEX.test(expectedDecisionDigest)||!Number.isSafeInteger(nowMs))fail('EXCHANGE33H_EXTERNAL_PINS_REQUIRED');
  const bytes=offlineConflictEquivocationPendingDecisionBytes(decision.body);
  if(offlineConflictEquivocationPendingReviewerGroupDigest(reviewerGroupA)!==expectedReviewerGroupADigest||
   offlineConflictEquivocationPendingReviewerGroupDigest(reviewerGroupB)!==expectedReviewerGroupBDigest||
   decision.body.reviewerGroupADigest!==expectedReviewerGroupADigest||
   decision.body.reviewerGroupBDigest!==expectedReviewerGroupBDigest||
   offlineConflictEquivocationPendingDecisionDigest(decision)!==expectedDecisionDigest)
   fail('EXCHANGE33H_EXTERNAL_PINS_MISMATCH');
  if(nowMs<decision.body.issuedAt||nowMs>decision.body.expiresAt)fail('EXCHANGE33H_DECISION_EXPIRED');
  if(decision.body.namespaceId!==expectedNamespaceId||decision.body.journalScopeDigest!==expectedJournalScopeDigest)
   fail('EXCHANGE33H_SCOPE_MISMATCH');
  const all=[...reviewerGroupA,...reviewerGroupB];
  if(new Set(all.map(x=>x.publicKey)).size!==6||new Set(all.map(x=>x.reviewerId)).size!==6)
   fail('EXCHANGE33H_REVIEWER_OVERLAP');
  for(const [group,sigs] of [[reviewerGroupA,decision.groupASignatures],[reviewerGroupB,decision.groupBSignatures]]){
   if(!Array.isArray(sigs)||sigs.length<2||sigs.length>3||Object.getPrototypeOf(sigs)!==Array.prototype||
    Reflect.ownKeys(sigs).length!==sigs.length+1)fail('EXCHANGE33H_SIGNATURES_INVALID');
   for(let i=0;i<sigs.length;i++){
    const sig=sigs[i];
    if(!exact(sig,['reviewerId','signature'])||!b64(sig.signature)||
     Buffer.from(sig.signature,'base64url').length!==64||
     (i>0&&sigs[i-1].reviewerId>=sig.reviewerId))fail('EXCHANGE33H_SIGNATURES_INVALID');
    const reviewer=group.find(x=>x.reviewerId===sig.reviewerId);
    if(!reviewer)fail('EXCHANGE33H_SIGNATURES_INVALID');
    let ok=false;
    try{const key=createPublicKey({key:Buffer.from(reviewer.publicKey,'base64url'),format:'der',type:'spki'});
     ok=key.asymmetricKeyType==='ed25519'&&verifySignature(null,bytes,key,Buffer.from(sig.signature,'base64url'));
    }catch{}
    if(!ok)fail('EXCHANGE33H_SIGNATURES_INVALID');
   }
  }
  return decision.body;
 }

export function createOfflineConflictEquivocationAcceptanceRegistry({directory,namespaceId,journalScopeDigest,
 lockTimeoutMs=3000,injectFault}={}){
 const genesis=offlineConflictEquivocationAcceptanceGenesisHead(namespaceId,journalScopeDigest);
 if(process.platform!=='linux'||!F.O_NOFOLLOW||typeof directory!=='string'||!directory.trim()||
 !Number.isSafeInteger(lockTimeoutMs)||lockTimeoutMs<0||lockTimeoutMs>10000||
 (injectFault!==undefined&&typeof injectFault!=='function'))fail('EXCHANGE33G_CONFIGURATION');
 const dir=resolve(directory),lockPath=join(dir,'.acceptance-lock'),pending=join(dir,'.pending.json');
 async function safeDir(create=true){
  if(create)await mkdir(dir,{recursive:true,mode:0o700});
  const [s,r]=await Promise.all([lstat(dir),realpath(dir)]);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0||r!==dir)
   fail('EXCHANGE33G_DIRECTORY_UNSAFE');
  return s;
 }
 async function withLock(fn,{readOnly=false}={}){
  const ds=await safeDir(!readOnly);let h;
  try{
   h=await open(lockPath,(readOnly?F.O_RDONLY:F.O_RDWR|F.O_CREAT)|F.O_NOFOLLOW,0o600);
   const [s,p]=await Promise.all([h.stat(),lstat(lockPath)]);
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.ino!==p.ino||s.dev!==p.dev)
    fail('EXCHANGE33G_LOCK_UNSAFE');
   await new Promise((ok,no)=>{
    const c=spawn('/usr/bin/flock',['-x','-w',(lockTimeoutMs/1000).toFixed(3),'3'],
     {stdio:['ignore','ignore','ignore',h.fd]});
    c.once('error',()=>no(Object.assign(new Error('EXCHANGE33G_LOCK_UNAVAILABLE'),{code:'EXCHANGE33G_LOCK_UNAVAILABLE'})));
    c.once('close',code=>code===0?ok():no(Object.assign(new Error('EXCHANGE33G_LOCK_UNAVAILABLE'),{code:'EXCHANGE33G_LOCK_UNAVAILABLE'})));
   });
   const check=async()=>{
    const [a,b]=await Promise.all([lstat(dir),lstat(lockPath)]);
    if(!a.isDirectory()||a.isSymbolicLink()||a.ino!==ds.ino||a.dev!==ds.dev||
     !b.isFile()||b.nlink!==1||b.ino!==s.ino||b.dev!==s.dev)fail('EXCHANGE33G_LOCK_UNSAFE');
   };
   await check();return await fn(check);
  }finally{if(h)await h.close();}
 }
 async function readSafe(path,allowLinked=false){
  let h;try{
   h=await open(path,F.O_RDONLY|F.O_NOFOLLOW);
   const [s,p]=await Promise.all([h.stat(),lstat(path)]);
   if(!s.isFile()||(!allowLinked&&s.nlink!==1)||(allowLinked&&![1,2].includes(s.nlink))||s.uid!==process.getuid()||(s.mode&0o077)!==0||
    s.ino!==p.ino||s.dev!==p.dev||s.size<2||s.size>MAX_BYTES)fail('EXCHANGE33G_RECORD_UNSAFE');
   return await h.readFile();
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e?.code))fail('EXCHANGE33G_RECORD_UNSAFE');throw e;}
  finally{if(h)await h.close();}
 }
 async function state({allowPending=false,linkedIndex=-1}={}){
  const names=await readdir(dir);
  if(!allowPending&&names.includes('.pending.json'))fail('EXCHANGE33G_UNCERTAIN_COMMIT');
  const files=names.filter(n=>n!=='.acceptance-lock'&&(!allowPending||n!=='.pending.json'));
  if(files.length>MAX_RECORDS||files.some(n=>!/^[0-9]{4}\.json$/.test(n)))fail('EXCHANGE33G_HISTORY_INVALID');
  let head=genesis.headDigest,lastEnvelopeDigest=genesis.headDigest;
  const digests=new Set(),nonces=new Set();
  for(let i=1;i<=files.length;i++){
   if(!names.includes(filename(i)))fail('EXCHANGE33G_HISTORY_INVALID');
   const bytes=await readSafe(join(dir,filename(i)),allowPending&&names.includes('.pending.json')&&i===linkedIndex);let e;
   try{e=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
   catch{fail('EXCHANGE33G_HISTORY_INVALID');}
   if(!exact(e,FIELDS)||!Buffer.from(JSON.stringify(e)).equals(bytes)||
    e.schema!==OFFLINE_CONFLICT_EQUIVOCATION_ACCEPTANCE_SCHEMA||e.index!==i||
    e.previousRecordDigest!==head||e.previousEnvelopeDigest!==lastEnvelopeDigest||
    !HEX.test(e.envelopeDigest)||!ID.test(e.nonce)||e.namespaceId!==namespaceId||
    e.journalScopeDigest!==journalScopeDigest||!ids(e.observerIds)||!pair(e.attestationDigests)||
    !pair(e.chainHeads)||!Number.isSafeInteger(e.forkIndex)||e.forkIndex<0||e.forkIndex>=8||
    !HEX.test(e.recordDigest)||digests.has(e.envelopeDigest)||nonces.has(e.nonce))
    fail('EXCHANGE33G_HISTORY_INVALID');
   const {recordDigest,...body}=e;
   if(recordHash(body)!==recordDigest)fail('EXCHANGE33G_HISTORY_INVALID');
   head=recordDigest;lastEnvelopeDigest=e.envelopeDigest;
   digests.add(e.envelopeDigest);nonces.add(e.nonce);
  }
  return {head:{count:files.length,headDigest:head},lastEnvelopeDigest,digests,nonces};
 }
 async function syncDir(){const h=await open(dir,F.O_RDONLY|F.O_DIRECTORY|F.O_NOFOLLOW);
  try{await h.sync();}finally{await h.close();}}
 function pinned(s,expectedHead){
  if(!validHead(expectedHead))fail('EXCHANGE33G_EXTERNAL_HEAD_REQUIRED');
  if(s.head.count!==expectedHead.count||s.head.headDigest!==expectedHead.headDigest)
   fail('EXCHANGE33G_STALE_OR_ROLLED_BACK_HEAD');
 }
 const view=s=>Object.freeze({...s.head,lastEnvelopeDigest:s.lastEnvelopeDigest,
  singleHostDurableReplayProtection:true,independentlyAnchored:false,globallyComplete:false,
  trustedTimestamp:false,hostedAuthentication:false,authorizesRepair:false,
  authorizesCheckout:false,authorizesProduction:false});
 async function inspect({expectedHead}={}){
  return withLock(async()=>{const s=await state();pinned(s,expectedHead);return view(s);});
 }
 async function accept({verificationArgs,expectedHead}={}){
  if(!verificationArgs||typeof verificationArgs!=='object'||Array.isArray(verificationArgs)||!validHead(expectedHead))
   fail('EXCHANGE33G_REQUEST_INVALID');
  return withLock(async check=>{
   const s=await state();pinned(s,expectedHead);
   if(s.head.count>=MAX_RECORDS)fail('EXCHANGE33G_HISTORY_FULL');
   if(s.digests.has(verificationArgs.expectedDigest)||s.nonces.has(verificationArgs.expectedNonce))
    fail('EXCHANGE33G_REPLAY');
   if(verificationArgs.expectedPreviousEnvelopeDigest!==s.lastEnvelopeDigest)
    fail('EXCHANGE33G_PREDECESSOR_MISMATCH');
   if(verificationArgs.expectedNamespaceId!==namespaceId||verificationArgs.expectedJournalScopeDigest!==journalScopeDigest)
    fail('EXCHANGE33G_SCOPE_MISMATCH');
   // This re-verifies all signed 33F nested evidence while holding the process lock.
   // Local state, not a caller-provided replay list, decides replay admission.
   const v=verifyOfflineConflictAuthorityEquivocationEnvelope({...verificationArgs,seenEnvelopeDigests:[]});
   if(v.verified!==true||v.status!=='equivocation'||v.digest!==verificationArgs.expectedDigest)
    fail('EXCHANGE33G_ENVELOPE_UNVERIFIED');
   const body={schema:OFFLINE_CONFLICT_EQUIVOCATION_ACCEPTANCE_SCHEMA,index:s.head.count+1,
    previousRecordDigest:s.head.headDigest,previousEnvelopeDigest:s.lastEnvelopeDigest,
    envelopeDigest:v.digest,nonce:v.nonce,namespaceId,journalScopeDigest,
    observerIds:[...v.observerIds],attestationDigests:[...verificationArgs.expectedAttestationDigests],
    chainHeads:[...verificationArgs.expectedChainHeads],forkIndex:v.forkIndex};
   const e={...body,recordDigest:recordHash(body)},bytes=Buffer.from(JSON.stringify(e));
   if(bytes.length>MAX_BYTES)fail('EXCHANGE33G_RECORD_TOO_LARGE');
   await check();let h;
   try{h=await open(pending,F.O_WRONLY|F.O_CREAT|F.O_EXCL|F.O_NOFOLLOW,0o600);
    await h.writeFile(bytes);await h.sync();}
   catch(err){if(err?.code==='EEXIST')fail('EXCHANGE33G_UNCERTAIN_COMMIT');throw err;}
   finally{if(h)await h.close();}
   await syncDir();if(injectFault)await injectFault('after-pending-sync');
   await check();
   try{await link(pending,join(dir,filename(e.index)));}
   catch(err){if(err?.code==='EEXIST')fail('EXCHANGE33G_UNCERTAIN_COMMIT');throw err;}
   await syncDir();if(injectFault)await injectFault('after-link-sync');
   await unlink(pending);await syncDir();
   if(injectFault)await injectFault('after-commit-sync');
   const committed=await state();
   if(committed.head.count!==e.index||committed.head.headDigest!==e.recordDigest)
    fail('EXCHANGE33G_UNCERTAIN_COMMIT');
   return view(committed);
  });
 }
 async function adjudicatePendingReadOnly(args={}){
  if(!args||typeof args!=='object'||Array.isArray(args))fail('EXCHANGE33H_REQUEST_INVALID');
  const body=verifyOfflineConflictEquivocationPendingDecisionApproval({...args,expectedNamespaceId:namespaceId,expectedJournalScopeDigest:journalScopeDigest});
  if(!HEX.test(args.expectedPendingBytesDigest)||args.expectedPendingBytesDigest!==body.pendingBytesDigest||
   !validHead(args.expectedPreHead)||args.expectedPreHead.count!==body.expectedPreHead.count||
   args.expectedPreHead.headDigest!==body.expectedPreHead.headDigest)
   fail('EXCHANGE33H_EXTERNAL_PINS_MISMATCH');
  return withLock(async()=>{
   const names=await readdir(dir);
   if(!names.includes('.pending.json'))fail('EXCHANGE33H_PENDING_MISSING');
   const pendingBytes=await readSafe(pending,true);
   if(sha(pendingBytes)!==body.pendingBytesDigest)fail('EXCHANGE33H_PENDING_TAMPERED');
   let e;try{e=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(pendingBytes));}
   catch{fail('EXCHANGE33H_PENDING_TAMPERED');}
   if(!exact(e,FIELDS)||!Buffer.from(JSON.stringify(e)).equals(pendingBytes)||
    e.schema!==OFFLINE_CONFLICT_EQUIVOCATION_ACCEPTANCE_SCHEMA||
    e.index!==body.pendingIndex||e.previousRecordDigest!==body.expectedPreHead.headDigest||
    e.recordDigest!==body.pendingRecordDigest||e.namespaceId!==namespaceId||
    e.journalScopeDigest!==journalScopeDigest||!HEX.test(e.envelopeDigest)||!ID.test(e.nonce)||
    !ids(e.observerIds)||!pair(e.attestationDigests)||!pair(e.chainHeads)||
    !Number.isSafeInteger(e.forkIndex)||e.forkIndex<0||e.forkIndex>=8)
    fail('EXCHANGE33H_PENDING_TAMPERED');
   const {recordDigest,...rest}=e;
   if(recordHash(rest)!==recordDigest)fail('EXCHANGE33H_PENDING_TAMPERED');
   const s=await state({allowPending:true,linkedIndex:body.pendingIndex});
   const pendingStat=await lstat(pending);
   const linked=s.head.count===body.expectedPreHead.count+1;
   if(!linked&&pendingStat.nlink!==1)fail('EXCHANGE33H_LINK_MISMATCH');
   if(!linked&&(s.head.count!==body.expectedPreHead.count||
     s.head.headDigest!==body.expectedPreHead.headDigest||
     s.lastEnvelopeDigest!==e.previousEnvelopeDigest||s.digests.has(e.envelopeDigest)||s.nonces.has(e.nonce)))
    fail('EXCHANGE33H_HEAD_FORK_OR_ROLLBACK');
   if(linked){
    if(s.head.headDigest!==e.recordDigest||s.lastEnvelopeDigest!==e.envelopeDigest)
     fail('EXCHANGE33H_HEAD_FORK_OR_ROLLBACK');
    const recordPath=join(dir,filename(e.index));
    const [a,b,linkedBytes]=await Promise.all([lstat(pending),lstat(recordPath),readSafe(recordPath,true)]);
    if(a.ino!==b.ino||a.dev!==b.dev||a.nlink!==2||b.nlink!==2||
      !linkedBytes.equals(pendingBytes))fail('EXCHANGE33H_LINK_MISMATCH');
   }
   if(s.head.count!==body.expectedPreHead.count+(linked?1:0)||
    (linked?'pending-linked':'pending-only')!==body.expectedPendingState)
    fail('EXCHANGE33H_STATE_MISMATCH');
   return Object.freeze({status:body.expectedPendingState,verified:true,
    pendingBytesDigest:body.pendingBytesDigest,pendingRecordDigest:e.recordDigest,
    preHead:Object.freeze({...body.expectedPreHead}),observedHead:Object.freeze({...s.head}),
    decisionDigest:args.expectedDecisionDigest,authorizesRepair:false,authorizesRecovery:false,
    authorizesCheckout:false,authorizesProduction:false,globallyComplete:false,
    independentlyWitnessed:false,trustedTimestamp:false,mutatedAcceptanceRecords:false});
  },{readOnly:true});
 }
 return Object.freeze({inspect,accept,adjudicatePendingReadOnly});
}
