/**
 * Objective 32D — offline, Linux-local, fail-closed at-most-one replay commitment.
 * A signed 32C decision is verified against an independently supplied head pin,
 * then a durable, immutable one-successor-per-head link is committed.
 * This is NOT a distributed transaction, external pin update, or authorization.
 */
import {createHash,randomUUID} from 'node:crypto';
import {constants as F} from 'node:fs';
import {mkdir,open,lstat,readdir,realpath,link,unlink} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {encodeOfflineOrphanReplaySnapshot,verifyOfflineOrphanSupervisorDecision} from './offline-orphan-supervisor-decision.mjs';

export const OFFLINE_SUPERVISOR_REPLAY_COMMIT_SCHEMA='TJ-OFFLINE-SUPERVISOR-REPLAY-COMMIT-1';
const HEX=/^[a-f0-9]{64}$/,ID=/^[A-Za-z0-9_-]{12,80}$/;
const sha=b=>createHash('sha256').update(b).digest('hex');
const fail=code=>{throw Object.assign(new Error(code),{code});};
const plain=o=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&[Object.prototype,null].includes(Object.getPrototypeOf(o));
const exact=(o,keys)=>plain(o)&&Object.keys(o).sort().join('|')===keys.slice().sort().join('|');
const stageName=s=>/^\.stage-[a-f0-9-]{36}$/.test(s);
const commitName=s=>/^commit-[a-f0-9]{64}\.json$/.test(s);
const bytesOf=x=>Buffer.from(JSON.stringify(x));
function checkedSnapshot(bytes,registryId){
 if(!Buffer.isBuffer(bytes)||bytes.length>1024*1024)fail('REPLAY32D_SNAPSHOT_INVALID');
 let parsed;try{parsed=JSON.parse(bytes.toString('utf8'));}catch{fail('REPLAY32D_SNAPSHOT_INVALID');}
 if(!exact(parsed,['schema','registryId','consumed'])||parsed.registryId!==registryId||
  !encodeOfflineOrphanReplaySnapshot(parsed).equals(bytes))fail('REPLAY32D_SNAPSHOT_INVALID');
 return parsed;
}
function nextSnapshot(previous,decision){
 const consumed=[...previous.consumed,{decisionId:decision.decisionId,nonce:decision.nonce}].sort((a,b)=>a.decisionId<b.decisionId?-1:a.decisionId>b.decisionId?1:0);
 return encodeOfflineOrphanReplaySnapshot({registryId:previous.registryId,consumed});
}
function validateRecord(record,parentDigest,registryId){
 if(!exact(record,['schema','registryId','previousDigest','nextDigest','decisionId','nonce','decisionDigest'])||
  record.schema!==OFFLINE_SUPERVISOR_REPLAY_COMMIT_SCHEMA||record.registryId!==registryId||record.previousDigest!==parentDigest||
  ![record.nextDigest,record.decisionDigest].every(x=>HEX.test(x||''))||
  !ID.test(record.decisionId||'')||!ID.test(record.nonce||''))fail('REPLAY32D_COMMIT_INVALID');
}
export function createOfflineSupervisorReplayCommit({directory,registryId,genesisBytes,expectedGenesisDigest,faultHook}={}){
 if(process.platform!=='linux'||!F.O_NOFOLLOW||typeof directory!=='string'||!directory.trim()||!ID.test(registryId||'')||
  !HEX.test(expectedGenesisDigest||'')||(faultHook!==undefined&&typeof faultHook!=='function'))fail('REPLAY32D_CONFIGURATION');
 const genesis=Buffer.from(genesisBytes||[]);
 if(sha(genesis)!==expectedGenesisDigest)fail('REPLAY32D_GENESIS_PIN_MISMATCH');
 checkedSnapshot(genesis,registryId);
 const root=resolve(directory);
 const recordPath=d=>join(root,`commit-${d}.json`);
 async function safeDirectory(){
  await mkdir(root,{recursive:true,mode:0o700});
  const st=await lstat(root);
  if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==process.getuid()||(st.mode&0o077)!==0||await realpath(root)!==root)
   fail('REPLAY32D_DIRECTORY_UNSAFE');
  return st;
 }
 async function syncDirectory(){const h=await open(root,F.O_RDONLY|F.O_DIRECTORY|F.O_NOFOLLOW);try{await h.sync();}finally{await h.close();}}
 async function safeRead(path){let h;try{
  h=await open(path,F.O_RDONLY|F.O_NOFOLLOW|F.O_NONBLOCK);
  const [a,b]=await Promise.all([h.stat(),lstat(path)]);
  if(!a.isFile()||a.uid!==process.getuid()||(a.mode&0o077)!==0||a.size<2||a.size>4096||a.ino!==b.ino||a.dev!==b.dev||a.nlink<1||a.nlink>2)
   fail('REPLAY32D_FILE_UNSAFE');
  const buf=await h.readFile(),c=await h.stat(),d=await lstat(path);
  if(buf.length!==a.size||a.ctimeMs!==c.ctimeMs||a.mtimeMs!==c.mtimeMs||d.ino!==a.ino||d.dev!==a.dev)
   fail('REPLAY32D_FILE_CHANGED');
  let obj;try{obj=JSON.parse(buf.toString('utf8'));}catch{fail('REPLAY32D_COMMIT_INVALID');}
  if(!bytesOf(obj).equals(buf))fail('REPLAY32D_COMMIT_INVALID');
  return {obj,stat:a};
 }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('REPLAY32D_FILE_UNSAFE');throw e;}finally{if(h)await h.close();}}
 async function scan({expectedHeadDigest,allowLinkedStages=false}={}){
  if(!HEX.test(expectedHeadDigest||''))fail('REPLAY32D_EXTERNAL_HEAD_REQUIRED');
  await safeDirectory();const names=await readdir(root);
  if(names.some(n=>!stageName(n)&&!commitName(n)))fail('REPLAY32D_UNEXPECTED_FILE');
  let state=checkedSnapshot(genesis,registryId),digest=expectedGenesisDigest;
  const visited=new Set();let depth=0;
  while(names.includes(`commit-${digest}.json`)){
   if(++depth>4096||visited.has(digest))fail('REPLAY32D_CHAIN_INVALID');visited.add(digest);
   const {obj}=await safeRead(recordPath(digest));validateRecord(obj,digest,registryId);
   if(state.consumed.some(c=>c.decisionId===obj.decisionId||c.nonce===obj.nonce))fail('REPLAY32D_CHAIN_REPLAY');
   const next=nextSnapshot(state,obj);
   if(sha(next)!==obj.nextDigest||obj.nextDigest===digest)fail('REPLAY32D_CHAIN_INVALID');
   state=checkedSnapshot(next,registryId);digest=obj.nextDigest;
  }
  // A disconnected, substituted, or rolled-back commit is never silently ignored.
  const reachable=new Set([...visited].map(x=>`commit-${x}.json`));
  if(names.some(n=>commitName(n)&&!reachable.has(n)))fail('REPLAY32D_ORPHAN_COMMIT');
  if(digest!==expectedHeadDigest)fail('REPLAY32D_EXTERNAL_HEAD_MISMATCH');
  const stages=names.filter(stageName).sort(),linked=[],unlinked=[];
  for(const name of stages){
   const s=await safeRead(join(root,name));
   const parent=s.obj?.previousDigest;
   const candidate=HEX.test(parent||'')?`commit-${parent}.json`:null;
   if(candidate&&reachable.has(candidate)){
    const c=await safeRead(join(root,candidate));
    if(c.stat.ino===s.stat.ino&&c.stat.dev===s.stat.dev&&bytesOf(c.obj).equals(bytesOf(s.obj))){linked.push(name);continue;}
   }
   unlinked.push(name);
  }
  if(unlinked.length||(!allowLinkedStages&&linked.length))fail('REPLAY32D_UNRESOLVED_STAGE');
  return {digest,bytes:encodeOfflineOrphanReplaySnapshot(state),consumed:state.consumed,depth,linkedStages:linked};
 }
 async function inspect({expectedHeadDigest}={}){
  const s=await scan({expectedHeadDigest});
  return Object.freeze({headDigest:s.digest,count:s.consumed.length,readOnly:true,externalPinRequired:true,
   authorizesRemediation:false,authorizesCheckout:false,productionApproved:false});
 }
 async function commit({expectedHeadDigest,report,expectedPins,decision,reviewers,quorum,expectedReviewerPolicyDigest,nowMs}={}){
  const s=await scan({expectedHeadDigest});
  if(s.consumed.length>=4096)fail('REPLAY32D_CAPACITY');
  const verified=verifyOfflineOrphanSupervisorDecision({report,expectedPins,decision,reviewers,quorum,
   expectedReviewerPolicyDigest,replayBytes:s.bytes,expectedReplayDigest:s.digest,nowMs});
  const body=decision.body,next=nextSnapshot(checkedSnapshot(s.bytes,registryId),body),nextDigest=sha(next);
  const record={schema:OFFLINE_SUPERVISOR_REPLAY_COMMIT_SCHEMA,registryId,previousDigest:s.digest,nextDigest,
   decisionId:body.decisionId,nonce:body.nonce,decisionDigest:verified.decisionDigest};
  const stage=join(root,`.stage-${randomUUID()}`),target=recordPath(s.digest);
  let handle,linked=false;
  try{
   handle=await open(stage,F.O_WRONLY|F.O_CREAT|F.O_EXCL|F.O_NOFOLLOW,0o600);
   await handle.writeFile(bytesOf(record));await handle.sync();await handle.close();handle=null;
   await syncDirectory();if(faultHook)await faultHook('afterStage');
   try{await link(stage,target);linked=true;}catch(e){if(e.code==='EEXIST')fail('REPLAY32D_CONCURRENT_COMMIT');throw e;}
   if(faultHook)await faultHook('afterLink');
   await syncDirectory();if(faultHook)await faultHook('afterCommitSync');
   await unlink(stage);await syncDirectory();
   return Object.freeze({committed:true,previousDigest:s.digest,nextDigest,decisionDigest:verified.decisionDigest,
    externalPinUpdateRequired:true,authorizesRemediation:false,authorizesCheckout:false,productionApproved:false});
  }finally{
   if(handle)await handle.close();
   // After the irreversible link, leave uncertain staging evidence intact for
   // independent supervisory finalization rather than silently cleaning it.
   if(!linked){try{await unlink(stage);await syncDirectory();}catch(e){if(e.code!=='ENOENT')throw e;}}
  }
 }
 async function finalizeLinkedStages({expectedHeadDigest,supervisorConfirmed=false}={}){
  if(supervisorConfirmed!==true)fail('REPLAY32D_SUPERVISOR_REQUIRED');
  const s=await scan({expectedHeadDigest,allowLinkedStages:true});
  for(const name of s.linkedStages){
   // Only hardlinks to already committed and externally pinned records may be
   // unlinked. Never delete an orphan stage or any forensic archive.
   const stage=join(root,name),{obj,stat}=await safeRead(stage),{stat:committed}=await safeRead(recordPath(obj.previousDigest));
   if(stat.ino!==committed.ino||stat.dev!==committed.dev)fail('REPLAY32D_STAGE_CHANGED');
   await unlink(stage);
  }
  await syncDirectory();await scan({expectedHeadDigest});
  return Object.freeze({finalized:s.linkedStages.length,headDigest:s.digest,authorizesRemediation:false,productionApproved:false});
 }
 return Object.freeze({inspect,commit,finalizeLinkedStages});
}
