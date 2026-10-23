/**
 * Objective 32B — OFFLINE read-only, externally pinned multi-directory anomaly
 * evidence. An orphan/marker is NEVER authenticated by its filename or hash.
 * No remediation, decisions, checkout, manufacturing, network or Shopify IO.
 */
import {createHash} from 'node:crypto';
import {constants as F} from 'node:fs';
import {lstat,open,readdir,realpath} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {encodeOfflinePinnedArchiveInventory} from './offline-pinned-multi-archive-inventory.mjs';
import {verifyOfflineAcquisitionEvidenceExport} from './offline-acquisition-evidence-export.mjs';
import {OFFLINE_EXPORT_REGISTRY_SCHEMA} from './offline-acquisition-export-receipt-registry.mjs';

export const OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA='TJ-OFFLINE-PINNED-ORPHAN-REPORT-1';
const ROOT='0'.repeat(64),HEX=/^[a-f0-9]{64}$/,ID=/^[A-Za-z0-9_-]{12,80}$/;
const MAX_ARCHIVE=32*1024*1024+32768,MAX_RECORD=16384,MAX_FILES=4096,MAX_DIRS=64,MAX_TOTAL=64*1024*1024;
const sha=x=>createHash('sha256').update(x).digest('hex');
const fail=code=>{throw Object.assign(new Error(code),{code});};
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>obj(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const recordName=i=>`${String(i).padStart(4,'0')}.json`;
const archiveName=d=>`${d}.tjexport`;
const head=x=>exact(x,['count','headDigest'])&&Number.isSafeInteger(x.count)&&x.count>=0&&x.count<=2000&&HEX.test(x.headDigest)&&(x.count===0)===(x.headDigest===ROOT);
const fingerprint=s=>({dev:String(s.dev),ino:String(s.ino),size:s.size,mode:s.mode,mtimeMs:s.mtimeMs,ctimeMs:s.ctimeMs,nlink:s.nlink});
async function privateDir(path){
 let s;try{s=await lstat(path);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)||await realpath(path)!==path)fail('ORPHAN_DIRECTORY_UNSAFE');}
 catch(e){if(e.code==='ORPHAN_DIRECTORY_UNSAFE')throw e;fail('ORPHAN_DIRECTORY_UNSAFE');}return fingerprint(s);
}
async function readPrivate(path,limit){
 let h;try{
  h=await open(path,F.O_RDONLY|F.O_NOFOLLOW|F.O_NONBLOCK);
  const s=await h.stat(),p=await lstat(path);
  if(!s.isFile()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)||s.nlink!==1||s.size<1||s.size>limit||s.dev!==p.dev||s.ino!==p.ino)fail('ORPHAN_FILE_UNSAFE');
  const b=await h.readFile(),after=await h.stat(),p2=await lstat(path);
  if(b.length!==s.size||!equal(fingerprint(s),fingerprint(after))||!equal(fingerprint(s),fingerprint(p2)))fail('ORPHAN_CONCURRENT_CHANGE');
  return {bytes:b,fingerprint:fingerprint(s)};
 }finally{await h?.close();}
}
function canonical(b,limit){
 if(!Buffer.isBuffer(b)||b.length<2||b.length>limit)fail('ORPHAN_CANONICAL_INVALID');
 const s=b.toString('utf8');if(!Buffer.from(s).equals(b))fail('ORPHAN_CANONICAL_INVALID');
 let o;try{o=JSON.parse(s);}catch{fail('ORPHAN_CANONICAL_INVALID');}
 if(!obj(o)||JSON.stringify(o)!==s)fail('ORPHAN_CANONICAL_INVALID');return o;
}
function safeName(n){return /^[A-Za-z0-9_.-]{1,160}$/.test(n)&&n!=='.'&&n!=='..';}
async function scanDirectory(dir,expected,index){
 const names=(await readdir(dir)).sort();if(names.length>MAX_FILES)fail('ORPHAN_DIRECTORY_TOO_MANY_ENTRIES');
 const evidence=[];
 for(const n of names){
  const isExpected=expected.has(n),isLock=n==='.coordination-lock';
  const label=isExpected?'SIGNED_ARCHIVE':isLock?'COORDINATOR_LOCK':n==='.pending-coordination.json'?'PENDING_INTENT_UNVERIFIED':
   n.startsWith('.orphan-')?'QUARANTINE_UNVERIFIED':n.endsWith('.tjexport')?'UNTRACKED_ARCHIVE_UNVERIFIED':'UNTRACKED_ENTRY_UNVERIFIED';
  const name=safeName(n)?n:null,entry={directoryIndex:index,name,nameDigest:sha(Buffer.from(n)),classification:label};
  let s;try{s=await lstat(join(dir,n));}catch(e){if(e.code==='ENOENT'){evidence.push({...entry,classification:'ENTRY_DISAPPEARED'});continue;}throw e;}
  const f=fingerprint(s);
  if(isLock&&s.isFile()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&!(s.mode&0o077)&&s.nlink===1&&s.size===0){
   evidence.push({...entry,fingerprint:f,bytes:0,digest:sha(Buffer.alloc(0))});continue;
  }
  if(!s.isFile()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)||s.nlink!==1||!safeName(n)||s.size<1||s.size>(isExpected?MAX_ARCHIVE:MAX_RECORD)){
   evidence.push({...entry,classification:isExpected?'SIGNED_ARCHIVE_UNSAFE':'UNSAFE_UNTRACKED_ENTRY',fingerprint:f});continue;
  }
  try{
   const {bytes}=await readPrivate(join(dir,n),isExpected?MAX_ARCHIVE:MAX_RECORD);
   evidence.push({...entry,fingerprint:f,bytes:bytes.length,digest:sha(bytes)});
  }catch(e){if(['ORPHAN_FILE_UNSAFE','ENOENT','ELOOP','ENOTDIR','EISDIR'].includes(e.code)){
   evidence.push({...entry,classification:isExpected?'SIGNED_ARCHIVE_UNSAFE':'UNSAFE_UNTRACKED_ENTRY',fingerprint:f});
  }else throw e;}
 }
 for(const n of expected.keys())if(!names.includes(n))evidence.push({directoryIndex:index,name:n,nameDigest:sha(Buffer.from(n)),classification:'SIGNED_ARCHIVE_MISSING'});
 evidence.sort((a,b)=>a.nameDigest.localeCompare(b.nameDigest));
 return evidence;
}
function frozen(x){if(x&&typeof x==='object'){Object.values(x).forEach(frozen);Object.freeze(x);}return x;}

export async function classifyOfflinePinnedArchiveOrphans({registry,registryDirectory,archiveDirectories,registryId,manifestBytes,
 expectedManifestDigest,expectedHead,expectedEpoch,expectedTransitionDigest,nowMs,injectFault}={}){
 if(process.platform!=='linux'||!F.O_NOFOLLOW||typeof registry?.inspect!=='function'||registry.registryId!==registryId||!ID.test(registryId||'')||
  typeof registryDirectory!=='string'||!registryDirectory.trim()||!Array.isArray(archiveDirectories)||archiveDirectories.length<1||
  archiveDirectories.length>MAX_DIRS||archiveDirectories.some(x=>typeof x!=='string'||!x.trim())||!head(expectedHead)||
  !Number.isSafeInteger(expectedEpoch)||expectedEpoch<0||expectedEpoch>20||!HEX.test(expectedTransitionDigest||'')||
  !HEX.test(expectedManifestDigest||'')||!Number.isSafeInteger(nowMs)||nowMs<0||
  (injectFault!==undefined&&typeof injectFault!=='function'))fail('ORPHAN_EXTERNAL_PINS_REQUIRED');
 if(!Buffer.isBuffer(manifestBytes)||sha(manifestBytes)!==expectedManifestDigest)fail('ORPHAN_MANIFEST_PIN_MISMATCH');
 const registryPath=resolve(registryDirectory),dirs=archiveDirectories.map(x=>resolve(x));
 if(new Set(dirs).size!==dirs.length||dirs.some(d=>d===registryPath||d.startsWith(registryPath+'/')||registryPath.startsWith(d+'/'))||
  dirs.some((d,i)=>dirs.some((e,j)=>i!==j&&(d.startsWith(e+'/')||e.startsWith(d+'/')))))fail('ORPHAN_DIRECTORY_OVERLAP');
 const manifest=canonical(manifestBytes,512*1024);
 let encoded;try{encoded=encodeOfflinePinnedArchiveInventory({registryId,expectedHead,expectedEpoch,expectedTransitionDigest,archives:manifest.archives});}
 catch{fail('ORPHAN_MANIFEST_INVALID');}
 if(!encoded.equals(manifestBytes)||manifest.archives.some(a=>a.directoryIndex>=dirs.length))fail('ORPHAN_MANIFEST_INVALID');
 if(manifest.archives.reduce((n,a)=>n+a.archiveBytes,0)>MAX_TOTAL)fail('ORPHAN_SCAN_BUDGET_EXCEEDED');
 const dirStart=await Promise.all([privateDir(registryPath),...dirs.map(privateDir)]);
 const pins={expectedHead,expectedEpoch,expectedTransitionDigest,nowMs};
 async function inspect(){const r=await registry.inspect(pins);if(!equal(r?.head,expectedHead)||r?.readOnly!==true||r?.productionApproved!==false)fail('ORPHAN_REGISTRY_UNVERIFIED');}
 await inspect();
 const expected=dirs.map(()=>new Map()),recordEvidence=[];
 let previous=ROOT;
 for(let i=1;i<=expectedHead.count;i++){
  const {bytes}=await readPrivate(join(registryPath,recordName(i)),MAX_RECORD),r=canonical(bytes,MAX_RECORD),a=manifest.archives[i-1];
  if(!exact(r,['schema','index','previousDigest','receipt','digest'])||r.schema!==OFFLINE_EXPORT_REGISTRY_SCHEMA||r.index!==i||
   r.previousDigest!==previous||!HEX.test(r.digest||''))fail('ORPHAN_REGISTRY_CHAIN_INVALID');
  const {digest,...body}=r;
  if(sha(Buffer.from(`${OFFLINE_EXPORT_REGISTRY_SCHEMA}\0${JSON.stringify(body)}`))!==digest||
   r.receipt?.body?.registryId!==registryId||r.receipt.body.sequence!==i||r.receipt.body.previousDigest!==previous||
   r.receipt.body.archiveDigest!==a.archiveDigest||r.receipt.body.acquisitionId!==a.acquisitionId||r.receipt.body.archiveBytes!==a.archiveBytes)
   fail('ORPHAN_RECEIPT_BINDING_INVALID');
  const name=archiveName(a.archiveDigest);if(expected[a.directoryIndex].has(name))fail('ORPHAN_DUPLICATE_ARCHIVE');
  expected[a.directoryIndex].set(name,a);recordEvidence.push({index:i,digest,bytesDigest:sha(bytes)});previous=digest;
 }
 if(previous!==expectedHead.headDigest)fail('ORPHAN_REGISTRY_HEAD_MISMATCH');
 async function snapshot(){
  const rows=[];for(let i=0;i<dirs.length;i++){
   const found=await scanDirectory(dirs[i],expected[i],i);
   for(const e of found){const a=expected[i].get(e.name);
    if(a&&e.classification==='SIGNED_ARCHIVE'){
     if(e.digest!==a.archiveDigest||e.bytes!==a.archiveBytes)e.classification='SIGNED_ARCHIVE_TAMPERED';
     else{
      const b=await readPrivate(join(dirs[i],e.name),MAX_ARCHIVE);
      try{if(sha(b.bytes)!==e.digest)fail('ORPHAN_CONCURRENT_CHANGE');
       verifyOfflineAcquisitionEvidenceExport({bytes:b.bytes,expectedDigest:a.archiveDigest,expectedAcquisitionId:a.acquisitionId});}
      catch(err){if(err.code==='ORPHAN_CONCURRENT_CHANGE')throw err;e.classification='SIGNED_ARCHIVE_INVALID_STRUCTURE';}
     }
    }
    rows.push(e);
   }
  }
  return rows;
 }
 const first=await snapshot();if(injectFault)await injectFault('between-snapshots');
 const second=await snapshot();if(!equal(first,second))fail('ORPHAN_CONCURRENT_CHANGE');
 for(let i=0;i<dirs.length+1;i++)if(!equal(dirStart[i],await privateDir(i===0?registryPath:dirs[i-1])))fail('ORPHAN_CONCURRENT_CHANGE');
 previous=ROOT;
 for(let i=1;i<=expectedHead.count;i++){
  const {bytes}=await readPrivate(join(registryPath,recordName(i)),MAX_RECORD),r=canonical(bytes,MAX_RECORD);
  if(recordEvidence[i-1].bytesDigest!==sha(bytes)||r.previousDigest!==previous||r.digest!==recordEvidence[i-1].digest)fail('ORPHAN_CONCURRENT_CHANGE');
  previous=r.digest;
 }
 await inspect();
 const issues=second.filter(e=>!['SIGNED_ARCHIVE','COORDINATOR_LOCK'].includes(e.classification));
 const body={schema:OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA,registryId,manifestDigest:expectedManifestDigest,head:expectedHead,
  epoch:expectedEpoch,transitionDigest:expectedTransitionDigest,recordsDigest:sha(Buffer.from(JSON.stringify(recordEvidence))),
  evidence:second,status:issues.length?'SUPERVISORY_REVIEW_REQUIRED':'NO_ANOMALIES_OBSERVED',issueCount:issues.length,
  supervisoryDisposition:'EXTERNAL_DECISION_REQUIRED_FOR_ANY_REMEDIATION',readOnly:true,productionApproved:false,
  mayDelete:false,mayRepair:false,mayManufacture:false,mayAcknowledge:false};
 return frozen({...body,reportDigest:sha(Buffer.from(`${OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA}\0${JSON.stringify(body)}`))});
}
