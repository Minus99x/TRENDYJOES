/**
 * Objective 32A — OFFLINE independently pinned, read-only complete inventory.
 * No archive creation, deletion, reconciliation write, Shopify access or claim
 * of atomicity. The caller must obtain the manifest SHA and receipt/policy pins
 * from an INDEPENDENT trust channel, not from the directories being inspected.
 */
import {createHash} from 'node:crypto';
import {constants as F} from 'node:fs';
import {open,lstat,readdir,realpath} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {verifyOfflineAcquisitionEvidenceExport} from './offline-acquisition-evidence-export.mjs';
import {OFFLINE_EXPORT_REGISTRY_SCHEMA} from './offline-acquisition-export-receipt-registry.mjs';

export const OFFLINE_PINNED_ARCHIVE_INVENTORY_SCHEMA='TJ-OFFLINE-PINNED-ARCHIVE-INVENTORY-1';
const ROOT='0'.repeat(64),HEX=/^[a-f0-9]{64}$/,ID=/^[A-Za-z0-9_-]{12,80}$/;
const MAX_ARCHIVE=32*1024*1024+32768,MAX_MANIFEST=512*1024,MAX_RECORD=16384,MAX_DIRS=64,MAX_RECORDS=2000;
const sha=b=>createHash('sha256').update(b).digest('hex');
const fail=code=>{throw Object.assign(new Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>obj(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const head=x=>exact(x,['count','headDigest'])&&Number.isSafeInteger(x.count)&&x.count>=0&&x.count<=MAX_RECORDS&&HEX.test(x.headDigest)&&(x.count===0)===(x.headDigest===ROOT);
const recDigest=b=>sha(Buffer.from(`${OFFLINE_EXPORT_REGISTRY_SCHEMA}\0${JSON.stringify(b)}`));
const archiveName=d=>`${d}.tjexport`;
const recordName=i=>`${String(i).padStart(4,'0')}.json`;

function parseCanonical(bytes,limit){
 if(!Buffer.isBuffer(bytes)||bytes.length<2||bytes.length>limit)fail('PINNED_INVENTORY_BYTES_INVALID');
 const raw=bytes.toString('utf8');if(!Buffer.from(raw).equals(bytes))fail('PINNED_INVENTORY_NOT_CANONICAL');
 let data;try{data=JSON.parse(raw);}catch{fail('PINNED_INVENTORY_NOT_CANONICAL');}
 if(!obj(data)||JSON.stringify(data)!==raw)fail('PINNED_INVENTORY_NOT_CANONICAL');return data;
}
function validateManifest(m,{registryId,expectedHead,expectedEpoch,expectedTransitionDigest,dirCount}){
 if(!exact(m,['schema','registryId','head','epoch','transitionDigest','archives'])||
  m.schema!==OFFLINE_PINNED_ARCHIVE_INVENTORY_SCHEMA||m.registryId!==registryId||!same(m.head,expectedHead)||
  m.epoch!==expectedEpoch||m.transitionDigest!==expectedTransitionDigest||!Array.isArray(m.archives)||
  m.archives.length!==expectedHead.count||m.archives.length>MAX_RECORDS)fail('PINNED_INVENTORY_MANIFEST_MISMATCH');
 for(let i=0;i<m.archives.length;i++){
  const a=m.archives[i];
  if(!exact(a,['sequence','directoryIndex','acquisitionId','archiveDigest','archiveBytes'])||
   a.sequence!==i+1||!Number.isSafeInteger(a.directoryIndex)||a.directoryIndex<0||a.directoryIndex>=dirCount||
   !ID.test(a.acquisitionId||'')||!HEX.test(a.archiveDigest||'')||
   !Number.isSafeInteger(a.archiveBytes)||a.archiveBytes<2||a.archiveBytes>MAX_ARCHIVE)fail('PINNED_INVENTORY_ENTRY_INVALID');
 }
}
async function safeDirectory(path){
 let s;try{s=await lstat(path);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||
  (s.mode&0o077)!==0||(await realpath(path))!==path)fail('PINNED_INVENTORY_DIRECTORY_UNSAFE');}
 catch(e){if(e.code==='PINNED_INVENTORY_DIRECTORY_UNSAFE')throw e;fail('PINNED_INVENTORY_DIRECTORY_UNSAFE');}return s;
}
async function safeRead(path,max){
 let h;try{
  h=await open(path,F.O_RDONLY|F.O_NOFOLLOW|F.O_NONBLOCK);
  const [s,p]=await Promise.all([h.stat(),lstat(path)]);
  if(!s.isFile()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.nlink!==1||
   s.size<2||s.size>max||s.dev!==p.dev||s.ino!==p.ino)fail('PINNED_INVENTORY_FILE_UNSAFE');
  const bytes=await h.readFile(),[after,p2]=await Promise.all([h.stat(),lstat(path)]);
  if(bytes.length!==s.size||after.size!==s.size||after.mtimeMs!==s.mtimeMs||after.ctimeMs!==s.ctimeMs||
   p2.dev!==s.dev||p2.ino!==s.ino||p2.ctimeMs!==s.ctimeMs)fail('PINNED_INVENTORY_FILE_CHANGED');
  return bytes;
 }catch(e){if(['ENOENT','ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('PINNED_INVENTORY_FILE_UNSAFE');throw e;}
 finally{if(h)await h.close();}
}
async function enumerate(dir,expected){
 const names=(await readdir(dir)).sort(),allowed=[...expected].sort();
 if(names.includes('.coordination-lock')){
  const p=join(dir,'.coordination-lock'),s=await lstat(p);
  if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0)fail('PINNED_INVENTORY_LOCK_UNSAFE');
  allowed.push('.coordination-lock');allowed.sort();
 }
 if(!same(names,allowed))fail('PINNED_INVENTORY_ORPHAN_MISSING_OR_PENDING');
}

/** Produce a canonical proposal only. Caller MUST independently retain its SHA. */
export function encodeOfflinePinnedArchiveInventory({registryId,expectedHead,expectedEpoch,expectedTransitionDigest,archives}={}){
 if(!ID.test(registryId||'')||!head(expectedHead)||!Number.isSafeInteger(expectedEpoch)||expectedEpoch<0||expectedEpoch>20||
  !HEX.test(expectedTransitionDigest||'')||!Array.isArray(archives))fail('PINNED_INVENTORY_EXTERNAL_PINS_REQUIRED');
 const manifest={schema:OFFLINE_PINNED_ARCHIVE_INVENTORY_SCHEMA,registryId,head:expectedHead,epoch:expectedEpoch,transitionDigest:expectedTransitionDigest,archives};
 validateManifest(manifest,{registryId,expectedHead,expectedEpoch,expectedTransitionDigest,dirCount:MAX_DIRS});
 const bytes=Buffer.from(JSON.stringify(manifest));if(bytes.length>MAX_MANIFEST)fail('PINNED_INVENTORY_BYTES_INVALID');return bytes;
}

/** Verify every signed registry record against every archived byte; fail closed. */
export async function verifyOfflinePinnedArchiveInventory({registry,registryDirectory,archiveDirectories,registryId,manifestBytes,
 expectedManifestDigest,expectedHead,expectedEpoch,expectedTransitionDigest,nowMs,injectFault}={}){
 if(process.platform!=='linux'||!F.O_NOFOLLOW||typeof registry?.inspect!=='function'||registry.registryId!==registryId||!ID.test(registryId||'')||
  typeof registryDirectory!=='string'||!registryDirectory.trim()||!Array.isArray(archiveDirectories)||
  archiveDirectories.length<1||archiveDirectories.length>MAX_DIRS||archiveDirectories.some(x=>typeof x!=='string'||!x.trim())||
  !head(expectedHead)||!Number.isSafeInteger(expectedEpoch)||expectedEpoch<0||expectedEpoch>20||
  !HEX.test(expectedTransitionDigest||'')||!HEX.test(expectedManifestDigest||'')||
  !Number.isSafeInteger(nowMs)||nowMs<0||(injectFault!==undefined&&typeof injectFault!=='function'))fail('PINNED_INVENTORY_EXTERNAL_PINS_REQUIRED');
 if(!Buffer.isBuffer(manifestBytes)||sha(manifestBytes)!==expectedManifestDigest)fail('PINNED_INVENTORY_DIGEST_MISMATCH');
 const registryPath=resolve(registryDirectory),dirs=archiveDirectories.map(x=>resolve(x));
 if(new Set(dirs).size!==dirs.length||dirs.some(d=>d===registryPath||d.startsWith(registryPath+'/')||registryPath.startsWith(d+'/'))||
  dirs.some((d,i)=>dirs.some((e,j)=>i!==j&&(d.startsWith(e+'/')||e.startsWith(d+'/')))))fail('PINNED_INVENTORY_DIRECTORY_OVERLAP');
 const manifest=parseCanonical(manifestBytes,MAX_MANIFEST);
 validateManifest(manifest,{registryId,expectedHead,expectedEpoch,expectedTransitionDigest,dirCount:dirs.length});
 const regStat=await safeDirectory(registryPath),dirStats=await Promise.all(dirs.map(safeDirectory));
 const pins={expectedHead,expectedTransitionDigest,expectedEpoch,nowMs};
 // Existing registry independently authenticates the ENTIRE witness-policy history.
 const inspected=await registry.inspect(pins);
 if(!same(inspected?.head,expectedHead)||inspected?.readOnly!==true||inspected?.productionApproved!==false)fail('PINNED_INVENTORY_REGISTRY_INSPECTION_INVALID');
 const expectedFiles=dirs.map(()=>new Set());
 let previous=ROOT;const seenAcquisitions=new Set(),seenDigests=new Set();
 for(let i=1;i<=expectedHead.count;i++){
  const a=manifest.archives[i-1],record=parseCanonical(await safeRead(join(registryPath,recordName(i)),MAX_RECORD),MAX_RECORD);
  if(!exact(record,['schema','index','previousDigest','receipt','digest'])||record.schema!==OFFLINE_EXPORT_REGISTRY_SCHEMA||
   record.index!==i||record.previousDigest!==previous||!HEX.test(record.digest||''))fail('PINNED_INVENTORY_REGISTRY_CHAIN');
  const {digest,...body}=record;if(recDigest(body)!==digest)fail('PINNED_INVENTORY_REGISTRY_CHAIN');
  const r=record.receipt?.body;
  if(r?.registryId!==registryId||r.sequence!==i||r.previousDigest!==previous||r.acquisitionId!==a.acquisitionId||
   r.archiveDigest!==a.archiveDigest||r.archiveBytes!==a.archiveBytes||seenAcquisitions.has(r.acquisitionId)||seenDigests.has(r.archiveDigest))fail('PINNED_INVENTORY_RECEIPT_MISMATCH');
  seenAcquisitions.add(r.acquisitionId);seenDigests.add(r.archiveDigest);
  const filename=archiveName(a.archiveDigest),file=join(dirs[a.directoryIndex],filename);
  if(expectedFiles[a.directoryIndex].has(filename))fail('PINNED_INVENTORY_DUPLICATE_ARCHIVE');
  expectedFiles[a.directoryIndex].add(filename);
  const bytes=await safeRead(file,MAX_ARCHIVE);
  if(bytes.length!==a.archiveBytes||sha(bytes)!==a.archiveDigest)fail('PINNED_INVENTORY_ARCHIVE_TAMPERED');
  verifyOfflineAcquisitionEvidenceExport({bytes,expectedDigest:a.archiveDigest,expectedAcquisitionId:a.acquisitionId});
  previous=digest;
 }
 if(previous!==expectedHead.headDigest)fail('PINNED_INVENTORY_HEAD_MISMATCH');
 if(injectFault)await injectFault('before-final-reconciliation');
 for(let i=0;i<dirs.length;i++)await enumerate(dirs[i],expectedFiles[i]);
 // Re-read ALL archive bytes and registry records, not merely directory names;
 // detect ordinary concurrent edits during the verification window.
 previous=ROOT;
 for(let i=1;i<=expectedHead.count;i++){
  const a=manifest.archives[i-1],record=parseCanonical(await safeRead(join(registryPath,recordName(i)),MAX_RECORD),MAX_RECORD);
  const {digest,...body}=record;
  if(record.previousDigest!==previous||recDigest(body)!==digest||record.receipt?.body?.archiveDigest!==a.archiveDigest||
   record.receipt?.body?.acquisitionId!==a.acquisitionId)fail('PINNED_INVENTORY_CONCURRENT_REGISTRY_CHANGE');
  const bytes=await safeRead(join(dirs[a.directoryIndex],archiveName(a.archiveDigest)),MAX_ARCHIVE);
  if(sha(bytes)!==a.archiveDigest||bytes.length!==a.archiveBytes)fail('PINNED_INVENTORY_CONCURRENT_ARCHIVE_CHANGE');
  previous=digest;
 }
 for(let i=0;i<dirs.length;i++){
  const s=await safeDirectory(dirs[i]);if(s.ino!==dirStats[i].ino||s.dev!==dirStats[i].dev)fail('PINNED_INVENTORY_DIRECTORY_CHANGED');
  await enumerate(dirs[i],expectedFiles[i]);
 }
 const s=await safeDirectory(registryPath);if(s.ino!==regStat.ino||s.dev!==regStat.dev)fail('PINNED_INVENTORY_DIRECTORY_CHANGED');
 const inspectedAgain=await registry.inspect(pins);
 if(!same(inspectedAgain?.head,expectedHead)||inspectedAgain?.readOnly!==true||inspectedAgain?.productionApproved!==false)fail('PINNED_INVENTORY_REGISTRY_INSPECTION_INVALID');
 return Object.freeze({status:'INDEPENDENTLY_PINNED_COMPLETE_OFFLINE_INVENTORY',count:expectedHead.count,head:Object.freeze({...expectedHead}),
  inventoryDigest:expectedManifestDigest,epoch:expectedEpoch,transitionDigest:expectedTransitionDigest,
  archiveDirectoryCount:dirs.length,readOnly:true,mayManufacture:false,mayAcknowledge:false,productionApproved:false});
}
