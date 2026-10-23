/**
 * Objective 31R: deterministic, bounded, read-only transport of one complete
 * offline forensic acquisition. An external SHA-256 pin is REQUIRED to import.
 * Transport verification is NOT witness, retention, forensic, or Shopify auth.
 * Only private, owner-controlled Linux directories are accepted for collection.
 */
import {createHash} from 'node:crypto';
import {constants as F} from 'node:fs';
import {lstat,open,readdir} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {OFFLINE_ACQUISITION_SESSION_SCHEMA} from './offline-acquisition-session-journal.mjs';
import {OFFLINE_ACQUISITION_MANIFEST_SCHEMA} from './offline-forensic-acquisition-provenance.mjs';

export const OFFLINE_ACQUISITION_EXPORT_SCHEMA='TJ-OFFLINE-ACQUISITION-EVIDENCE-EXPORT-1';
const MAGIC=Buffer.from(`${OFFLINE_ACQUISITION_EXPORT_SCHEMA}\n`);
const HEX=/^[a-f0-9]{64}$/;
const ID=/^[A-Za-z0-9_-]{12,80}$/;
const ROOT='0'.repeat(64);
const MAX_FILES=64, MAX_FILE=12*1024*1024, MAX_TOTAL=32*1024*1024, MAX_HEADER=16384;
const required=['manifest.json','session/0001.json','session/0002.json','session/0003.json'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>obj(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const nameOk=p=>typeof p==='string'&&(required.includes(p)||/^evidence\/[a-z0-9][a-z0-9_-]{0,63}\.json$/.test(p));
function namesOk(paths){
 if(!Array.isArray(paths)||paths.length<4||paths.length>MAX_FILES||paths.some(p=>!nameOk(p)))fail('ACQUISITION_EXPORT_PATH_INVALID');
 const sorted=[...paths].sort();
 if(new Set(sorted).size!==sorted.length||required.some(p=>!sorted.includes(p)))fail('ACQUISITION_EXPORT_ENUMERATION_INVALID');
 return sorted;
}
function parseCanonical(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<2||bytes.length>MAX_FILE)fail('ACQUISITION_EXPORT_FILE_SIZE');
 const str=bytes.toString('utf8');
 if(!Buffer.from(str,'utf8').equals(bytes))fail('ACQUISITION_EXPORT_JSON_INVALID');
 let value;try{value=JSON.parse(str);}catch{fail('ACQUISITION_EXPORT_JSON_INVALID');}
 if(!obj(value)||JSON.stringify(value)!==str)fail('ACQUISITION_EXPORT_JSON_INVALID');
 return value;
}
function checkEvidence(files,acquisitionId){
 const manifest=parseCanonical(files.get('manifest.json'));
 if(!exact(manifest,['schema','acquisitionId','envelope','receiptHistory'])||manifest.schema!==OFFLINE_ACQUISITION_MANIFEST_SCHEMA||manifest.acquisitionId!==acquisitionId||!Array.isArray(manifest.receiptHistory)||manifest.receiptHistory.length<2)fail('ACQUISITION_EXPORT_MANIFEST_INVALID');
 let previous=ROOT;const sessionEvents=[];
 for(let i=1;i<=3;i++){
  const e=parseCanonical(files.get(`session/${String(i).padStart(4,'0')}.json`));
  if(!exact(e,['schema','index','previousDigest','action','payload','digest'])||e.schema!==OFFLINE_ACQUISITION_SESSION_SCHEMA||e.index!==i||e.action!==['BEGIN','PRE','POST'][i-1]||e.previousDigest!==previous||!HEX.test(e.digest||''))fail('ACQUISITION_EXPORT_SESSION_INVALID');
  const {digest,...body}=e;
  if(sha(Buffer.from(`${OFFLINE_ACQUISITION_SESSION_SCHEMA}\0${JSON.stringify(body)}`))!==digest)fail('ACQUISITION_EXPORT_SESSION_INVALID');
  previous=digest;sessionEvents.push(e);
 }
 if(sessionEvents[0].payload?.acquisitionId!==acquisitionId||
    JSON.stringify(sessionEvents[1].payload)!==JSON.stringify(manifest.receiptHistory.at(-2))||
    JSON.stringify(sessionEvents[2].payload)!==JSON.stringify(manifest))fail('ACQUISITION_EXPORT_BINDING_INVALID');
 for(const [name,bytes] of files)if(name.startsWith('evidence/'))parseCanonical(bytes);
 return {manifest,sessionEvents};
}
function privateDir(s){return s.isDirectory()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&(s.mode&0o077)===0;}
async function checkEnumeration(root,paths){
 const expectedRoot=['manifest.json','session',...(paths.some(p=>p.startsWith('evidence/'))?['evidence']:[])].sort();
 const expectedSession=paths.filter(p=>p.startsWith('session/')).map(p=>p.slice(8));
 const expectedEvidence=paths.filter(p=>p.startsWith('evidence/')).map(p=>p.slice(9));
 let rootNames,sessionNames,evidenceNames=[];
 try{
  rootNames=(await readdir(root)).sort();
  sessionNames=(await readdir(join(root,'session'))).filter(p=>p!=='.session-lock').sort();
  if(expectedEvidence.length)evidenceNames=(await readdir(join(root,'evidence'))).sort();
 }catch{fail('ACQUISITION_EXPORT_ENUMERATION_INVALID');}
 if(JSON.stringify(rootNames)!==JSON.stringify(expectedRoot)||
    JSON.stringify(sessionNames)!==JSON.stringify(expectedSession)||
    JSON.stringify(evidenceNames)!==JSON.stringify(expectedEvidence))fail('ACQUISITION_EXPORT_ENUMERATION_INVALID');
 // The journal's known, non-evidence .session-lock is excluded by contract.
 if((await readdir(join(root,'session'))).includes('.session-lock')){
  const s=await lstat(join(root,'session','.session-lock'));
  if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0)fail('ACQUISITION_EXPORT_FILE_UNSAFE');
 }
}
async function safeFile(root,relative){
 const segments=relative.split('/');let current=root;
 for(const segment of segments.slice(0,-1)){
  current=join(current,segment);let s;
  try{s=await lstat(current);}catch{fail('ACQUISITION_EXPORT_DIRECTORY_UNSAFE');}
  if(!privateDir(s))fail('ACQUISITION_EXPORT_DIRECTORY_UNSAFE');
 }
 const path=join(root,relative);let handle;
 try{
  handle=await open(path,F.O_RDONLY|F.O_NOFOLLOW|F.O_NONBLOCK);
  const [s,p]=await Promise.all([handle.stat(),lstat(path)]);
  if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.size<2||s.size>MAX_FILE||s.ino!==p.ino||s.dev!==p.dev)fail('ACQUISITION_EXPORT_FILE_UNSAFE');
  const bytes=await handle.readFile();
  const after=await handle.stat();
  const pathAfter=await lstat(path);
  if(after.size!==s.size||after.mtimeMs!==s.mtimeMs||after.ctimeMs!==s.ctimeMs||pathAfter.ino!==s.ino||pathAfter.dev!==s.dev||bytes.length!==s.size)fail('ACQUISITION_EXPORT_FILE_CHANGED');
  return bytes;
 }catch(e){if(['ELOOP','EISDIR','ENOTDIR','ENOENT'].includes(e.code))fail('ACQUISITION_EXPORT_FILE_UNSAFE');throw e;}
 finally{if(handle)await handle.close();}
}
/** Collects explicit files only; no recursive traversal, no writes, no network. */
export async function createOfflineAcquisitionEvidenceExport({rootDirectory,acquisitionId,relativePaths,injectFault}={}){
 if(process.platform!=='linux'||!F.O_NOFOLLOW||!ID.test(acquisitionId||'')||typeof rootDirectory!=='string'||!rootDirectory.trim()||(injectFault!==undefined&&typeof injectFault!=='function'))fail('ACQUISITION_EXPORT_CONFIGURATION');
 const paths=namesOk(relativePaths),root=resolve(rootDirectory);
 let rootStat;try{rootStat=await lstat(root);}catch{fail('ACQUISITION_EXPORT_DIRECTORY_UNSAFE');}
 if(!privateDir(rootStat))fail('ACQUISITION_EXPORT_DIRECTORY_UNSAFE');
 await checkEnumeration(root,paths);
 const files=new Map();let total=0;
 for(const path of paths){const bytes=await safeFile(root,path);total+=bytes.length;if(total>MAX_TOTAL)fail('ACQUISITION_EXPORT_TOTAL_SIZE');files.set(path,bytes);}
 checkEvidence(files,acquisitionId);
 if(injectFault)await injectFault('after-first-pass');
 // A second independent read detects mutation/replacement during collection.
 const again=await lstat(root);
 if(!privateDir(again)||again.ino!==rootStat.ino||again.dev!==rootStat.dev)fail('ACQUISITION_EXPORT_DIRECTORY_CHANGED');
 await checkEnumeration(root,paths);
 for(const path of paths)if(!(await safeFile(root,path)).equals(files.get(path)))fail('ACQUISITION_EXPORT_FILE_CHANGED');
 const entries=[],payload=[];let offset=0;
 for(const path of paths){const bytes=files.get(path);entries.push({path,offset,size:bytes.length,sha256:sha(bytes)});payload.push(bytes);offset+=bytes.length;}
 const body=Buffer.concat(payload,total);
 const header=Buffer.from(JSON.stringify({schema:OFFLINE_ACQUISITION_EXPORT_SCHEMA,acquisitionId,files:entries,payloadBytes:total,payloadDigest:sha(body)}));
 if(header.length>MAX_HEADER)fail('ACQUISITION_EXPORT_HEADER_SIZE');
 const len=Buffer.alloc(4);len.writeUInt32BE(header.length);
 const bytes=Buffer.concat([MAGIC,len,header,body]);
 return {bytes,digest:sha(bytes),fileCount:paths.length,payloadBytes:total,readOnly:true,productionApproved:false};
}
/** Requires a separately supplied, trusted SHA-256 and acquisition identity. */
export function verifyOfflineAcquisitionEvidenceExport({bytes,expectedDigest,expectedAcquisitionId}={}){
 if(!HEX.test(expectedDigest||'')||!ID.test(expectedAcquisitionId||''))fail('ACQUISITION_EXPORT_EXTERNAL_PIN_REQUIRED');
 if(!Buffer.isBuffer(bytes)||bytes.length<MAGIC.length+4+2||bytes.length>MAGIC.length+4+MAX_HEADER+MAX_TOTAL||!bytes.subarray(0,MAGIC.length).equals(MAGIC))fail('ACQUISITION_EXPORT_FORMAT_INVALID');
 if(sha(bytes)!==expectedDigest)fail('ACQUISITION_EXPORT_PIN_MISMATCH');
 const headerLength=bytes.readUInt32BE(MAGIC.length),start=MAGIC.length+4,end=start+headerLength;
 if(headerLength<2||headerLength>MAX_HEADER||end>bytes.length)fail('ACQUISITION_EXPORT_FORMAT_INVALID');
 const header=parseCanonical(bytes.subarray(start,end));
 if(!exact(header,['schema','acquisitionId','files','payloadBytes','payloadDigest'])||header.schema!==OFFLINE_ACQUISITION_EXPORT_SCHEMA||header.acquisitionId!==expectedAcquisitionId||!Array.isArray(header.files)||!Number.isSafeInteger(header.payloadBytes)||header.payloadBytes<1||header.payloadBytes>MAX_TOTAL||!HEX.test(header.payloadDigest||''))fail('ACQUISITION_EXPORT_HEADER_INVALID');
 const paths=namesOk(header.files.map(f=>f?.path));
 if(header.files.length!==paths.length||paths.some((p,i)=>header.files[i].path!==p))fail('ACQUISITION_EXPORT_ENUMERATION_INVALID');
 const payload=bytes.subarray(end);
 if(payload.length!==header.payloadBytes||sha(payload)!==header.payloadDigest)fail('ACQUISITION_EXPORT_TRUNCATED_OR_TAMPERED');
 const files=new Map();let offset=0;
 for(const f of header.files){
  if(!exact(f,['path','offset','size','sha256'])||!Number.isSafeInteger(f.offset)||f.offset!==offset||!Number.isSafeInteger(f.size)||f.size<2||f.size>MAX_FILE||!HEX.test(f.sha256||'')||offset+f.size>payload.length)fail('ACQUISITION_EXPORT_ENTRY_INVALID');
  const chunk=payload.subarray(offset,offset+f.size);
  if(sha(chunk)!==f.sha256)fail('ACQUISITION_EXPORT_ENTRY_INVALID');
  files.set(f.path,chunk);offset+=f.size;
 }
 if(offset!==payload.length)fail('ACQUISITION_EXPORT_ENUMERATION_INVALID');
 const {manifest,sessionEvents}=checkEvidence(files,expectedAcquisitionId);
 const auxiliaryEvidence=Object.fromEntries([...files].filter(([p])=>p.startsWith('evidence/')).map(([p,b])=>[p,parseCanonical(b)]));
 return {verified:true,classification:'EXTERNALLY_PINNED_TRANSPORT_ONLY',digest:expectedDigest,acquisitionId:expectedAcquisitionId,fileCount:paths.length,payloadBytes:payload.length,manifest,sessionEvents,auxiliaryEvidence,readOnly:true,mayRetry:false,mayAcknowledge:false,mayManufacture:false,productionApproved:false,underlyingSignaturesVerified:false};
}
