/** Objective 35U: conservative, read-only local artwork reference inventory.
 * Not a garbage collector, storage authorization boundary, or production retention policy.
 */
import * as fs from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {withLocalArtworkLease} from './preview-local-artwork-coordination.mjs';
const artworkId=/^art_[a-f0-9]{32}$/;
const designId=/^TJ-[A-F0-9]{24}$/;
const revisionFile=/^([1-9][0-9]*)\.json$/;
const artworkFile=/^(art_[a-f0-9]{32})\.(png|jpeg|webp|json)$/;
const pendingFile=/^\.art_[a-f0-9]{32}\.pending-[a-f0-9]{24}\.json$/;
// Mirrors LocalDesignStore's 5 MiB maximum upload. This scan never trusts metadata
// to decide how much image content to read.
const DEFAULT_MAX_ARTWORK_BYTES=5*1024*1024;
const fail=(code,cause)=>Object.assign(new Error(code),{code,cause});
const fingerprint=s=>[s.dev,s.ino,s.mode,s.size,s.mtimeMs,s.ctimeMs].join(':');
const checkLimit=(value,max)=>Number.isSafeInteger(value)&&value>0&&value<=max;

/** Refuses symbolic links, special files, unreadable revisions and changing files. */
async function regular(path,io){
 const s=await io.lstat(path);
 if(!s.isFile()||s.isSymbolicLink())throw fail('LOCAL_RETENTION_UNSAFE_ENTRY');
 return s;
}
async function directory(path,io){
 const s=await io.lstat(path);
 if(!s.isDirectory()||s.isSymbolicLink())throw fail('LOCAL_RETENTION_UNSAFE_DIRECTORY');
 return s;
}
async function readStable(path,io,maxBytes){
 const before=await regular(path,io);
 if(before.size>maxBytes)throw fail('LOCAL_RETENTION_FILE_TOO_LARGE');
 const bytes=await io.readFile(path);
 const after=await regular(path,io);
 if(fingerprint(before)!==fingerprint(after)||bytes.length!==after.size)
  throw fail('LOCAL_RETENTION_CONCURRENT_CHANGE');
 return {bytes,stamp:fingerprint(after)+':'+createHash('sha256').update(bytes).digest('hex')};
}
async function snapshot(root,io,limits){
 const designs=join(root,'designs'),artworks=join(root,'artworks');
 await directory(root,io);await directory(designs,io);await directory(artworks,io);
 const dirs=await io.readdir(designs,{withFileTypes:true});
 if(dirs.length>limits.maxDesigns)throw fail('LOCAL_RETENTION_DESIGN_LIMIT');
 const refs=new Set(),signatures=[],revisionKeys=[];
 let revisions=0;
 for(const entry of dirs.sort((a,b)=>a.name.localeCompare(b.name))){
  if(!designId.test(entry.name)||!entry.isDirectory()||entry.isSymbolicLink())
   throw fail('LOCAL_RETENTION_UNKNOWN_DESIGN_ENTRY');
  const base=join(designs,entry.name);const ds=await directory(base,io);
  signatures.push(`D:${entry.name}:${fingerprint(ds)}`);
  const files=await io.readdir(base,{withFileTypes:true});
  if(files.length>limits.maxRevisions)throw fail('LOCAL_RETENTION_REVISION_LIMIT');
  const nums=[];
  for(const f of files.sort((a,b)=>a.name.localeCompare(b.name))){
   if(!f.isFile()||f.isSymbolicLink())throw fail('LOCAL_RETENTION_UNSAFE_ENTRY');
   if(f.name==='owner.sha256'){
    const data=await readStable(join(base,f.name),io,128);
    if(!/^[a-f0-9]{64}\s*$/.test(data.bytes.toString('utf8')))throw fail('LOCAL_RETENTION_OWNER_INVALID');
    signatures.push(`O:${entry.name}:${data.stamp}`);continue;
   }
   const m=revisionFile.exec(f.name);
   if(!m||!Number.isSafeInteger(Number(m[1])))throw fail('LOCAL_RETENTION_UNKNOWN_REVISION_ENTRY');
   const n=Number(m[1]);nums.push(n);revisions++;
   if(revisions>limits.maxRevisions)throw fail('LOCAL_RETENTION_REVISION_LIMIT');
   const data=await readStable(join(base,f.name),io,limits.maxRevisionBytes);
   let record;try{record=JSON.parse(data.bytes.toString('utf8'));}catch{throw fail('LOCAL_RETENTION_REVISION_CORRUPT');}
   if(!record||record.reference!==entry.name||record.revision!==n||!Array.isArray(record.layers)||record.layers.length>50)
    throw fail('LOCAL_RETENTION_REVISION_CORRUPT');
   for(const layer of record.layers){
    if(!layer||typeof layer!=='object'||typeof layer.type!=='string')throw fail('LOCAL_RETENTION_LAYER_INVALID');
    if(layer.type==='artwork'){
     if(!artworkId.test(layer.artworkId))throw fail('LOCAL_RETENTION_ARTWORK_REFERENCE_INVALID');
     refs.add(layer.artworkId);
    }else if(layer.artworkId!==undefined)throw fail('LOCAL_RETENTION_AMBIGUOUS_ARTWORK_REFERENCE');
   }
   revisionKeys.push(`${entry.name}/${n}`);
   signatures.push(`R:${entry.name}/${n}:${data.stamp}`);
  }
  if(!files.some(f=>f.name==='owner.sha256')||nums.length===0)throw fail('LOCAL_RETENTION_INCOMPLETE_DESIGN');
  nums.sort((a,b)=>a-b);
  if(nums.some((n,i)=>n!==i+1))throw fail('LOCAL_RETENTION_REVISION_GAP');
 }
 const entries=await io.readdir(artworks,{withFileTypes:true});
 if(entries.length>limits.maxArtworkEntries)throw fail('LOCAL_RETENTION_ARTWORK_LIMIT');
 const pair=new Map(),pending=[];
 for(const e of entries.sort((a,b)=>a.name.localeCompare(b.name))){
  if(pendingFile.test(e.name)){
   if(!e.isFile()||e.isSymbolicLink())throw fail('LOCAL_RETENTION_UNSAFE_ENTRY');
   const s=await regular(join(artworks,e.name),io);
   pending.push(e.name);signatures.push(`P:${e.name}:${fingerprint(s)}`);continue;
  }
  const m=artworkFile.exec(e.name);
  if(!m)throw fail('LOCAL_RETENTION_UNKNOWN_ARTWORK_ENTRY');
  if(!e.isFile()||e.isSymbolicLink())throw fail('LOCAL_RETENTION_UNSAFE_ENTRY');
  const record=pair.get(m[1])??{id:m[1],metadata:null,images:[]};
  if(m[2]==='json'){
   const data=await readStable(join(artworks,e.name),io,limits.maxMetadataBytes);
   let meta;try{meta=JSON.parse(data.bytes.toString('utf8'));}catch{throw fail('LOCAL_RETENTION_METADATA_CORRUPT');}
   if(meta?.id!==m[1]||!['png','jpeg','webp'].includes(meta.extension)||!Number.isSafeInteger(meta.bytes)||meta.bytes<1||!/^[a-f0-9]{64}$/.test(meta.sha256||''))
    throw fail('LOCAL_RETENTION_METADATA_CORRUPT');
   record.metadata=meta;signatures.push(`A:${e.name}:${data.stamp}`);
  }else{
   // A stat-only pin can miss same-size image substitution. Read and hash the
   // actual image under the cooperative lease, with before/after stat checks.
   const data=await readStable(join(artworks,e.name),io,limits.maxArtworkBytes);
   record.images.push({extension:m[2],size:data.bytes.length,sha256:createHash('sha256').update(data.bytes).digest('hex')});
   signatures.push(`A:${e.name}:${data.stamp}`);
  }
  pair.set(m[1],record);
 }
 const incomplete=[];const complete=[];
 for(const record of pair.values()){
  if(!record.metadata||record.images.length!==1||record.images[0].extension!==record.metadata.extension||record.images[0].size!==record.metadata.bytes)
   incomplete.push(record.id);
  else if(record.images[0].sha256!==record.metadata.sha256)throw fail('LOCAL_RETENTION_ARTWORK_DIGEST_MISMATCH');
  else complete.push(record.id);
 }
 const missing=[...refs].filter(id=>!complete.includes(id)).sort();
 return {signatures:signatures.sort(),references:[...refs].sort(),revisions,designs:dirs.length,
  complete:complete.sort(),incomplete:incomplete.sort(),pending:pending.sort(),missing,
  revisionKeys:revisionKeys.sort()};
}
/**
 * Scan twice; any observed concurrent mutation refuses an inventory result.
 * Even a stable result is NEVER authorization to delete: a writer may race after
 * the scan. The cooperative local lease is not a production-wide writer fence.
 */
export async function inspectLocalArtworkRetention(root,{io=fs,maxDesigns=10000,maxRevisions=100000,
 maxArtworkEntries=10000,maxRevisionBytes=1024*1024,maxMetadataBytes=16384,
 maxArtworkBytes=DEFAULT_MAX_ARTWORK_BYTES}={}){
 if(typeof root!=='string'||!root||![maxDesigns,maxRevisions,maxArtworkEntries,maxRevisionBytes,maxMetadataBytes,maxArtworkBytes]
  .every(v=>checkLimit(v,10000000)))throw fail('LOCAL_RETENTION_INVALID_OPTIONS');
 const limits={maxDesigns,maxRevisions,maxArtworkEntries,maxRevisionBytes,maxMetadataBytes,maxArtworkBytes};
 try{
  return await withLocalArtworkLease(root,async()=>{
  const first=await snapshot(resolve(root),io,limits);
  const second=await snapshot(resolve(root),io,limits);
  if(JSON.stringify(first)!==JSON.stringify(second))throw fail('LOCAL_RETENTION_CONCURRENT_CHANGE');
  const referenced=new Set(second.references);
  // Binds a review to the observed design-revision and artwork-entry snapshot.
  // This is a freshness pin, NOT an authorization or a production writer fence.
  const referencePin=createHash('sha256').update(JSON.stringify(second)).digest('hex');
  return Object.freeze({schema:'trendyjoes.local-artwork-retention.v1',
   designCount:second.designs,revisionCount:second.revisions,referencePin,
   referencedArtworkIds:Object.freeze(second.references),
   unreferencedCompleteArtworkIds:Object.freeze(second.complete.filter(id=>!referenced.has(id))),
   missingOrIncompleteReferencedArtworkIds:Object.freeze(second.missing),
   incompleteArtworkIds:Object.freeze(second.incomplete),
   pendingStageFiles:Object.freeze(second.pending),
   referenceScanComplete:true,safeToAutoDelete:false,
   reason:'READ_ONLY_COOPERATIVE_LEASE_NO_QUARANTINE_AUTHORITY'});
  },{io});
 }catch(error){if(error?.code?.startsWith('LOCAL_RETENTION_')||error?.code?.startsWith('LOCAL_ARTWORK_LEASE_'))throw error;
  throw fail('LOCAL_RETENTION_UNCERTAIN',error);}
}
