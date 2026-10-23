/** Objective 35T: local-only two-file artwork publication, no hosted durability claim. */
import * as fs from 'node:fs/promises';
import {join} from 'node:path';
import {randomBytes} from 'node:crypto';
const idPattern=/^art_[a-f0-9]{32}$/;
const extensions=new Set(['png','jpeg','webp']);
const fail=(code,cause)=>Object.assign(new Error(code),{code,cause});

/**
 * Stage complete metadata first, create image exclusively, then hard-link metadata
 * into its final name without overwriting another record. Only after the link is
 * created is the pair published. A process crash can leave incomplete artifacts;
 * those require operator review and must NEVER be silently swept.
 */
export async function writeLocalArtworkPair({directory,id,extension,bytes,metadata,io=fs,nonce=randomBytes(12).toString('hex')}={}){
 if(typeof directory!=='string'||!idPattern.test(id)||!extensions.has(extension)||
  !Buffer.isBuffer(bytes)||!metadata||metadata.id!==id||metadata.extension!==extension||
  !/^[a-f0-9]{24}$/.test(nonce))throw fail('LOCAL_ARTWORK_WRITE_INVALID');
 const image=join(directory,`${id}.${extension}`),final=join(directory,`${id}.json`);
 const staged=join(directory,`.${id}.pending-${nonce}.json`);
 let stagedOwned=false,imageOwned=false,published=false;
 try{
  await io.writeFile(staged,JSON.stringify(metadata),{flag:'wx',mode:0o600});stagedOwned=true;
  await io.writeFile(image,bytes,{flag:'wx',mode:0o600});imageOwned=true;
  await io.link(staged,final);published=true;
  // Failure to remove the extra link does not invalidate the already published
  // image/metadata pair. Leave it for read-only orphan inspection.
  try{await io.unlink(staged);}catch{}
  return Object.freeze({published:true});
 }catch(error){
  if(published)throw fail('LOCAL_ARTWORK_PUBLISHED_CLEANUP_UNCERTAIN',error);
  const failures=[];
  if(imageOwned)try{await io.unlink(image);}catch(e){failures.push(e);}
  if(stagedOwned)try{await io.unlink(staged);}catch(e){failures.push(e);}
  if(failures.length)throw fail('LOCAL_ARTWORK_ROLLBACK_UNCERTAIN',error);
  throw error;
 }
}

/** Bounded read-only inventory; never deletes, authenticates, or repairs files. */
export async function inspectLocalArtworkOrphans(directory,{io=fs,maxEntries=10000}={}){
 if(typeof directory!=='string'||!Number.isSafeInteger(maxEntries)||maxEntries<1||maxEntries>100000)
  throw fail('LOCAL_ARTWORK_INSPECTION_INVALID');
 const entries=await io.readdir(directory,{withFileTypes:true});
 if(entries.length>maxEntries)throw fail('LOCAL_ARTWORK_INSPECTION_BOUNDED');
 const records=new Map(),pending=[];
 for(const entry of entries){
  const name=entry.name;
  if(/^\.art_[a-f0-9]{32}\.pending-[a-f0-9]{24}\.json$/.test(name)){
   pending.push(name);continue;
  }
  const m=/^(art_[a-f0-9]{32})\.(png|jpeg|webp|json)$/.exec(name);
  if(!m)continue;
  const r=records.get(m[1])??{id:m[1],metadata:false,images:[],unsafe:[]};
  if(!entry.isFile())r.unsafe.push(name);
  else if(m[2]==='json')r.metadata=true;
  else r.images.push(m[2]);
  records.set(m[1],r);
 }
 const incomplete=[...records.values()].filter(r=>!r.metadata||r.images.length!==1||r.unsafe.length).sort((a,b)=>a.id.localeCompare(b.id));
 return Object.freeze({incomplete,pending:pending.sort(),scannedEntries:entries.length,
  safeToAutoDelete:false,productionEvidence:false});
}
