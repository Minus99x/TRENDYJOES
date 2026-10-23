/** Local-only proof storage. No user auth, no cloud storage, no production acceptance. */
import {mkdir,writeFile,readFile,stat} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {randomBytes,createHash,timingSafeEqual} from 'node:crypto';
import {validateComposition,preflight} from './core.mjs';
import {MANIFEST_BY_ID} from './catalog.mjs';
import {normalizePreviewSelection} from './preview-product-options.mjs';
import {inspectRaster} from './image-inspection.mjs';
import {writeLocalArtworkPair} from './preview-local-artwork-persistence.mjs';
import {withLocalArtworkLease} from './preview-local-artwork-coordination.mjs';
const MAX_IMAGE_BYTES=5*1024*1024;
const random=bytes=>randomBytes(bytes).toString('hex');
const bad=(message,status=400)=>Object.assign(new Error(message),{status});
const safeKey=v=>typeof v==='string'&&/^[A-Za-z0-9_-]{1,100}$/.test(v);
const safeDesign=v=>typeof v==='string'&&/^TJ-[A-F0-9]{24}$/.test(v);
const equal=(x,y)=>{if(typeof x!=='string'||typeof y!=='string'||x.length!==y.length)return false;return timingSafeEqual(Buffer.from(x),Buffer.from(y));};
export class LocalDesignStore {
 constructor(root,{manifests=MANIFEST_BY_ID,artworkIO=null}={}){this.root=resolve(root);this.designs=join(this.root,'designs');this.artworks=join(this.root,'artworks');this.manifests=manifests;this.artworkIO=artworkIO;}
 async init(){await mkdir(this.designs,{recursive:true,mode:0o700});await mkdir(this.artworks,{recursive:true,mode:0o700});}
 async putArtwork(bytes,claimedType){
  if(!Buffer.isBuffer(bytes)||bytes.length>MAX_IMAGE_BYTES)throw bad('Artwork exceeds 5 MB or is invalid',413);
  let type;try{type=inspectRaster(bytes,claimedType);}catch(e){throw bad(e.message);}
  const id=`art_${random(16)}`, grant=random(32);const digest=createHash('sha256').update(bytes).digest('hex');
  const info={id,mediaType:type.mediaType,extension:type.extension,width:type.width,height:type.height,bytes:bytes.length,sha256:digest,grantSha256:createHash('sha256').update(grant).digest('hex'),createdAt:new Date().toISOString()};
  await withLocalArtworkLease(this.root,()=>writeLocalArtworkPair({directory:this.artworks,id,extension:info.extension,bytes,metadata:info,io:this.artworkIO??undefined}));
  return {id,grant,width:info.width,height:info.height,mediaType:info.mediaType,bytes:info.bytes};
 }
 async assertGrant(id,grant){
  if(!/^art_[a-f0-9]{32}$/.test(id||''))throw bad('Invalid artwork reference');
  let meta;try{meta=JSON.parse(await readFile(join(this.artworks,id+'.json'),'utf8'));}catch{throw bad('Artwork not found',404);}
  if(!equal(meta.grantSha256,createHash('sha256').update(String(grant||'')).digest('hex')))throw bad('Artwork access denied',403);
  return meta;
 }
 async readArtwork(id,grant){
  const meta=await this.assertGrant(id,grant);
  if(!['png','jpeg','webp'].includes(meta.extension)||meta.id!==id)throw bad('Artwork metadata damaged',409);
  let bytes;try{bytes=await readFile(join(this.artworks,id+'.'+meta.extension));}catch{throw bad('Artwork missing or damaged',409);}
  if(bytes.length!==meta.bytes||createHash('sha256').update(bytes).digest('hex')!==meta.sha256)throw bad('Artwork checksum mismatch',409);
  try{inspectRaster(bytes,meta.mediaType);}catch{throw bad('Artwork structure changed',409);}
  return {meta,bytes};
 }
 async assertArtworkIntegrity(id){
  if(!/^art_[a-f0-9]{32}$/.test(id||''))throw bad('Invalid artwork identity');
  let meta,bytes;
  try{
   meta=JSON.parse(await readFile(join(this.artworks,id+'.json'),'utf8'));
   if(meta.id!==id||!['png','jpeg','webp'].includes(meta.extension))throw Error('metadata mismatch');
   bytes=await readFile(join(this.artworks,id+'.'+meta.extension));
  }catch{throw bad('Artwork missing or damaged',409);}
  if(createHash('sha256').update(bytes).digest('hex')!==meta.sha256||bytes.length!==meta.bytes)throw bad('Artwork checksum mismatch',409);
  try{inspectRaster(bytes,meta.mediaType);}catch{throw bad('Artwork structure changed',409);}
  return {id,sha256:meta.sha256,bytes:meta.bytes};
 }
 async validateDraft(input){
  if(!input||typeof input!=='object'||!safeKey(input.productManifestId))throw bad('Product manifest ID required');
  const product=this.manifests[input.productManifestId];if(!product)throw bad('Unknown product manifest');
  const layers=input.layers;if(!Array.isArray(layers)||layers.length>50)throw bad('Layers must be a list of at most 50');
  const errors=validateComposition(product,{layers});if(errors.length)throw bad('Invalid composition: '+errors.map(e=>e.code).join(', '));
  const grants=input.artworkGrants||{};
  for(const l of layers){if(l.type==='artwork')await this.assertGrant(l.artworkId,grants[l.artworkId]);}
  const safeLayers=layers.map(l=>{
   // Store only explicitly permitted composition properties, no tokens, markup or foreign keys.
   const keys=['id','type','surfaceId','x','y','width','height','rotationDeg','scaleFactor','value','artworkId'];
   return Object.fromEntries(keys.filter(k=>l[k]!==undefined).map(k=>[k,l[k]]));
  });
  return {product,productManifestId:product.id,layers:safeLayers,previewSelection:normalizePreviewSelection(product,input.previewSelection),preflight:preflight(product,{layers:safeLayers})};
 }
 async putDesign(input){return withLocalArtworkLease(this.root,async()=>{
  const parsed=await this.validateDraft(input);const reference=`TJ-${random(12).toUpperCase()}`,ownerToken=random(32);
  const record={reference,productManifestId:parsed.productManifestId,revision:1,previewOnly:true,productionApproved:false,checkoutEnabled:false,layers:parsed.layers,previewSelection:parsed.previewSelection,createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()};
  const dirname=join(this.designs,reference);await mkdir(dirname,{mode:0o700});
  await writeFile(join(dirname,'owner.sha256'),createHash('sha256').update(ownerToken).digest('hex'),{flag:'wx',mode:0o600});
  await writeFile(join(dirname,'1.json'),JSON.stringify(record),{flag:'wx',mode:0o600});
  return {reference,ownerToken,revision:1,previewOnly:true,productionApproved:false,checkoutEnabled:false};
 });}
 async authenticate(reference,token){
  if(!safeDesign(reference))throw bad('Unknown design reference',404);
  let stored;try{stored=(await readFile(join(this.designs,reference,'owner.sha256'),'utf8')).trim();}catch{throw bad('Unknown design reference',404);}
  if(!equal(stored,createHash('sha256').update(String(token||'')).digest('hex')))throw bad('Design access denied',403);
 }
 async latestRevision(reference){
  let i=1;for(;;i++)try{await stat(join(this.designs,reference,`${i}.json`));}catch{return i-1;}
 }
 async getDesign(reference,token,revision){
  await this.authenticate(reference,token);const version=revision||await this.latestRevision(reference);
  if(!Number.isSafeInteger(version)||version<1)throw bad('Bad revision');
  try{return JSON.parse(await readFile(join(this.designs,reference,`${version}.json`),'utf8'));}catch{throw bad('Revision not found',404);}
 }
 async reviseDesign(reference,token,input){return withLocalArtworkLease(this.root,async()=>{
  await this.authenticate(reference,token);const latest=await this.getDesign(reference,token);
  if(input?.expectedRevision!==latest.revision)throw bad('Revision conflict; reload before editing',409);
  if(input?.productManifestId!==latest.productManifestId)throw bad('Product cannot change within a saved draft');
  const effectiveInput=Object.hasOwn(input,'previewSelection')?input:{...input,previewSelection:latest.previewSelection};
  const parsed=await this.validateDraft(effectiveInput);
  const record={...latest,layers:parsed.layers,previewSelection:parsed.previewSelection,revision:latest.revision+1,updatedAt:new Date().toISOString()};
  await writeFile(join(this.designs,reference,`${record.revision}.json`),JSON.stringify(record),{flag:'wx',mode:0o600});
  return {reference,revision:record.revision,previewOnly:true,productionApproved:false,checkoutEnabled:false};
 });}
}
