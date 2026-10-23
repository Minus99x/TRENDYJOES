/**
 * Local preview-only safeguards for delayed draft catalog snapshots.
 * These decisions never authorize inventory, pricing, customer identity or checkout.
 */
const own=(object,key)=>Object.prototype.hasOwnProperty.call(object,key);
const safeId=/^[a-z][a-z0-9-]{0,63}$/;

export function hasCustomerWork({layers=[],imported=null,calibration=null,saved=null,savedSnapshot=null,previewSelection=null,defaultSelection=null}={}){
 if(Array.isArray(layers)&&layers.length>0)return true;
 if(imported||calibration||saved||savedSnapshot)return true;
 if(previewSelection&&defaultSelection&&(
   previewSelection.colorId!==defaultSelection.colorId||previewSelection.sizeId!==defaultSelection.sizeId
 ))return true;
 return false;
}

/** Reject duplicate, colliding, malformed or flagged entries before modifying UI state. */
export function eligibleSnapshotEntries(entries,knownManifests){
 if(!Array.isArray(entries)||entries.length>250)return [];
 const seen=new Set(),accepted=[];
 for(const entry of entries){
  if(!entry||typeof entry!=='object'||Array.isArray(entry)||!entry.manifest||typeof entry.manifest!=='object'||Array.isArray(entry.manifest))continue;
  if(!Array.isArray(entry.issues)||entry.issues.length>0)continue;
  const {id,surfaces}=entry.manifest;
  if(typeof id!=='string'||!safeId.test(id)||['constructor','prototype','__proto__'].includes(id)||seen.has(id)||own(knownManifests,id))continue;
  if(typeof entry.title!=='string'||entry.title.length<1||entry.title.length>150)continue;
  if(!Array.isArray(surfaces)||surfaces.length===0||!surfaces[0]||typeof surfaces[0].id!=='string')continue;
  seen.add(id);accepted.push(entry);
 }
 return accepted;
}

/** Late arrival must not replace a user-chosen or edited product, even if a URL requested it. */
export function mayApplyDelayedEntry({initialEntryStatus,resolvedEntry,userInteracted,currentProductId,initialProductId,currentSnapshot,initialSnapshot,hasWork}){
 return initialEntryStatus==='UNKNOWN_PRODUCT'&&resolvedEntry?.status==='SELECTED'&&
  userInteracted===false&&hasWork===false&&currentProductId===initialProductId&&
  typeof currentSnapshot==='string'&&currentSnapshot===initialSnapshot;
}
