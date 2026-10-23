/** Imported GLBs are preview-only and never silently activate unsupported 3D. */
export function permittedPreviewMode({requestedMode,product,imported}={}){
 if(!['2d','3d'].includes(requestedMode))return '2d';
 if(requestedMode==='2d')return '2d';
 if(imported?.asset?.status==='IMPORTED_UNVERIFIED'&&imported?.asset?.triangles?.length>0&&
   imported?.approval==='UNVERIFIED_LOCAL_PREVIEW_ONLY')return '3d';
 const procedural=product?.geometry?.subtype;
 return ['crew-short-sleeve','v-neck-short-sleeve','crew-long-sleeve','hooded-pullover','tapered-cylinder','backpack','rectangular-textile'].includes(procedural)?'3d':'2d';
}
export function previewModelStatus({product,imported}={}){
 if(imported?.asset?.status==='IMPORTED_UNVERIFIED')return 'Imported GLB concept · unverified, not manufacturable';
 return permittedPreviewMode({requestedMode:'3d',product,imported})==='3d'?'Procedural 3D concept · not calibrated':'2D silhouette only · no approved 3D model';
}
