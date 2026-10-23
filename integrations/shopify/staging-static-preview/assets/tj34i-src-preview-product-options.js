/** Safe normalized, manifest-driven concept-only blank selection.
 * Never infer inventory, actual supplier finishes, manufacturing suitability or Shopify variants.
 * New merchandise categories extend through manifest metadata, not apparel-specific code.
 */
const bad=()=>Object.assign(new Error('Invalid concept product option selection'),{status:400});
const safe=(items)=>Array.isArray(items)?items:[];
export function getPreviewOptions(manifest){
 const colors=safe(manifest?.previewOptions?.colors);
 const sizes=safe(manifest?.previewOptions?.sizes);
 return {colors,sizes};
}
export function normalizePreviewSelection(manifest,requested){
 const {colors,sizes}=getPreviewOptions(manifest);
 if(requested!==undefined && (requested===null||typeof requested!=='object'||Array.isArray(requested)||Object.keys(requested).some(k=>!['colorId','sizeId'].includes(k))))throw bad();
 const colorId=requested?.colorId??colors[0]?.id??null;
 const sizeId=requested?.sizeId??sizes[0]?.id??null;
 if(typeof colorId!==(colorId===null?'object':'string')||typeof sizeId!==(sizeId===null?'object':'string'))throw bad();
 if(colors.length?!colors.some(c=>c.id===colorId):colorId!==null)throw bad();
 if(sizes.length?!sizes.some(s=>s.id===sizeId):sizeId!==null)throw bad();
 return {colorId,sizeId};
}
export function describePreviewSelection(manifest,selection){
 const valid=normalizePreviewSelection(manifest,selection);
 const {colors,sizes}=getPreviewOptions(manifest);
 return {color:colors.find(c=>c.id===valid.colorId)||null,size:sizes.find(s=>s.id===valid.sizeId)||null};
}
