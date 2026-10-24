/** Local concept-only variant chooser. Never emits SKU, inventory, order or price. */
const label=s=>typeof s==='string'&&s.length>0&&s.length<=48&&/^[a-zA-Z0-9 ._-]+$/.test(s);
export function buildPreviewVariantChoices({sizes,colors,surfaces}={}){
 const arrays=[sizes,colors,surfaces];if(arrays.some(a=>!Array.isArray(a)||a.length<1||a.length>12||a.some(x=>!label(x))||new Set(a.map(x=>x.toLowerCase())).size!==a.length)||arrays.reduce((n,a)=>n*a.length,1)>144)throw new TypeError('PREVIEW_VARIANTS_INPUT');
 const entries=[];for(const size of sizes)for(const color of colors)for(const surface of surfaces)entries.push(Object.freeze({size,color,surface,localOnly:true}));
 return Object.freeze({schema:'TJ-PREVIEW-VARIANTS-1',count:entries.length,choices:Object.freeze(entries),inventoryVerified:false,priceApproved:false,checkoutEnabled:false,localOnly:true});
}
