/** Preview-only nearest swatch match in ordinary RGB; approximate, not color-managed proof. */
const hex=s=>typeof s==='string'&&/^#[0-9a-fA-F]{6}$/.test(s);
const rgb=s=>[1,3,5].map(i=>parseInt(s.slice(i,i+2),16));
export function matchPreviewPalette({color,swatches}={}){
 if(!hex(color)||!Array.isArray(swatches)||swatches.length===0||swatches.length>32||swatches.some(s=>!s||typeof s.label!=='string'||!/^[-a-zA-Z0-9 ]{1,40}$/.test(s.label)||!hex(s.hex))||new Set(swatches.map(x=>x.label.toLowerCase())).size!==swatches.length)throw new TypeError('PREVIEW_PALETTE_INPUT');
 const c=rgb(color),ranked=swatches.map(s=>{const r=rgb(s.hex),distance=Math.hypot(...r.map((v,i)=>v-c[i]));return {label:s.label,hex:s.hex.toUpperCase(),distance};}).sort((a,b)=>a.distance-b.distance||a.label.localeCompare(b.label));
 const first=ranked[0];return Object.freeze({schema:'TJ-PREVIEW-PALETTE-1',closestLabel:first.label,closestHex:first.hex,rgbDistance:Number(first.distance.toFixed(4)),approximate:true,colorManaged:false,localOnly:true});
}
