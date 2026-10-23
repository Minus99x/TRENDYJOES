/** Human-readable active-surface state without credential or artwork URL leakage. */
const safe=(s,max=90)=>typeof s==='string'?s.replace(/[\u0000-\u001f\u007f]/g,' ').trim().slice(0,max):'';
export function describeActivePreview({product,surfaceId,layers,selectedId,mode}={}){
 if(!product||!Array.isArray(product.surfaces)||!Array.isArray(layers))return 'Concept preview unavailable.';
 const surface=product.surfaces.find(s=>s.id===surfaceId);
 if(!surface)return 'Design surface unavailable.';
 const visible=layers.filter(l=>l?.surfaceId===surfaceId),selected=visible.find(l=>l.id===selectedId);
 const category=safe(product.category||product.label||'merchandise');
 return `${category} — ${safe(surface.label||surface.id)}. ${visible.length} design element${visible.length===1?'':'s'} on this surface. ${selected?'Selected design element is ready for positioning.':'Choose a design element to position.'} ${mode==='3d'?'Concept 3D view.':'Editable 2D view.'} Unverified, not ready to manufacture or order.`;
}
