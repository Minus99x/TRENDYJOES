/** Rectangular print-zone collision warnings, scoped to the exact selected surface. */
const finite=n=>typeof n==='number'&&Number.isFinite(n)&&Math.abs(n)<=100000;
const id=s=>typeof s==='string'&&s.length>0&&s.length<=80&&/^[a-zA-Z0-9_-]+$/.test(s);
export function analyzePreviewOverlaps({surfaceId,rectangles}={}){
 if(!id(surfaceId)||!Array.isArray(rectangles)||rectangles.length>64||rectangles.some(r=>!r||!id(r.id)||!id(r.surfaceId)||![r.x,r.y,r.width,r.height].every(finite)||r.width<=0||r.height<=0)||new Set(rectangles.map(r=>r.id)).size!==rectangles.length)throw new TypeError('PREVIEW_OVERLAP_INPUT');
 const chosen=rectangles.filter(r=>r.surfaceId===surfaceId),pairs=[];
 for(let i=0;i<chosen.length;i++)for(let j=i+1;j<chosen.length;j++){const a=chosen[i],b=chosen[j],overlapWidth=Math.min(a.x+a.width,b.x+b.width)-Math.max(a.x,b.x),overlapHeight=Math.min(a.y+a.height,b.y+b.height)-Math.max(a.y,b.y);if(overlapWidth>0&&overlapHeight>0)pairs.push(Object.freeze({firstId:a.id,secondId:b.id,areaMm2:overlapWidth*overlapHeight}));}
 return Object.freeze({schema:'TJ-PREVIEW-OVERLAP-1',surfaceId,overlapCount:pairs.length,pairs:Object.freeze(pairs),localOnly:true,manufacturingApproved:false});
}
