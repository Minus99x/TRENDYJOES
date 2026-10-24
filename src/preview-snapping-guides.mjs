/** Deterministic magnetic guides in millimeters; no editor or product state mutated. */
const valid=n=>typeof n==='number'&&Number.isFinite(n)&&Math.abs(n)<=100000;
export function snapPreviewPosition({x,y,zoneWidth,zoneHeight,width,height,threshold=2,gridMm=null}={}){
 if(![x,y,zoneWidth,zoneHeight,width,height,threshold].every(valid)||width<=0||height<=0||zoneWidth<=0||zoneHeight<=0||threshold<0||threshold>100||gridMm!==null&&(!valid(gridMm)||gridMm<=0))throw new RangeError('PREVIEW_SNAP_INPUT');
 const axis=(p,z,size)=>{const targets=[{value:0,guide:'edge-start'},{value:(z-size)/2,guide:'center'},{value:z-size,guide:'edge-end'}];if(gridMm!==null)targets.push({value:Math.round(p/gridMm)*gridMm,guide:'grid'});
  const options=targets.filter(t=>Math.abs(t.value-p)<=threshold).sort((a,b)=>Math.abs(a.value-p)-Math.abs(b.value-p)||['edge-start','center','edge-end','grid'].indexOf(a.guide)-['edge-start','center','edge-end','grid'].indexOf(b.guide));const best=options[0];return Object.freeze({position:best?.value??p,guide:best?.guide??null});};
 const sx=axis(x,zoneWidth,width),sy=axis(y,zoneHeight,height);
 return Object.freeze({schema:'TJ-PREVIEW-SNAP-1',x:sx.position,y:sy.position,xGuide:sx.guide,yGuide:sy.guide,localOnly:true});
}
