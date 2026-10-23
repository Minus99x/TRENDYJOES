/** Sampled concept-only UV overlap detector. Samples never certify full production coverage. */
import {rotatedBounds} from './core.mjs';
import {uvPointInTriangle} from './preview-uv-triangle.mjs';
const deny=(code)=>Object.freeze({covered:false,reason:code,sampleCount:0,missingSamples:[],manufacturingApproved:false});
export function checkPreviewArtworkUvFootprint(layer,inspection,{grid=5}={}){
 if(!Number.isSafeInteger(grid)||grid<3||grid>11||!layer||!inspection||
  typeof layer.surfaceId!=='string'||!Array.isArray(inspection.asset?.triangles)||inspection.asset.triangles.length>45000||
  ![layer.x,layer.y,layer.width,layer.height,layer.rotationDeg??0].every(Number.isFinite)||
  layer.width<=0||layer.height<=0)return deny('INVALID_PREVIEW_UV_INPUT');
 const bounds=rotatedBounds(layer);
 if([bounds.left,bounds.right,bounds.top,bounds.bottom].some(x=>!Number.isFinite(x)||x<0||x>1))return deny('OUTSIDE_PREVIEW_ZONE');
 const mapped=inspection.asset.triangles.filter(t=>t?.surfaceId===layer.surfaceId);
 if(mapped.some(t=>!Array.isArray(t.uv)||t.uv.length!==3||t.uv.some(u=>!Array.isArray(u)||u.length!==2||u.some(v=>typeof v!=='number'||!Number.isFinite(v)||v<0||v>1))))return deny('INVALID_MAPPED_UV');
 if(mapped.some(t=>{const [a,b,c]=t.uv;return Math.abs((b[0]-a[0])*(c[1]-a[1])-(b[1]-a[1])*(c[0]-a[0]))<=1e-12;}))return deny('DEGENERATE_MAPPED_UV');
 const tris=mapped;
 if(!tris.length)return deny('NO_MAPPED_UV_SURFACE');
 if(tris.length>5000)return deny('UV_PREVIEW_COMPLEXITY_LIMIT');
 const cx=layer.x+layer.width/2,cy=layer.y+layer.height/2,a=(layer.rotationDeg??0)*Math.PI/180;
 const cos=Math.cos(a),sin=Math.sin(a),missingSamples=[];
 for(let i=0;i<grid;i++)for(let j=0;j<grid;j++){
  const dx=((i+.5)/grid-.5)*layer.width,dy=((j+.5)/grid-.5)*layer.height;
  const pt=[cx+dx*cos-dy*sin,cy+dx*sin+dy*cos];
  if(!tris.some(t=>uvPointInTriangle(pt,t.uv)))missingSamples.push([i,j]);
 }
 return Object.freeze({covered:missingSamples.length===0,reason:missingSamples.length?'UV_PREVIEW_GAP':'SAMPLED_ONLY',
  sampleCount:grid*grid,missingSamples:Object.freeze(missingSamples),manufacturingApproved:false});
}
