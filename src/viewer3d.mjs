/** Browser-only CPU mesh viewer for procedural CONCEPT models.
 * No external CDN/dependencies, WebGL, cookies, app installs or commerce calls.
 * UV composition uses affine triangle subdivision; it is visual only, NOT a proof.
 */
import {createConceptMesh,buildConceptSurfacePatch,project3D,triangleNormal} from './geometry3d.mjs';
const palette={fabric:[82,105,122],seam:[58,69,78],hood:[111,132,146],pocket:[68,91,108],vessel:[191,156,109],rim:[218,188,141],pack:[162,110,83],strap:[91,66,54],rug:[164,139,100]};
const cache=new Map();
function getArt(id,url,onReady){
 if(!url)return null;
 let o=cache.get(id);if(o?.url===url)return o.ready?o.img:null;
 const img=new Image();o={img,url,ready:false};cache.set(id,o);
 img.onload=()=>{o.ready=true;onReady?.();};img.onerror=()=>{o.ready=false;};img.src=url;return null;
}
function makeTexture(layers,artUrls,redraw){
 const tex=document.createElement('canvas');tex.width=512;tex.height=512;const c=tex.getContext('2d');
 for(const l of layers){
  const x=l.x*512,y=l.y*512,w=l.width*512,h=l.height*512;
  c.save();c.translate(x+w/2,y+h/2);c.rotate((l.rotationDeg||0)*Math.PI/180);
  if(l.type==='text'){
   c.fillStyle='#231F20';c.font=`bold ${Math.max(9,Math.min(62,h*.86))}px Georgia,serif`;
   c.textBaseline='middle';c.textAlign='center';c.fillText(l.value,0,0,w*.94);
  }else if(l.type==='artwork'){
   const img=getArt(l.artworkId,artUrls.get(l.artworkId),redraw);
   if(img){const r=Math.min(w/img.naturalWidth,h/img.naturalHeight);
    c.drawImage(img,-img.naturalWidth*r/2,-img.naturalHeight*r/2,img.naturalWidth*r,img.naturalHeight*r);
   }else{c.setLineDash([5,4]);c.strokeStyle='#7A2A30';c.strokeRect(-w/2,-h/2,w,h);c.font='18px Georgia';c.textAlign='center';c.fillStyle='#7A2A30';c.fillText('Artwork',0,2);}
  }
  c.restore();
 }
 return tex;
}
function affineTriangle(ctx,texture,uv,points){
 // Solve affine map source texture-pixels -> screen coordinates.
 const a=uv[0].map((x)=>x*texture.width),b=uv[1].map(x=>x*texture.width),c=uv[2].map(x=>x*texture.width);
 // texture is square in this v0.3 concept renderer.
 const D=a[0]*(b[1]-c[1])+b[0]*(c[1]-a[1])+c[0]*(a[1]-b[1]);
 if(Math.abs(D)<1e-7)return;
 const coeff=axis=>{
  const p=points.map(t=>t[axis]);
  return [
   (p[0]*(b[1]-c[1])+p[1]*(c[1]-a[1])+p[2]*(a[1]-b[1]))/D,
   (p[0]*(c[0]-b[0])+p[1]*(a[0]-c[0])+p[2]*(b[0]-a[0]))/D,
   (p[0]*(b[0]*c[1]-c[0]*b[1])+p[1]*(c[0]*a[1]-a[0]*c[1])+p[2]*(a[0]*b[1]-b[0]*a[1]))/D
  ];
 };
 const [xx,xy,xo]=coeff('x'),[yx,yy,yo]=coeff('y');
 ctx.save();ctx.beginPath();ctx.moveTo(points[0].x,points[0].y);ctx.lineTo(points[1].x,points[1].y);ctx.lineTo(points[2].x,points[2].y);ctx.closePath();ctx.clip();
 ctx.setTransform(xx,yx,xy,yy,xo,yo);ctx.drawImage(texture,0,0);ctx.restore();
}
function faceColor(t,conceptColorHex=null){
 const n=triangleNormal(t);const light=Math.max(.28,.65+(.25*n[0]+.24*n[1]+.35*n[2])*.65);
 let c=palette[t.material]||palette.fabric;
 // Tint the primary *concept* body and broad fabric panels only. Real model
 // materials, sublimation results and color-matched manufacturing remain unverified.
 if(typeof conceptColorHex==='string'&&/^#[0-9a-fA-F]{6}$/.test(conceptColorHex)&&['fabric','hood','pocket','vessel','pack','rug'].includes(t.material)){
  const rgb=[1,3,5].map(i=>parseInt(conceptColorHex.slice(i,i+2),16));
  const factor=t.material==='pocket'?.82:t.material==='hood'?.93:1;
  c=rgb.map(v=>v*factor);
 }
 return `rgb(${c.map(v=>Math.round(Math.min(255,v*light))).join(',')})`;
}
const finite=p=>p&&Number.isFinite(p.x)&&Number.isFinite(p.y)&&Number.isFinite(p.depth);
const midpoint=t=>(t[0].depth+t[1].depth+t[2].depth)/3;
function surfaceFacingCamera(manifest,id,yaw){
 // Skip patches on the invisible opposite torso face, so draft designs cannot bleed through.
 if(manifest.geometry.kind==='garment'){
  if(id==='back')return Math.cos(yaw)<-.03;
  if(id==='front'||id==='sleeve-left')return Math.cos(yaw)>.03;
 }
 if(manifest.geometry.subtype==='backpack')return Math.cos(yaw)>.03;
 return true;
}
/** Draw one concept mesh and optional artwork overlays. Returns render metadata for QA. */
export function render3D(canvas,manifest,layers,artUrls,{yaw=0,pitch=.08,zoom=1}={},redraw,externalMesh=null,conceptColorHex=null){
 const mesh=externalMesh||createConceptMesh(manifest);if(!mesh)return {supported:false,reason:'No matching 3D concept geometry'};
 const rect=canvas.getBoundingClientRect();const width=Math.max(1,Math.round(rect.width||canvas.clientWidth||680)),height=Math.max(1,Math.round(rect.height||canvas.clientHeight||490));
 const scale=Math.min(window.devicePixelRatio||1,2);canvas.width=Math.round(width*scale);canvas.height=Math.round(height*scale);
 const ctx=canvas.getContext('2d');ctx.setTransform(scale,0,0,scale,0,0);ctx.clearRect(0,0,width,height);
 const camera={yaw,pitch,zoom,distance:5.2,width,height};const renderables=[];
 for(const t of mesh.triangles){
  // Avoid depth-sorting artifacts from overlapping front/back faces of broad 2D extrusions.
  if(['garment','irregular'].includes(manifest.geometry.kind)) {
   if(t.side==='back'&&Math.cos(yaw)>.03)continue;
   if(t.side==='front'&&Math.cos(yaw)<-.03)continue;
  }
  const points=[t.a,t.b,t.c].map(p=>project3D(p,camera));if(points.every(finite))renderables.push({kind:'body',points,depth:midpoint(points),color:faceColor(t,conceptColorHex)});
 }
 const bySurface=new Map();for(const l of layers){if(!bySurface.has(l.surfaceId))bySurface.set(l.surfaceId,[]);bySurface.get(l.surfaceId).push(l);}
 for(const [surfaceId,used] of bySurface){
  if(!used.length||(!externalMesh&&!surfaceFacingCamera(manifest,surfaceId,yaw)))continue;
  const patch=externalMesh?{triangles:mesh.triangles.filter(t=>t.surfaceId===surfaceId&&t.uv).map(t=>[{xyz:t.a,uv:t.uv[0]},{xyz:t.b,uv:t.uv[1]},{xyz:t.c,uv:t.uv[2]}])}:buildConceptSurfacePatch(manifest,surfaceId);if(!patch||!patch.triangles.length)continue;
  const texture=makeTexture(used,artUrls,redraw);
  for(const t of patch.triangles){
   const points=t.map(p=>project3D(p.xyz,camera));if(points.every(finite))renderables.push({kind:'artwork',points,uv:t.map(p=>p.uv),texture,depth:midpoint(points)});
  }
 }
 renderables.sort((a,b)=>a.depth-b.depth); // Camera looks down -Z; more negative is farther.
 for(const t of renderables){
  if(t.kind==='artwork')affineTriangle(ctx,t.texture,t.uv,t.points);
  else{
   ctx.beginPath();ctx.moveTo(t.points[0].x,t.points[0].y);ctx.lineTo(t.points[1].x,t.points[1].y);ctx.lineTo(t.points[2].x,t.points[2].y);ctx.closePath();ctx.fillStyle=t.color;ctx.fill();
  }
 }
 // Development limitation is visible in HTML instead of drawn over product art.
 return {supported:true,modelId:mesh.modelId,source:externalMesh?'IMPORTED_UNVERIFIED':'PROCEDURAL_CONCEPT',renderedTriangles:renderables.length,calibrated:false};
}

/** Objective 34K: bounded, deterministic camera controls for keyboard, touch and
 * responsive static previews. This is visual-only and never approves geometry. */
export const CONCEPT_PREVIEW_CAMERA_DEFAULT=Object.freeze({yaw:.18,pitch:.10,zoom:1});
const cameraFail=()=>{throw new Error('INVALID_CONCEPT_CAMERA_ACTION');};
export function updateConceptPreviewCamera(camera,action){
 if(!camera||typeof camera!=='object'||!['yaw','pitch','zoom'].every(k=>Number.isFinite(camera[k]))||
    !action||typeof action!=='object'||Array.isArray(action)||typeof action.type!=='string')cameraFail();
 const next={yaw:camera.yaw,pitch:camera.pitch,zoom:camera.zoom};
 if(action.type==='RESET')return {...CONCEPT_PREVIEW_CAMERA_DEFAULT};
 if(action.type==='ORBIT'){
  if(!Number.isFinite(action.yawDelta)||!Number.isFinite(action.pitchDelta)||
     Math.abs(action.yawDelta)>4||Math.abs(action.pitchDelta)>4)cameraFail();
  next.yaw=Math.atan2(Math.sin(next.yaw+action.yawDelta),Math.cos(next.yaw+action.yawDelta));
  next.pitch=Math.max(-.7,Math.min(.7,next.pitch+action.pitchDelta));
 }else if(action.type==='ZOOM'){
  if(!Number.isFinite(action.factor)||action.factor<.5||action.factor>2)cameraFail();
  next.zoom=Math.max(.6,Math.min(1.8,next.zoom*action.factor));
 }else cameraFail();
 return next;
}
/** Returns null for Tab, typing, modifier-only and other browser-owned keys. */
export function conceptPreviewKeyAction(key){
 switch(key){
  case 'ArrowLeft':return {type:'ORBIT',yawDelta:-.22,pitchDelta:0};
  case 'ArrowRight':return {type:'ORBIT',yawDelta:.22,pitchDelta:0};
  case 'ArrowUp':return {type:'ORBIT',yawDelta:0,pitchDelta:-.12};
  case 'ArrowDown':return {type:'ORBIT',yawDelta:0,pitchDelta:.12};
  case '+':case '=':return {type:'ZOOM',factor:1.2};
  case '-':case '_':return {type:'ZOOM',factor:1/1.2};
  case 'Home':return {type:'RESET'};
  default:return null;
 }
}

/** Objective 34N: orient the concept camera to the selected design surface.
 * Pure visual navigation only: does not approve 3D geometry or print zones.
 * Switching to a garment back must reveal its back-side lettering without
 * requiring the customer to discover manual rotation controls.
 */
export function conceptCameraForSurface(manifest,surfaceId,{zoom=1}={}){
 if(!manifest || typeof manifest!=='object' || !Array.isArray(manifest.surfaces) ||
    typeof surfaceId!=='string' || !manifest.surfaces.some(s=>s.id===surfaceId) ||
    !Number.isFinite(zoom) || zoom<.6 || zoom>1.8)cameraFail();
 const yaw=manifest.geometry?.kind==='garment' && surfaceId==='back'
  ? Math.PI-CONCEPT_PREVIEW_CAMERA_DEFAULT.yaw
  : manifest.geometry?.kind==='garment' && surfaceId==='sleeve-left'
    ? .9 : CONCEPT_PREVIEW_CAMERA_DEFAULT.yaw;
 return {yaw,pitch:CONCEPT_PREVIEW_CAMERA_DEFAULT.pitch,zoom};
}

/** Objective 34L: pure, fail-closed pointer gesture contract for concept cameras.
 * No browser globals, storage, network or manufacturing authorization. */
const validConceptPointer = p => p && typeof p === 'object' &&
 Number.isSafeInteger(p.pointerId) && p.pointerId >= 0 &&
 Number.isFinite(p.x) && Number.isFinite(p.y) &&
 Math.abs(p.x) <= 1e7 && Math.abs(p.y) <= 1e7;
const validPointerEvent = e => e && typeof e === 'object' &&
 Number.isSafeInteger(e.pointerId) && e.pointerId >= 0 &&
 Number.isFinite(e.clientX) && Number.isFinite(e.clientY) &&
 Math.abs(e.clientX) <= 1e7 && Math.abs(e.clientY) <= 1e7;
export function beginConceptPointerDrag(active,event){
 if(active != null || !validPointerEvent(event) || event.isPrimary === false || event.button !== 0)return null;
 return {pointerId:event.pointerId,x:event.clientX,y:event.clientY};
}
export function moveConceptPointerDrag(active,event){
 if(!validConceptPointer(active))return {gesture:null,action:null};
 if(!validPointerEvent(event) || event.pointerId !== active.pointerId || event.isPrimary === false)
  return {gesture:active,action:null};
 // A released mouse button outside the canvas must not cause a ghost drag.
 if(event.pointerType === 'mouse' && event.buttons === 0)return {gesture:null,action:null};
 const yawDelta=Math.max(-4,Math.min(4,(event.clientX-active.x)*.008));
 const pitchDelta=Math.max(-4,Math.min(4,(event.clientY-active.y)*.005));
 return {gesture:{pointerId:active.pointerId,x:event.clientX,y:event.clientY},
  action: yawDelta===0 && pitchDelta===0 ? null : {type:'ORBIT',yawDelta,pitchDelta}};
}
export function endConceptPointerDrag(active,event){
 if(!validConceptPointer(active))return null;
 return event && event.pointerId === active.pointerId ? null : active;
}
