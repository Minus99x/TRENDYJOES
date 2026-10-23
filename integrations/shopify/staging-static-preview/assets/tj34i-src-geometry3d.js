/**
 * TrendyJoes procedural 3D CONCEPT meshes. Not measured manufacturing blanks.
 * Geometry and surface UV mappings are distinct for each product subtype.
 * The maps support exploration only; production requires scanned/supplier models,
 * verified print zones, calibrated UV assets, and signed-off materials.
 * Coordinate convention: +X right, +Y up, +Z toward front viewer.
 */
const v=(x,y,z)=>[x,y,z];
const finite=p=>Array.isArray(p)&&p.length===3&&p.every(Number.isFinite);
const tri=(out,a,b,c,material,side='other')=>out.push({a,b,c,material,side});
function polygonArea(points){let a=0;for(let i=0;i<points.length;i++){let p=points[i],q=points[(i+1)%points.length];a+=p[0]*q[1]-q[0]*p[1];}return a/2;}
function pointInside(a,b,c,p){const cross=(x,y,z)=>(y[0]-x[0])*(z[1]-x[1])-(y[1]-x[1])*(z[0]-x[0]); const x=cross(a,b,p),y=cross(b,c,p),z=cross(c,a,p);return x>=-1e-9&&y>=-1e-9&&z>=-1e-9;}
/** Convex-ear triangulation for simple polygons. Explicit failure on bad shapes. */
export function triangulatePolygon(outline){
 if(!Array.isArray(outline)||outline.length<3||outline.some(p=>!Array.isArray(p)||p.length!==2||!p.every(Number.isFinite)))throw Error('Invalid polygon');
 const points=polygonArea(outline)>=0?outline:outline.toReversed();
 const indices=points.map((_,i)=>i),result=[];
 const cross=(a,b,c)=>(b[0]-a[0])*(c[1]-a[1])-(b[1]-a[1])*(c[0]-a[0]);
 let watchdog=0;
 while(indices.length>3){
  if(++watchdog>1000)throw Error('Polygon triangulation stalled');
  let found=false;
  for(let i=0;i<indices.length;i++){
   const ia=indices[(i-1+indices.length)%indices.length],ib=indices[i],ic=indices[(i+1)%indices.length];
   const a=points[ia],b=points[ib],c=points[ic];
   if(cross(a,b,c)<1e-8)continue;
   if(indices.some(j=>j!==ia&&j!==ib&&j!==ic&&pointInside(a,b,c,points[j])))continue;
   result.push([a,b,c]);indices.splice(i,1);found=true;break;
  }
  if(!found)throw Error('Polygon is degenerate or non-simple');
 }
 result.push(indices.map(i=>points[i]));return result;
}
function extrusion(out,outline,frontZ,backZ,mat='fabric'){
 for(const [a,b,c] of triangulatePolygon(outline)){
  tri(out,v(...a,frontZ),v(...b,frontZ),v(...c,frontZ),mat,'front');
  tri(out,v(...c,backZ),v(...b,backZ),v(...a,backZ),mat,'back');
 }
 for(let i=0;i<outline.length;i++){
  const a=outline[i],b=outline[(i+1)%outline.length];
  tri(out,v(...a,frontZ),v(...a,backZ),v(...b,frontZ),'seam');
  tri(out,v(...b,frontZ),v(...a,backZ),v(...b,backZ),'seam');
 }
}
function box(out,x1,y1,z1,x2,y2,z2,material){
 const a=v(x1,y1,z1),b=v(x2,y1,z1),c=v(x2,y2,z1),d=v(x1,y2,z1),e=v(x1,y1,z2),f=v(x2,y1,z2),g=v(x2,y2,z2),h=v(x1,y2,z2);
 const faces=[[a,b,c,d],[f,e,h,g],[e,a,d,h],[b,f,g,c],[d,c,g,h],[e,f,b,a]];
 for(const [p,q,r,s] of faces){tri(out,p,q,r,material);tri(out,p,r,s,material);}
}
function circle(out,{top=1,bottom=-1,topRadius=.61,bottomRadius=.48,centerZ=0,segments=40,material='vessel'}){
 for(let i=0;i<segments;i++){
  const a=2*Math.PI*i/segments,b=2*Math.PI*(i+1)/segments;
  const p=v(Math.sin(a)*topRadius,top,Math.cos(a)*topRadius+centerZ);
  const q=v(Math.sin(b)*topRadius,top,Math.cos(b)*topRadius+centerZ);
  const s=v(Math.sin(a)*bottomRadius,bottom,Math.cos(a)*bottomRadius+centerZ);
  const t=v(Math.sin(b)*bottomRadius,bottom,Math.cos(b)*bottomRadius+centerZ);
  tri(out,p,s,q,material);tri(out,q,s,t,material);
  tri(out,v(0,top,centerZ),q,p,'rim');
  tri(out,v(0,bottom,centerZ),s,t,'rim');
 }
}
const garments={
 'crew-short-sleeve':{
  outline:[[-.47,1.04],[-.77,.95],[-1.10,.73],[-1.37,.28],[-1.05,.02],[-.78,.37],[-.70,-1.05],[.70,-1.05],[.78,.37],[1.05,.02],[1.37,.28],[1.10,.73],[.77,.95],[.47,1.04],[.34,.92],[0,.83],[-.34,.92]],
  neck:'crew'
 },
 'v-neck-short-sleeve':{
  outline:[[-.47,1.04],[-.77,.95],[-1.10,.73],[-1.37,.28],[-1.05,.02],[-.78,.37],[-.70,-1.05],[.70,-1.05],[.78,.37],[1.05,.02],[1.37,.28],[1.10,.73],[.77,.95],[.47,1.04],[0,.60]],
  neck:'v-neck'
 },
 'crew-long-sleeve':{
  outline:[[-.47,1.04],[-.75,.95],[-1.01,.72],[-1.54,-.55],[-1.08,-.72],[-.77,.22],[-.70,-1.05],[.70,-1.05],[.77,.22],[1.08,-.72],[1.54,-.55],[1.01,.72],[.75,.95],[.47,1.04],[.34,.92],[0,.83],[-.34,.92]],
  neck:'crew'
 },
 'hooded-pullover':{
  outline:[[-.50,.95],[-.82,.84],[-1.06,.55],[-1.45,-.40],[-1.00,-.59],[-.76,.16],[-.70,-1.05],[.70,-1.05],[.76,.16],[1.00,-.59],[1.45,-.40],[1.06,.55],[.82,.84],[.50,.95],[.35,.84],[0,.72],[-.35,.84]],
  neck:'hoodie'
 }
};
function createGarment(manifest,triangles){
 const spec=garments[manifest.geometry.subtype];if(!spec)return false;
 extrusion(triangles,spec.outline,.115,-.11,'fabric');
 if(spec.neck==='hoodie'){
  // Hood has its own actual thickness, offset behind the garment collar.
  extrusion(triangles,[[-.51,.73],[-.56,1.21],[-.42,1.47],[0,1.54],[.42,1.47],[.56,1.21],[.51,.73],[.25,.79],[0,.85],[-.25,.79]],.035,-.31,'hood');
  box(triangles,-.46,-.80,.119,.46,-.49,.147,'pocket');
 }
 return true;
}
function createBackpack(triangles){
 const body=[[-.56,.97],[-.76,.68],[-.80,-.74],[-.64,-1.04],[.64,-1.04],[.80,-.74],[.76,.68],[.56,.97]];
 extrusion(triangles,body,.24,-.24,'pack');
 extrusion(triangles,[[-.54,-.16],[-.57,-.78],[-.46,-.90],[.46,-.90],[.57,-.78],[.54,-.16]],.285,.243,'pocket');
 box(triangles,-.64,-.74,-.42,-.42,.94,-.24,'strap');
 box(triangles,.42,-.74,-.42,.64,.94,-.24,'strap');
 box(triangles,-.27,.89,-.21,.27,1.08,-.06,'strap');
}
function createRug(triangles){box(triangles,-1.45,-.037,-.95,1.45,.037,.95,'rug');}
/** Returns renderable triangles, or null for unsupported geometry (2D fallback). */
export function createConceptMesh(manifest){
 if(!manifest?.geometry?.subtype||!Array.isArray(manifest.surfaces))return null;
 const triangles=[];const {subtype}=manifest.geometry;
 if(manifest.geometry.kind==='garment'){if(!createGarment(manifest,triangles))return null;}
 else if(subtype==='tapered-cylinder')circle(triangles,{top:1,bottom:-1.08,topRadius:.63,bottomRadius:.48});
 else if(subtype==='backpack')createBackpack(triangles);
 else if(subtype==='rectangular-textile')createRug(triangles);
 else return null;
 if(triangles.some(t=>![t.a,t.b,t.c].every(finite)))throw Error('Nonfinite geometry');
 return {modelId:`concept-procedural-${subtype}`,status:'PROCEDURAL_CONCEPT_UNCALIBRATED',triangles,surfaceIds:manifest.surfaces.map(s=>s.id)};
}
function garmentSurface(surface,u,w){
 if(surface==='front')return v(-.51+1.02*u,.56-1.38*w,.135);
 if(surface==='back')return v(.51-1.02*u,.56-1.38*w,-.131);
 if(surface==='sleeve-left')return v(-1.17+.28*u, .58-.45*w,.145);
 return null;
}
/** Surface-local UV to 3D position. These mappings are conceptual and not DPI-calibrated. */
export function sampleConceptSurface(manifest,surfaceId,u,w){
 if(!manifest?.surfaces?.some(s=>s.id===surfaceId))return null;
 if(!Number.isFinite(u)||!Number.isFinite(w)||u<0||u>1||w<0||w>1)return null;
 const g=manifest.geometry;
 if(g.kind==='garment')return garmentSurface(surfaceId,u,w);
 if(g.subtype==='tapered-cylinder'&&surfaceId==='wrap'){
  const y=.77-1.56*w, t=(u-.5)*Math.PI*2, r=.48+(.63-.48)*(y+1.08)/2.08;
  return v(Math.sin(t)*r*1.015,y,Math.cos(t)*r*1.015);
 }
 if(g.subtype==='backpack'&&surfaceId==='front-panel')return v(-.48+.96*u,.47-1.05*w,.301);
 if(g.subtype==='rectangular-textile'&&surfaceId==='top')return v(-1.25+2.50*u,.048,.78-1.56*w);
 return null;
}
/** Build a gridded patch to conform to curved surfaces. UV stays continuous at cylinder seams. */
export function buildConceptSurfacePatch(manifest,surfaceId,{columns,rows}={}){
 const curved=manifest.geometry.subtype==='tapered-cylinder';
 const nx=columns??(curved?72:8),ny=rows??(curved?14:8);
 if(!Number.isInteger(nx)||!Number.isInteger(ny)||nx<1||ny<1||nx>128||ny>128)throw Error('Invalid patch divisions');
 const triangles=[];
 const point=(u,w)=>({xyz:sampleConceptSurface(manifest,surfaceId,u,w),uv:[u,w]});
 for(let j=0;j<ny;j++)for(let i=0;i<nx;i++){
  const u=i/nx,u2=(i+1)/nx,w=j/ny,w2=(j+1)/ny;
  const a=point(u,w),b=point(u2,w),c=point(u2,w2),d=point(u,w2);
  if([a,b,c,d].some(p=>!finite(p.xyz)))return null;
  triangles.push([a,b,c],[a,c,d]);
 }
 return {surfaceId,triangles,calibrated:false,uvMapping:'CONCEPT_ONLY'};
}
/** Orthographic-like perspective, 3D yaw/pitch orbit camera, pure to enable deterministic tests. */
export function project3D(point,{yaw=0,pitch=.1,zoom=1,distance=4.8,width=640,height=490}={}){
 if(!finite(point)||![yaw,pitch,zoom,distance,width,height].every(Number.isFinite)||zoom<=0||distance<=2||width<=0||height<=0)return null;
 const [x,y,z]=point,cy=Math.cos(yaw),sy=Math.sin(yaw),cx=Math.cos(pitch),sx=Math.sin(pitch);
 const xx=cy*x+sy*z,zz=-sy*x+cy*z,yy=cx*y-sx*zz,depth=sx*y+cx*zz;
 if(depth>=distance-.05)return null;
 const focal=Math.min(width*.86,height*.99)*1.45*zoom;
 return {x:width/2+xx*focal/(distance-depth),y:height/2-yy*focal/(distance-depth),depth};
}
export function triangleNormal(t){const a=t.a,b=t.b,c=t.c,ab=b.map((x,i)=>x-a[i]),ac=c.map((x,i)=>x-a[i]);const n=[ab[1]*ac[2]-ab[2]*ac[1],ab[2]*ac[0]-ab[0]*ac[2],ab[0]*ac[1]-ab[1]*ac[0]];const m=Math.hypot(...n)||1;return n.map(x=>x/m);}
