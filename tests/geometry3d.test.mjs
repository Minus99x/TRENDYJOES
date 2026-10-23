import test from 'node:test';
import assert from 'node:assert/strict';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {createConceptMesh,buildConceptSurfacePatch,sampleConceptSurface,project3D,triangulatePolygon,triangleNormal} from '../src/geometry3d.mjs';
const get=id=>PRODUCT_MANIFESTS.find(m=>m.id===id);
test('each existing manifest has an independent, finite 3D concept mesh',()=>{
 const ids=new Set();
 for(const m of PRODUCT_MANIFESTS){if(m.id==='concept-sneaker'){assert.equal(createConceptMesh(m),null);continue;}const x=createConceptMesh(m);assert.ok(x,m.id);assert.ok(x.triangles.length>=12,m.id);assert.match(x.status,/UNCALIBRATED/);ids.add(x.modelId);
  for(const t of x.triangles){for(const p of [t.a,t.b,t.c]){assert.equal(p.length,3);assert.ok(p.every(Number.isFinite));}assert.ok(triangleNormal(t).every(Number.isFinite));}
 }
 assert.equal(ids.size,PRODUCT_MANIFESTS.length-1);
});
test('crew, V neck, long-sleeve and hoodie have distinct mesh silhouette geometry',()=>{
 const groups=['concept-crew-tee','concept-v-tee','concept-long-sleeve','concept-hoodie'].map(id=>createConceptMesh(get(id)));
 const fingerprints=groups.map(g=>JSON.stringify(g.triangles.map(t=>t.a)));
 assert.equal(new Set(fingerprints).size,groups.length);
 assert.ok(groups[3].triangles.length>groups[0].triangles.length);
});
test('all printable manifest surfaces produce continuous conceptual UV patches',()=>{
 for(const m of PRODUCT_MANIFESTS){
  if(m.id==='concept-sneaker')continue;
  for(const s of m.surfaces){const mesh=buildConceptSurfacePatch(m,s.id);assert.ok(mesh,`${m.id} ${s.id}`);
   assert.equal(mesh.calibrated,false);assert.equal(mesh.triangles.length,(m.geometry.kind==='cylinder'?72*14:8*8)*2);
   for(const t of mesh.triangles)for(const q of t){assert.ok(q.xyz.every(Number.isFinite));assert.ok(q.uv.every(v=>v>=0&&v<=1));}
  }
 }
});
test('garment front and back map to opposite physical model sides',()=>{
 const m=get('concept-crew-tee');const front=sampleConceptSurface(m,'front',.37,.51);const back=sampleConceptSurface(m,'back',.37,.51);
 assert.ok(front[2]>0&&back[2]<0);
 assert.ok(front[0]*back[0]<0);
});
test('tumbler is tapered and its wrap is curved with a consistent seam',()=>{
 const m=get('concept-tumbler');const left=sampleConceptSurface(m,'wrap',0,.5),right=sampleConceptSurface(m,'wrap',1,.5);
 assert.ok(Math.hypot(...left.map((v,i)=>v-right[i]))<1e-8);
 const t=sampleConceptSurface(m,'wrap',.5,0),b=sampleConceptSurface(m,'wrap',.5,1);
 assert.ok(Math.hypot(t[0],t[2])>Math.hypot(b[0],b[2]));
 const side=sampleConceptSurface(m,'wrap',.75,.5);assert.ok(Math.abs(side[0])>.4);
});
test('rug top is horizontal and backpack surface is front-facing',()=>{
 const rug=get('concept-rug'),pack=get('concept-backpack');
 const q=sampleConceptSurface(rug,'top',.2,.8),r=sampleConceptSurface(rug,'top',.8,.2);
 assert.equal(q[1],r[1]);assert.ok(sampleConceptSurface(pack,'front-panel',.5,.5)[2]>.24);
});
test('unknown products and invalid surface coordinates safely fall back',()=>{
 assert.equal(createConceptMesh({geometry:{kind:'other',subtype:'unknown'},surfaces:[]}),null);
 const m=get('concept-tumbler');assert.equal(sampleConceptSurface(m,'invalid',.5,.5),null);
 assert.equal(sampleConceptSurface(m,'wrap',-0.001,.5),null);
 assert.equal(sampleConceptSurface(m,'wrap',NaN,.5),null);
});
test('camera orbit and zoom are deterministic, finite, and directional',()=>{
 const p=[.7,.2,.5];const front=project3D(p,{yaw:0}),back=project3D(p,{yaw:Math.PI});assert.ok(front&&back);
 assert.ok(front.x>320&&back.x<320);
 const zoomed=project3D(p,{zoom:1.5});assert.ok(Math.abs(zoomed.x-320)>Math.abs(front.x-320));
 assert.equal(project3D(p,{distance:0.1}),null);
});
test('triangulation supports concave neck openings and rejects malformed outlines',()=>{
 const t=triangulatePolygon([[0,0],[2,0],[2,2],[1,1],[0,2]]);assert.equal(t.length,3);
 assert.throws(()=>triangulatePolygon([[0,0],[1,0]]));
});
test('browser view explicitly preserves 2D editing and never enables checkout',async()=>{
 const fs=await import('node:fs/promises');const h=await fs.readFile(new URL('../demo/index.html',import.meta.url),'utf8');
 for(const id of ['mode-2d','mode-3d','stage','stage-3d','view-front','view-back','orbit-left','orbit-right','view-reset'])assert.ok(h.includes(`id="${id}"`));
 assert.ok(h.includes('Checkout unavailable'));assert.ok(h.includes('disabled class="disabled-checkout"'));
});
