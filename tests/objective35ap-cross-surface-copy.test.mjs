import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {MANIFEST_BY_ID,PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {validateComposition,preflight} from '../src/core.mjs';
import {duplicatePreviewLayerToSurface as copy} from '../src/preview-surface-copy.mjs';
const tee=MANIFEST_BY_ID['concept-crew-tee'];
const source={id:'selected',type:'text',surfaceId:'front',x:.24,y:.26,width:.43,height:.18,rotationDeg:0,scaleFactor:1,value:'Hello'};
const make=(overrides={})=>({product:tee,layers:[source],selectedId:'selected',sourceSurfaceId:'front',targetSurfaceId:'back',newId:'copy-safe01',...overrides});
const attempt=overrides=>copy(make(overrides));
test('35AP makes a distinct valid surface layer without mutating its source',()=>{
 const layers=[source];const before=structuredClone(layers);const result=attempt({layers});
 assert.equal(result.applied,true);assert.equal(result.layers.length,2);
 assert.notEqual(result.layers,layers);assert.deepEqual(layers,before);
 assert.equal(result.layers[0],source);assert.equal(result.layers[1].id,'copy-safe01');
 assert.equal(result.layers[1].surfaceId,'back');assert.equal(result.layers[1].value,'Hello');
 assert.deepEqual(validateComposition(tee,{layers:result.layers}),[]);
});
test('35AP does not copy embedded authority/security fields onto target',()=>{
 const layer={...source,ownerToken:'secret',artworkGrant:'secret',privateKey:'secret',sessionId:'secret'};
 const r=attempt({layers:[layer]});assert.equal(r.applied,true);
 assert.deepEqual(Object.keys(r.layers[1]).sort(),['id','type','surfaceId','x','y','width','height','rotationDeg','scaleFactor','value'].sort());
 assert.ok(!JSON.stringify(r.layers[1]).includes('secret'));assert.equal(r.layers[0],layer);
});
test('35AP duplicates privately held artwork reference without owner credentials',()=>{
 const artwork={...source,type:'artwork',artworkId:'opaque-local-photo',value:undefined};
 const r=attempt({layers:[artwork]});assert.equal(r.applied,true);
 assert.equal(r.layers[1].artworkId,'opaque-local-photo');
 assert.equal(Object.hasOwn(r.layers[1],'value'),false);
 assert.ok(!('authorization' in r.layers[1]));
});
for(const [label,changed,reason] of [
 ['same source and target',{targetSurfaceId:'front'},'INVALID_ACTION'],
 ['invalid target',{targetSurfaceId:'heel'},'INVALID_SURFACE'],
 ['unavailable source',{sourceSurfaceId:'upper'},'INVALID_SURFACE'],
 ['selected on different surface',{sourceSurfaceId:'back',targetSurfaceId:'front'},'DIFFERENT_SURFACE'],
 ['missing selection',{selectedId:'absent'},'NO_SELECTED_LAYER'],
 ['duplicate layer id',{newId:'copy-safe01',layers:[source,{...source,id:'copy-safe01'}]},'DUPLICATE_LAYER_ID'],
 ['unsafe id',{newId:'copy-a/b'},'INVALID_ACTION'],
 ['missing layer list',{layers:undefined},'INVALID_ACTION'],
 ['bad target input',{targetSurfaceId:null},'INVALID_ACTION']]){
 test('35AP rejects '+label+' immutably',()=>{
  const req=make(changed);const orig=req.layers;
  const r=copy(req);assert.equal(r.applied,false);assert.equal(r.reason,reason);assert.equal(r.layers,orig);
 });
}
test('35AP refuses invalid source design and preserves exact original refs',()=>{
 const invalid={...source,x:10};const layers=[invalid];const r=attempt({layers});
 assert.equal(r.applied,false);assert.equal(r.reason,'INVALID_COMPOSITION');assert.equal(r.layers,layers);
});
test('35AP copied layer cannot accidentally authorize production or checkout',()=>{
 const r=attempt();assert.equal(r.applied,true);const p=preflight(tee,{layers:r.layers});
 assert.equal(p.previewValid,true);assert.equal(p.productionReady,false);
 assert.ok(p.blockers.some(b=>b.code==='UNAPPROVED_PRODUCT'));
});
test('35AP blocks duplication for single-surface products and respects every multi-surface product',()=>{
 for(const p of PRODUCT_MANIFESTS){const a=p.surfaces[0],b=p.surfaces[1];const l={...source,surfaceId:a.id};
  const r=copy({product:p,layers:[l],selectedId:'selected',sourceSurfaceId:a.id,targetSurfaceId:b?.id||a.id,newId:'copy-next'});
  assert.equal(r.applied,!!b,p.id);
  if(b)assert.deepEqual(validateComposition(p,{layers:r.layers}),[]);
 }
});
test('35AP same-surface bounds and rotations remain valid on target without silent normalizing',()=>{
 const l={...source,rotationDeg:48};assert.equal(validateComposition(tee,{layers:[l]}).length,0);
 const r=attempt({layers:[l]});assert.equal(r.applied,true);assert.equal(r.layers[1].rotationDeg,48);
 const tooWide={...source,width:2};const denied=attempt({layers:[tooWide]});
 assert.equal(denied.applied,false);assert.equal(denied.reason,'INVALID_COMPOSITION');
});
test('35AP UI exposes discoverable target and copies safely without touching staging candidate',async()=>{
 const html=await readFile(new URL('../demo/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../demo/studio.mjs',import.meta.url),'utf8');
 assert.match(html,/id="copy-target-surface"[^>]*disabled/);assert.match(html,/id="copy-selected-surface"[^>]*disabled/);
 assert.match(html,/concept only/);assert.match(js,/duplicatePreviewLayerToSurface\(/);
 assert.match(js,/state\.saved=null;state\.savedSnapshot=null/);
 assert.match(js,/\$\('layers'\)\.focus/);assert.match(html,/disabled class="disabled-checkout"/);
});
