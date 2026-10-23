import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {resolve,join} from 'node:path';
import {createStaticPreviewState,updateStaticPreview,reviewStaticPreview} from '../src/static-preview-contract.mjs';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const act=(s,type,params={})=>updateStaticPreview(s,{type,...params});
const start=()=>act(createStaticPreviewState('?product=concept-crew-tee'),'ADD_TEXT',{value:'FRONT PRIVATE TEXT'});
const back=s=>act(s,'SELECT_SURFACE',{surfaceId:'back'});
test('34M changing design surface deselects hidden front layer without losing artwork',()=>{
 const a=start(),b=back(a);
 assert.equal(a.selectedLayerId,a.layers[0].id);assert.equal(b.selectedLayerId,null);
 assert.deepEqual(b.layers,a.layers);assert.equal(b.surfaceId,'back');
});
test('34M invisible front layer cannot be selected on back',()=>{
 const a=start(),b=back(a);
 assert.throws(()=>act(b,'SELECT_LAYER',{layerId:a.layers[0].id}),/LAYER_NOT_ON_ACTIVE_SURFACE/);
 assert.equal(b.selectedLayerId,null);assert.equal(a.selectedLayerId,a.layers[0].id);
});
test('34M invisible layer cannot be rotated, scaled, or removed on another surface',()=>{
 const b=back(start());
 for(const [type,params] of [['ROTATE_LAYER',{degrees:50}],['SCALE_LAYER',{percent:130}]])
  assert.throws(()=>act(b,type,params),/NO_SELECTED_LAYER/);
 assert.equal(act(b,'REMOVE_LAYER').layers.length,1);
});
test('34M adding back text selects back layer and retains front design',()=>{
 const b=act(back(start()),'ADD_TEXT',{value:'BACK TEXT'});
 assert.equal(b.layers.length,2);assert.equal(b.selectedLayerId,b.layers[1].id);
 assert.deepEqual(b.layers.map(x=>x.surfaceId),['front','back']);
});
test('34M switching back from back clears selected back layer',()=>{
 const b=act(back(start()),'ADD_TEXT',{value:'BACK TEXT'});
 const f=act(b,'SELECT_SURFACE',{surfaceId:'front'});
 assert.equal(f.selectedLayerId,null);assert.equal(f.layers.length,2);
 assert.equal(act(f,'SELECT_LAYER',{layerId:f.layers[0].id}).selectedLayerId,f.layers[0].id);
});
test('34M cross-surface selection rejection is atomic even when active layer selected',()=>{
 const b=act(back(start()),'ADD_TEXT',{value:'BACK TEXT'});
 assert.throws(()=>act(b,'SELECT_LAYER',{layerId:b.layers[0].id}),/LAYER_NOT_ON_ACTIVE_SURFACE/);
 assert.equal(b.selectedLayerId,b.layers[1].id);
});
test('34M unknown layer still reports unknown rather than surface mismatch',()=>{
 assert.throws(()=>act(back(start()),'SELECT_LAYER',{layerId:'forged-layer'}),/UNKNOWN_LAYER/);
});
test('34M empty selection is allowed on all surfaces',()=>{
 const b=act(back(start()),'SELECT_LAYER',{layerId:null});assert.equal(b.selectedLayerId,null);
});
test('34M same-surface selection is preserved when reselecting surface',()=>{
 const a=start();const b=act(a,'SELECT_SURFACE',{surfaceId:'front'});assert.equal(b.selectedLayerId,a.selectedLayerId);
});
test('34M all eight merchandise categories preserve review and layer counts',()=>{
 for(const p of PRODUCT_MANIFESTS){
  let s=createStaticPreviewState('?product='+p.id);s=act(s,'ADD_TEXT',{value:'TEXT'});
  if(p.surfaces.length>1){s=act(s,'SELECT_SURFACE',{surfaceId:p.surfaces[1].id});assert.equal(s.selectedLayerId,null);}
  const r=reviewStaticPreview(s);assert.equal(r.layerCount,1);assert.equal(r.checkoutEnabled,false);
 }
});
test('34M browser editor renders only active-surface layers in selection control',async()=>{
 const code=await readFile(join(root,'demo/static-preview.mjs'),'utf8');
 assert.match(code,/state\.layers\.filter\(l=>l\.surfaceId===state\.surfaceId\)\.map/);
 assert.match(code,/\$\('layers'\)\.value=state\.selectedLayerId\|\|''/);
});
test('34M staging generated module includes same surface-scoped layer selector',async()=>{
 const {files,manifest}=await buildStagingStaticBundle({root});
 assert.equal(manifest.sourceVersion,JSON.parse(await readFile(join(root,'package.json'),'utf8')).version);
 assert.match(files.get('assets/tj34i-demo-static-preview.js'),/state\.layers\.filter\(l=>l\.surfaceId===state\.surfaceId\)\.map/);
 assert.equal(manifest.checkoutEnabled,false);assert.equal(manifest.shopifyThemeInstalled,false);
});
