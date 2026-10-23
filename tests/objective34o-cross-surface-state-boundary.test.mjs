import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createStaticPreviewState,updateStaticPreview} from '../src/static-preview-contract.mjs';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const update=(state,type,params={})=>updateStaticPreview(state,{type,...params});
const fixture=()=>{
 let front=createStaticPreviewState('?product=concept-crew-tee');
 front=update(front,'ADD_TEXT',{value:'PRIVATE FRONT'});
 const back=update(front,'SELECT_SURFACE',{surfaceId:'back'});
 return {front,back,stale:{...back,selectedLayerId:front.layers[0].id}};
};
const actions=[['ROTATE_LAYER',{degrees:42}],['SCALE_LAYER',{percent:130}],['REMOVE_LAYER',{}]];
for(const [type,params] of actions){
 test(`34O stale cross-surface selected ID rejects ${type} atomically`,()=>{
  const {stale}=fixture(),before=structuredClone(stale);
  assert.throws(()=>update(stale,type,params),/LAYER_NOT_ON_ACTIVE_SURFACE/);
  assert.deepEqual(stale,before);
 });
}
test('34O stale selected ID that no longer exists cannot mutate or remove layers',()=>{
 const {back}=fixture(),stale={...back,selectedLayerId:'static-layer-999'};
 for(const [type,params] of actions)assert.throws(()=>update(stale,type,params),/UNKNOWN_SELECTED_LAYER/);
 assert.equal(back.layers.length,1);
});
test('34O forged duplicate selected IDs cannot target an arbitrary layer',()=>{
 const {front}=fixture(),duplicate={...front,layers:[...front.layers,{...front.layers[0],surfaceId:'back'}]};
 for(const [type,params] of actions)assert.throws(()=>update(duplicate,type,params),/AMBIGUOUS_LAYER_ID/);
 assert.throws(()=>update(duplicate,'SELECT_LAYER',{layerId:front.layers[0].id}),/AMBIGUOUS_LAYER_ID/);
});
test('34O null selection remains a harmless remove no-op for legitimate surface changes',()=>{
 const {back}=fixture();const after=update(back,'REMOVE_LAYER');
 assert.deepEqual(after.layers,back.layers);assert.equal(after.selectedLayerId,null);
});
test('34O active front layer remains editable and removable',()=>{
 const {front}=fixture();
 const rotated=update(front,'ROTATE_LAYER',{degrees:33});assert.equal(rotated.layers[0].rotationDeg,33);
 const scaled=update(rotated,'SCALE_LAYER',{percent:110});assert.equal(scaled.layers[0].scaleFactor,1.1);
 const removed=update(scaled,'REMOVE_LAYER');assert.equal(removed.layers.length,0);
 assert.equal(front.layers[0].rotationDeg,0);
});
test('34O active back layer remains editable without changing front layer',()=>{
 const {back}=fixture();const both=update(back,'ADD_TEXT',{value:'BACK TEXT'});
 const rotated=update(both,'ROTATE_LAYER',{degrees:40});
 assert.equal(rotated.layers[0].rotationDeg,0);assert.equal(rotated.layers[1].rotationDeg,40);
 const removed=update(rotated,'REMOVE_LAYER');assert.deepEqual(removed.layers.map(l=>l.value),['PRIVATE FRONT']);
});
test('34O cross-surface selection must be explicitly changed before editing',()=>{
 const {stale}=fixture();const cleaned=update(stale,'SELECT_SURFACE',{surfaceId:'back'});
 assert.equal(cleaned.selectedLayerId,null);
 const restored=update(cleaned,'SELECT_SURFACE',{surfaceId:'front'});
 const selected=update(restored,'SELECT_LAYER',{layerId:stale.layers[0].id});
 assert.equal(update(selected,'ROTATE_LAYER',{degrees:20}).layers[0].rotationDeg,20);
});
test('34O selection of unknown or forged cross-surface IDs remains rejected',()=>{
 const {back}=fixture();
 assert.throws(()=>update(back,'SELECT_LAYER',{layerId:'missing'}),/UNKNOWN_LAYER/);
 assert.throws(()=>update(back,'SELECT_LAYER',{layerId:back.layers[0].id}),/LAYER_NOT_ON_ACTIVE_SURFACE/);
});
test('34O generated staging client carries updated boundary and remains non-purchasing',async()=>{
 const {files,manifest}=await buildStagingStaticBundle({root});
 const code=files.get('assets/tj34i-src-static-preview-contract.js');
 assert.match(code,/function|const activeLayerIndex=/);
 assert.match(code,/LAYER_NOT_ON_ACTIVE_SURFACE/);
 assert.match(code,/AMBIGUOUS_LAYER_ID/);
 assert.equal(manifest.sourceVersion,JSON.parse(await readFile(join(root,'package.json'),'utf8')).version);
 assert.equal(manifest.checkoutEnabled,false);
 assert.equal(manifest.shopifyThemeInstalled,false);
});
test('34O source contract does not enable network, storage or checkout',async()=>{
 const code=await readFile(join(root,'src/static-preview-contract.mjs'),'utf8');
 assert.doesNotMatch(code,/\bfetch\s*\(|localStorage|sessionStorage|XMLHttpRequest|WebSocket|\/cart\/add/);
});
