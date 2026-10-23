import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {createStaticPreviewState,updateStaticPreview,reviewStaticPreview,staticPreviewReviewAvailability} from '../src/static-preview-contract.mjs';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const act=(s,type,params={})=>updateStaticPreview(s,{type,...params});
const crew=()=>createStaticPreviewState('?product=concept-crew-tee');
const front=()=>act(crew(),'ADD_TEXT',{value:'SECRET FRONT TEXT'});
const both=()=>act(act(front(),'SELECT_SURFACE',{surfaceId:'back'}),'ADD_TEXT',{value:'SECRET BACK TEXT'});

test('34P all eight empty concepts have review disabled with a safe action hint',()=>{
 for(const p of PRODUCT_MANIFESTS){const gate=staticPreviewReviewAvailability(createStaticPreviewState('?product='+p.id));
  assert.deepEqual(gate,{ready:false,reason:'ADD_LETTERING'});}
});
test('34P first legitimate lettering enables review',()=>{
 assert.deepEqual(staticPreviewReviewAvailability(front()),{ready:true,reason:null});
});
test('34P front/back review reports separate surface counts in manifest order',()=>{
 const review=reviewStaticPreview(both());
 assert.deepEqual(review.surfaceLayerCounts,[{surfaceLabel:'Front',layerCount:1},{surfaceLabel:'Back',layerCount:1}]);
 assert.equal(review.layerCount,2);
});
test('34P changing active surface does not hide previously designed surface in review',()=>{
 const state=act(front(),'SELECT_SURFACE',{surfaceId:'back'});
 assert.deepEqual(reviewStaticPreview(state).surfaceLayerCounts,[{surfaceLabel:'Front',layerCount:1}]);
 assert.deepEqual(staticPreviewReviewAvailability(state),{ready:true,reason:null});
});
test('34P deleting back lettering updates review without erasing front artwork',()=>{
 const state=act(both(),'REMOVE_LAYER');const review=reviewStaticPreview(state);
 assert.equal(review.layerCount,1);
 assert.deepEqual(review.surfaceLayerCounts,[{surfaceLabel:'Front',layerCount:1}]);
});
test('34P removing final lettering disables review again',()=>{
 const state=act(front(),'REMOVE_LAYER');
 assert.deepEqual(staticPreviewReviewAvailability(state),{ready:false,reason:'ADD_LETTERING'});
});
test('34P changing products with explicit discard disables review and clears previous counts',()=>{
 const state=act(both(),'SELECT_PRODUCT',{productManifestId:'concept-rug',confirmed:true});
 assert.deepEqual(staticPreviewReviewAvailability(state),{ready:false,reason:'ADD_LETTERING'});
 assert.equal(state.layers.length,0);
});
test('34P forged private artwork is not eligible for client-only review',()=>{
 const state=front();state.layers.push({...state.layers[0],id:'forged-art',type:'artwork',artworkId:'private'});
 assert.deepEqual(staticPreviewReviewAvailability(state),{ready:false,reason:'INVALID_PREVIEW'});
});
test('34P ambiguous duplicate layer identities cannot enable review',()=>{
 const state=front();state.layers.push({...state.layers[0]});
 assert.deepEqual(staticPreviewReviewAvailability(state),{ready:false,reason:'INVALID_PREVIEW'});
});
test('34P review surface counts do not leak lettering or customer identity',()=>{
 const review=reviewStaticPreview({...both(),ownerToken:'FORGED-CUSTOMER-SECRET'});
 assert.doesNotMatch(JSON.stringify(review.surfaceLayerCounts),/SECRET|FORGED|owner|artworkId|price|variant/);
 assert.equal(review.checkoutEnabled,false);
});
test('34P browser UI includes accessible review gating and per-surface explanation',async()=>{
 const html=await readFile(join(root,'demo/static-preview.html'),'utf8');
 const js=await readFile(join(root,'demo/static-preview.mjs'),'utf8');
 assert.match(html,/id="review-help"/);
 assert.match(html,/id="review-preview"[^>]*aria-describedby="review-help"/);
 assert.match(js,/staticPreviewReviewAvailability\(state\)/);
 assert.match(js,/\$\('review-preview'\)\.disabled=!gate\.ready\|\|hasUnaddedWording/);
 assert.match(js,/surfaceLayerCounts\.map/);
});
test('34P generated staging section and ESM preserve review gate with isolated IDs',async()=>{
 const {files,manifest}=await buildStagingStaticBundle({root});
 const liquid=files.get('sections/tj-static-preview-34i.liquid');
 assert.match(liquid,/id="tj34i-review-help"/);
 assert.match(liquid,/aria-describedby="tj34i-review-help"/);
 assert.match(files.get('assets/tj34i-demo-static-preview.js'),/staticPreviewReviewAvailability\(state\)/);
 assert.equal(manifest.checkoutEnabled,false);
 assert.equal(manifest.shopifyThemeInstalled,false);
});
test('34P offline preview gate never introduces network, storage or commerce',async()=>{
 for(const path of ['src/static-preview-contract.mjs','demo/static-preview.mjs']){
  const code=await readFile(join(root,path),'utf8');
  assert.doesNotMatch(code,/\bfetch\s*\(|\b(?:localStorage|sessionStorage)\s*\.|\bnew\s+(?:XMLHttpRequest|WebSocket)\b|\/cart\/add/);
 }
});
