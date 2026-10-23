import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {createStaticPreviewState,updateStaticPreview,staticPreviewHasPendingWork} from '../src/static-preview-contract.mjs';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const fresh=()=>createStaticPreviewState('?product=concept-crew-tee');
const add=s=>updateStaticPreview(s,{type:'ADD_TEXT',value:'PRIVATE CUSTOMER WORDING'});

test('34R all eight empty products have no pending work',()=>{
 for(const product of PRODUCT_MANIFESTS)assert.equal(staticPreviewHasPendingWork(createStaticPreviewState('?product='+product.id),''),false);
});
test('34R unadded customer wording alone triggers discard warning',()=>{
 assert.equal(staticPreviewHasPendingWork(fresh(),'PRIVATE CUSTOMER WORDING'),true);
});
test('34R even whitespace-only typed drafts require deliberate discard',()=>{
 for(const draft of [' ','\n','\t','   '])assert.equal(staticPreviewHasPendingWork(fresh(),draft),true);
});
test('34R committed lettering requires warning even with empty composer',()=>{
 assert.equal(staticPreviewHasPendingWork(add(fresh()),''),true);
});
test('34R removed final layer still leaves separately typed draft pending',()=>{
 const cleared=updateStaticPreview(add(fresh()),{type:'REMOVE_LAYER'});
 assert.equal(staticPreviewHasPendingWork(cleared,''),false);
 assert.equal(staticPreviewHasPendingWork(cleared,'still typing'),true);
});
test('34R hidden back/front layers still require confirmation',()=>{
 const back=updateStaticPreview(add(fresh()),{type:'SELECT_SURFACE',surfaceId:'back'});
 assert.equal(back.selectedLayerId,null);
 assert.equal(staticPreviewHasPendingWork(back,''),true);
});
test('34R malformed composer values fail closed rather than silently discard',()=>{
 for(const draft of [null,undefined,42,{},[],new String('secret')]){
  assert.equal(staticPreviewHasPendingWork(fresh(),draft),true);
 }
});
test('34R malformed state or layer collections fail closed',()=>{
 for(const state of [null,{}, {...fresh(),layers:null},{...fresh(),layers:{}},{...fresh(),layers:'secret'}]){
  assert.equal(staticPreviewHasPendingWork(state,''),true);
 }
});
test('34R guard is boolean-only and never returns sensitive wording',()=>{
 const result=staticPreviewHasPendingWork(fresh(),'CUSTOMER-SECRET-123');
 assert.equal(typeof result,'boolean');assert.equal(JSON.stringify(result),'true');
});
test('34R pending-work check never mutates caller state or draft',()=>{
 const state=add(fresh()),snapshot=structuredClone(state),draft='PRIVATE CUSTOMER WORDING';
 assert.equal(staticPreviewHasPendingWork(state,draft),true);
 assert.deepEqual(state,snapshot);assert.equal(draft,'PRIVATE CUSTOMER WORDING');
});
test('34R product change warns for typed-only drafts and restores selection on cancel',async()=>{
 const js=await readFile(join(root,'demo/static-preview.mjs'),'utf8');
 assert.match(js,/staticPreviewHasPendingWork\(state,\$\('text-entry'\)\.value\)/);
 assert.match(js,/if\(!confirmed\)\{event\.target\.value=state\.productManifestId;return;\}/);
 assert.match(js,/if\(apply\(\{type:'SELECT_PRODUCT',productManifestId:id,confirmed\}\)\)clearComposer\(\)/);
});
test('34R Clear design warns for typed-only draft and clears composer only after success',async()=>{
 const js=await readFile(join(root,'demo/static-preview.mjs'),'utf8');
 assert.match(js,/Clear all temporary design elements and unadded wording\?/);
 assert.match(js,/if\(apply\(\{type:'RESET'\}\)\)clearComposer\(\)/);
 assert.match(js,/function clearComposer\(\)\{[\s\S]*?\$\('text-entry'\)\.value='';[\s\S]*?removeAttribute\('aria-invalid'\)/);
});
test('34R offline HTML and generated staging keep private composer nonpersistent',async()=>{
 const html=await readFile(join(root,'demo/static-preview.html'),'utf8');
 assert.match(html,/id="text-entry"[^>]*autocomplete="off"/);
 const {files,manifest}=await buildStagingStaticBundle({root});
 assert.match(files.get('sections/tj-static-preview-34i.liquid'),/id="tj34i-text-entry"[^>]*autocomplete="off"/);
 assert.match(files.get('assets/tj34i-demo-static-preview.js'),/staticPreviewHasPendingWork/);
 assert.equal(manifest.sourceVersion,JSON.parse(await readFile(join(root,'package.json'),'utf8')).version);assert.equal(manifest.checkoutEnabled,false);
});
test('34R privacy fix introduces no client storage, network or checkout',async()=>{
 for(const name of ['demo/static-preview.mjs','src/static-preview-contract.mjs']){
  const js=await readFile(join(root,name),'utf8');
  assert.doesNotMatch(js,/\bfetch\s*\(|\blocalStorage\b|\bsessionStorage\b|\bnew\s+(?:WebSocket|XMLHttpRequest)\b|\/cart\/add/);
 }
});
