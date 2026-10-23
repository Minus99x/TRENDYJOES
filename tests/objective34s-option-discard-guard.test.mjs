import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {PRODUCT_MANIFESTS,MANIFEST_BY_ID} from '../src/catalog.mjs';
import {getPreviewOptions,normalizePreviewSelection} from '../src/preview-product-options.mjs';
import {createStaticPreviewState,updateStaticPreview,staticPreviewHasPendingWork} from '../src/static-preview-contract.mjs';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const fresh=(id='concept-crew-tee')=>createStaticPreviewState('?product='+id);
const color=(s,id='slate')=>updateStaticPreview(s,{type:'SELECT_COLOR',colorId:id});
const size=(s,id='m')=>updateStaticPreview(s,{type:'SELECT_SIZE',sizeId:id});
const switchTo=(s,confirmed)=>updateStaticPreview(s,{type:'SELECT_PRODUCT',productManifestId:'concept-rug',...(confirmed===undefined?{}:{confirmed})});

test('34S default option selections across all merchandise categories do not prompt',()=>{
 for(const p of PRODUCT_MANIFESTS)assert.equal(staticPreviewHasPendingWork(fresh(p.id),''),false,p.id);
});
test('34S alternate color alone is pending work across all eight concepts',()=>{
 for(const p of PRODUCT_MANIFESTS){const state=fresh(p.id),options=getPreviewOptions(p);
  assert.ok(options.colors.length>1,p.id);
  assert.equal(staticPreviewHasPendingWork(color(state,options.colors[1].id),''),true,p.id);}
});
test('34S size-only changes count as pending work on every sized concept',()=>{
 let checked=0;
 for(const p of PRODUCT_MANIFESTS){const options=getPreviewOptions(p);
  if(options.sizes.length<2)continue;
  const changed=size(fresh(p.id),options.sizes[1].id);
  assert.equal(staticPreviewHasPendingWork(changed,''),true,p.id);checked++;}
 assert.ok(checked>=4);
});
test('34S selecting the existing default color does not produce false warnings',()=>{
 const state=fresh();assert.equal(staticPreviewHasPendingWork(color(state,'oxblood'),''),false);
});
test('34S selecting the existing default size does not produce false warnings',()=>{
 const state=fresh();assert.equal(staticPreviewHasPendingWork(size(state,'s'),''),false);
});
test('34S color-only product substitution requires explicit confirmation at contract boundary',()=>{
 assert.throws(()=>switchTo(color(fresh())),/UNSAVED_WORK_CONFIRMATION_REQUIRED/);
});
test('34S size-only product substitution requires explicit confirmation at contract boundary',()=>{
 assert.throws(()=>switchTo(size(fresh())),/UNSAVED_WORK_CONFIRMATION_REQUIRED/);
});
test('34S confirmed color-only product switch discards selection without copying it to new product',()=>{
 const changed=switchTo(color(fresh()),true),defaults=normalizePreviewSelection(MANIFEST_BY_ID['concept-rug']);
 assert.equal(changed.productManifestId,'concept-rug');assert.deepEqual(changed.previewSelection,defaults);
 assert.equal(staticPreviewHasPendingWork(changed,''),false);
});
test('34S confirmed size-only product switch drops old size and retains empty layers',()=>{
 const changed=switchTo(size(fresh()),true);
 assert.equal(changed.previewSelection.sizeId,null);assert.deepEqual(changed.layers,[]);
});
test('34S no pending changes permits an ordinary product switch',()=>{
 assert.equal(switchTo(fresh()).productManifestId,'concept-rug');
});
test('34S reverting both options to their defaults removes option-only pending status',()=>{
 let state=size(color(fresh()));assert.equal(staticPreviewHasPendingWork(state,''),true);
 state=color(state,'oxblood');state=size(state,'s');assert.equal(staticPreviewHasPendingWork(state,''),false);
});
test('34S viewing in 2D is not itself a discarded personalization choice',()=>{
 const state=updateStaticPreview(fresh(),{type:'SET_MODE',mode:'2d'});
 assert.equal(staticPreviewHasPendingWork(state,''),false);
});
test('34S malformed or missing option state fails closed before discard',()=>{
 for(const value of [null,undefined,42,[],{},'oxblood',{colorId:'oxblood'},
  {sizeId:'s'},{colorId:'invalid',sizeId:'s'},{colorId:'oxblood',sizeId:'invalid'},
  {colorId:'oxblood',sizeId:'s',owner:'FORGED'}]){
  assert.equal(staticPreviewHasPendingWork({...fresh(),previewSelection:value},''),true,JSON.stringify(value));
 }
});
test('34S forged unknown product identity fails closed',()=>{
 assert.equal(staticPreviewHasPendingWork({...fresh(),productManifestId:'forged-variant'},''),true);
});
test('34S hostile option property getter fails closed without surfacing customer text',()=>{
 const selection={sizeId:'s'};Object.defineProperty(selection,'colorId',{enumerable:true,get(){throw Error('PRIVATE CUSTOMER DATA');}});
 assert.equal(staticPreviewHasPendingWork({...fresh(),previewSelection:selection},''),true);
});
test('34S option-only guard is boolean and never mutates customer selection',()=>{
 const state=color(fresh());const before=structuredClone(state);
 const result=staticPreviewHasPendingWork(state,'');assert.equal(typeof result,'boolean');assert.equal(result,true);
 assert.deepEqual(state,before);assert.doesNotMatch(String(result),/oxblood|slate|customer/i);
});
test('34S product selector and Clear design both consult the pending-work guard',async()=>{
 const code=await readFile(join(root,'demo/static-preview.mjs'),'utf8');
 // Product switch, Clear Design and browser navigation share the same fail-closed predicate.
 assert.equal((code.match(/staticPreviewHasPendingWork\(state,\$\('text-entry'\)\.value\)/g)||[]).length,3);
 assert.match(code,/if\(!confirmed\)\{event\.target\.value=state\.productManifestId;return;\}/);
 assert.match(code,/if\(apply\(\{type:'RESET'\}\)\)clearComposer\(\)/);
});
test('34S generated offline staging integration includes option discard boundary',async()=>{
 const {files,manifest}=await buildStagingStaticBundle({root});
 const contract=files.get('assets/tj34i-src-static-preview-contract.js');
 assert.match(contract,/staticPreviewHasPendingWork\(state,''\)/);
 assert.match(contract,/normalizePreviewSelection\(product,selection\)/);
 assert.match(files.get('assets/tj34i-demo-static-preview.js'),/staticPreviewHasPendingWork/);
 assert.equal(manifest.sourceVersion,JSON.parse(await readFile(join(root,'package.json'),'utf8')).version);assert.equal(manifest.shopifyThemeInstalled,false);
});
test('34S option guard remains local-only without storage, network, cart or checkout',async()=>{
 for(const name of ['src/static-preview-contract.mjs','demo/static-preview.mjs']){
  const source=await readFile(join(root,name),'utf8');
  assert.doesNotMatch(source,/\bfetch\s*\(|\blocalStorage\b|\bsessionStorage\b|\bnew\s+(?:XMLHttpRequest|WebSocket)\b|\/cart\/add/);
 }
});
