import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {resolve,join} from 'node:path';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {createStaticPreviewState,updateStaticPreview,staticPreviewAccessibilitySummary,
 staticPreviewActionAnnouncement,staticPreviewErrorAnnouncement} from '../src/static-preview-contract.mjs';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const act=(state,type,props={})=>updateStaticPreview(state,{type,...props});
const fresh=()=>createStaticPreviewState('?product=concept-crew-tee');
const front=()=>act(fresh(),'ADD_TEXT',{value:'PRIVATE CUSTOMER WORDING'});
const both=()=>act(act(front(),'SELECT_SURFACE',{surfaceId:'back'}),'ADD_TEXT',{value:'ANOTHER PRIVATE MESSAGE'});

test('34Q each concept has safe approved catalog description and zero layers',()=>{
 for(const product of PRODUCT_MANIFESTS){
  const state=createStaticPreviewState('?product='+product.id);
  const view=staticPreviewAccessibilitySummary(state);
  assert.equal(view.valid,true);assert.equal(view.productLabel,product.label);
  assert.equal(view.totalLayerCount,0);assert.equal(view.activeLayerCount,0);
  assert.match(view.description,/No lettering layer selected/);
 }
});
test('34Q active front/back counts reflect selected surface, not total',()=>{
 const state=both(),back=staticPreviewAccessibilitySummary(state);
 assert.equal(back.surfaceLabel,'Back');assert.equal(back.activeLayerCount,1);assert.equal(back.totalLayerCount,2);
 const f=staticPreviewAccessibilitySummary(act(state,'SELECT_SURFACE',{surfaceId:'front'}));
 assert.equal(f.surfaceLabel,'Front');assert.equal(f.activeLayerCount,1);assert.equal(f.totalLayerCount,2);
});
test('34Q selected layer is announced by ordinal, never customer wording',()=>{
 const view=staticPreviewAccessibilitySummary(front());
 assert.match(view.description,/Layer 1 selected/);
 assert.doesNotMatch(JSON.stringify(view),/PRIVATE|CUSTOMER|WORDING|static-layer/);
});
test('34Q mode switching changes description without losing layer counts',()=>{
 const a=front(),b=act(a,'SET_MODE',{mode:'2d'});
 assert.match(staticPreviewAccessibilitySummary(a).description,/3D concept/);
 assert.match(staticPreviewAccessibilitySummary(b).description,/2D concept/);
 assert.equal(staticPreviewAccessibilitySummary(b).totalLayerCount,1);
});
test('34Q malicious lettering and forged identity never appear in announcements',()=>{
 const s={...both(),ownerToken:'FORGED-OWNER-SECRET',variantId:'FORGED-VARIANT'};
 for(const type of ['SELECT_SURFACE','ADD_TEXT','REMOVE_LAYER','SELECT_LAYER','SELECT_PRODUCT','SELECT_COLOR','SELECT_SIZE','SET_MODE','RESET']){
  const output=staticPreviewActionAnnouncement({type,value:'UNTRUSTED-PAYLOAD'},s);
  assert.doesNotMatch(output,/PRIVATE|CUSTOMER|ANOTHER|FORGED|UNTRUSTED|static-layer/);
 }
 assert.doesNotMatch(staticPreviewAccessibilitySummary(s).description,/PRIVATE|CUSTOMER|ANOTHER|FORGED/);
});
test('34Q malformed or unknown product state has neutral fail-closed description',()=>{
 for(const s of [null,{}, {...fresh(),productManifestId:'../../private'}, {...fresh(),layers:null},
  {...fresh(),surfaceId:'other'}, {...fresh(),mode:'checkout'}]){
  const view=staticPreviewAccessibilitySummary(s);assert.equal(view.valid,false);
  assert.equal(view.description,'Concept status unavailable. No changes were saved.');
 }
});
test('34Q stale hidden selection is not represented as a valid active selection',()=>{
 const s=act(front(),'SELECT_SURFACE',{surfaceId:'back'});
 const forged={...s,selectedLayerId:'static-layer-1'};
 assert.equal(staticPreviewAccessibilitySummary(forged).valid,false);
});
test('34Q forged artwork and duplicated identities fail closed',()=>{
 const a=front(),b=front();
 a.layers.push({...a.layers[0],id:'fake-art',type:'artwork',artworkId:'SECRET'});
 b.layers.push({...b.layers[0]});
 assert.equal(staticPreviewAccessibilitySummary(a).valid,false);
 assert.equal(staticPreviewAccessibilitySummary(b).valid,false);
});
test('34Q surface switch and text add announcements carry safe counts',()=>{
 const s=act(front(),'SELECT_SURFACE',{surfaceId:'back'});
 assert.equal(staticPreviewActionAnnouncement({type:'SELECT_SURFACE'},s),'Back surface selected. 0 lettering layers on this surface.');
 const t=act(s,'ADD_TEXT',{value:'secret'});
 assert.equal(staticPreviewActionAnnouncement({type:'ADD_TEXT'},t),'Lettering added to Back. 1 lettering layer on this surface.');
});
test('34Q continuous slider actions deliberately produce no repeated live status',()=>{
 for(const type of ['ROTATE_LAYER','SCALE_LAYER'])assert.equal(staticPreviewActionAnnouncement({type},front()),null);
});
test('34Q error messages are actionable and do not reflect arbitrary exceptions',()=>{
 assert.match(staticPreviewErrorAnnouncement(new Error('INVALID_TEXT')),/1 to 200/);
 assert.match(staticPreviewErrorAnnouncement(new Error('LAYER_LIMIT')),/25/);
 assert.match(staticPreviewErrorAnnouncement(new Error('INVALID_COMPOSITION:OUTSIDE')),/conceptual design area/);
 assert.doesNotMatch(staticPreviewErrorAnnouncement(new Error('PRIVATE-CUSTOMER-SECRET')),/PRIVATE|SECRET/);
});
test('34Q reset and product change clear prior temporary lettering',()=>{
 const s=act(front(),'RESET');
 assert.equal(staticPreviewAccessibilitySummary(s).totalLayerCount,0);
 assert.match(staticPreviewActionAnnouncement({type:'RESET'},s),/Nothing was saved or purchased/);
 const changed=act(front(),'SELECT_PRODUCT',{productManifestId:'concept-rug',confirmed:true});
 assert.equal(staticPreviewAccessibilitySummary(changed).totalLayerCount,0);
});
test('34Q browser controls expose accessible canvas summary and recoverable text error',async()=>{
 const html=await readFile(join(root,'demo/static-preview.html'),'utf8');
 const js=await readFile(join(root,'demo/static-preview.mjs'),'utf8');
 const css=await readFile(join(root,'demo/static-preview.css'),'utf8');
 assert.match(html,/id="concept-a11y-summary"/);
 assert.match(html,/id="stage"[^>]*aria-describedby="concept-a11y-summary"/);
 assert.match(html,/id="stage-3d"[^>]*aria-describedby="camera-help concept-a11y-summary"/);
 assert.match(html,/id="text-entry"[^>]*aria-describedby="text-help"/);
 assert.match(js,/staticPreviewAccessibilitySummary\(state\)\.description/);
 assert.match(js,/staticPreviewActionAnnouncement\(action,state\)/);
 assert.match(js,/setAttribute\('aria-invalid','true'\)/);
 assert.match(css,/\.visually-hidden/);
});
test('34Q regenerated staging bundle scopes accessible descriptions and preserves no-commerce',async()=>{
 const {files,manifest}=await buildStagingStaticBundle({root});
 const section=files.get('sections/tj-static-preview-34i.liquid');
 assert.match(section,/id="tj34i-concept-a11y-summary"/);
 assert.match(section,/aria-describedby="tj34i-camera-help tj34i-concept-a11y-summary"/);
 assert.match(section,/aria-describedby="tj34i-text-help"/);
 assert.match(files.get('assets/tj34i-demo-static-preview.js'),/staticPreviewActionAnnouncement\(action,state\)/);
 assert.equal(manifest.checkoutEnabled,false);
 assert.equal(manifest.customerStorageEnabled,false);
 assert.equal(manifest.sourceVersion,JSON.parse(await readFile(join(root,'package.json'),'utf8')).version);
});
test('34Q accessibility additions introduce no storage, network or checkout',async()=>{
 for(const name of ['src/static-preview-contract.mjs','demo/static-preview.mjs']){
  const source=await readFile(join(root,name),'utf8');
  assert.doesNotMatch(source,/\bfetch\s*\(|\blocalStorage\b|\bsessionStorage\b|\bnew\s+(?:WebSocket|XMLHttpRequest)\b|\/cart\/add/);
 }
});
