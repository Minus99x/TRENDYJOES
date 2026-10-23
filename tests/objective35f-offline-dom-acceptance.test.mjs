import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {buildMainStagingReconciliation} from '../src/main-staging-reconciliation.mjs';
import {validateOfflineMainDom,verifyOfflineMainAssetBytes} from '../src/offline-main-dom-acceptance.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const section='sections/tj-static-preview-34i.liquid';
const css='assets/tj34i-demo-studio.css';
const css2='assets/tj34i-demo-static-preview.css';
const base=async()=>(await buildMainStagingReconciliation({root})).files;
const mutate=async(path,fn)=>{const files=new Map(await base());files.set(path,fn(files.get(path)));return files;};
const reject=async(path,fn,code)=>{const files=await mutate(path,fn);assert.throws(()=>validateOfflineMainDom({files}),new RegExp(code));};
test('35F accepts exact Main35/Night35E candidate with 2D/3D and accessibility seams',async()=>{
 const result=validateOfflineMainDom({files:await base()});
 assert.equal(result.idCount,44);assert.equal(result.linkedReferences,14);
 assert.equal(result.moduleCount,1);assert.equal(result.stylesheetCount,2);
 assert.equal(result.assetCount,13);assert.equal(result.shopifyWrites,0);
 assert.equal(result.nativeBrowserVerified,false);
 assert.match(result.markup,/<h2>Ideas made/);assert.match(result.markup,/<canvas id="tj34i-stage-3d"/);
});
test('35F generated candidate remains byte-identical to validated source',async()=>{
 const files=await base();validateOfflineMainDom({files});
 for(const [path,content] of files)assert.equal(await readFile(join(root,'integrations/shopify/main-staging-reconciliation-candidate',path),'utf8'),content);
});
test('35F rejects duplicate IDs',()=>reject(section,s=>s.replace('id="tj34i-review-help"','id="tj34i-product"'),'DOM_DUPLICATE_ID'));
test('35F rejects duplicate attributes',()=>reject(section,s=>s.replace('id="tj34i-product"','id="tj34i-product" id="shadow"'),'DOM_DUPLICATE_ATTRIBUTE'));
test('35F rejects broken aria-describedby',()=>reject(section,s=>s.replace('aria-describedby="tj34i-text-help"','aria-describedby="missing-help"'),'DOM_ARIA_TARGET_MISSING'));
test('35F rejects broken aria-labelledby',()=>reject(section,s=>s.replace('aria-labelledby="tj34i-preview-summary-heading"','aria-labelledby="missing-heading"'),'DOM_ARIA_TARGET_MISSING'));
test('35F rejects broken label target',()=>reject(section,s=>s.replace('for="tj34i-product"','for="missing-product"'),'DOM_LABEL_TARGET_MISSING'));
test('35F rejects empty ARIA target',()=>reject(section,s=>s.replace('aria-describedby="tj34i-text-help"','aria-describedby=" "'),'DOM_EMPTY_REFERENCE'));
test('35F rejects missing required 3D canvas',()=>reject(section,s=>s.replace('id="tj34i-stage-3d"','id="missing-stage"'),'DOM_REQUIRED_CONTROL_MISSING'));
test('35F rejects swapped 3D surface',()=>reject(section,s=>s.replace('<canvas id="tj34i-stage-3d"','<div id="tj34i-stage-3d"'),'DOM_2D_3D_SURFACE_MISSING'));
test('35F rejects review initially enabled',()=>reject(section,s=>s.replace('id="tj34i-review-preview" aria-describedby="tj34i-review-help" disabled','id="tj34i-review-preview" aria-describedby="tj34i-review-help"'),'DOM_REVIEW_INITIAL_GATE_MISSING'));
test('35F rejects checkout enabled',()=>reject(section,s=>s.replace('<button type="button" disabled class="disabled-checkout">','<button type="button" class="disabled-checkout">'),'DOM_CHECKOUT_GATE_MISSING'));
test('35F rejects implicit submit button',()=>reject(section,s=>s.replace('<button type="button" class="primary" id="tj34i-add-text"','<button class="primary" id="tj34i-add-text"'),'DOM_IMPLICIT_SUBMIT_BUTTON'));
test('35F rejects inserted form',()=>reject(section,s=>s+'<form action="/checkout"></form>','DOM_UNTRUSTED_MARKUP'));
test('35F rejects inserted file upload',()=>reject(section,s=>s+'<input type="file">','DOM_COMMERCE_FORBIDDEN'));
test('35F rejects inline event handlers',()=>reject(section,s=>s.replace('id="tj34i-product"','id="tj34i-product" onclick="alert(1)"'),'DOM_EXECUTABLE_MARKUP'));
test('35F rejects injected remote link',()=>reject(section,s=>s.replace('href="#tj-try-studio"','href="https://example.org"'),'DOM_EXTERNAL_REFERENCE'));
test('35F rejects duplicate artwork link',()=>reject(section,s=>s.replace('</aside>','<a href="#tj-try-studio">duplicate</a></aside>'),'DOM_MAIN_ARTWORK_LINK_INVALID'));
test('35F rejects unknown internal anchor',()=>reject(section,s=>s.replace('href="#tj-try-studio"','href="#unknown"'),'DOM_LINK_NOT_APPROVED'));
test('35F rejects extra script',()=>reject(section,s=>s+'<script type="module" src="/assets/evil.js"></script>','DOM_EXECUTABLE_MARKUP'));
test('35F rejects unapproved Liquid expression',()=>reject(section,s=>s+'{{ customer.id }}','DOM_UNTRUSTED_MARKUP'));
test('35F rejects missing stylesheet',()=>reject(section,s=>s.replace("{{ 'tj34i-demo-studio.css' | asset_url | stylesheet_tag }}",''),'DOM_STYLESHEET_GRAPH_INVALID'));
test('35F rejects unapproved stylesheet',()=>reject(section,s=>s.replace('tj34i-demo-studio.css','evil.css'),'DOM_STYLESHEET_GRAPH_INVALID'));
test('35F rejects missing script',()=>reject(section,s=>s.replace(/<script type="module"[^\n]+<\/script>/,''),'DOM_SCRIPT_GRAPH_INVALID'));
test('35F rejects removed graph asset',async()=>{const files=await base();files.delete(css);assert.throws(()=>validateOfflineMainDom({files}),/DOM_ASSET_GRAPH_INVALID/);});
test('35F rejects extra graph asset',async()=>{const files=await base();files.set('assets/evil.js','evil');assert.throws(()=>validateOfflineMainDom({files}),/DOM_ASSET_GRAPH_INVALID/);});
test('35F rejects remote stylesheet import',()=>reject(css,s=>s+'\n@import url(https://example.org/style.css);','DOM_EXTERNAL_STYLE_FORBIDDEN'));
test('35F rejects remote CSS url',()=>reject(css2,s=>s+'\n.x{background:url(https://example.org/pixel)}','DOM_EXTERNAL_STYLE_FORBIDDEN'));
test('35F rejects missing focus-visible rule',()=>reject(css2,s=>s.replaceAll(':focus-visible',':not-focus-visible'),'DOM_STYLE_ACCESSIBILITY_MISSING'));
test('35F rejects Main heading downgrade',()=>reject(css,s=>s.replaceAll('.masthead h2','.masthead h1'),'DOM_STYLE_ACCESSIBILITY_MISSING'));
test('35F rejects fake disabled token inside an aria-label',()=>reject(section,s=>s.replace('disabled class="disabled-checkout"','aria-label="disabled fake" class="disabled-checkout"'),'DOM_CHECKOUT_GATE_MISSING'));

test('35F verifies all 13 reconciled candidate asset bytes before browser launch',async()=>{
 const files=await base();const r=await verifyOfflineMainAssetBytes(files,path=>readFile(join(root,'integrations/shopify/main-staging-reconciliation-candidate',path),'utf8'));
 assert.deepEqual(r,{verifiedAssets:13,shopifyWrites:0});
});
test('35F rejects stale on-disk candidate JS',async()=>{
 const files=await base();await assert.rejects(()=>verifyOfflineMainAssetBytes(files,async path=>path==='assets/tj34i-demo-static-preview.js'?'tampered':files.get(path)),/DOM_CANDIDATE_ASSET_DRIFT/);
});
test('35F rejects missing on-disk candidate CSS',async()=>{
 const files=await base();await assert.rejects(()=>verifyOfflineMainAssetBytes(files,async path=>{if(path===css)throw new Error('ENOENT');return files.get(path);}),/DOM_CANDIDATE_ASSET_MISSING/);
});
test('35F rejects absent asset reader',async()=>{
 const files=await base();await assert.rejects(()=>verifyOfflineMainAssetBytes(files,null),/DOM_ASSET_READER_REQUIRED/);
});
