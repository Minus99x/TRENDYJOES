import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {buildMainStagingReconciliation,reconcileMainStaging} from '../src/main-staging-reconciliation.mjs';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {createStaticPreviewState,updateStaticPreview,reviewStaticPreview,staticPreviewHasPendingWork,staticPreviewReviewAvailability,staticPreviewAccessibilitySummary} from '../src/static-preview-contract.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const out=join(root,'integrations/shopify/main-staging-reconciliation-candidate');
const fixtures=join(root,'fixtures/main-staging-reconciliation');
const sha=s=>createHash('sha256').update(s).digest('hex');
const setup=async()=>{
 const night=(await buildStagingStaticBundle({root})).files;
 const mainManifest=JSON.parse(await readFile(join(fixtures,'main35/MAIN_OBJECTIVE35_INTEGRATION_MANIFEST.json'),'utf8'));
 const main36Manifest=JSON.parse(await readFile(join(fixtures,'main36/manifest.json'),'utf8'));
 const main35={},main36={};
 for(const p of ['assets/tj34i-demo-studio.css','assets/tj34i-demo-static-preview.css','sections/tj-static-preview-34i.liquid'])main35[p]=await readFile(join(fixtures,'main35',p),'utf8');
 for(const p of ['assets/tj34i-src-static-preview-contract.js','assets/tj34i-demo-static-preview.js'])main36[p]=await readFile(join(fixtures,'main36/staging',p),'utf8');
 return {night,main35,main36,mainManifest,main36Manifest};
};
const section='sections/tj-static-preview-34i.liquid',css='assets/tj34i-demo-studio.css';
const source=()=>buildMainStagingReconciliation({root});
test('35E candidate is deterministic and retains all 13 offline Night asset paths',async()=>{
 const a=await source(),b=await source();assert.equal(a.files.size,13);assert.deepEqual(a.manifest,b.manifest);
 for(const [p,s] of a.files)assert.equal(s,b.files.get(p));
});
test('35E generated candidate is reproducible byte-for-byte from pinned sources',async()=>{
 const {files,manifest}=await source();for(const [p,s] of files)assert.equal(await readFile(join(out,p),'utf8'),s);
 assert.deepEqual(JSON.parse(await readFile(join(out,'main-night-reconciliation-manifest.json'),'utf8')),manifest);
});
test('35E every candidate asset hash and byte length is independently verifiable',async()=>{
 const {files,manifest}=await source();assert.equal(manifest.entries.length,13);
 for(const e of manifest.entries){const s=files.get(e.path);assert.equal(e.sha256,sha(s));assert.equal(e.bytes,Buffer.byteLength(s));}
});
test('35E preserves Main approved h2 and its typography rather than inserting a second H1',async()=>{
 const {files}=await source();const s=files.get(section),c=files.get(css);
 assert.match(s,/<h2>Ideas made <em>yours\.<\/em><\/h2>/);assert.doesNotMatch(s,/<h1\b/i);
 assert.match(c,/#tj34i-root \.masthead h2\{/);assert.doesNotMatch(c,/#tj34i-root \.masthead h1\{/);
});
test('35E preserves Main artwork tryout anchor exactly once without enabling upload',async()=>{
 const {files}=await source();const s=files.get(section);
 assert.equal((s.match(/href="#tj-try-studio"/g)||[]).length,1);
 assert.match(s,/Artwork uploads, GLB imports, saved drafts/);assert.doesNotMatch(s,/<input[^>]+type=["']file/);
});
test('35E retains Main-specific focus-visible artwork link CSS',async()=>{
 const {files}=await source();const c=files.get(css);
 assert.match(c,/\.panel \.fineprint a:focus-visible\{outline:3px solid #52697A/);
});
test('35E preserves every non-conflicting Night asset byte for byte',async()=>{
 const {files}=await source(),{files:night}=await buildStagingStaticBundle({root});
 for(const [p,s] of night)if(p!==section&&p!==css)assert.equal(files.get(p),s,p);
});
test('35E retains Night review gate and accessibility section hooks',async()=>{
 const {files}=await source();const s=files.get(section),js=files.get('assets/tj34i-demo-static-preview.js');
 for(const id of ['tj34i-concept-a11y-summary','tj34i-review-help','tj34i-text-help','tj34i-preview-summary-panel'])assert.match(s,new RegExp('id="'+id+'"'));
 assert.match(js,/staticPreviewReviewAvailability/);assert.match(js,/staticPreviewSurfaceDraftTransition/);
});
test('35E preserves fail-closed review, pending-draft, mutation integrity and Unicode guards',async()=>{
 const s=createStaticPreviewState(),p=PRODUCT_MANIFESTS.find(x=>x.id===s.productManifestId);
 assert.equal(staticPreviewReviewAvailability(s).ready,false);
 assert.equal(staticPreviewHasPendingWork(s,'Unadded wording'),true);
 assert.ok(staticPreviewAccessibilitySummary(s).description);
 assert.throws(()=>updateStaticPreview(s,{type:'ADD_TEXT',value:'\u202Eabc'}));
 const added=updateStaticPreview(s,{type:'ADD_TEXT',value:'Hello'});
 assert.equal(reviewStaticPreview(added).layerCount,1);
 const tampered={...added,layers:added.layers.map(l=>({...l,rotationDeg:NaN}))};
 assert.throws(()=>reviewStaticPreview(tampered));assert.throws(()=>updateStaticPreview(tampered,{type:'RESET'}));
 assert.ok(p);
});
test('35E keeps all customer/checkout/storage/manufacturing gates false',async()=>{
 const {manifest,files}=await source();for(const key of ['hostedAuthentication','customerStorage','checkoutEnabled','manufacturingApproved'])assert.equal(manifest[key],false);
 assert.equal(manifest.shopifyWrites,0);assert.match(manifest.scope,/NOT_INSTALLED/);
 assert.doesNotMatch(files.get(section),/<form\b|href=["']\/(?:cart|checkout)|\btype=["']submit["']/i);
});
test('35E Main35 pinned fixture corruption fails closed',async()=>{
 const x=await setup();x.main35[css]+='/* injected */';assert.throws(()=>reconcileMainStaging(x),/MAIN35_FIXTURE_TAMPER/);
});
test('35E Main36 pinned deployed JS corruption fails closed',async()=>{
 const x=await setup();x.main36['assets/tj34i-demo-static-preview.js']+='// injected';assert.throws(()=>reconcileMainStaging(x),/MAIN36_FIXTURE_TAMPER/);
});
test('35E forged Main35 manifest hash fails closed',async()=>{
 const x=await setup();x.mainManifest.files[css].sha256='0'.repeat(64);assert.throws(()=>reconcileMainStaging(x),/MAIN35_PROVENANCE_MISMATCH/);
});
test('35E forged Main36 provenance fails closed',async()=>{
 const x=await setup();x.main36Manifest.nightSourceSha256='0'.repeat(64);assert.throws(()=>reconcileMainStaging(x),/MAIN36_PROVENANCE_MISMATCH/);
});
test('35E missing Main35 fixture fails closed',async()=>{
 const x=await setup();delete x.main35[section];assert.throws(()=>reconcileMainStaging(x),/MAIN35_FIXTURE_SET_MISMATCH/);
});
test('35E unexpected Main35 fixture fails closed',async()=>{
 const x=await setup();x.main35['assets/evil.js']='hi';assert.throws(()=>reconcileMainStaging(x),/MAIN35_FIXTURE_SET_MISMATCH/);
});
test('35E missing Night asset fails closed',async()=>{
 const x=await setup();x.night.delete('assets/tj34i-src-static-preview-contract.js');assert.throws(()=>reconcileMainStaging(x),/NIGHT_ASSET_GRAPH_MISMATCH/);
});
test('35E duplicate Night artwork link fails closed',async()=>{
 const x=await setup();x.night.set(section,x.night.get(section).replace('Artwork uploads, GLB imports','Artwork uploads, GLB imports')+'<p class="fineprint"><a href="#tj-try-studio">Need to preview your own artwork? Open our separate 2D artwork tryout below.</a></p>');
 assert.throws(()=>reconcileMainStaging(x),/DUPLICATE_MAIN_ARTWORK_LINK/);
});
test('35E unexpected Night heading change fails closed',async()=>{
 const x=await setup();x.night.set(section,x.night.get(section).replace('<h1>Ideas made','<h2>Ideas made'));
 assert.throws(()=>reconcileMainStaging(x),/NIGHT_HEADING_CONFLICT/);
});
test('35E malformed Night candidate checkout markup fails closed',async()=>{
 const x=await setup();x.night.set(section,x.night.get(section)+'<form action="/checkout"></form>');
 assert.throws(()=>reconcileMainStaging(x),/COMMERCE_MARKUP_FORBIDDEN/);
});
test('35E Main CSS missing approved link rules fails closed even if its manifest is repinned',async()=>{
 const x=await setup();x.main35[css]=x.main35[css].replace(/\n#tj34i-root \.panel \.fineprint a\{[^\n]+\n/,'');x.mainManifest.files[css].sha256=sha(x.main35[css]);
 assert.throws(()=>reconcileMainStaging(x),/MAIN35_PROVENANCE_MISMATCH/);
});
test('35E Night accessibility guards missing fails closed',async()=>{
 const x=await setup();x.night.set(section,x.night.get(section).replace('id="tj34i-concept-a11y-summary"','id="tj34i-missing-summary"'));
 assert.throws(()=>reconcileMainStaging(x),/NIGHT_GUARDS_MISSING/);
});
test('35E theme ESM dependencies remain entirely local to the candidate',async()=>{
 const {files}=await source();for(const [p,s] of files){if(!p.endsWith('.js'))continue;
  for(const m of s.matchAll(/\b(?:import|export)\s+(?:[^'"\n]*?\sfrom\s*)?['"](\.\/[^'"\n]+)['"]/g))assert.ok(files.has('assets/'+m[1].slice(2)),p+':'+m[1]);
  assert.doesNotMatch(s,/from\s*['"]https?:/);
 }
});

test('35E Main36 re-pinned altered deployed code is rejected by immutable manifest provenance',async()=>{
 const x=await setup();x.main36['assets/tj34i-demo-static-preview.js']+='// forged';
 x.main36Manifest.files['assets/tj34i-demo-static-preview.js'].deployedSha256=sha(x.main36['assets/tj34i-demo-static-preview.js']);
 assert.throws(()=>reconcileMainStaging(x),/MAIN36_PROVENANCE_MISMATCH/);
});
