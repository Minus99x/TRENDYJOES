import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,writeFile,rm} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {buildStagingStaticBundle,themeAssetName,rewriteThemeModule,scopeThemeCss,themeSectionFromHtml} from '../src/staging-static-package.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const base=join(root,'integrations/shopify/staging-static-preview');
const sha=b=>createHash('sha256').update(b).digest('hex');
const build=()=>buildStagingStaticBundle({root});
test('34I source-pinned staging bundle contains 12 flat browser assets and one Shopify section candidate',async()=>{
 const {files,manifest}=await build();assert.equal(files.size,13);assert.equal(manifest.entries.length,13);
 assert.equal(manifest.hostedPreviewReady,false);assert.equal(manifest.checkoutEnabled,false);
 assert.equal(manifest.customerStorageEnabled,false);assert.equal(manifest.requiresMainEngineeringAcceptance,true);
 for(const item of manifest.entries){const data=files.get(item.path);assert.ok(data,item.path);assert.equal(item.bytes,Buffer.byteLength(data));assert.equal(item.sha256,sha(data));}
});
test('34I release assets and integrity manifest match deterministic generation byte for byte',async()=>{
 const a=await build(),b=await build();assert.deepEqual(a.manifest,b.manifest);
 for(const [path,content] of a.files){assert.equal(content,b.files.get(path));assert.equal(content,await readFile(join(base,path),'utf8'));}
 assert.deepEqual(JSON.parse(await readFile(join(base,'staging-static-preview-bundle-manifest.json'),'utf8')),a.manifest);
});
test('34I rewritten ESM imports resolve to flat, present theme asset files',async()=>{
 const {files}=await build();let importCount=0;
 for(const [path,code] of files){if(!path.endsWith('.js'))continue;
  assert.doesNotMatch(code,/from\s*['"]\.\.\//);assert.doesNotMatch(code,/from\s*['"]https?:/);
  for(const m of code.matchAll(/\b(?:import|export)\s+(?:[^'"\n]*?\sfrom\s*)?['"](\.\/[^'"\n]+)['"]/g)){
   importCount++;assert.ok(files.has('assets/'+m[1].slice(2)),m[1]);assert.match(m[1],/^\.\/tj34i-[a-z0-9-]+\.js$/);
  }
 }
 assert.ok(importCount>=8,`expected module graph edges, got ${importCount}`);
});
test('34I section is preview-only Liquid with locally scoped IDs and existing editor controls',async()=>{
 const {files}=await build();const code=files.get('sections/tj-static-preview-34i.liquid');
 assert.match(code,/\{% schema %\}/);assert.match(code,/"limit": 1/);assert.match(code,/id="tj34i-product"/);
 assert.match(code,/for="tj34i-product"/);assert.match(code,/aria-labelledby="tj34i-preview-summary-heading"/);
 assert.match(code,/id="tj34i-mode-2d"/);assert.match(code,/id="tj34i-mode-3d"/);
 assert.match(code,/id="tj34i-review-preview"/);assert.match(code,/type="module"/);
 assert.doesNotMatch(code,/<form\b|<input[^>]*type="file"|href="\/(?:checkout|cart)"/i);
 assert.match(code,/NOT SAVED · NO PURCHASE OR ORDER CREATED/);
});
test('34I CSS selectors are scoped and mobile media queries remain intact',async()=>{
 const {files}=await build();for(const [path,code] of files){if(!path.endsWith('.css'))continue;
  assert.match(code,/#tj34i-root/);assert.doesNotMatch(code,/(?:^|})\s*(?:body|:root|\.workspace|#stage)\s*\{/);
  assert.doesNotMatch(code,/@import\b|url\s*\(/);assert.match(code,/#tj34i-stage-3d/);
 }
 assert.match(files.get('assets/tj34i-demo-studio.css'),/@media\(max-width:700px\)/);
});
test('34I staging editor references namespaced DOM IDs, not Shopify document-global common IDs',async()=>{
 const {files}=await build();const code=files.get('assets/tj34i-demo-static-preview.js');
 assert.match(code,/document\.getElementById\('tj34i-'\+id\)/);
 assert.doesNotMatch(code,/document\.getElementById\(id\)/);
});
test('34I rejects forged, absolute, traversal, external and missing module dependencies',()=>{
 const mapping=new Map([['demo/static-preview.mjs','tj34i-demo-static-preview.js']]);
 for(const path of ['../secret.mjs','/etc/passwd','demo/../src/x.mjs','src/file.js','demo/%2e%2e.mjs'])assert.throws(()=>themeAssetName(path),/UNSAFE_STAGING_SOURCE_PATH/);
 for(const spec of ['https://example.com/x.mjs','../src/private.mjs','./missing.mjs','/src/x.mjs','./x.mjs?token=1'])assert.throws(()=>rewriteThemeModule(`import x from '${spec}';`,'demo/static-preview.mjs',mapping),/NONLOCAL_THEME_IMPORT|MISSING_THEME_DEPENDENCY/);
 assert.throws(()=>rewriteThemeModule("import('./x.mjs')",'demo/static-preview.mjs',mapping),/UNSUPPORTED_THEME_IMPORT/);
});
test('34I rejects unsafe CSS and unsupported at-rules without silently emitting unscoped selectors',()=>{
 for(const css of ["@import url('https://example.com/x.css');",'body{background:url(https://evil.example/a)}','@font-face{font-family:x}','div{color:red'])assert.throws(()=>scopeThemeCss(css),/UNSAFE_THEME_CSS|UNSUPPORTED_THEME_CSS_AT_RULE|UNBALANCED_THEME_CSS/);
 assert.equal(scopeThemeCss(':root{--x:red}body{color:var(--x)}'), '#tj34i-root{box-sizing:border-box;}\n#tj34i-root{--x:red}#tj34i-root{color:var(--x)}\n');
});
test('34I rejects malformed or hostile static section source and duplicate IDs',()=>{
 const css=['tj34i-demo-studio.css','tj34i-demo-static-preview.css'];const js='tj34i-demo-static-preview.js';
 for(const body of ['<div id="a"></div><div id="a"></div>','<form action="/checkout"></form>','<button onclick="steal()">X</button>','<script>alert(1)</script>'])assert.throws(()=>themeSectionFromHtml(`<html><body>${body}<script type="module" src="./static-preview.mjs"></script></body></html>`,css,js),/INVALID_STATIC_IDS|UNSAFE_STATIC_MARKUP/);
});
test('34I original standalone static demo remains unmodified by staging adapter',async()=>{
 const html=await readFile(join(root,'demo/static-preview.html'),'utf8');const js=await readFile(join(root,'demo/static-preview.mjs'),'utf8');
 assert.match(html,/id="product"/);assert.match(js,/document\.getElementById\(id\)/);
 assert.doesNotMatch(html,/tj34i-/);assert.doesNotMatch(js,/tj34i-/);
});
