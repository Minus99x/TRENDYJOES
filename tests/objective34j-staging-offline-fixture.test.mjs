import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {buildStagingStaticBundle,themeSectionFromHtml} from '../src/staging-static-package.mjs';
import {validateOfflineStagingCandidate,renderOfflineStagingFixture,createOfflineStagingFixtureServer} from '../src/staging-offline-fixture.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const build=()=>buildStagingStaticBundle({root});
const section='sections/tj-static-preview-34i.liquid';
const clone=o=>structuredClone(o);

test('34J generated section removes embedded main and scopes header/footer to named region',async()=>{
 const {files,manifest}=await build();const liquid=files.get(section);const html=renderOfflineStagingFixture(files,manifest);
 assert.doesNotMatch(liquid,/<main\b|<\/main>/i);
 assert.match(liquid,/<section id="tj34i-root"[^>]*aria-label="Design Works concept preview"/);
 assert.match(liquid,/<div class="workspace" role="group" aria-label="Customization workspace">/);
 assert.equal([...html.matchAll(/<main\b/g)].length,1);assert.equal([...html.matchAll(/<\/main>/g)].length,1);
 assert.match(html,/<main id="offline-host-main">/);
 assert.match(html,/<header>Simulated host header<\/header>/);
 assert.match(html,/<footer>Simulated host footer<\/footer>/);
});
test('34J all staging ID references resolve inside its isolated region',async()=>{
 const {files}=await build();const liquid=files.get(section);
 const ids=[...liquid.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);const known=new Set(ids);
 assert.equal(ids.length,known.size);
 for(const [,attr,value] of liquid.matchAll(/\b(for|aria-labelledby|aria-describedby|aria-controls)="([^"]+)"/g))for(const id of value.split(/\s+/))assert.ok(known.has(id),`${attr}: ${id}`);
 assert.ok(ids.length>20);assert.ok(ids.every(id=>id.startsWith('tj34i-')));
});
test('34J source candidate integrity and deterministic local Liquid substitution',async()=>{
 const a=await build();assert.equal(validateOfflineStagingCandidate(a.files,a.manifest),true);
 const html=renderOfflineStagingFixture(a.files,a.manifest);
 assert.equal(html,renderOfflineStagingFixture(a.files,a.manifest));
 assert.doesNotMatch(html,/\{%|\{\{|\/checkout|\/cart|<form\b/i);
 assert.equal((html.match(/rel="stylesheet"/g)||[]).length,2);
 assert.match(html,/<script type="module" src="\/assets\/tj34i-demo-static-preview.js"><\/script>/);
});
test('34J tampered or missing asset is rejected before fixture can serve',async()=>{
 const {files,manifest}=await build();const changed=new Map(files);changed.set('assets/tj34i-demo-studio.css',changed.get('assets/tj34i-demo-studio.css')+'/* tamper */');
 assert.throws(()=>createOfflineStagingFixtureServer(changed,manifest),/CANDIDATE_INTEGRITY_MISMATCH/);
 changed.delete('assets/tj34i-demo-studio.css');assert.throws(()=>renderOfflineStagingFixture(changed,manifest),/INCOMPLETE_OFFLINE_CANDIDATE/);
});
test('34J duplicate, forged, or traversal manifest entries are rejected',async()=>{
 const {files,manifest}=await build();for(const bad of ['../outside.js','assets/../../outside.js','assets/evil.js','assets/tj34i-evil%2f.js']){
  const altered=clone(manifest);altered.entries[0].path=bad;
  assert.throws(()=>validateOfflineStagingCandidate(files,altered),/INVALID_CANDIDATE_PATH|CANDIDATE_INTEGRITY_MISMATCH/);
 }
 const dup=clone(manifest);dup.entries[1].path=dup.entries[0].path;
 assert.throws(()=>validateOfflineStagingCandidate(files,dup),/INVALID_CANDIDATE_PATH/);
});
test('34J unsupported Liquid or injected checkout markup fails closed',async()=>{
 const {files,manifest}=await build();for(const attack of ['{% render "secret" %}','{{ shop.email }}','<form action="/checkout"></form>']){
  const modified=new Map(files);modified.set(section,modified.get(section).replace('Demonstration only.',attack+' Demonstration only.'));
  const altered=clone(manifest);const item=altered.entries.find(x=>x.path===section);
  item.bytes=Buffer.byteLength(modified.get(section));
  const {createHash}=await import('node:crypto');item.sha256=createHash('sha256').update(modified.get(section)).digest('hex');
  assert.throws(()=>renderOfflineStagingFixture(modified,altered),/UNSUPPORTED_FIXTURE_LIQUID|FORBIDDEN_FIXTURE_COMMERCE/);
 }
});
test('34J rejects malformed nested main rather than embedding a second main',()=>{
 const html='<html><body><main class="workspace">X</main><main class="workspace">Y</main><script type="module" src="./static-preview.mjs"></script></body></html>';
 assert.throws(()=>themeSectionFromHtml(html,['tj34i-demo-studio.css','tj34i-demo-static-preview.css'],'tj34i-demo-static-preview.js'),/INVALID_EMBEDDED_MAIN_LANDMARK/);
});
test('34J local HTTP fixture serves preview and every flat asset with correct MIME',async(t)=>{
 const {files,manifest}=await build();const server=createOfflineStagingFixtureServer(files,manifest);
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
 const base=`http://127.0.0.1:${server.address().port}`;
 const page=await fetch(base+'/preview');assert.equal(page.status,200);assert.match(page.headers.get('content-type'),/text\/html/);
 assert.match(page.headers.get('content-security-policy'),/connect-src 'none'/);
 assert.match(await page.text(),/Design Works concept preview/);
 for(const [path,code] of files){if(!path.startsWith('assets/'))continue;
  const response=await fetch(base+'/'+path);assert.equal(response.status,200,path);
  assert.match(response.headers.get('content-type'),path.endsWith('.js')?/text\/javascript/:/text\/css/);
  assert.equal(await response.text(),code);
 }
});
test('34J local HTTP ESM graph resolves all transitive module imports without missing paths',async(t)=>{
 const {files,manifest}=await build();const server=createOfflineStagingFixtureServer(files,manifest);
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
 const base=`http://127.0.0.1:${server.address().port}`;
 const visited=new Set();let edges=0;
 async function walk(name){if(visited.has(name))return;visited.add(name);
  const response=await fetch(base+'/assets/'+name);assert.equal(response.status,200,name);
  const code=await response.text();assert.doesNotMatch(code,/\bimport\s*\(/);
  for(const match of code.matchAll(/\b(?:import|export)\s+(?:[^'"\n]*?\sfrom\s*)?['"](\.\/[^'"\n]+)['"]/g)){
   edges++;assert.match(match[1],/^\.\/tj34i-[a-z0-9-]+\.js$/);
   await walk(match[1].slice(2));
  }
 }
 await walk('tj34i-demo-static-preview.js');assert.ok(visited.size>=5);assert.ok(edges>=8);
});
test('34J offline fixture never exposes checkout or writes and rejects hostile URLs',async(t)=>{
 const {files,manifest}=await build();const server=createOfflineStagingFixtureServer(files,manifest);
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
 const base=`http://127.0.0.1:${server.address().port}`;
 for(const path of ['/cart','/checkout','/admin','/assets/../secret.js','/assets/tj34i-demo-static-preview.js?checkout=1','/assets/tj34i-evil%2f.js']){
  const response=await fetch(base+path,{redirect:'manual'});assert.equal(response.status,404,path);
 }
 for(const method of ['POST','PUT','DELETE']){const response=await fetch(base+'/preview',{method});assert.equal(response.status,405,method);}
});
test('34J standalone demo remains unchanged and staging bundle generated output is current',async()=>{
 const {files}=await build();const standalone=await readFile(join(root,'demo/static-preview.html'),'utf8');
 assert.match(standalone,/<main class="workspace">/);assert.doesNotMatch(standalone,/tj34i-root/);
 for(const [path,data] of files)assert.equal(data,await readFile(join(root,'integrations/shopify/staging-static-preview',path),'utf8'));
});
