import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {PRODUCT_MANIFESTS,MANIFEST_BY_ID} from '../src/catalog.mjs';
import {resolvePreviewEntry,previewEntryHref} from '../src/preview-entry.mjs';
import {createLocalServer} from '../src/local-server.mjs';
const html=await readFile(new URL('../demo/start.html',import.meta.url),'utf8');
const studio=await readFile(new URL('../demo/studio.mjs',import.meta.url),'utf8');
const editor=await readFile(new URL('../demo/index.html',import.meta.url),'utf8');
const css=await readFile(new URL('../demo/entry.css',import.meta.url),'utf8');
test('34B all eight universal concept cards deep-link to exact allowed manifests',()=>{
 const links=[...html.matchAll(/href="(\/demo\/\?product=[a-z0-9-]+)"/g)].map(m=>m[1]);
 assert.equal(links.length,PRODUCT_MANIFESTS.length);assert.equal(new Set(links).size,links.length);
 for(const m of PRODUCT_MANIFESTS){
  const href=previewEntryHref(m.id);assert.ok(links.includes(href));
  assert.deepEqual(resolvePreviewEntry(href.split('?')[1]),{status:'SELECTED',manifestId:m.id});
 }
});
test('34B product link rejects token, variant, owner, revision, price and extra parameters',()=>{
 for(const q of ['?product=concept-rug&ownerToken=abc','?product=concept-rug&variantGid=123','?product=concept-rug&checkout=true','?product=concept-rug&product=concept-tumbler','?owner=abc','?product=concept-rug&revision=1','?product=concept-rug&price=0']){
  assert.equal(resolvePreviewEntry(q).status,'INVALID_LINK',q);
 }
});
test('34B forged product IDs and prototype properties cannot be selected',()=>{
 for(const q of ['?product=__proto__','?product=constructor','?product=toString','?product=concept-rug%2F..','?product=%3Cscript%3E','?product=not-in-catalog','?product=concept-rug%ZZ','?product='+('x'.repeat(300))]){
  assert.notEqual(resolvePreviewEntry(q).status,'SELECTED',q);
 }
 assert.equal(previewEntryHref('__proto__'),null);assert.equal(previewEntryHref('missing'),null);
 assert.equal(resolvePreviewEntry('?product=concept-rug',{...MANIFEST_BY_ID,'concept-rug':{id:'different'}}).status,'UNKNOWN_PRODUCT');
});
test('34B no product link defaults to first manifest, without granting permissions',()=>{
 assert.deepEqual(resolvePreviewEntry(''),{status:'DEFAULT',manifestId:PRODUCT_MANIFESTS[0].id});
 assert.equal(resolvePreviewEntry('?product=concept-rug').manifestId,'concept-rug');
});
test('34B gateway includes explicit preview disclaimers, keyboard navigation and responsive styles',()=>{
 assert.match(html,/<main id="canvases">/);assert.match(html,/Local demonstration only/);
 assert.match(html,/No actual products, prices, checkout, orders/);
 assert.match(css,/:focus-visible/);assert.match(css,/@media\(max-width:520px\)/);
 assert.match(editor,/id="entry-feedback"/);assert.match(editor,/href="\/demo\/start.html"/);
 assert.match(studio,/resolvePreviewEntry\(window.location.search,availableManifests\)/);
 assert.match(studio,/applyPreviewEntry\(\);/);
 assert.doesNotMatch(html,/<form|<script|http:\/\/|https:\/\//i);
});
test('34B local HTTP gateway and editor deep link serve real assets, never commerce endpoints',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'tj-34b-'));
 const app=await createLocalServer({dataDir:dir});const {port}=await app.listen(0);
 const base=`http://127.0.0.1:${port}`;
 try{
  for(const [path,type] of [['/demo/start.html','text/html'],['/demo/entry.css','text/css'],['/demo/?product=concept-tumbler','text/html'],['/src/preview-entry.mjs','text/javascript']]){
   const r=await fetch(base+path);assert.equal(r.status,200,path);assert.ok(r.headers.get('content-type').includes(type));assert.equal(r.headers.get('x-frame-options'),'DENY');
  }
  const response=await fetch(base+'/api/shopify/cart/add',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
  assert.equal(response.status,404);
  assert.equal((await(await fetch(base+'/api/health')).json()).checkoutEnabled,false);
 }finally{await new Promise((resolve,reject)=>app.server.close(e=>e?reject(e):resolve()));await rm(dir,{recursive:true,force:true});}
});
