import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';

// Actual offline static-preview browser handlers, deterministic fake DOM.
// This is not hosted/Shopify/native-browser acceptance.
function fakeBrowser(product='concept-crew-tee'){
 const elements=new Map();
 class FakeElement{
  constructor(id){this.id=id;this.value='';this.textContent='';this.hidden=false;this.disabled=false;this.listeners=new Map();this.children=[];this.attrs=new Map();}
  addEventListener(type,fn){this.listeners.set(type,fn);}
  fire(type){const fn=this.listeners.get(type);assert.ok(fn,`listener ${this.id}:${type}`);return fn({target:this,currentTarget:this});}
  replaceChildren(...children){this.children=children;}
  append(...children){this.children.push(...children);}
  setAttribute(k,v){this.attrs.set(k,String(v));}
  removeAttribute(k){this.attrs.delete(k);}
  focus(){}
 }
 globalThis.document={createElementNS(_namespace,tag){return new FakeElement(tag);},getElementById(id){if(!elements.has(id))elements.set(id,new FakeElement(id));return elements.get(id);},addEventListener(){},hidden:false};
 globalThis.window={location:{search:`?product=${product}`},addEventListener(){},confirm(){return true;}};
 globalThis.Option=class{constructor(label,value){this.label=label;this.value=value;}};
 globalThis.requestAnimationFrame=()=>1;globalThis.ResizeObserver=undefined;
 return {el:id=>document.getElementById(id)};
}
let sequence=0;
async function load(product){const ui=fakeBrowser(product);await import(`../demo/static-preview.mjs?34x=${++sequence}`);return ui;}
function add(ui,value){ui.el('text-entry').value=value;ui.el('text-entry').fire('input');ui.el('add-text').fire('click');}
function draft(ui,value){ui.el('text-entry').value=value;ui.el('text-entry').fire('input');}

for(const product of PRODUCT_MANIFESTS){
 test(`34X ${product.id} blocks review of uncommitted wording`,async()=>{
  const ui=await load(product.id);add(ui,'COMMITTED LETTERING');
  assert.equal(ui.el('review-preview').disabled,false,'committed design should be reviewable');
  draft(ui,'UNADDED CUSTOMER WORDING');
  assert.equal(ui.el('review-preview').disabled,true,'review must not omit pending customer wording');
  assert.match(ui.el('review-help').textContent,/add or clear/i);
  ui.el('review-preview').fire('click');
  assert.equal(ui.el('preview-summary-panel').hidden,true,'forged click must not open stale review');
  assert.doesNotMatch(ui.el('status').textContent,/UNADDED|CUSTOMER|WORDING/);
 });
 test(`34X ${product.id} invalidates previously opened review when draft changes`,async()=>{
  const ui=await load(product.id);add(ui,'COMMITTED LETTERING');
  ui.el('review-preview').fire('click');assert.equal(ui.el('preview-summary-panel').hidden,false);
  draft(ui,'ANOTHER PRIVATE DRAFT');
  assert.equal(ui.el('preview-summary-panel').hidden,true);
  assert.equal(ui.el('review-product').textContent,'');
  assert.equal(ui.el('review-preview').disabled,true);
  assert.doesNotMatch(ui.el('status').textContent,/ANOTHER|PRIVATE|DRAFT/);
 });
}
test('34X empty draft restores review readiness after committed lettering',async()=>{
 const ui=await load();add(ui,'ONE');draft(ui,'pending');assert.equal(ui.el('review-preview').disabled,true);
 draft(ui,'');assert.equal(ui.el('review-preview').disabled,false);
 ui.el('review-preview').fire('click');assert.equal(ui.el('preview-summary-panel').hidden,false);
});
test('34X whitespace-only draft is treated as uncommitted customer work',async()=>{
 const ui=await load();add(ui,'ONE');draft(ui,'  \n  ');
 assert.equal(ui.el('review-preview').disabled,true);
});
test('34X adding pending wording restores review readiness and counts all committed layers',async()=>{
 const ui=await load();add(ui,'ONE');draft(ui,'TWO');assert.equal(ui.el('review-preview').disabled,true);
 ui.el('add-text').fire('click');assert.equal(ui.el('text-entry').value,'');
 assert.equal(ui.el('review-preview').disabled,false);
 ui.el('review-preview').fire('click');assert.equal(ui.el('preview-summary-panel').hidden,false);
 assert.match(ui.el('review-layers').textContent,/2 lettering element/);
});
test('34X invalid add preserves private draft and keeps review closed',async()=>{
 const ui=await load();add(ui,'ONE');draft(ui,'  ');
 ui.el('add-text').fire('click');assert.equal(ui.el('review-preview').disabled,true);
 assert.equal(ui.el('text-entry').value,'  ');
 ui.el('review-preview').fire('click');assert.equal(ui.el('preview-summary-panel').hidden,true);
});
test('34X generated staging browser module enforces the same draft review gate',async()=>{
 const {files,manifest}=await buildStagingStaticBundle({root:new URL('..',import.meta.url).pathname});
 const js=files.get('assets/tj34i-demo-static-preview.js');
 assert.match(js,/refreshReviewAvailability/);
 assert.match(js,/Add or clear unadded wording before reviewing/);
 assert.equal(manifest.checkoutEnabled,false);assert.equal(manifest.customerStorageEnabled,false);
});
test('34X no new storage, network, or commerce capability in browser handlers',async()=>{
 const source=await readFile(new URL('../demo/static-preview.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(source,/\bfetch\s*\(|\blocalStorage\b|\bsessionStorage\b|\bnew\s+(?:XMLHttpRequest|WebSocket)\b|\/cart\/add/);
});
