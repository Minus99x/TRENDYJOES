import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {getPreviewOptions} from '../src/preview-product-options.mjs';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';

// Deterministic offline execution of the actual browser event handlers.
// A native browser can suppress beforeunload prompts without user activation;
// these tests prove the handler contract, not a cross-browser acceptance claim.
function fakeBrowser(product='concept-crew-tee'){
 const elements=new Map(),windowListeners=new Map();let confirmation=true;
 class FakeElement{
  constructor(id){this.id=id;this.value='';this.textContent='';this.hidden=false;this.disabled=false;this.listeners=new Map();this.children=[];this.attrs=new Map();}
  addEventListener(type,fn){this.listeners.set(type,fn);}
  fire(type){const fn=this.listeners.get(type);assert.ok(fn,`missing ${this.id}:${type}`);return fn({target:this,currentTarget:this});}
  replaceChildren(...children){this.children=children;}
  append(...children){this.children.push(...children);}
  setAttribute(k,v){this.attrs.set(k,String(v));}
  removeAttribute(k){this.attrs.delete(k);}
  focus(){}
 }
 globalThis.document={createElementNS(_namespace,tag){return new FakeElement(tag);},getElementById(id){if(!elements.has(id))elements.set(id,new FakeElement(id));return elements.get(id);},addEventListener(){},hidden:false};
 globalThis.window={location:{search:`?product=${product}`},addEventListener(type,fn){windowListeners.set(type,fn);},confirm(){return confirmation;}};
 globalThis.Option=class{constructor(label,value){this.label=label;this.value=value;}};
 globalThis.requestAnimationFrame=()=>1;globalThis.ResizeObserver=undefined;
 const unload=()=>{const event={defaultPrevented:false,returnValue:undefined,preventDefault(){this.defaultPrevented=true;}};
  const fn=windowListeners.get('beforeunload');assert.equal(typeof fn,'function','missing beforeunload protection');fn(event);return event;};
 return {el:id=>document.getElementById(id),unload,confirm(value){confirmation=value;}};
}
let sequence=0;
async function load(product){const ui=fakeBrowser(product);await import(`../demo/static-preview.mjs?34w=${++sequence}`);return ui;}
const warns=e=>e.defaultPrevented===true&&e.returnValue==='';
const quiet=e=>e.defaultPrevented===false&&e.returnValue===undefined;

for(const product of PRODUCT_MANIFESTS){
 test(`34W pristine ${product.id} does not intercept browser navigation`,async()=>{
  const ui=await load(product.id);assert.equal(quiet(ui.unload()),true);
 });
 test(`34W ${product.id} protects added unsaved lettering on navigation`,async()=>{
  const ui=await load(product.id);ui.el('text-entry').value='PRIVATE CUSTOMER DESIGN';ui.el('add-text').fire('click');
  assert.equal(ui.el('text-entry').value,'');assert.equal(warns(ui.unload()),true);
 });
}
test('34W unadded wording triggers native navigation warning without saving text',async()=>{
 const ui=await load();ui.el('text-entry').value='PRIVATE UNSAVED COMPOSER';
 const e=ui.unload();assert.equal(warns(e),true);assert.equal(ui.el('text-entry').value,'PRIVATE UNSAVED COMPOSER');
 assert.doesNotMatch(String(e.returnValue),/PRIVATE|UNSAVED|COMPOSER/);
});
test('34W whitespace-only composer is still deliberate work',async()=>{
 const ui=await load();ui.el('text-entry').value='  \n ';assert.equal(warns(ui.unload()),true);
});
test('34W changed illustrative color alone triggers warning',async()=>{
 const ui=await load(),color=ui.el('concept-color');color.value='slate';color.fire('change');assert.equal(warns(ui.unload()),true);
});
test('34W changed illustrative size alone triggers warning',async()=>{
 const ui=await load(),size=ui.el('concept-size');size.value='m';size.fire('change');assert.equal(warns(ui.unload()),true);
});
test('34W 2D/3D viewing alone does not trigger warning',async()=>{
 const ui=await load();ui.el('mode-2d').fire('click');assert.equal(quiet(ui.unload()),true);
});
test('34W clearing design removes navigation warning and private draft',async()=>{
 const ui=await load();ui.el('text-entry').value='SECRET';ui.el('add-text').fire('click');
 assert.equal(warns(ui.unload()),true);ui.el('reset').fire('click');
 assert.equal(quiet(ui.unload()),true);assert.equal(ui.el('text-entry').value,'');
});
test('34W confirmed product switch clears old warning when destination is pristine',async()=>{
 const ui=await load();ui.el('text-entry').value='SECRET';ui.el('add-text').fire('click');
 ui.el('product').value='concept-rug';ui.el('product').fire('change');
 assert.equal(quiet(ui.unload()),true);assert.equal(ui.el('text-entry').value,'');
});
test('34W cancelled product switch retains warning and private design',async()=>{
 const ui=await load();ui.confirm(false);ui.el('text-entry').value='SECRET';
 ui.el('product').value='concept-rug';ui.el('product').fire('change');
 assert.equal(ui.el('product').value,'concept-crew-tee');assert.equal(ui.el('text-entry').value,'SECRET');
 assert.equal(warns(ui.unload()),true);
});
test('34W returned navigation event never contains customer wording, IDs or tokens',async()=>{
 const ui=await load();ui.el('text-entry').value='SECRET TOKEN CUSTOMER-123';
 const e=ui.unload();assert.deepEqual(Object.keys(e).sort(),['defaultPrevented','preventDefault','returnValue'].sort());
 assert.doesNotMatch(JSON.stringify(e),/SECRET|TOKEN|CUSTOMER|static-layer/);
});
test('34W offline staged browser asset includes the navigation guard',async()=>{
 const {files,manifest}=await buildStagingStaticBundle({root:new URL('..',import.meta.url).pathname});
 assert.match(files.get('assets/tj34i-demo-static-preview.js'),/beforeunload/);
 assert.equal(manifest.checkoutEnabled,false);assert.equal(manifest.customerStorageEnabled,false);
});
test('34W navigation protection adds no persistence, network or commerce capability',async()=>{
 const source=await readFile(new URL('../demo/static-preview.mjs',import.meta.url),'utf8');
 assert.match(source,/beforeunload/);
 assert.doesNotMatch(source,/\bfetch\s*\(|\blocalStorage\b|\bsessionStorage\b|\bnew\s+(?:XMLHttpRequest|WebSocket)\b|\/cart\/add/);
});
