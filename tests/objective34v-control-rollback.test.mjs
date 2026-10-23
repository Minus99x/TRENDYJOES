import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {getPreviewOptions} from '../src/preview-product-options.mjs';

// Exercise the actual offline DOM handlers without network or a Shopify session.
function fakeBrowser(product='concept-crew-tee'){
 const elements=new Map();
 class FakeElement{
  constructor(id){this.id=id;this.value='';this.textContent='';this.hidden=false;this.disabled=false;this.listeners=new Map();this.children=[];this.attrs=new Map();}
  addEventListener(type,fn){this.listeners.set(type,fn);}
  fire(type){const fn=this.listeners.get(type);assert.ok(fn,`listener ${this.id}:${type}`);return fn({target:this,currentTarget:this});}
  replaceChildren(...children){this.children=children;}
  append(...children){this.children.push(...children);}
  setAttribute(name,value){this.attrs.set(name,String(value));}
  removeAttribute(name){this.attrs.delete(name);}
  focus(){}
 }
 globalThis.document={createElementNS(_namespace,tag){return new FakeElement(tag);},getElementById(id){if(!elements.has(id))elements.set(id,new FakeElement(id));return elements.get(id);},addEventListener(){},hidden:false};
 globalThis.window={location:{search:`?product=${product}`},addEventListener(){},confirm(){return true;}};
 globalThis.Option=class{constructor(label,value){this.label=label;this.value=value;}};
 globalThis.requestAnimationFrame=()=>1;
 globalThis.ResizeObserver=undefined;
 return {el:id=>document.getElementById(id)};
}
let sequence=0;
async function load(product){const ui=fakeBrowser(product);await import(`../demo/static-preview.mjs?34v=${++sequence}`);return ui;}

for(const product of PRODUCT_MANIFESTS){
 test(`34V rejected forged color restores the visible selection for ${product.id}`,async()=>{
  const ui=await load(product.id),color=ui.el('concept-color'),original=color.value;
  color.value='forged-color';color.fire('change');
  assert.equal(color.value,original,'DOM must match unchanged model after failed color action');
  assert.match(ui.el('status').textContent,/could not be applied/i);
 });
}
test('34V rejected forged size restores the previously valid selected size',async()=>{
 const ui=await load('concept-crew-tee'),size=ui.el('concept-size');
 const before=size.value;size.value='forged-size';size.fire('change');assert.equal(size.value,before);
});
test('34V rollback uses last committed color, not catalog default',async()=>{
 const ui=await load('concept-crew-tee'),color=ui.el('concept-color');
 color.value='slate';color.fire('change');assert.equal(color.value,'slate');
 color.value='forged-color';color.fire('change');assert.equal(color.value,'slate');
});
test('34V forged layer ID restores the previously selected active layer',async()=>{
 const ui=await load('concept-crew-tee');ui.el('text-entry').value='Layer one';ui.el('add-text').fire('click');
 const layers=ui.el('layers'),prior=layers.value;assert.match(prior,/static-layer-/);
 layers.value='forged-layer';layers.fire('change');assert.equal(layers.value,prior);
});
test('34V cross-surface hidden layer cannot remain visibly selected after rejection',async()=>{
 const ui=await load('concept-crew-tee');ui.el('text-entry').value='Front lettering';ui.el('add-text').fire('click');
 const frontId=ui.el('layers').value;ui.el('surface').value='back';ui.el('surface').fire('change');
 const layers=ui.el('layers');assert.equal(layers.value,'');
 layers.value=frontId;layers.fire('change');assert.equal(layers.value,'');
});
test('34V rejected controls do not prevent later valid option changes',async()=>{
 const ui=await load('concept-crew-tee'),color=ui.el('concept-color'),size=ui.el('concept-size');
 color.value='forged';color.fire('change');size.value='forged';size.fire('change');
 color.value='slate';color.fire('change');size.value='m';size.fire('change');
 assert.equal(color.value,'slate');assert.equal(size.value,'m');
 assert.match(ui.el('status').textContent,/Illustrative size or format changed/);
});
test('34V rejected option does not leak unadded customer wording into feedback',async()=>{
 const ui=await load('concept-crew-tee');ui.el('text-entry').value='PRIVATE CUSTOMER WORDING';
 ui.el('concept-color').value='forged';ui.el('concept-color').fire('change');
 assert.doesNotMatch(ui.el('status').textContent,/PRIVATE|CUSTOMER|WORDING/);
 assert.equal(ui.el('text-entry').value,'PRIVATE CUSTOMER WORDING');
});
test('34V offline DOM control handlers contain no persistence or commerce requests',async()=>{
 const source=await readFile(new URL('../demo/static-preview.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(source,/\bfetch\s*\(|\blocalStorage\b|\bsessionStorage\b|\bnew\s+(?:XMLHttpRequest|WebSocket)\b|\/cart\/add/);
});
