import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {resolve,join} from 'node:path';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {createStaticPreviewState,updateStaticPreview} from '../src/static-preview-contract.mjs';
import * as contract from '../src/static-preview-contract.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const fresh=()=>createStaticPreviewState('?product=concept-crew-tee');
const choose=(state,surfaceId)=>updateStaticPreview(state,{type:'SELECT_SURFACE',surfaceId});
const decision=(state,draft,target)=>contract.staticPreviewSurfaceDraftTransition(state,draft,target);

test('34U typed front wording requires confirmation before changing to back',()=>{
 assert.equal(decision(fresh(),'FRONT-ONLY PRIVATE WORDING','back'),'DISCARD_CONFIRMATION_REQUIRED');
});
test('34U typed draft requires confirmation for every other valid surface',()=>{
 const state=fresh();
 for(const target of ['back','sleeve-left'])assert.equal(decision(state,'private draft',target),'DISCARD_CONFIRMATION_REQUIRED');
});
test('34U whitespace-only draft is protected rather than silently discarded',()=>{
 assert.equal(decision(fresh(),' \n  ','back'),'DISCARD_CONFIRMATION_REQUIRED');
});
test('34U no typed wording permits a normal surface switch',()=>{
 assert.equal(decision(fresh(),'','back'),'SAFE');
});
test('34U selecting the current surface is a no-op even with a draft',()=>{
 assert.equal(decision(fresh(),'PRIVATE','front'),'SAME_SURFACE');
});
test('34U draft guard follows product-specific surfaces without apparel assumptions',()=>{
 for(const product of PRODUCT_MANIFESTS){
  const state=createStaticPreviewState('?product='+product.id);
  const other=product.surfaces.find(s=>s.id!==state.surfaceId);
  if(!other)continue;
  assert.equal(decision(state,'CUSTOM WORDING',other.id),'DISCARD_CONFIRMATION_REQUIRED',product.id);
 }
});
test('34U switching away and back without draft does not change the design state',()=>{
 const state=fresh();
 assert.equal(decision(state,'','back'),'SAFE');
 assert.equal(decision(choose(state,'back'),'','front'),'SAFE');
 assert.deepEqual(choose(choose(state,'back'),'front').layers,[]);
});
test('34U forged surface IDs fail closed without exposing draft',()=>{
 for(const target of [null,undefined,42,{},'unknown','__proto__','constructor']){
  assert.equal(decision(fresh(),'PRIVATE CUSTOMER WORDING',target),'REJECTED');
 }
});
test('34U malformed state and nonstring composer values fail closed',()=>{
 for(const state of [null,{}, {...fresh(),surfaceId:'forged'}, {...fresh(),productManifestId:'forged'}, {...fresh(),layers:null}, {...fresh(),previewSelection:null}]){
  assert.equal(decision(state,'PRIVATE','back'),'REJECTED');
 }
 for(const draft of [null,undefined,0,{},[],new String('PRIVATE')])assert.equal(decision(fresh(),draft,'back'),'REJECTED');
});
test('34U pure guard never changes state or reflects private wording',()=>{
 const state=fresh(),before=structuredClone(state);
 const result=decision(state,'SECRET CUSTOMER NAME','back');
 assert.deepEqual(state,before);assert.doesNotMatch(result,/SECRET|CUSTOMER|NAME/);
});

function fakeBrowser(){
 const elements=new Map();let confirmations=0,confirmationResponse=false;
 class FakeElement{
  constructor(id){this.id=id;this.value='';this.textContent='';this.hidden=false;this.disabled=false;this.listeners=new Map();this.children=[];this.attrs=new Map();this.focused=false;}
  addEventListener(type,fn){this.listeners.set(type,fn);}
  fire(type){const fn=this.listeners.get(type);assert.ok(fn,`listener for ${this.id}:${type}`);return fn({target:this,currentTarget:this});}
  replaceChildren(...children){this.children=children;}
  append(...children){this.children.push(...children);}
  setAttribute(name,value){this.attrs.set(name,String(value));}
  removeAttribute(name){this.attrs.delete(name);}
  focus(){this.focused=true;}
 }
 globalThis.document={getElementById(id){if(!elements.has(id))elements.set(id,new FakeElement(id));return elements.get(id);},addEventListener(){},hidden:false};
 globalThis.window={location:{search:'?product=concept-crew-tee'},addEventListener(){},confirm(){confirmations++;return confirmationResponse;}};
 globalThis.Option=class {constructor(label,value){this.label=label;this.value=value;}};
 globalThis.requestAnimationFrame=()=>1; // avoid WebGL; exercise actual DOM event handlers
 globalThis.ResizeObserver=undefined;
 return {el:id=>document.getElementById(id),confirm(value){confirmationResponse=value;},get confirmations(){return confirmations;}};
}
let demoCase=0;
async function loadDemo(){
 const browser=fakeBrowser();
 await import(`../demo/static-preview.mjs?34u=${++demoCase}`);
 return browser;
}
test('34U DOM: cancel keeps front selected and unadded wording untouched',async()=>{
 const ui=await loadDemo();ui.confirm(false);
 ui.el('text-entry').value='FRONT PRIVATE TEXT';ui.el('surface').value='back';ui.el('surface').fire('change');
 assert.equal(ui.confirmations,1);assert.equal(ui.el('surface').value,'front');
 assert.equal(ui.el('text-entry').value,'FRONT PRIVATE TEXT');
});
test('34U DOM: confirmed switch clears unadded wording instead of moving it to back',async()=>{
 const ui=await loadDemo();ui.confirm(true);
 ui.el('text-entry').value='FRONT PRIVATE TEXT';ui.el('surface').value='back';ui.el('surface').fire('change');
 assert.equal(ui.confirmations,1);assert.equal(ui.el('surface').value,'back');assert.equal(ui.el('text-entry').value,'');
 ui.el('add-text').fire('click');assert.equal(ui.el('layers').children.length,1,'no lettering silently added to back');
});
test('34U DOM: blank composer switches surfaces without unnecessary prompt',async()=>{
 const ui=await loadDemo();ui.el('surface').value='back';ui.el('surface').fire('change');
 assert.equal(ui.confirmations,0);assert.equal(ui.el('surface').value,'back');
});
test('34U DOM: after cancellation, adding wording still targets original front',async()=>{
 const ui=await loadDemo();ui.confirm(false);
 ui.el('text-entry').value='FRONT TEXT';ui.el('surface').value='back';ui.el('surface').fire('change');
 ui.el('add-text').fire('click');assert.equal(ui.el('layers').children.length,2);
 assert.equal(ui.el('surface').value,'front');assert.equal(ui.el('text-entry').value,'');
});
test('34U offline generated browser source and assets carry the surface-draft guard',async()=>{
 const demo=await readFile(join(root,'demo/static-preview.mjs'),'utf8');
 const browser=await readFile(join(root,'integrations/shopify/staging-static-preview/assets/tj34i-demo-static-preview.js'),'utf8');
 const contract=await readFile(join(root,'integrations/shopify/staging-static-preview/assets/tj34i-src-static-preview-contract.js'),'utf8');
 for(const text of [demo,browser])assert.match(text,/staticPreviewSurfaceDraftTransition/);
 assert.match(contract,/DISCARD_CONFIRMATION_REQUIRED/);
});
test('34U surface draft guard remains offline-only and never authorizes commerce',async()=>{
 const code=await readFile(join(root,'demo/static-preview.mjs'),'utf8');
 assert.doesNotMatch(code,/\bfetch\s*\(|\blocalStorage\b|\bsessionStorage\b|\bnew\s+(?:XMLHttpRequest|WebSocket)\b|\/cart\/add/);
});
