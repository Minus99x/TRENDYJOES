import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {MANIFEST_BY_ID,PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {validateComposition} from '../src/core.mjs';
import {nudgePreviewLayer,previewNudgeKeyAction} from '../src/preview-keyboard-position.mjs';
const tee=MANIFEST_BY_ID['concept-crew-tee'];
const base=()=>[{id:'A',type:'text',surfaceId:'front',x:.25,y:.32,width:.45,height:.17,rotationDeg:0,scaleFactor:1,value:'HELLO'}];
const run=(layers=base(),overrides={})=>nudgePreviewLayer({product:tee,layers,selectedId:'A',surfaceId:'front',direction:'right',...overrides});
for(const [key,direction] of [['ArrowLeft','left'],['ArrowRight','right'],['ArrowUp','up'],['ArrowDown','down']]){
 test(`keyboard ${key} maps to a fine movement and shift coarse movement`,()=>{
  assert.deepEqual(previewNudgeKeyAction({key}),{direction,step:.01});
  assert.deepEqual(previewNudgeKeyAction({key,shiftKey:true}),{direction,step:.05});
 });
}
test('browser-owned shortcuts, modifiers and arbitrary input do not move a layer',()=>{
 for(const event of [null,{},'ArrowRight',{key:'Tab'},{key:'Home'},
  {key:'ArrowRight',ctrlKey:true},{key:'ArrowRight',altKey:true},{key:'ArrowRight',metaKey:true}])
  assert.equal(previewNudgeKeyAction(event),null);
});
test('nudge is immutable, moves selected layer only and preserves artwork grants',()=>{
 const layers=[...base(),{id:'B',type:'artwork',surfaceId:'front',x:.1,y:.1,width:.2,height:.2,rotationDeg:0,artworkId:'PRIVATE'}];
 const before=structuredClone(layers);const result=run(layers);
 assert.equal(result.applied,true);assert.equal(result.layers[0].x,.26);
 assert.deepEqual(result.layers[1],before[1]);assert.deepEqual(layers,before);
 assert.equal(validateComposition(tee,{layers:result.layers}).length,0);
});
test('all four directions support coarse positioning without losing exact composition',()=>{
 for(const [direction,field,delta] of [['left','x',-.05],['right','x',.05],['up','y',-.05],['down','y',.05]]){
  const result=run(base(),{direction,step:.05});assert.equal(result.applied,true);
  assert.ok(Math.abs(result.layers[0][field]-(base()[0][field]+delta))<1e-8);
 }
});
test('rotated boundary collision fails closed and retains original reference',()=>{
 const layer={...base()[0],x:.01,y:.32,width:.2,height:.17,rotationDeg:45};
 // Start with a legal rotated layer and walk left until its rotated extent hits the zone.
 const w=.2,h=.17,rotWidth=Math.abs(w*Math.cos(Math.PI/4))+Math.abs(h*Math.sin(Math.PI/4));
 layer.x=Number(((rotWidth-w)/2+.00001).toFixed(6));
 assert.equal(validateComposition(tee,{layers:[layer]}).length,0);
 const input=[layer];const result=run(input,{direction:'left'});
 assert.equal(result.applied,false);assert.equal(result.reason,'ZONE_BOUNDARY');assert.equal(result.layers,input);
 assert.equal(input[0].x,layer.x);
});
test('invalid actions, missing selection and wrong surface fail closed',()=>{
 const l=base();
 for(const overrides of [{direction:'diagonal'},{direction:'__proto__'},{step:.001},{step:NaN},
  {selectedId:'B'},{surfaceId:'back'},{layers:null},{selectedId:7}]){
  const r=run(l,overrides);assert.equal(r.applied,false,JSON.stringify(overrides));assert.equal(r.layers,Object.hasOwn(overrides,'layers')?overrides.layers:l);
 }
});
test('existing invalid layer composition is never silently normalized',()=>{
 const layers=[{...base()[0],value:' '}];const r=run(layers);
 assert.equal(r.applied,false);assert.equal(r.reason,'INVALID_COMPOSITION');assert.equal(r.layers,layers);
});
test('same operation works for every merchandise category and refuses unavailable surface',()=>{
 for(const product of PRODUCT_MANIFESTS){
  const layer={...base()[0],surfaceId:product.surfaces[0].id};
  const result=nudgePreviewLayer({product,layers:[layer],selectedId:'A',surfaceId:layer.surfaceId,direction:'up'});
  assert.equal(result.applied,true,product.id);
  assert.equal(validateComposition(product,{layers:result.layers}).length,0);
 }
});
test('browser markup provides accessible position controls, focus target, no purchasing gate',async()=>{
 const html=await readFile(new URL('../demo/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../demo/studio.mjs',import.meta.url),'utf8');
 for(const id of ['nudge-up','nudge-down','nudge-left','nudge-right','nudge-help'])assert.ok(html.includes(`id="${id}"`));
 assert.match(html,/id="stage"[^>]*tabindex="0"[^>]*aria-describedby="nudge-help"/);
 assert.match(js,/previewNudgeKeyAction\(event\)/);assert.match(js,/nudgePreviewLayer\(/);
 assert.match(html,/disabled class="disabled-checkout"/);
});
