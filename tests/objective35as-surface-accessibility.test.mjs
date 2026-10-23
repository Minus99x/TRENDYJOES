import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {MANIFEST_BY_ID} from '../src/catalog.mjs';
import {validateComposition,preflight} from '../src/core.mjs';
import {nudgePreviewLayer} from '../src/preview-keyboard-position.mjs';
const shoe=MANIFEST_BY_ID['concept-sneaker'];
const layers=[
 {id:'outer',type:'text',surfaceId:'outer-side',x:.25,y:.32,width:.45,height:.17,rotationDeg:0,scaleFactor:1,value:'OUTER'},
 {id:'tongue',type:'text',surfaceId:'tongue',x:.25,y:.32,width:.45,height:.17,rotationDeg:0,scaleFactor:1,value:'TONGUE'}
];
test('35AS multi-surface sneaker positions stay independently normalized and immutable',()=>{
 assert.deepEqual(validateComposition(shoe,{layers}),[]);
 const before=structuredClone(layers);
 const moved=nudgePreviewLayer({product:shoe,layers,selectedId:'tongue',surfaceId:'tongue',direction:'left',step:.05});
 assert.equal(moved.applied,true);assert.equal(moved.layers[1].x,.20);
 assert.deepEqual(moved.layers[0],before[0]);assert.deepEqual(layers,before);
 assert.equal(preflight(shoe,{layers:moved.layers}).productionReady,false);
});
test('35AS hidden surface cannot be repositioned by keyboard nudge',()=>{
 const denied=nudgePreviewLayer({product:shoe,layers,selectedId:'tongue',surfaceId:'outer-side',direction:'up'});
 assert.equal(denied.applied,false);assert.equal(denied.reason,'DIFFERENT_SURFACE');assert.equal(denied.layers,layers);
});
test('35AS source preserves surface-only picker, accessible live context and keyboard focus',async()=>{
 const [html,js]=await Promise.all([
  readFile(new URL('../demo/index.html',import.meta.url),'utf8'),
  readFile(new URL('../demo/studio.mjs',import.meta.url),'utf8')]);
 assert.match(html,/id="surface-edit-context"[^>]*role="status"[^>]*aria-live="polite"/);
 assert.match(html,/id="stage"[^>]*tabindex="0"/);
 assert.match(js,/state\.layers\.filter\(l=>l\.surfaceId===state\.surface\)/);
 assert.match(js,/visibleLayers\.some\(l=>l\.id===state\.selected\)/);
 assert.match(js,/\$\('stage'\)\.setAttribute\('aria-label'/);
 assert.match(js,/\$\('surface-edit-context'\)\.textContent/);
 assert.match(html,/disabled class="disabled-checkout"/);
});
