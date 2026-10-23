import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {CONCEPT_PREVIEW_CAMERA_DEFAULT,updateConceptPreviewCamera,conceptPreviewKeyAction} from '../src/viewer3d.mjs';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';
import {createOfflineStagingFixtureServer,renderOfflineStagingFixture} from '../src/staging-offline-fixture.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const cam=()=>({...CONCEPT_PREVIEW_CAMERA_DEFAULT});
const update=(camera,action)=>updateConceptPreviewCamera(camera,action);
const orbit=(yawDelta,pitchDelta)=>({type:'ORBIT',yawDelta,pitchDelta});
const zoom=factor=>({type:'ZOOM',factor});
const read=p=>readFile(join(root,p),'utf8');

test('34K camera default is a frozen, deterministic conceptual view',()=>{
 assert.equal(Object.isFrozen(CONCEPT_PREVIEW_CAMERA_DEFAULT),true);
 assert.deepEqual(cam(),{yaw:.18,pitch:.10,zoom:1});
 assert.deepEqual(update({yaw:2,pitch:.7,zoom:1.8},{type:'RESET'}),cam());
});
test('34K left/right orbit updates yaw without modifying input',()=>{
 const original=cam();const result=update(original,orbit(.3,0));
 assert.ok(Math.abs(result.yaw-.48)<1e-12);assert.equal(result.pitch,.10);assert.equal(result.zoom,1);
 assert.deepEqual(original,cam());
});
test('34K large repeated rotation wraps yaw to finite [-pi, pi]',()=>{
 let c=cam();for(let i=0;i<100;i++)c=update(c,orbit(3,0));
 assert.ok(Number.isFinite(c.yaw));assert.ok(Math.abs(c.yaw)<=Math.PI);
});
test('34K vertical orbit clamps pitch against upside-down/unusable views',()=>{
 assert.equal(update(cam(),orbit(0,3)).pitch,.7);
 assert.equal(update(cam(),orbit(0,-3)).pitch,-.7);
});
test('34K zoom-in and zoom-out are bounded and reversible within limits',()=>{
 const start=cam();const zoomed=update(start,zoom(1.2));
 assert.equal(zoomed.zoom,1.2);
 assert.ok(Math.abs(update(zoomed,zoom(1/1.2)).zoom-1)<1e-12);
 let high=cam(),low=cam();for(let i=0;i<50;i++){high=update(high,zoom(2));low=update(low,zoom(.5));}
 assert.equal(high.zoom,1.8);assert.equal(low.zoom,.6);
});
test('34K rejects nonfinite, excessive and negative orbit deltas',()=>{
 for(const delta of [NaN,Infinity,-Infinity,4.01,-4.01,'0.2',null]){
  assert.throws(()=>update(cam(),orbit(delta,0)),/INVALID_CONCEPT_CAMERA_ACTION/);
  assert.throws(()=>update(cam(),orbit(0,delta)),/INVALID_CONCEPT_CAMERA_ACTION/);
 }
});
test('34K rejects nonfinite, excessive, zero and negative zoom factors',()=>{
 for(const factor of [NaN,Infinity,-Infinity,0,-1,.49,2.01,'1.2',null])
  assert.throws(()=>update(cam(),zoom(factor)),/INVALID_CONCEPT_CAMERA_ACTION/);
});
test('34K malformed camera and unauthorized action types fail closed',()=>{
 for(const bad of [null,{},[],{yaw:NaN,pitch:0,zoom:1},{yaw:0,pitch:Infinity,zoom:1},{yaw:0,pitch:0,zoom:'1'}])
  assert.throws(()=>update(bad,{type:'RESET'}),/INVALID_CONCEPT_CAMERA_ACTION/);
 for(const action of [null,[],{},'ORBIT',{type:'CHECKOUT'},{type:'ZOOM',factor:1e10}])
  assert.throws(()=>update(cam(),action),/INVALID_CONCEPT_CAMERA_ACTION/);
});
test('34K arrow-key mappings are bounded rotations and do not trigger purchases',()=>{
 const keys=['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'];
 for(const key of keys){const action=conceptPreviewKeyAction(key);assert.equal(action.type,'ORBIT');assert.ok(Math.abs(action.yawDelta)<=.3);assert.ok(Math.abs(action.pitchDelta)<=.3);assert.doesNotThrow(()=>update(cam(),action));}
});
test('34K zoom and reset keys work; Tab, Enter, Escape, letters and unknown keys are browser-owned',()=>{
 for(const key of ['+','=','-','_'])assert.equal(conceptPreviewKeyAction(key).type,'ZOOM');
 assert.equal(conceptPreviewKeyAction('Home').type,'RESET');
 for(const key of ['Tab','Enter','Escape',' ','a','Checkout','F5',undefined])assert.equal(conceptPreviewKeyAction(key),null);
});
test('34K static preview exposes visible keyboard instructions and focusable 3D canvas',async()=>{
 const html=await read('demo/static-preview.html');
 assert.match(html,/<canvas id="stage-3d"[^>]*tabindex="0"[^>]*aria-describedby="camera-help(?: [^"]+)?"/);
 assert.match(html,/<p id="camera-help"[^>]*>3D view:/);
 for(const id of ['zoom-in','zoom-out','view-reset','orbit-left','orbit-right'])assert.match(html,new RegExp(`id="${id}"`));
 assert.match(html,/Checkout unavailable/);
});
test('34K static preview wires key handling without intercepting Tab/modifiers',async()=>{
 const code=await read('demo/static-preview.mjs');
 assert.match(code,/addEventListener\('keydown',event=>/);
 assert.match(code,/event\.altKey\|\|event\.ctrlKey\|\|event\.metaKey/);
 assert.match(code,/conceptPreviewKeyAction\(event\.key\)/);
 assert.match(code,/\$\('camera-help'\)\.hidden=state\.mode!=='3d'/);
 assert.match(code,/if\(!action\)return;\s*event\.preventDefault\(\)/);
 assert.match(code,/updateConceptPreviewCamera\(camera,action\)/);
});
test('34K touch drag cannot inherit stale pointer capture and redraws on resize',async()=>{
 const code=await read('demo/static-preview.mjs');
 assert.match(code,/beginConceptPointerDrag\(drag,event\)/);
 assert.match(code,/moveConceptPointerDrag\(drag,event\)/);
 const viewer=await read('src/viewer3d.mjs');
 assert.match(viewer,/event\.isPrimary === false/);
 assert.match(viewer,/event\.pointerId !== active\.pointerId/);
 assert.match(code,/addEventListener\('pointercancel',endDrag\)/);
 assert.match(code,/addEventListener\('lostpointercapture',endDrag\)/);
 assert.match(code,/new ResizeObserver\(\(\)=>schedule3D\(\)\)/);
 assert.match(code,/window\.addEventListener\('resize',\(\)=>schedule3D\(\)/);
});
test('34K focus and mobile zoom affordances remain inside scoped preview CSS',async()=>{
 const css=await read('demo/static-preview.css');
 assert.match(css,/#stage-3d:focus-visible\{/);
 assert.match(css,/\.camera-help\{/);
 assert.match(css,/@media\(max-width:700px\)/);
 assert.doesNotMatch(css,/@import\b|url\s*\(/);
});
test('34K generated staging section maps help and camera IDs without global Shopify collisions',async()=>{
 const {files,manifest}=await buildStagingStaticBundle({root});
 const html=renderOfflineStagingFixture(files,manifest);
 assert.match(html,/id="tj34i-stage-3d"[^>]*tabindex="0"[^>]*aria-describedby="tj34i-camera-help(?: [^"]+)?"/);
 assert.match(html,/id="tj34i-camera-help"/);
 for(const id of ['zoom-in','zoom-out','view-reset'])assert.match(html,new RegExp(`id="tj34i-${id}"`));
 assert.doesNotMatch(html,/id="stage-3d"|id="zoom-in"|<form\b|\/checkout|\/cart/i);
 assert.equal(manifest.sourceVersion,JSON.parse(await read('package.json')).version);
});
test('34K generated module uses scoped DOM and includes keyboard/resize behavior over loopback HTTP',async(t)=>{
 const {files,manifest}=await buildStagingStaticBundle({root});
 const server=createOfflineStagingFixtureServer(files,manifest);
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 t.after(()=>new Promise(resolve=>server.close(resolve)));
 const base=`http://127.0.0.1:${server.address().port}`;
 const page=await fetch(base+'/preview');assert.equal(page.status,200);
 assert.match(await page.text(),/tj34i-camera-help/);
 const js=await fetch(base+'/assets/tj34i-demo-static-preview.js');assert.equal(js.status,200);
 const code=await js.text();assert.match(code,/document\.getElementById\('tj34i-'\+id\)/);
 assert.match(code,/conceptPreviewKeyAction/);assert.match(code,/ResizeObserver/);
 const css=await fetch(base+'/assets/tj34i-demo-static-preview.css');assert.equal(css.status,200);
 assert.match(await css.text(),/#tj34i-root #tj34i-stage-3d:focus-visible/);
 for(const method of ['POST','PUT','DELETE'])assert.equal((await fetch(base+'/preview',{method})).status,405);
 assert.equal((await fetch(base+'/checkout')).status,404);
});
