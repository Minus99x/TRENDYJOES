import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {beginConceptPointerDrag,moveConceptPointerDrag,endConceptPointerDrag,updateConceptPreviewCamera,CONCEPT_PREVIEW_CAMERA_DEFAULT} from '../src/viewer3d.mjs';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';
import {createOfflineStagingFixtureServer} from '../src/staging-offline-fixture.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const e=(pointerId=1,clientX=100,clientY=200,extra={})=>({pointerId,clientX,clientY,isPrimary:true,button:0,pointerType:'touch',buttons:1,...extra});
const start=()=>beginConceptPointerDrag(null,e());
const move=(active,event)=>moveConceptPointerDrag(active,event);
const read=p=>readFile(join(root,p),'utf8');

test('34L primary left-button touch starts with immutable input event',()=>{
 const event=e();const active=beginConceptPointerDrag(null,event);
 assert.deepEqual(active,{pointerId:1,x:100,y:200});assert.deepEqual(event,e());
});
test('34L active gesture cannot be hijacked by a second pointerdown',()=>{
 const first=start();assert.equal(beginConceptPointerDrag(first,e(2)),null);
 assert.deepEqual(first,{pointerId:1,x:100,y:200});
});
test('34L nonprimary, right-click and middle-click pointerdown rejected',()=>{
 for(const bad of [e(1,100,200,{isPrimary:false}),e(1,100,200,{button:1}),e(1,100,200,{button:2})])
  assert.equal(beginConceptPointerDrag(null,bad),null);
});
test('34L malformed and adversarial pointer identifiers rejected at start',()=>{
 for(const id of [undefined,null,-1,1.5,NaN,Infinity,'1',Number.MAX_SAFE_INTEGER+1])
  assert.equal(beginConceptPointerDrag(null,e(1,100,200,{pointerId:id})),null);
});
test('34L nonfinite, huge and malformed pointer coordinates rejected',()=>{
 for(const value of [NaN,Infinity,-Infinity,1e30,'123',null]){
  assert.equal(beginConceptPointerDrag(null,e(1,value,0)),null);
  assert.equal(beginConceptPointerDrag(null,e(1,0,value)),null);
 }
 assert.equal(beginConceptPointerDrag(null,null),null);
 assert.equal(beginConceptPointerDrag(null,{}),null);
});
test('34L matching pointer movement creates bounded ORBIT and updated coordinates',()=>{
 const out=move(start(),e(1,150,160));
 assert.deepEqual(out.gesture,{pointerId:1,x:150,y:160});
 assert.deepEqual(out.action,{type:'ORBIT',yawDelta:.4,pitchDelta:-.2});
 assert.doesNotThrow(()=>updateConceptPreviewCamera(CONCEPT_PREVIEW_CAMERA_DEFAULT,out.action));
});
test('34L unrelated pointer movement cannot move camera or steal gesture',()=>{
 const first=start();const out=move(first,e(2,900,900));
 assert.equal(out.action,null);assert.strictEqual(out.gesture,first);
});
test('34L nonprimary pointer move ignored even if identifier matches',()=>{
 const first=start();const out=move(first,e(1,200,300,{isPrimary:false}));
 assert.equal(out.action,null);assert.strictEqual(out.gesture,first);
});
test('34L invalid movement ignored without advancing previous coordinates',()=>{
 const first=start();for(const event of [null,{},e(1,NaN,1),e(1,1,Infinity),e(1,1e20,2)]){
  const out=move(first,event);assert.equal(out.action,null);assert.strictEqual(out.gesture,first);
 }
});
test('34L extreme but finite jump clamps to bounded camera actions',()=>{
 const out=move(start(),e(1,1e7,-1e7));
 assert.deepEqual(out.action,{type:'ORBIT',yawDelta:4,pitchDelta:-4});
 assert.doesNotThrow(()=>updateConceptPreviewCamera(CONCEPT_PREVIEW_CAMERA_DEFAULT,out.action));
});
test('34L zero movement does not schedule needless redraw',()=>{
 const out=move(start(),e());assert.equal(out.action,null);assert.deepEqual(out.gesture,start());
});
test('34L mouse button released outside canvas cancels ghost drag',()=>{
 const out=move(start(),e(1,140,200,{pointerType:'mouse',buttons:0}));
 assert.equal(out.gesture,null);assert.equal(out.action,null);
});
test('34L pointer up/cancel/lost capture match identity and reject foreign release',()=>{
 const first=start();assert.strictEqual(endConceptPointerDrag(first,e(2)),first);
 assert.equal(endConceptPointerDrag(first,e(1)),null);
 assert.equal(endConceptPointerDrag(null,e(1)),null);
 assert.equal(endConceptPointerDrag({pointerId:1,x:NaN,y:1},e(1)),null);
});
test('34L static editor cancels capture on blur, hidden tab, product reset and mode exit',async()=>{
 const code=await read('demo/static-preview.mjs');
 assert.match(code,/if\(state\.mode!=='3d'\|\|action\.type==='SELECT_PRODUCT'\|\|action\.type==='RESET'\|\|action\.type==='SELECT_SURFACE'\)cancelDrag\(\)/);
 assert.match(code,/window\.addEventListener\('blur',cancelDrag\)/);
 assert.match(code,/document\.addEventListener\('visibilitychange'/);
 assert.match(code,/canvas\.releasePointerCapture\(previous\.pointerId\)/);
 assert.match(code,/catch\{drag=null;message\('Pointer capture unavailable/);
 assert.match(code,/beginConceptPointerDrag\(drag,event\)/);
 assert.match(code,/moveConceptPointerDrag\(drag,event\)/);
 assert.match(code,/endConceptPointerDrag\(drag,event\)/);
});
test('34L touch canvas permits mobile vertical page scroll while retaining horizontal gestures',async()=>{
 const css=await read('demo/static-preview.css');
 assert.match(css,/#stage-3d\{[^}]*touch-action:pan-y/);
 assert.doesNotMatch(css,/body\s*\{[^}]*touch-action:none/);
});
test('34L generated staging package includes pointer protections and isolated touch CSS',async()=>{
 const {files,manifest}=await buildStagingStaticBundle({root});
 assert.equal(manifest.sourceVersion,JSON.parse(await read('package.json')).version);
 assert.equal(manifest.hostedPreviewReady,false);assert.equal(manifest.checkoutEnabled,false);
 const js=files.get('assets/tj34i-demo-static-preview.js');
 assert.match(js,/beginConceptPointerDrag/);assert.match(js,/visibilitychange/);
 assert.match(js,/document\.getElementById\('tj34i-'\+id\)/);
 assert.match(files.get('assets/tj34i-demo-static-preview.css'),/#tj34i-root #tj34i-stage-3d\{[^}]*touch-action:pan-y/);
});
test('34L loopback fixture serves gesture ESM and denies commerce writes',async t=>{
 const {files,manifest}=await buildStagingStaticBundle({root});
 const server=createOfflineStagingFixtureServer(files,manifest);
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 t.after(()=>new Promise(resolve=>server.close(resolve)));
 const base=`http://127.0.0.1:${server.address().port}`;
 const js=await fetch(base+'/assets/tj34i-src-viewer3d.js');assert.equal(js.status,200);
 assert.match(await js.text(),/function beginConceptPointerDrag/);
 const css=await fetch(base+'/assets/tj34i-demo-static-preview.css');assert.equal(css.status,200);
 assert.match(await css.text(),/touch-action:pan-y/);
 for(const method of ['POST','PUT','DELETE'])assert.equal((await fetch(base+'/preview',{method})).status,405);
 assert.equal((await fetch(base+'/checkout')).status,404);
});
