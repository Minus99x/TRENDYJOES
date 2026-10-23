function validGlbHeader(){const b=new ArrayBuffer(24),v=new DataView(b);v.setUint32(0,0x46546c67,true);v.setUint32(4,2,true);v.setUint32(8,24,true);v.setUint32(12,4,true);v.setUint32(16,0x4e4f534a,true);return b;}
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createPreviewEditorAsyncGate,validateLocalArtworkReceipt} from '../src/preview-editor-async-gate.mjs';
import {createModelImportLifecycle} from '../src/preview-model-import-lifecycle.mjs';
import {validateLocalModelInspection} from '../src/preview-model-receipt.mjs';
import {readBoundedLocalGlb} from '../src/preview-glb-file-read.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
const reference='TJ-'+'A'.repeat(24);
const receipt=(changes={})=>({id:'art_'+'a'.repeat(32),grant:'b'.repeat(64),width:800,height:400,mediaType:'image/png',bytes:100,...changes});
const binding=(changes={})=>({productManifestId:'crew-shirt',surfaceId:'front',variantGid:'gid://shopify/ProductVariant/1',reference:null,revision:null,...changes});
const fixture=()=>{let value=binding();const gate=createPreviewEditorAsyncGate({readBinding:()=>value});return {gate,set:changes=>{value={...value,...changes};},get:()=>value};};
const file={type:'image/png',size:100};
const expected={mediaType:'image/png',bytes:100};
const js=await readFile(resolve(root,'demo/studio.mjs'),'utf8');
function compile(id,env){
 const prefix=`$('${id}').addEventListener('change',`;
 const start=js.indexOf(prefix);assert.notEqual(start,-1);
 const end=js.indexOf('\n});',start);assert.ok(end>start);
 const source=js.slice(start+prefix.length,end+2);
 return Function(...Object.keys(env),`return (${source});`)(...Object.values(env));
}
function artworkFixture({allow=true}={}){
 const f=fixture(),pending=deferred(),elements={status:{textContent:''},artwork:{value:'test'}};
 const state={product:{id:'crew-shirt'},surface:'front',layers:[],selected:null,artUrls:new Map(),artGrants:new Map()};
 const urls=[],revoked=[];
 const URL={createObjectURL(){const url='blob:local-'+(urls.length+1);urls.push(url);return url;},revokeObjectURL(url){revoked.push(url);}};
 let additions=0;
 const addLayer=(type,{artworkId})=>{additions++;if(!allow)return false;state.layers.push({type,artworkId,surfaceId:state.surface});return true;};
 const env={state,$:id=>elements[id],editorAsyncGate:f.gate,fetch:()=>pending.promise,URL,validateLocalArtworkReceipt,addLayer};
 const run=compile('artwork',env);
 const event={target:{files:[file],value:'selected'}};
 const respond=data=>pending.resolve({ok:true,json:async()=>data});
 return {...f,run,event,respond,state,elements,urls,revoked,get additions(){return additions;}};
}
test('35R valid binding ticket is single-use and cannot replay side effects',()=>{
 const f=fixture(),t=f.gate.begin('artwork');let effects=0;
 assert.equal(f.gate.commit(t,()=>++effects).applied,true);assert.equal(effects,1);
 assert.equal(f.gate.commit(t,()=>++effects).applied,false);assert.equal(effects,1);
});
test('35R changing product invalidates pending ticket even without render',()=>{
 const f=fixture(),t=f.gate.begin('model');f.set({productManifestId:'tumbler'});
 assert.equal(f.gate.current(t),false);assert.equal(f.gate.commit(t,()=>{throw Error('STALE_MUTATION');}).applied,false);
});
test('35R changing surface invalidates pending artwork placement',()=>{
 const f=fixture(),t=f.gate.begin('artwork');f.set({surfaceId:'back'});assert.equal(f.gate.current(t),false);
});
test('35R changing variant invalidates pending artwork placement',()=>{
 const f=fixture(),t=f.gate.begin('artwork');f.set({variantGid:'gid://shopify/ProductVariant/2'});assert.equal(f.gate.current(t),false);
});
test('35R changing saved revision invalidates pending local save',()=>{
 const f=fixture();f.set({reference,revision:1});const t=f.gate.begin('save');f.set({revision:2});assert.equal(f.gate.current(t),false);
});
test('35R new request supersedes older same-kind and cross-kind tickets',()=>{
 const f=fixture(),a=f.gate.begin('artwork'),b=f.gate.begin('artwork'),c=f.gate.begin('model');
 assert.equal(f.gate.current(a),false);assert.equal(f.gate.current(b),false);assert.equal(f.gate.current(c),true);
});
test('35R invalidation prevents return-to-original binding ABA replay',()=>{
 const f=fixture(),t=f.gate.begin('artwork');f.set({surfaceId:'back'});f.gate.invalidate();f.set({surfaceId:'front'});
 assert.equal(f.gate.current(t),false);
});
test('35R rejects forged, malformed and getter-backed bindings',()=>{
 assert.throws(()=>createPreviewEditorAsyncGate(),{code:'EDITOR_ASYNC_CONFIGURATION'});
 const f=createPreviewEditorAsyncGate({readBinding:()=>({...binding(),ownerToken:'private'})});
 assert.throws(()=>f.begin('artwork'),{code:'EDITOR_ASYNC_BINDING_INVALID'});
 const g=createPreviewEditorAsyncGate({readBinding:()=>Object.defineProperty(binding(),'surfaceId',{get(){return 'front';},enumerable:true})});
 assert.throws(()=>g.begin('artwork'),{code:'EDITOR_ASYNC_BINDING_INVALID'});
 assert.throws(()=>fixture().gate.begin('checkout'),{code:'EDITOR_ASYNC_KIND_INVALID'});
});
test('35R current fails closed when live binding reader throws',()=>{
 let fail=false;const f=createPreviewEditorAsyncGate({readBinding:()=>{if(fail)throw Error('dom gone');return binding();}});
 const t=f.begin('artwork');fail=true;assert.equal(f.current(t),false);
});
test('35R receipt rejects identity substitution, secret shape and fake commerce fields',()=>{
 const invalid=[{id:'art_wrong'},{grant:'z'.repeat(64)},{width:0},{height:-1},{mediaType:'image/svg+xml'},
  {bytes:101},{checkoutEnabled:true},{grant:'c'.repeat(64),cartLine:{}},{id:'art_'+'A'.repeat(32)}];
 for(const x of invalid)assert.throws(()=>validateLocalArtworkReceipt(receipt(x),expected),{code:'EDITOR_ARTWORK_RECEIPT_INVALID'});
 assert.equal(validateLocalArtworkReceipt(receipt(),expected).id,receipt().id);
});
test('35R receipt rejects getters, missing data, oversized and mismatched MIME',()=>{
 const value=Object.defineProperty(receipt(),'grant',{get(){throw Error('leak');},enumerable:true});
 assert.throws(()=>validateLocalArtworkReceipt(value,file),{code:'EDITOR_ARTWORK_RECEIPT_INVALID'});
 assert.throws(()=>validateLocalArtworkReceipt(receipt(),{mediaType:'image/webp',bytes:100}),{code:'EDITOR_ARTWORK_RECEIPT_INVALID'});
 assert.throws(()=>validateLocalArtworkReceipt(receipt({bytes:6*1024*1024}),{mediaType:'image/png',bytes:6*1024*1024}),{code:'EDITOR_ARTWORK_RECEIPT_INVALID'});
});
test('35R actual artwork event listener commits matching response and retains one grant',async()=>{
 const f=artworkFixture(),p=f.run(f.event);f.respond(receipt());await p;
 assert.equal(f.state.layers.length,1);assert.equal(f.state.artGrants.get(receipt().id),receipt().grant);
 assert.equal(f.urls.length,1);assert.equal(f.revoked.length,0);assert.match(f.elements.status.textContent,/Artwork stored/);
});
test('35R actual artwork event listener drops stale response after surface switch',async()=>{
 const f=artworkFixture(),p=f.run(f.event);f.set({surfaceId:'back'});f.state.surface='back';f.gate.invalidate();
 f.respond(receipt());await p;assert.equal(f.state.layers.length,0);assert.equal(f.state.artGrants.size,0);assert.equal(f.urls.length,0);
});
test('35R actual artwork event listener drops stale response after variant switch',async()=>{
 const f=artworkFixture(),p=f.run(f.event);f.set({variantGid:'gid://shopify/ProductVariant/2'});
 f.respond(receipt());await p;assert.equal(f.state.layers.length,0);assert.equal(f.state.artGrants.size,0);
});
test('35R actual artwork event listener cleans rejected placement and revokes blob URL',async()=>{
 const f=artworkFixture({allow:false}),p=f.run(f.event);f.respond(receipt());await p;
 assert.equal(f.state.layers.length,0);assert.equal(f.state.artGrants.size,0);assert.deepEqual(f.revoked,f.urls);
 assert.match(f.elements.status.textContent,/placement was refused/);
});
test('35R actual artwork event listener refuses malformed server response without grant retention',async()=>{
 const f=artworkFixture(),p=f.run(f.event);f.respond(receipt({checkoutEnabled:true}));await p;
 assert.equal(f.state.artGrants.size,0);assert.equal(f.urls.length,0);assert.match(f.elements.status.textContent,/RECEIPT_INVALID/);
});
test('35R actual artwork event listener refuses duplicate artwork identity without replacing grant',async()=>{
 const f=artworkFixture();f.state.artUrls.set(receipt().id,'blob:existing');f.state.artGrants.set(receipt().id,'original');
 const p=f.run(f.event);f.respond(receipt());await p;
 assert.equal(f.state.artGrants.get(receipt().id),'original');assert.equal(f.urls.length,0);
});
test('35R source wires model import, local save, receipt open and variant invalidation',()=>{
 assert.match(js,/const ticket=modelImportLifecycle\.begin\(\),product=state\.product/);
 assert.match(js,/modelImportLifecycle\.commit\(ticket,\(\)=>\{\s*state\.imported=model/);
 assert.match(js,/validateLocalModelInspection\(model,product\)/);
 assert.match(js,/const ticket=editorAsyncGate\.begin\('save'\)/);
 assert.match(js,/if\(!editorAsyncGate\.current\(ticket\)\)return; \/\/ A newer editor/);
 assert.match(js,/editorAsyncGate\.invalidate\(\);const opening=\+\+privateReceiptOpenEpoch/);
 assert.match(js,/shopify-variant'\)\.addEventListener\('change',\(\)=>\{editorAsyncGate\.invalidate\(\)/);
});
test('35R editor gate grants no checkout authority, persistent storage or network rights',async()=>{
 const source=await readFile(resolve(root,'src/preview-editor-async-gate.mjs'),'utf8');
 assert.doesNotMatch(source,/fetch\(|writeFile|localStorage|sessionStorage|Authorization|ownerToken|checkoutEnabled\s*:\s*true/);
 assert.equal(fixture().gate.checkoutEnabled,false);
});
function modelFixture(){
 const f=fixture(),pending=deferred(),state={product:{id:'crew-shirt',surfaces:[{id:'front'}]},surface:'front',layers:[],imported:null,calibration:{issues:[]}};
 const elements={'model-import-summary':{textContent:''},'export-calibration':{disabled:false},'clear-model':{disabled:true}};
 const sha='a'.repeat(64);
 const inspected={sha256:sha,byteLength:24,nodeCount:1,vertexCount:3,triangleCount:1,
  mappedSurfaces:['front'],missingSurfaces:[],approval:'UNVERIFIED_LOCAL_PREVIEW_ONLY',
  assetBoundsMeters:{min:[0,0,0],max:[1,1,0],extent:[1,1,0]},
  asset:{sha256:sha,status:'IMPORTED_UNVERIFIED',modelId:`imported-${sha.slice(0,14)}`,surfaceIds:['front'],
   triangles:[{a:[0,0,0],b:[1,0,0],c:[0,1,0],material:'fabric',side:'asset',surfaceId:'front',uv:[[0,0],[1,0],[0,1]]}]}};
 const modelImportLifecycle=createModelImportLifecycle({readContext:()=>({productId:state.product.id,surfaceId:state.surface,variantId:''})});
 let renders=0;
 const env={state,$:id=>elements[id],modelImportLifecycle,readBoundedLocalGlb,
  inspectGlb:async()=>inspected,validateLocalModelInspection,buildConceptUvReport:()=>({issues:[]}),
  invalidateCalibration:()=>{state.calibration=null;},render:()=>{renders++;}};
 const run=compile('model-file',env);
 const event={target:{files:[{name:'model.glb',size:24,arrayBuffer:()=>pending.promise}],value:'model.glb'}};
 return {...f,state,elements,run,event,pending,modelImportLifecycle,get renders(){return renders;}};
}
test('35R actual model import listener cannot install GLB after product switch',async()=>{
 const f=modelFixture(),p=f.run(f.event);f.set({productManifestId:'tumbler'});f.state.product={id:'tumbler'};f.modelImportLifecycle.invalidate();
 f.pending.resolve(validGlbHeader());await p;assert.equal(f.state.imported,null);assert.equal(f.renders,0);
});
test('35R actual model import listener installs matching GLB as unverified only',async()=>{
 const f=modelFixture(),p=f.run(f.event);f.pending.resolve(validGlbHeader());await p;
 assert.equal(f.state.imported.triangleCount,1);assert.equal(f.state.calibration,null);
 assert.equal(f.elements['clear-model'].disabled,false);assert.equal(f.renders,1);
 assert.match(f.elements['model-import-summary'].textContent,/UNVERIFIED/);
});
function compileSave(env){
 const start=js.indexOf('async function saveToLocal(){'),end=js.indexOf("\n}\n$('save-local')",start);
 assert.ok(start>=0&&end>start);
 return Function(...Object.keys(env),`return (${js.slice(start,end+2)});`)(...Object.values(env));
}
function saveFixture(){
 const f=fixture(),pending=deferred(),state={product:{id:'crew-shirt'},layers:[],previewSelection:{colorId:null,sizeId:null},saved:null,savedSnapshot:null};
 const elements={'save-local':{disabled:false},status:{textContent:''},'shopify-binding-result':{textContent:''},'cart-readiness-result':{textContent:''}};
 let show=0;
 const env={state,$:id=>elements[id],editorAsyncGate:f.gate,saveOperation:{current:0},invalidatePreviewReview(){},uploadGrants:()=>({}),
  editorSnapshot:()=>({digest:'snapshot'}),fetch:()=>pending.promise,showSaved(){show++;}};
 const run=compileSave(env),respond=data=>pending.resolve({ok:true,json:async()=>data});
 return {...f,run,respond,state,elements,get show(){return show;}};
}
test('35R actual save completion cannot attach old private owner token to switched product',async()=>{
 const f=saveFixture(),p=f.run();f.state.product={id:'tumbler'};f.set({productManifestId:'tumbler'});f.gate.invalidate();
 f.respond({reference,revision:1,ownerToken:'b'.repeat(64)});await p;
 assert.equal(f.state.saved,null);assert.equal(f.state.savedSnapshot,null);assert.equal(f.show,0);
 assert.equal(f.elements['save-local'].disabled,false);
});
test('35R actual save completion attaches matching local revision only',async()=>{
 const f=saveFixture(),p=f.run();f.respond({reference,revision:1,ownerToken:'b'.repeat(64)});await p;
 assert.equal(f.state.saved.reference,reference);assert.equal(f.state.saved.revision,1);
 assert.equal(f.show,1);assert.equal(f.elements['save-local'].disabled,false);
});
