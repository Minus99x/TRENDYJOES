import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {commitPrivateReceiptRestore} from '../src/preview-private-receipt-transaction.mjs';
import {createPreviewEditorAsyncGate} from '../src/preview-editor-async-gate.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const js=await readFile(resolve(root,'demo/studio.mjs'),'utf8');
const ref='TJ-'+'A'.repeat(24),token='b'.repeat(64);
const oldProduct={id:'old',surfaces:[{id:'front'}]},product={id:'new',surfaces:[{id:'front'}]};
const initial=()=>({product:oldProduct,surface:'front',previewSelection:{colorId:'old'},layers:[{type:'text'}],
 selected:'old-layer',savedSnapshot:{old:true},saved:{reference:'TJ-'+'C'.repeat(24),revision:1,ownerToken:'d'.repeat(64)},
 artGrants:new Map([['art_old','old-secret']]),artUrls:new Map([['art_old','blob:old']]),imported:{sha256:'old'},calibration:{issues:[]}});
const candidate=()=>({product,surface:'front',previewSelection:{colorId:'new'},layers:[],selected:null,
 savedSnapshot:{new:true},saved:{reference:ref,revision:1,ownerToken:token},
 artGrants:new Map(),artUrls:new Map([['art_new','blob:new']]),imported:null,calibration:null});
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
function extractListener(prefix,env){const start=js.indexOf(prefix);assert.ok(start>=0,prefix);const stop=js.indexOf('\n});',start);assert.ok(stop>start);return Function(...Object.keys(env),`return (${js.slice(start+prefix.length,stop+2)});`)(...Object.values(env));}
function extractSave(env){const start=js.indexOf('async function saveToLocal(){'),stop=js.indexOf('\n}',start);assert.ok(start>=0&&stop>start);return Function(...Object.keys(env),`return (${js.slice(start,stop+2)});`)(...Object.values(env));}
function fixture({layers=[],throwRender=false,throwSnapshot=false,designRevision=1}={}){
 const state=initial(),revoke=[],created=[],elements=new Map(),calls=[];let customFetch=null;
 const $=id=>{if(!elements.has(id))elements.set(id,{value:id==='product'?'old':'',disabled:false,textContent:'',focus(){}});return elements.get(id);};
 const receipt={format:'TJ-LOCAL-RECOVERY-1',reference:ref,revision:1,ownerToken:token,artworkGrants:Object.fromEntries(layers.map(l=>[l.artworkId,'f'.repeat(64)]))};
 const design={reference:ref,revision:designRevision,productManifestId:'new',previewSelection:{colorId:'new'},layers};
 const file={size:120,text:async()=>JSON.stringify(receipt)};
 const URL={createObjectURL(){const url='blob:new-'+(created.length+1);created.push(url);return url;},revokeObjectURL:url=>revoke.push(url)};
 const env={state,$,editorAsyncGate:{invalidate(){}},privateReceiptOpenEpoch:0,recoveryConfirmation:{cancel(){}},
  fetch:async path=>{calls.push(path);if(customFetch)return customFetch(path);return path.startsWith('/api/designs/')?{ok:true,json:async()=>design}:{ok:true,blob:async()=>({})};},
  availableManifests:{new:product},URL,normalizePreviewSelection:(p,v)=>({colorId:v.colorId}),
  editorSnapshot:()=>{if(throwSnapshot)throw Error('SNAPSHOT_FAILED');return {new:true};},
  commitPrivateReceiptRestore,render:()=>{if(throwRender){throwRender=false;throw Error('RENDER_FAILED');}},
  multiRecovery:{list:()=>[]},shopifyEntries:new Map(),renderMultiReview(){},showSaved(){}};
 const run=extractListener("$('resume-project').addEventListener('change',",env);
 return {run,state,revoke,created,elements,$,calls,receipt,design,file,URL,setFetch:fn=>{customFetch=fn;}};
}
const unchanged=(f,before)=>{for(const key of Object.keys(before))assert.deepEqual(f.state[key],before[key],key);assert.equal(f.$('product').value,'old');};
test('35S commits valid private receipt then revokes only displaced old artwork',async()=>{
 const f=fixture({layers:[{type:'artwork',artworkId:'art_new'}]});await f.run({target:{files:[f.file],value:'x'}});
 assert.equal(f.state.saved.reference,ref);assert.equal(f.state.artUrls.get('art_new'),'blob:new-1');
 assert.deepEqual(f.revoke,['blob:old']);assert.equal(f.state.imported,null);assert.equal(f.state.calibration,null);
 assert.equal(f.$('product').value,'new');
});
test('35S validation error retains old private state and old artwork URL',async()=>{
 const f=fixture({layers:[{type:'artwork',artworkId:'art_new'}],throwSnapshot:true}),before=initial();
 await f.run({target:{files:[f.file],value:'x'}});unchanged(f,before);
 assert.deepEqual(f.revoke,['blob:new-1']);
});
test('35S render failure rolls back credentials, design, selection and URL ownership',async()=>{
 const f=fixture({layers:[{type:'artwork',artworkId:'art_new'}],throwRender:true}),before=initial();
 await f.run({target:{files:[f.file],value:'x'}});unchanged(f,before);
 assert.deepEqual(f.revoke,['blob:new-1']);
});
test('35S stale private receipt revision refuses without mutation',async()=>{
 const f=fixture({designRevision:2}),before=initial();await f.run({target:{files:[f.file],value:'x'}});
 unchanged(f,before);assert.deepEqual(f.revoke,[]);
});
test('35S mismatched server reference refuses without mutation',async()=>{
 const f=fixture(),before=initial();f.design.reference='TJ-'+'F'.repeat(24);
 await f.run({target:{files:[f.file],value:'x'}});unchanged(f,before);
});
test('35S missing artwork grant preserves prior design and never fetches artwork',async()=>{
 const f=fixture({layers:[{type:'artwork',artworkId:'art_new'}]}),before=initial();delete f.receipt.artworkGrants.art_new;
 await f.run({target:{files:[f.file],value:'x'}});unchanged(f,before);
 assert.equal(f.calls.filter(x=>x.startsWith('/api/artworks/')).length,0);
});

test('35S second artwork fetch failure releases first provisional URL and retains old state',async()=>{
 const f=fixture({layers:[{type:'artwork',artworkId:'art_one'},{type:'artwork',artworkId:'art_two'}]}),before=initial();
 f.setFetch(async path=>path.startsWith('/api/designs/')?{ok:true,json:async()=>f.design}:
  path.endsWith('art_one')?{ok:true,blob:async()=>({})}:{ok:false});
 await f.run({target:{files:[f.file],value:'x'}});unchanged(f,before);
 assert.deepEqual(f.revoke,['blob:new-1']);
});
test('35S superseded private receipt cannot commit after another opening begins',async()=>{
 const f=fixture({layers:[{type:'artwork',artworkId:'art_new'}]}),hold=deferred();let delayed=true;
 f.setFetch(async path=>path.startsWith('/api/designs/')?{ok:true,json:async()=>f.design}:
  {ok:true,blob:()=>delayed?hold.promise:Promise.resolve({})});
 const first=f.run({target:{files:[f.file],value:'first'}});
 // Flush microtasks until the first request has reached its artwork fetch.
 for(let i=0;i<20&&f.calls.filter(x=>x.startsWith('/api/artworks/')).length<1;i++)await Promise.resolve();
 assert.equal(f.calls.filter(x=>x.startsWith('/api/artworks/')).length,1);
 delayed=false;const second=f.run({target:{files:[f.file],value:'second'}});await second;
 hold.resolve({});await first;
 assert.equal(f.state.saved.reference,ref);assert.equal(f.state.artUrls.get('art_new'),'blob:new-1');
 assert.deepEqual(f.revoke,['blob:old']);
});
test('35S commit helper refuses accessor-backed candidate without mutation',()=>{
 const state=initial(),next=candidate();Object.defineProperty(next,'saved',{enumerable:true,get(){throw Error('ACCESSOR');}});
 assert.throws(()=>commitPrivateReceiptRestore({state,next,render(){},revokeOldUrl(){}}),{code:'PRIVATE_RESTORE_TRANSACTION_INVALID'});
 assert.deepEqual(state,initial());
});
test('35S commit helper refuses partial candidate without mutation',()=>{
 const state=initial(),next=candidate();delete next.artGrants;
 assert.throws(()=>commitPrivateReceiptRestore({state,next,render(){},revokeOldUrl(){}}),{code:'PRIVATE_RESTORE_TRANSACTION_INVALID'});
 assert.deepEqual(state,initial());
});
test('35S commit helper restores old state even if rollback render also throws',()=>{
 const state=initial(),before=initial();let renders=0;
 assert.throws(()=>commitPrivateReceiptRestore({state,next:candidate(),render(){renders++;throw Error('render');},revokeOldUrl(){throw Error('never');}}),/render/);
 assert.equal(renders,2);assert.deepEqual(state,before);
});
test('35S cleanup failure cannot undo a successfully rendered draft',()=>{
 const state=initial();assert.equal(commitPrivateReceiptRestore({state,next:candidate(),render(){},revokeOldUrl(){throw Error('cleanup');}}),true);
 assert.equal(state.saved.reference,ref);
});
test('35S retained URL is never revoked when shared between old and new states',()=>{
 const state=initial(),next=candidate(),revoked=[];next.artUrls.set('art_new','blob:old');
 commitPrivateReceiptRestore({state,next,render(){},revokeOldUrl:url=>revoked.push(url)});
 assert.deepEqual(revoked,[]);
});
function saveFixture(){
 const state={product:{id:'old'},layers:[],previewSelection:{colorId:null},saved:null,savedSnapshot:null},responses=[],button={disabled:false},elements=new Map([['save-local',button]]);
 const $=id=>{if(!elements.has(id))elements.set(id,{textContent:''});return elements.get(id);};
 const gate=createPreviewEditorAsyncGate({readBinding:()=>({productManifestId:state.product.id,surfaceId:'front',variantGid:'gid://shopify/ProductVariant/1',reference:state.saved?.reference??null,revision:state.saved?.revision??null})});
 const env={state,$,editorAsyncGate:gate,saveOperation:{current:0},invalidatePreviewReview(){},uploadGrants:()=>({}),
  editorSnapshot:()=>({digest:'snapshot'}),fetch:()=>{const d=deferred();responses.push(d);return d.promise;},showSaved(){}};
 const run=extractSave(env);
 return {run,state,responses,button,gate,$};
}
test('35S stale save finally cannot unlock a newer pending save',async()=>{
 const f=saveFixture();const first=f.run();assert.equal(f.button.disabled,true);
 f.state.product={id:'new'};f.gate.invalidate();f.button.disabled=false;
 const second=f.run();assert.equal(f.button.disabled,true);
 f.responses[0].resolve({ok:true,json:async()=>({reference:ref,revision:1,ownerToken:token})});await first;
 assert.equal(f.button.disabled,true,'older finally must not unlock current save');
 f.responses[1].resolve({ok:true,json:async()=>({reference:ref,revision:1,ownerToken:token})});await second;
 assert.equal(f.button.disabled,false);assert.equal(f.state.saved.reference,ref);
});
test('35S current save error releases button for a subsequent retry',async()=>{
 const f=saveFixture(),pending=f.run();f.responses[0].reject(Error('network'));
 await pending;assert.equal(f.button.disabled,false);assert.match(f.$('status').textContent,/Save failed/);
});
