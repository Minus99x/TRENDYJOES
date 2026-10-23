import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {PRODUCT_MANIFESTS,MANIFEST_BY_ID} from '../src/catalog.mjs';
import {getPreviewOptions,normalizePreviewSelection,describePreviewSelection} from '../src/preview-product-options.mjs';
import {editorSnapshot,savedDraftMatchesEditor,reviewSelectionMatches} from '../src/preview-editor-state.mjs';
import {createLocalServer} from '../src/local-server.mjs';
import {render3D} from '../src/viewer3d.mjs';
const manifest=MANIFEST_BY_ID['concept-crew-tee'];
const layer={id:'personalization',type:'text',surfaceId:'front',x:.2,y:.2,width:.4,height:.18,rotationDeg:0,value:'CREATIVE'};
async function withServer(fn){
 const dir=await mkdtemp(join(tmpdir(),'tj-obj32-'));const inst=await createLocalServer({dataDir:dir});
 const {port}=await inst.listen(0);const url=`http://127.0.0.1:${port}`;
 async function post(path,body,owner){const response=await fetch(url+path,{method:'POST',headers:{'Content-Type':'application/json',...(owner?{Authorization:`Bearer ${owner}`}:{})},body:JSON.stringify(body)});return {status:response.status,data:await response.json()};}
 try{await fn({dir,url,post});}finally{await new Promise(done=>inst.server.close(done));await rm(dir,{recursive:true,force:true});}
}
test('every concept product has extensible, explicit visual choices; apparel sizes never imply inventory',()=>{
 assert.equal(PRODUCT_MANIFESTS.length,8);
 for(const p of PRODUCT_MANIFESTS){
  const {colors,sizes}=getPreviewOptions(p);
  assert.ok(colors.length>0,p.id);assert.equal(new Set(colors.map(x=>x.id)).size,colors.length);
  assert.deepEqual(normalizePreviewSelection(p),{colorId:colors[0].id,sizeId:sizes[0]?.id??null});
  assert.equal(describePreviewSelection(p).color.hex,colors[0].hex);
 }
 assert.equal(getPreviewOptions(MANIFEST_BY_ID['concept-rug']).sizes.length,0);
 assert.ok(getPreviewOptions(manifest).sizes.some(s=>s.id==='xl'));
 const unknown={...manifest,previewOptions:undefined};
 assert.deepEqual(normalizePreviewSelection(unknown),{colorId:null,sizeId:null});
});
test('malicious, mismatched and out-of-catalog options fail closed',()=>{
 for(const choice of [{colorId:'neon-not-mapped',sizeId:'m'},{colorId:'oxblood',sizeId:'XXL-HACK'},
  {colorId:4,sizeId:'m'},{colorId:'oxblood',sizeId:'m',approvedForProduction:true},
  ['oxblood','m'],null])assert.throws(()=>normalizePreviewSelection(manifest,choice),/Invalid concept/);
 assert.throws(()=>normalizePreviewSelection(MANIFEST_BY_ID['concept-rug'],{colorId:'slate',sizeId:'xl'}),/Invalid concept/);
});
test('recoloring or resizing a saved design always invalidates editor and pending Shopify snapshot review',()=>{
 const original={colorId:'oxblood',sizeId:'s'};
 const saved={reference:'TJ-AAAAAAAAAAAAAAAAAAAAAAAA',revision:1};
 const savedSnapshot=editorSnapshot(manifest.id,[layer],original);
 const params={productManifestId:manifest.id,layers:[layer],previewSelection:original,saved,savedSnapshot};
 assert.equal(savedDraftMatchesEditor(params),true);
 for(const previewSelection of [{...original,colorId:'slate'},{...original,sizeId:'m'}]){
  assert.equal(savedDraftMatchesEditor({...params,previewSelection}),false);
  assert.equal(reviewSelectionMatches({...params,previewSelection,productGid:'gid://shopify/Product/1',variantGid:'gid://shopify/ProductVariant/1',requested:{reference:saved.reference,expectedRevision:1,productGid:'gid://shopify/Product/1',variantGid:'gid://shopify/ProductVariant/1'}}),false);
 }
});
test('authenticated drafts persist their exact concept color and size through revisions without enabling checkout',async()=>withServer(async({dir,url,post})=>{
 const body={productManifestId:manifest.id,layers:[layer],previewSelection:{colorId:'oxblood',sizeId:'m'}};
 const initial=await post('/api/designs',body);assert.equal(initial.status,201);
 const {ownerToken,reference}=initial.data;
 let stored=JSON.parse(await readFile(join(dir,'designs',reference,'1.json'),'utf8'));
 assert.deepEqual(stored.previewSelection,body.previewSelection);assert.equal(stored.checkoutEnabled,false);
 assert.equal(JSON.stringify(stored).includes(ownerToken),false);
 const next=await post(`/api/designs/${reference}/revisions`,{...body,previewSelection:{colorId:'slate',sizeId:'xl'},expectedRevision:1},ownerToken);
 assert.equal(next.status,201);assert.equal(next.data.revision,2);
 stored=JSON.parse(await readFile(join(dir,'designs',reference,'2.json'),'utf8'));
 assert.deepEqual(stored.previewSelection,{colorId:'slate',sizeId:'xl'});
 assert.equal(stored.checkoutEnabled,false);assert.equal(stored.productionApproved,false);
 const response=await fetch(`${url}/api/designs/${reference}`,{headers:{Authorization:`Bearer ${ownerToken}`}});
 assert.deepEqual((await response.json()).previewSelection,{colorId:'slate',sizeId:'xl'});
 assert.equal((await post(`/api/designs/${reference}/revisions`,{...body,expectedRevision:2,previewSelection:{colorId:'not-allowed',sizeId:'m'}},ownerToken)).status,400);
 assert.equal((await post(`/api/designs/${reference}/revisions`,{...body,expectedRevision:1},ownerToken)).status,409);
 assert.equal((await fetch(`${url}/api/designs/${reference}`)).status,403);
}));
test('a tampered preview option cannot be planted in a new draft',async()=>withServer(async({post})=>{
 const r=await post('/api/designs',{productManifestId:manifest.id,layers:[layer],previewSelection:{colorId:'javascript:alert(1)',sizeId:'m'}});
 assert.equal(r.status,400);
}));
test('concept 3D renderer responds to selected swatch without manufacturing approval',()=>{
 const prev=globalThis.window;globalThis.window={devicePixelRatio:1};
 function paints(hex){
  const colors=[];const ctx={fillStyle:'',setTransform(){},clearRect(){},beginPath(){},moveTo(){},lineTo(){},closePath(){},fill(){colors.push(this.fillStyle);}};
  const canvas={getBoundingClientRect:()=>({width:640,height:480}),getContext:()=>ctx,clientWidth:640,clientHeight:480};
  const metadata=render3D(canvas,manifest,[],new Map(),{},null,null,hex);
  assert.equal(metadata.calibrated,false);assert.equal(metadata.source,'PROCEDURAL_CONCEPT');
  return colors;
 }
 try{const red=paints('#7A2A30'),blue=paints('#52697A');assert.ok(red.length>20);assert.notDeepEqual(red,blue);}finally{globalThis.window=prev;}
});
