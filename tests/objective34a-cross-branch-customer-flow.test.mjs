import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdtemp,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createLocalServer} from '../src/local-server.mjs';
import {getPreviewOptions} from '../src/preview-product-options.mjs';
import {MANIFEST_BY_ID} from '../src/catalog.mjs';
const fixture=JSON.parse(await readFile(new URL('../fixtures/shopify-draft-manufacturing-2026-10-14.json',import.meta.url),'utf8')).products;
const layer={id:'front-personalization',type:'text',surfaceId:'front',x:.3,y:.33,width:.35,height:.14,rotationDeg:0,value:'HELLO'};
const selected={colorId:'oxblood',sizeId:'m'};
async function withServer(fn){
 const dir=await mkdtemp(join(tmpdir(),'tj-34a-'));
 const app=await createLocalServer({dataDir:dir,shopifySnapshot:fixture});
 const {port}=await app.listen(0),url=`http://127.0.0.1:${port}`;
 const post=async(path,body,ownerToken)=>{
  const r=await fetch(url+path,{method:'POST',headers:{'Content-Type':'application/json',...(ownerToken?{Authorization:`Bearer ${ownerToken}`}:{})},body:JSON.stringify(body)});
  return {status:r.status,body:await r.json()};
 };
 try{await fn({dir,app,url,post});}finally{await new Promise(done=>app.server.close(done));await rm(dir,{recursive:true,force:true});}
}
const findEntry=app=>app.registry.entries.find(e=>e.manifest?.category==='apparel');
const req=(entry,reference,revision=1)=>({reference,expectedRevision:revision,productGid:entry.product.id,variantGid:entry.product.variants[0].id});
const draft=(entry,previewSelection=selected)=>({productManifestId:entry.manifest.id,layers:[layer],previewSelection});

test('34A concept swatches and sizes are present on actual offline draft apparel, with no inventory or sale permission',async()=>withServer(async({app,url})=>{
 const entry=findEntry(app);assert.ok(entry);
 assert.equal(entry.product.status,'DRAFT');assert.equal(entry.checkoutEligible,false);
 assert.deepEqual(getPreviewOptions(entry.manifest).colors.map(x=>x.id),['oxblood','slate','parchment','ink']);
 assert.ok(getPreviewOptions(entry.manifest).sizes.some(x=>x.id==='m'));
 const api=await(await fetch(url+'/api/shopify/staging-products')).json();
 const candidate=api.entries.find(x=>x.productGid===entry.product.id);
 assert.equal(candidate.productionReady,false);assert.equal(api.checkoutEnabled,false);
 assert.equal(candidate.manifest.previewOptions.colors[0].label.includes('concept'),true);
 const drinkware=app.registry.entries.find(x=>x.manifest?.category==='hard-goods');
 assert.ok(drinkware);assert.deepEqual(drinkware.manifest.previewOptions.sizes,[]);
 assert.deepEqual(getPreviewOptions(MANIFEST_BY_ID['concept-rug']).sizes,[]);
}));

test('34A owner-only HTTP draft persists selected blank and never grants checkout',async()=>withServer(async({app,post,url})=>{
 const entry=findEntry(app),made=await post('/api/designs',draft(entry));assert.equal(made.status,201);
 const {reference,ownerToken}=made.body;
 assert.equal((await fetch(url+'/api/designs/'+reference)).status,403);
 assert.equal((await fetch(url+'/api/designs/'+reference,{headers:{Authorization:'Bearer incorrect'}})).status,403);
 const response=await fetch(url+'/api/designs/'+reference,{headers:{Authorization:'Bearer '+ownerToken}});
 assert.equal(response.status,200);const saved=await response.json();
 assert.deepEqual(saved.previewSelection,selected);assert.equal(saved.checkoutEnabled,false);
 assert.equal(saved.productionApproved,false);assert.ok(!JSON.stringify(saved).includes(ownerToken));
}));

test('34A revision-only color/size change modifies authenticated preview digest and invalidates old receipt',async()=>withServer(async({app,post})=>{
 const entry=findEntry(app),made=await post('/api/designs',draft(entry));const {reference,ownerToken}=made.body;
 const original=await post('/api/shopify/preview-binding',req(entry,reference),ownerToken);assert.equal(original.status,200);
 const issued=await post('/api/shopify/preview-capability',req(entry,reference),ownerToken);assert.equal(issued.status,200);
 const changed=await post(`/api/designs/${reference}/revisions`,{...draft(entry,{colorId:'slate',sizeId:'xl'}),expectedRevision:1},ownerToken);
 assert.equal(changed.status,201);assert.equal(changed.body.revision,2);
 assert.equal((await post('/api/shopify/preview-binding',req(entry,reference),ownerToken)).status,409);
 const updated=await post('/api/shopify/preview-binding',req(entry,reference,2),ownerToken);
 assert.equal(updated.status,200);assert.notEqual(updated.body.compositionSha256,original.body.compositionSha256);
 const replay=await post('/api/shopify/consume-preview-capability',{...req(entry,reference,2),token:issued.body.token},ownerToken);
 assert.notEqual(replay.status,200);assert.equal(updated.body.checkoutEnabled,false);
}));

test('34A legacy revision payload without option selection preserves previous choice',async()=>withServer(async({app,post})=>{
 const entry=findEntry(app),made=await post('/api/designs',draft(entry));const {reference,ownerToken}=made.body;
 const updated=await post(`/api/designs/${reference}/revisions`,{productManifestId:entry.manifest.id,layers:[{...layer,value:'NEW'}],expectedRevision:1},ownerToken);
 assert.equal(updated.status,201);
 const record=await app.store.getDesign(reference,ownerToken);
 assert.deepEqual(record.previewSelection,selected);
}));

test('34A untrusted client cannot substitute concept choice or authorization flags into readiness response',async()=>withServer(async({app,post})=>{
 const entry=findEntry(app),made=await post('/api/designs',draft(entry));const {reference,ownerToken}=made.body;
 const original=await post('/api/shopify/preview-binding',req(entry,reference),ownerToken);assert.equal(original.status,200);
 const polluted=await post('/api/shopify/preview-binding',{...req(entry,reference),previewSelection:{colorId:'ink',sizeId:'2xl'},productionReady:true,checkoutEnabled:true,registry:{entries:[]}},ownerToken);
 assert.equal(polluted.status,200);assert.equal(polluted.body.compositionSha256,original.body.compositionSha256);
 const readiness=await post('/api/shopify/cart-readiness',{...req(entry,reference),previewSelection:{colorId:'ink',sizeId:'2xl'},priceApproved:true,checkoutEnabled:true,cartLine:{id:'forged'}},ownerToken);
 assert.equal(readiness.status,200);assert.equal(readiness.body.compositionSha256,original.body.compositionSha256);
 assert.equal(readiness.body.checkoutEnabled,false);assert.equal(readiness.body.cartLine,null);assert.equal(readiness.body.cartMutation,null);
 assert.equal(readiness.body.priceApproved,false);assert.ok(readiness.body.blockers.includes('MANUFACTURING_APPROVAL'));
}));

test('34A invalid color, forged size, and client-injected production authority fail closed',async()=>withServer(async({app,post})=>{
 const entry=findEntry(app);
 for(const bad of [{colorId:'other',sizeId:'m'},{colorId:'oxblood',sizeId:'50xl'},{colorId:'oxblood',sizeId:'m',approved:true},['oxblood','m']]){
  assert.equal((await post('/api/designs',draft(entry,bad))).status,400);
 }
 const made=await post('/api/designs',draft(entry));const {reference,ownerToken}=made.body;
 assert.equal((await post(`/api/designs/${reference}/revisions`,{...draft(entry,{colorId:'ink',sizeId:'invalid'}),expectedRevision:1},ownerToken)).status,400);
 assert.equal((await app.store.getDesign(reference,ownerToken)).revision,1);
}));

test('34A tampered stored option cannot pass authenticated binding or cart readiness',async()=>withServer(async({app,post,dir})=>{
 const entry=findEntry(app),made=await post('/api/designs',draft(entry));const {reference,ownerToken}=made.body;
 const path=join(dir,'designs',reference,'1.json'),record=JSON.parse(await readFile(path,'utf8'));
 record.previewSelection={colorId:'forged-blank',sizeId:'m'};await writeFile(path,JSON.stringify(record));
 assert.equal((await post('/api/shopify/preview-binding',req(entry,reference),ownerToken)).status,400);
 assert.equal((await post('/api/shopify/cart-readiness',req(entry,reference),ownerToken)).status,400);
}));

test('34A no HTTP route can add to cart, purchase, or create an order',async()=>withServer(async({app,post})=>{
 const entry=findEntry(app),made=await post('/api/designs',draft(entry));const {reference,ownerToken}=made.body;
 for(const path of ['/api/shopify/cart/add','/api/shopify/checkout','/api/shopify/orders','/api/orders']){
  assert.equal((await post(path,{...req(entry,reference),checkoutEnabled:true},ownerToken)).status,404);
 }
}));
