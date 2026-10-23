import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createLocalServer} from '../src/local-server.mjs';
import {editorSnapshot,savedDraftMatchesEditor,reviewSelectionMatches} from '../src/preview-editor-state.mjs';
import {reviewCustomerCartReadiness} from '../src/customer-cart-readiness.mjs';
import {createStagingRegistry} from '../src/shopify-bridge.mjs';
const products=JSON.parse(await readFile(new URL('../fixtures/shopify-draft-manufacturing-2026-10-14.json',import.meta.url),'utf8')).products;
const registry=createStagingRegistry(products);
const entry=registry.entries.find(e=>e.manifest&&e.manifest.surfaces.some(s=>s.id==='front'));
const variantGid=entry.product.variants[0].id;
const textLayer={id:'customer-name',type:'text',surfaceId:'front',x:.25,y:.2,width:.4,height:.18,rotationDeg:0,value:'Made for you'};
const PNG=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/lIgAAAAASUVORK5CYII=','base64');
const design={productManifestId:entry.manifest.id,layers:[textLayer]};
async function fixture(fn){
 const dir=await mkdtemp(join(tmpdir(),'tj-obj31-'));
 const inst=await createLocalServer({dataDir:dir,shopifySnapshot:products}); const addr=await inst.listen(0);
 const url=`http://127.0.0.1:${addr.port}`;
 const post=async(path,body,ownerToken,extra={})=>{
  const result=await fetch(url+path,{method:'POST',headers:{'Content-Type':'application/json',...(ownerToken?{Authorization:`Bearer ${ownerToken}`}:{})},body:JSON.stringify({...body,...extra})});
  return {status:result.status,body:await result.json()};
 };
 try{await fn({dir,url,inst,post});}finally{await new Promise(r=>inst.server.close(r));await rm(dir,{recursive:true,force:true});}
}
const input=(reference,revision=1)=>({reference,expectedRevision:revision,productGid:entry.product.id,variantGid});

test('local saved editor snapshot detects every unsaved composition mutation and product switch',()=>{
 const saved={reference:'TJ-AAAAAAAAAAAAAAAAAAAAAAAA',revision:1};
 const snapshot=editorSnapshot(design.productManifestId,design.layers);
 const same=()=>savedDraftMatchesEditor({...design,saved,savedSnapshot:snapshot});
 assert.equal(same(),true);
 const edits=[
  {...design,layers:[]},
  {...design,layers:[{...textLayer,value:'Changed name'}]},
  {...design,layers:[{...textLayer,rotationDeg:4}]},
  {...design,layers:[{...textLayer,x:.28}]},
  {...design,productManifestId:'concept-rug'},
  {...design,layers:[{...textLayer},{...textLayer,id:'new-layer'}]}
 ];
 for(const e of edits)assert.equal(savedDraftMatchesEditor({...e,saved,savedSnapshot:snapshot}),false);
 assert.equal(savedDraftMatchesEditor({...design,saved:null,savedSnapshot:snapshot}),false);
 assert.equal(savedDraftMatchesEditor({...design,saved,savedSnapshot:null}),false);
 assert.equal(savedDraftMatchesEditor({...design,saved:{...saved,revision:0},savedSnapshot:snapshot}),false);
 assert.throws(()=>editorSnapshot('bad',null),/INVALID_EDITOR_STATE/);
 const productGid=entry.product.id;const requested={reference:saved.reference,expectedRevision:saved.revision,productGid,variantGid};
 const check=(changes={})=>reviewSelectionMatches({productManifestId:design.productManifestId,layers:design.layers,saved,savedSnapshot:snapshot,productGid,variantGid,requested,...changes});
 assert.equal(check(),true);
 assert.equal(check({requested:{...requested,variantGid:'gid://shopify/ProductVariant/555'}}),false);
 assert.equal(check({requested:{...requested,expectedRevision:2}}),false);
 assert.equal(check({requested:{...requested,reference:'TJ-BBBBBBBBBBBBBBBBBBBBBBBB'}}),false);
 assert.equal(check({layers:[{...textLayer,value:'late change'}]}),false);
 assert.equal(check({productGid:'gid://shopify/Product/456'}),false);
 assert.equal(check({requested:null}),false);
});

test('authenticated draft-to-cart readiness reports all real blocking gates; never emits a Shopify cart line',async()=>fixture(async({post})=>{
 const created=await post('/api/designs',design);assert.equal(created.status,201);
 const {reference,ownerToken}=created.body;
 const ready=await post('/api/shopify/cart-readiness',input(reference),ownerToken);
 assert.equal(ready.status,200);
 const r=ready.body;
 assert.equal(r.schema,'TJ-CUSTOMER-CART-READINESS-1');
 assert.equal(r.scope,'OFFLINE_PREVIEW_ONLY');
 assert.equal(r.reference,reference);assert.equal(r.revision,1);
 assert.equal(r.productGid,entry.product.id);assert.equal(r.variantGid,variantGid);
 assert.match(r.compositionSha256,/^[0-9a-f]{64}$/);
 assert.equal(r.localOwnerChecked,true);assert.equal(r.shopifyCustomerAuthenticated,false);
 assert.equal(r.catalogCurrent,false);assert.equal(r.priceApproved,false);
 assert.equal(r.previewValid,true);assert.equal(r.productionReady,false);assert.equal(r.checkoutEnabled,false);
 assert.equal(r.cartLine,null);assert.equal(r.cartMutation,null);assert.equal(r.checkoutUrl,null);assert.equal(r.shopifyOrderId,null);
 assert.deepEqual(r.checks.filter(c=>c.status==='LOCAL_ONLY').map(c=>c.id),['LOCAL_DESIGN_OWNER']);
 assert.deepEqual(r.checks.filter(c=>c.status==='SNAPSHOT_ONLY').map(c=>c.id),['LOCAL_PRODUCT_VARIANT']);
 assert.ok(r.blockers.includes('CURRENT_CATALOG'));
 for(const hold of ['AUTHORITATIVE_PRICE','CUSTOMER_AUTHENTICATION','PRIVATE_ARTWORK_STORAGE','MANUFACTURING_APPROVAL','CHECKOUT_ORDER_RECONCILIATION','ACTIVE_PURCHASABLE_VARIANT'])assert.ok(r.blockers.includes(hold));
 assert.ok(r.checks.find(c=>c.id==='ACTIVE_PURCHASABLE_VARIANT').reason.includes('DRAFT'));
 assert.equal(JSON.stringify(r).includes(ownerToken),false);
 assert.ok(!Object.keys(r).some(k=>/customerEmail|ownerToken|artworkGrant|secret|sessionCookie/i.test(k))); 
 assert.equal((await post('/api/shopify/checkout',input(reference),ownerToken)).status,404);
 assert.equal((await post('/api/shopify/cart/add',input(reference),ownerToken)).status,404);
}));

test('visitor cannot ask for another owner design/cart; invalid/stale revision and variant rejected',async()=>fixture(async({post})=>{
 const made=await post('/api/designs',design);
 const valid=input(made.body.reference);
 assert.equal((await post('/api/shopify/cart-readiness',valid)).status,403);
 assert.equal((await post('/api/shopify/cart-readiness',valid,'wrong-token')).status,403);
 assert.equal((await post('/api/shopify/cart-readiness',{...valid,expectedRevision:2},made.body.ownerToken)).status,409);
 assert.equal((await post('/api/shopify/cart-readiness',{...valid,variantGid:'gid://shopify/ProductVariant/999999'},made.body.ownerToken)).status,400);
 assert.equal((await post('/api/shopify/cart-readiness',{...valid,productGid:'gid://shopify/Product/999999'},made.body.ownerToken)).status,404);
 assert.equal((await post('/api/shopify/cart-readiness',{...valid,productGid:products[0].id},made.body.ownerToken)).status,409);
 assert.equal((await post('/api/shopify/cart-readiness',{...valid,reference:'TJ-AAAAAAAAAAAAAAAAAAAAAAAA'},made.body.ownerToken)).status,404);
 const overwrite=await post('/api/shopify/cart-readiness',valid,made.body.ownerToken,{checkoutEnabled:true,productionReady:true,priceApproved:true,cartLine:{id:123456}});
 assert.equal(overwrite.status,200);assert.equal(overwrite.body.checkoutEnabled,false);assert.equal(overwrite.body.productionReady,false);assert.equal(overwrite.body.cartLine,null);
 const polluted=await post('/api/shopify/cart-readiness',valid,made.body.ownerToken,{registry:{entries:[{product:{id:entry.product.id,status:'ACTIVE',variants:[{id:variantGid,price:'1000.00'}]},manifest:entry.manifest}]},store:{},checkoutEnabled:true});
 assert.equal(polluted.status,200);assert.match(polluted.body.checks.find(c=>c.id==='ACTIVE_PURCHASABLE_VARIANT').reason,/DRAFT/);
 const legacyPolluted=await post('/api/shopify/preview-binding',valid,made.body.ownerToken,{registry:{entries:[]},store:{}});
 assert.equal(legacyPolluted.status,200);assert.equal(legacyPolluted.body.checkoutEnabled,false);
}));

test('revising a saved design invalidates the old revision; new revision can be reviewed, never purchased',async()=>fixture(async({post})=>{
 const made=await post('/api/designs',design);const valid=input(made.body.reference);
 const updated=await post(`/api/designs/${made.body.reference}/revisions`,{...design,expectedRevision:1,layers:[{...textLayer,value:'Revised'}]},made.body.ownerToken);
 assert.equal(updated.status,201);assert.equal(updated.body.revision,2);
 assert.equal((await post('/api/shopify/cart-readiness',valid,made.body.ownerToken)).status,409);
 const current=await post('/api/shopify/cart-readiness',input(made.body.reference,2),made.body.ownerToken);
 assert.equal(current.status,200);assert.equal(current.body.revision,2);assert.equal(current.body.cartLine,null);
}));

test('corrupted previously-uploaded artwork blocks the cart handoff',async()=>fixture(async({post,url,dir})=>{
 const uploaded=await fetch(url+'/api/artworks',{method:'POST',headers:{'Content-Type':'image/png'},body:PNG});
 assert.equal(uploaded.status,201);const art=await uploaded.json();
 const artwork={...textLayer,type:'artwork',artworkId:art.id};delete artwork.value;
 const made=await post('/api/designs',{productManifestId:entry.manifest.id,layers:[artwork],artworkGrants:{[art.id]:art.grant}});
 assert.equal(made.status,201);
 assert.equal((await post('/api/shopify/cart-readiness',input(made.body.reference),made.body.ownerToken)).status,200);
 await writeFile(join(dir,'artworks',art.id+'.png'),'corrupt');
 assert.equal((await post('/api/shopify/cart-readiness',input(made.body.reference),made.body.ownerToken)).status,409);
}));

test('no artifact permits checkout even if a forged registry snapshot product is set ACTIVE and expensive',async()=>{
 const fake=structuredClone(products);const p=fake.find(p=>p.id===entry.product.id);p.status='ACTIVE';p.variants.edges[0].node.price='999.00';
 const dir=await mkdtemp(join(tmpdir(),'tj-obj31-unit-'));
 let inst;
 try{inst=await createLocalServer({dataDir:dir,shopifySnapshot:fake});const stored=await inst.store.putDesign(design);
  const r=await reviewCustomerCartReadiness({store:inst.store,registry:inst.registry,...input(stored.reference),ownerToken:stored.ownerToken});
  assert.equal(r.checkoutEnabled,false);assert.equal(r.cartLine,null);
  assert.match(r.checks.find(c=>c.id==='ACTIVE_PURCHASABLE_VARIANT').reason,/snapshot only/i);
  assert.ok(r.blockers.includes('AUTHORITATIVE_PRICE'));
 }finally{await rm(dir,{recursive:true,force:true});}
});
