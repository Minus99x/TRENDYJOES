import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {randomBytes} from 'node:crypto';
import {createStagingRegistry,createStagingEntry,inspectStagingDesign,validateProfileCompatibility} from '../src/shopify-bridge.mjs';
import {prepareStagingBinding,signOrderMetadata,verifyOrderMetadata} from '../src/shopify-intents.mjs';
import {createLocalServer} from '../src/local-server.mjs';
const source=JSON.parse(await readFile(new URL('../fixtures/shopify-draft-manufacturing-2026-10-14.json',import.meta.url),'utf8'));
const products=source.products;
const registry=createStagingRegistry(products);
const entry=registry.entries.find(e=>e.product.handle==='draft-template-custom-dtg-printed-apparel');
const variantGid=entry.product.variants[0].id;
const layer={id:'custom-text',type:'text',surfaceId:'front',x:.3,y:.3,width:.4,height:.2,rotationDeg:0,value:'Your logo'};
const draft={productManifestId:entry.manifest.id,layers:[layer]};
const PNG=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/lIgAAAAASUVORK5CYII=','base64');

async function withShopifyServer(fn){const dir=await mkdtemp(join(tmpdir(),'tj-bridge-'));
 const inst=await createLocalServer({dataDir:dir,shopifySnapshot:products});const addr=await inst.listen(0);const url=`http://127.0.0.1:${addr.port}`;
 try{await fn({url,dir,inst});}finally{await new Promise(resolve=>inst.server.close(resolve));await rm(dir,{force:true,recursive:true});}
}
async function post(url,path,obj,auth){const r=await fetch(url+path,{method:'POST',headers:{'Content-Type':'application/json',...(auth?{Authorization:`Bearer ${auth}`}:{})},body:JSON.stringify(obj)});return {status:r.status,body:await r.json()};}

test('six real Shopify production template IDs map one-to-one and remain disabled',()=>{
 assert.equal(registry.entries.length,6);assert.equal(registry.entries.filter(e=>e.manifest).length,5);
 assert.equal(registry.entries.filter(e=>!e.customizable).length,1);
 for(const p of registry.entries){assert.deepEqual(p.issues,[]);assert.equal(p.product.status,'DRAFT');assert.equal(p.checkoutEligible,false);
  assert.match(p.product.id,/^gid:\/\/shopify\/Product\/\d+$/);
  assert.match(p.product.variants[0].id,/^gid:\/\/shopify\/ProductVariant\/\d+$/);
  if(p.manifest)assert.deepEqual(validateProfileCompatibility(p),[]);
 }
});
test('process and physical geometry differ; assets require explicit matching UV-bound surfaces',()=>{
 const types=new Map(registry.entries.map(e=>[e.product.handle,e.manifest]));
 assert.equal(types.get('draft-template-custom-3d-printed-item').geometry.kind,'other');
 assert.equal(types.get('draft-template-custom-uv-dtf-decal').geometry.kind,'flat');
 assert.equal(types.get('draft-template-custom-dtg-printed-apparel').geometry.kind,'garment');
 assert.equal(types.get('draft-template-ready-to-ship-3d-printed-decor'),null);
 const p=products.find(x=>x.handle==='draft-template-custom-dtg-printed-apparel');
 const bad=createStagingEntry(p,{assets:{[p.id]:{storageKey:'approved.glb',sha256:'0'.repeat(64),mappedSurfaceIds:['unrelated']}}});
 assert.equal(bad.manifest,null);assert.equal(bad.issues[0].code,'ASSET_PROFILE');
 const ok=createStagingEntry(p,{assets:{[p.id]:{storageKey:'candidate/garment.glb',sha256:'a'.repeat(64),mappedSurfaceIds:['front']}}});
 assert.equal(ok.manifest.geometry.modelAsset.verificationStatus,'UNVERIFIED');assert.equal(ok.checkoutEligible,false);
});
test('unmapped new product stays catalog-only, and duplicate ids cannot collide',()=>{
 const unknown=createStagingEntry({...products[0],handle:'made-to-order-one-of-a-kind-product'});
 assert.equal(unknown.issues[0].code,'UNMAPPED_PRODUCT');assert.equal(unknown.manifest,null);
 const wrongType=createStagingEntry({...products[0],productType:'Made to Order - UV DTF'});
 assert.equal(wrongType.issues[0].code,'PROCESS_IDENTITY_MISMATCH');
 const wrongSku=structuredClone(products[0]);wrongSku.variants.edges[0].node.sku='UNRELATED';
 assert.equal(createStagingEntry(wrongSku).issues[0].code,'PROCESS_IDENTITY_MISMATCH');
 const dupe=createStagingRegistry([products[0],products[0]]);
 assert.equal(dupe.entries[1].issues.at(-1).code,'DUPLICATE_PRODUCT');
});
test('missing/invalid variants, negative prices and forged identifiers fail closed',()=>{
 const p=products[0];
 for(const change of [{id:'gid://shopify/Product/not-a-number'}, {variants: {edges: []}}, {variants: {edges: [{node:{id:'gid://shopify/ProductVariant/1',price:'-5'}}]}}]){
  const e=createStagingEntry({...p,...change});assert.ok(e.issues.length);assert.equal(e.manifest,null);
 }
 const partial=createStagingEntry({...p,variantsCount:{count:4}});assert.equal(partial.issues[0].code,'PARTIAL_VARIANTS');
 const invalid=inspectStagingDesign({entry,variantGid:'gid://shopify/ProductVariant/999',design:{layers:[layer]}});
 assert.ok(invalid.issues.some(i=>i.code==='VARIANT_MISMATCH'));assert.equal(invalid.checkoutEnabled,false);
});
test('surface mismatch, rotation outside measured area and incorrect manufacturing route reject',()=>{
 const out=inspectStagingDesign({entry,variantGid,design:{layers:[{...layer,x:.92}]}});
 assert.ok(out.issues.some(i=>i.code==='OUTSIDE_PRINT_ZONE'));
 const bad=inspectStagingDesign({entry,variantGid,design:{layers:[{...layer,surfaceId:'wrap'}]}});
 assert.ok(bad.issues.some(i=>i.code==='INVALID_SURFACE'));
 const altered=structuredClone(entry);altered.manifest.surfaces[0].allowableMethods=['UV-FLAT'];
 assert.ok(inspectStagingDesign({entry:altered,variantGid,design:{layers:[layer]}}).issues.some(i=>i.code==='METHOD_SURFACE_MISMATCH'));
});
test('real draft SKU and zero price never produce production-ready or purchasable line',()=>{
 const r=inspectStagingDesign({entry,variantGid,design:{layers:[layer]}});
 assert.equal(r.previewValid,true);assert.equal(r.productionReady,false);assert.equal(r.checkoutEnabled,false);
 assert.ok(r.issues.some(x=>x.code==='UNPRICED_VARIANT'));
 assert.ok(r.blockers.some(x=>x.code==='DRAFT_OR_INACTIVE'));
});
test('authenticated binding to real Shopify GIDs emits only non-purchasable preview receipt',async()=>withShopifyServer(async({url})=>{
 const listed=await(await fetch(url+'/api/shopify/staging-products')).json();
 assert.equal(listed.entries.length,6);assert.equal(listed.checkoutEnabled,false);
 const created=await post(url,'/api/designs',draft);assert.equal(created.status,201);
 const {reference,ownerToken}=created.body;
 const input={reference,expectedRevision:1,productGid:entry.product.id,variantGid};
 assert.equal((await post(url,'/api/shopify/preview-binding',input)).status,403);
 assert.equal((await post(url,'/api/shopify/preview-binding',input,'wrong')).status,403);
 const binding=await post(url,'/api/shopify/preview-binding',input,ownerToken);
 assert.equal(binding.status,200);assert.equal(binding.body.reference,reference);
 assert.equal(binding.body.checkoutEnabled,false);assert.equal(binding.body.cartLine,null);
 assert.equal(binding.body.productGid,entry.product.id);assert.equal(binding.body.variantGid,variantGid);
 assert.ok(!JSON.stringify(binding.body).includes(ownerToken));
 assert.equal((await post(url,'/api/shopify/preview-binding',{...input,expectedRevision:2},ownerToken)).status,409);
 assert.equal((await post(url,'/api/shopify/preview-binding',{...input,variantGid:'gid://shopify/ProductVariant/5'},ownerToken)).status,400);
 assert.equal((await post(url,'/api/shopify/preview-binding',{...input,productGid:products[0].id},ownerToken)).status,409);
 const empty=await post(url,'/api/designs',{productManifestId:draft.productManifestId,layers:[]});
 assert.equal((await post(url,'/api/shopify/preview-binding',{...input,reference:empty.body.reference},empty.body.ownerToken)).status,400);
 assert.throws(()=>signOrderMetadata(binding.body,randomBytes(32)),/INVALID_BINDING/);
}));
test('previous upload file corruption blocks binding; valid artwork requires grant',async()=>withShopifyServer(async({url,dir})=>{
 const aResp=await fetch(url+'/api/artworks',{method:'POST',headers:{'Content-Type':'image/png'},body:PNG});const art=await aResp.json();
 const artwork={...layer,type:'artwork',artworkId:art.id};delete artwork.value;
 const payload={...draft,layers:[artwork]};
 assert.equal((await post(url,'/api/designs',payload)).status,403);
 const made=await post(url,'/api/designs',{...payload,artworkGrants:{[art.id]:art.grant}});assert.equal(made.status,201);
 const input={reference:made.body.reference,expectedRevision:1,productGid:entry.product.id,variantGid};
 assert.equal((await post(url,'/api/shopify/preview-binding',input,made.body.ownerToken)).status,200);
 await writeFile(join(dir,'artworks',art.id+'.png'),'damaged asset');
 assert.equal((await post(url,'/api/shopify/preview-binding',input,made.body.ownerToken)).status,409);
}));
test('future order metadata HMAC binds exact product, variant, revision and digest; cannot sign previews',()=>{
 const secret=randomBytes(32);
 const authorized={schema:'TJ-SHOPIFY-AUTHORIZED-CHECKOUT-1',checkoutEnabled:true,productionReady:true,
  reference:'TJ-'+randomBytes(12).toString('hex').toUpperCase(),revision:3,productGid:entry.product.id,variantGid,compositionSha256:'a'.repeat(64)};
 const signed=signOrderMetadata(authorized,secret);
 assert.equal(verifyOrderMetadata(signed,secret,{productGid:entry.product.id,variantGid}),true);
 assert.equal(verifyOrderMetadata({...signed,'_TJ Design Revision':'4'},secret),false);
 assert.equal(verifyOrderMetadata(signed,secret,{variantGid:'gid://shopify/ProductVariant/123'}),false);
 assert.equal(verifyOrderMetadata(signed,randomBytes(32)),false);
 assert.ok(!JSON.stringify(signed).includes('ownerToken'));
 assert.throws(()=>signOrderMetadata({...authorized,productionReady:false},secret),/INVALID_BINDING/);
 assert.throws(()=>signOrderMetadata(authorized,Buffer.from('short')),/SERVER_SECRET_REQUIRED/);
});
