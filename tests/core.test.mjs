import test from 'node:test';
import assert from 'node:assert/strict';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {validateManifest,validateComposition,preflight,artworkDpi,rotatedBounds,buildShopifyLine} from '../src/core.mjs';
const base=PRODUCT_MANIFESTS[0];
const layer={id:'L1',type:'text',surfaceId:'front',value:'Hello',x:.2,y:.2,width:.25,height:.2,rotationDeg:0};
const composition={layers:[layer]};
test('all eight distinct product manifests pass structural validation',()=>{
 assert.equal(PRODUCT_MANIFESTS.length,8);
 for(const manifest of PRODUCT_MANIFESTS)assert.deepEqual(validateManifest(manifest),[],manifest.id);
 assert.equal(new Set(PRODUCT_MANIFESTS.map(m=>m.geometry.subtype)).size,8);
});
test('preview composition passes for valid artwork placement',()=>assert.deepEqual(validateComposition(base,composition),[]));
test('unknown surface fails instead of silently falling back',()=>assert.ok(validateComposition(base,{layers:[{...layer,surfaceId:'nonexistent'}]}).some(e=>e.code==='INVALID_SURFACE')));
test('duplicate layer IDs fail',()=>assert.ok(validateComposition(base,{layers:[layer,{...layer}]}).some(e=>e.code==='DUPLICATE_LAYER')));
test('rotated artwork must fit in printable zone',()=>{
 const bad={...layer,x:.80,y:.80,width:.22,height:.22,rotationDeg:45};
 assert.ok(validateComposition(base,{layers:[bad]}).some(e=>e.code==='OUTSIDE_PRINT_ZONE'));
});
test('non-finite transforms fail',()=>assert.ok(validateComposition(base,{layers:[{...layer,width:NaN}]}).some(e=>e.code==='BAD_TRANSFORM')));
test('unapproved concepts display but cannot be manufactured',()=>{
 const r=preflight(base,composition);
 assert.equal(r.previewValid,true);assert.equal(r.productionReady,false);
 assert.ok(r.blockers.some(b=>b.code==='UNAPPROVED_PRODUCT'));
});
test('missing physical calibration stops production',()=>assert.ok(preflight(base,composition).blockers.some(e=>e.code==='SURFACE_UNCALIBRATED')));
test('DPI measured using actual calibrated millimeters',()=>assert.ok(Math.abs(artworkDpi({sourcePixels:3000,printedMm:254})-300)<1e-10));
test('DPI unknown instead of invented without dimensions',()=>assert.equal(artworkDpi({sourcePixels:3000,printedMm:null}),null));
test('cart serializer refuses concept products',()=>assert.throws(()=>buildShopifyLine({variantGid:'gid://shopify/ProductVariant/12345',designReference:'TJ-12345678',product:base,design:composition,serverApprovedPrice:2000}),/gates/));
test('cart serializer uses only opaque reference when approved and properly verified',()=>{
 const approved=structuredClone(base);
 approved.lifecycle='PRODUCTION_APPROVED';
 approved.manufacturing.materialsVerified=true; approved.manufacturing.approvedMethods=['DTF-TEXTILE'];
 approved.commerce.pricingVerified=true;approved.commerce.variantIds=['gid://shopify/ProductVariant/12345'];
 approved.surfaces.find(s=>s.id==='front').calibrated=true;
 approved.surfaces.find(s=>s.id==='front').printableWidthMm=250;
 approved.surfaces.find(s=>s.id==='front').printableHeightMm=300;
 assert.deepEqual(buildShopifyLine({variantGid:'gid://shopify/ProductVariant/12345',designReference:'TJ-AABBCCDD',product:approved,design:composition,serverApprovedPrice:2200}),{id:12345,quantity:1,properties:{'Design Reference':'TJ-AABBCCDD'}});
});
test('bogus product variant gets rejected even if product is approved',()=>{
 const approved=structuredClone(base);
 approved.lifecycle='PRODUCTION_APPROVED';approved.manufacturing.materialsVerified=true;approved.commerce.pricingVerified=true;
 approved.surfaces[0].calibrated=true;approved.surfaces[0].printableWidthMm=100;approved.surfaces[0].printableHeightMm=100;
 assert.throws(()=>buildShopifyLine({variantGid:'gid://shopify/ProductVariant/12345',designReference:'TJ-AABBCCDD',product:approved,design:composition,serverApprovedPrice:2200}),/Variant/);
});
