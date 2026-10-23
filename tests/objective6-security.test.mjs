import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes} from 'node:crypto';
import {LocalDesignStore} from '../src/local-store.mjs';
import {createStagingRegistry} from '../src/shopify-bridge.mjs';
import {LocalPreviewCapabilityAuthority} from '../src/preview-capabilities.mjs';
import {localArtworkStorageInterface,reviewCommerceLine,reviewManufacturingGeometry} from '../src/integration-security.mjs';
import {createCalibrationWorksheet} from '../src/calibration.mjs';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {createLocalServer} from '../src/local-server.mjs';
import {signOrderMetadata} from '../src/shopify-intents.mjs';

const source=JSON.parse(await readFile(new URL('../fixtures/shopify-draft-manufacturing-2026-10-14.json',import.meta.url),'utf8'));
const registry=createStagingRegistry(source.products);
const entry=registry.entries.find(e=>e.product.handle==='draft-template-custom-dtg-printed-apparel');
const variantGid=entry.product.variants[0].id;
const layer={id:'text-1',type:'text',surfaceId:'front',x:.2,y:.2,width:.5,height:.4,rotationDeg:0,value:'Test'};
const PNG=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/lIgAAAAASUVORK5CYII=','base64');
const time0=1792000000000;
async function fixture(fn){
 const dir=await mkdtemp(join(tmpdir(),'tj-o6-'));const store=new LocalDesignStore(dir,{manifests:{[entry.manifest.id]:entry.manifest}});
 await store.init();
 try{
  const design=await store.putDesign({productManifestId:entry.manifest.id,layers:[layer]});
  const input={store,registry,reference:design.reference,ownerToken:design.ownerToken,expectedRevision:1,productGid:entry.product.id,variantGid};
  await fn({dir,store,design,input});
 }finally{await rm(dir,{recursive:true,force:true});}
}
function auth({clock=()=>time0,secret=randomBytes(32),ttlMs=60000}={}){return new LocalPreviewCapabilityAuthority({clock,secret,ttlMs});}
test('owner required at issue; capability carries exact product + revision, no owner secret, no checkout',async()=>fixture(async({input,design})=>{
 const authority=auth();
 await assert.rejects(authority.issue({...input,ownerToken:'other'}),/Design access denied/);
 const cap=await authority.issue(input);
 assert.equal(cap.schema,'TJ-PREVIEW-CAPABILITY-1');assert.equal(cap.checkoutEnabled,false);assert.equal(cap.productionReady,false);
 assert.equal(cap.cartLine,null);assert.equal(cap.shopifyOrderId,null);assert.equal(cap.previewOnly,true);
 assert.ok(!JSON.stringify(cap).includes(design.ownerToken));
 const verified=await authority.consume({...input,token:cap.token});
 assert.equal(verified.reference,design.reference);assert.equal(verified.checkoutEnabled,false);
 await assert.rejects(authority.consume({...input,token:cap.token}),/PREVIEW_REPLAY_BLOCKED/);
}));
test('tampered signature, swapped product, variant, secret, noncanonical field, wrong owner fail closed',async()=>fixture(async({input})=>{
 const a=auth(),cap=await a.issue(input);
 const tokenParts=cap.token.split('.');tokenParts[2]=(tokenParts[2][0]==='A'?'B':'A')+tokenParts[2].slice(1);
 await assert.rejects(a.consume({...input,token:tokenParts.join('.')}),/INVALID_PREVIEW_CAPABILITY/);
 await assert.rejects(auth().consume({...input,token:cap.token}),/INVALID_PREVIEW_CAPABILITY/);
 await assert.rejects(a.consume({...input,token:cap.token,variantGid:'gid://shopify/ProductVariant/2'}),/PREVIEW_IDENTITY_MISMATCH/);
 await assert.rejects(a.consume({...input,token:cap.token,productGid:'gid://shopify/Product/2'}),/PREVIEW_IDENTITY_MISMATCH/);
 await assert.rejects(a.consume({...input,token:cap.token,ownerToken:'bad'}),/Design access denied/);
 assert.equal((await a.consume({...input,token:cap.token})).previewValid,true); // failed owner doesn't burn a receipt
}));
test('expiry, future clock and invalid configuration fail closed',async()=>fixture(async({input})=>{
 let now=time0;const a=auth({clock:()=>now,ttlMs:1000});const cap=await a.issue(input);
 now+=1000;await assert.rejects(a.consume({...input,token:cap.token}),/EXPIRED_PREVIEW_CAPABILITY/);
 now-=1001;await assert.rejects(a.consume({...input,token:cap.token}),/EXPIRED_PREVIEW_CAPABILITY/);
 assert.throws(()=>auth({secret:Buffer.alloc(8)}),/CAPABILITY_SECRET_REQUIRED/);
 assert.throws(()=>auth({ttlMs:60*60*1000}),/INVALID_CAPABILITY_CONFIG/);
}));
test('updated design invalidates old revision and cannot be consumed after change',async()=>fixture(async({input,store})=>{
 const a=auth();const cap=await a.issue(input);
 await store.reviseDesign(input.reference,input.ownerToken,{productManifestId:entry.manifest.id,expectedRevision:1,layers:[{...layer,value:'Changed'}]});
 await assert.rejects(a.consume({...input,token:cap.token}),/STALE_DESIGN_REVISION/);
 await assert.rejects(a.issue(input),/STALE_DESIGN_REVISION/);
 const changed=await a.issue({...input,expectedRevision:2});
 assert.equal((await a.consume({...input,expectedRevision:2,token:changed.token})).revision,2);
}));
test('simultaneous consumption is atomic for one process and one receipt',async()=>fixture(async({input})=>{
 const a=auth(),cap=await a.issue(input);
 const responses=await Promise.allSettled(Array.from({length:12},()=>a.consume({...input,token:cap.token})));
 assert.equal(responses.filter(r=>r.status==='fulfilled').length,1);
 assert.equal(responses.filter(r=>r.status==='rejected'&&r.reason.code==='PREVIEW_REPLAY_BLOCKED').length,11);
}));
test('artwork interface enforces grants, checksum, structure and denies public URLs',async()=>fixture(async({dir,store})=>{
 const storage=localArtworkStorageInterface(store);const saved=await storage.upload(PNG,'image/png');
 assert.equal(storage.publicUrl(),null);
 await assert.rejects(storage.read({artworkId:saved.id,accessGrant:'wrong'}),/access denied/);
 const first=await storage.read({artworkId:saved.id,accessGrant:saved.grant});
 assert.ok(first.bytes.equals(PNG));assert.match(first.sha256,/^[a-f0-9]{64}$/);
 assert.equal((await storage.assertBound({artworkId:saved.id,accessGrant:saved.grant})).bytes,PNG.length);
 await writeFile(join(dir,'artworks',saved.id+'.png'),Buffer.from('corruption'));
 await assert.rejects(storage.read({artworkId:saved.id,accessGrant:saved.grant}),/checksum mismatch/);
 await assert.rejects(storage.assertBound({artworkId:saved.id,accessGrant:saved.grant}),/checksum mismatch/);
}));
test('cart/order metadata exact-identity validator never authorizes checkout or production',()=>{
 const secret=randomBytes(32);
 const binding={schema:'TJ-SHOPIFY-AUTHORIZED-CHECKOUT-1',checkoutEnabled:true,productionReady:true,
  reference:'TJ-'+randomBytes(12).toString('hex').toUpperCase(),revision:2,productGid:entry.product.id,variantGid,compositionSha256:'a'.repeat(64)};
 const properties=signOrderMetadata(binding,secret);
 const line={id:Number(variantGid.split('/').at(-1)),quantity:1,properties};
 const context={line,...binding,secret};
 const preview=reviewCommerceLine({...context,authorized:false});
 assert.equal(preview.metadataMatches,true);assert.equal(preview.acceptedForCheckout,false);assert.equal(preview.acceptedForProduction,false);
 assert.ok(preview.issues.some(x=>x.code==='NO_PRODUCTION_AUTHORIZATION'));
 const consistent=reviewCommerceLine({...context,authorized:true});
 assert.equal(consistent.metadataMatches,true);assert.equal(consistent.acceptedForProduction,false);
 const mutants=[{...line,id:999},{...line,quantity:0},{...line,properties:{...properties,'_TJ Design Revision':'3'}},
  {...line,properties:{...properties,extra:'inject'}},{...line,properties:{...properties,'_TJ Variant GID':'gid://shopify/ProductVariant/9'}}];
 for(const changed of mutants){assert.equal(reviewCommerceLine({...context,line:changed,authorized:true}).metadataMatches,false);}
 assert.equal(reviewCommerceLine({...context,secret:randomBytes(32),authorized:true}).metadataMatches,false);
});
test('physical review enforces measured routes, safe insets, wrapping and remains nonproduction',()=>{
 const manifest=PRODUCT_MANIFESTS[0];const input={blankSku:'MOCK-TEXTILE-1',measuredBy:'Test only',sourceDocument:'Mock bench evidence',measuredAt:'2026-10-14'};
 const zone={surfaceId:'front',widthMm:240,heightMm:300,blankWidthMm:300,blankHeightMm:400,processCode:'DTF-TEXTILE',fixtureReference:'Dummy fixture',safetyInsetMm:5};
 const worksheet=createCalibrationWorksheet(manifest,[zone],input);
 const good=reviewManufacturingGeometry({manifest,worksheet,design:{layers:[layer]}});
 assert.equal(good.reviewReady,true);assert.equal(good.productionApproved,false);assert.equal(good.checkoutEnabled,false);assert.equal(good.machineOutput,null);
 const out=reviewManufacturingGeometry({manifest,worksheet,design:{layers:[{...layer,x:.75,width:.23}]}});
 assert.equal(out.reviewReady,false);assert.ok(out.issues.some(x=>['OUTSIDE_SAFE_ZONE','OUTSIDE_PRINT_ZONE'].includes(x.code)));
 const broken=reviewManufacturingGeometry({manifest,worksheet:{...worksheet,zones:[{...worksheet.zones[0],processCode:'UV-FLAT'}]},design:{layers:[layer]}});
 assert.ok(broken.issues.some(x=>x.code==='MANUFACTURING_ROUTE'));
 const missing=reviewManufacturingGeometry({manifest,worksheet:{...worksheet,zones:[]},design:{layers:[layer]}});
 assert.ok(missing.issues.some(x=>x.code==='MISSING_MEASURED_SURFACE'));
 assert.equal(reviewManufacturingGeometry({manifest,worksheet,design:{layers:[]}}).reviewReady,false);
 const assetManifest=structuredClone(manifest);assetManifest.geometry.modelAsset={sha256:'f'.repeat(64)};
 const sha=reviewManufacturingGeometry({manifest:assetManifest,worksheet,design:{layers:[layer]}});
 assert.ok(sha.issues.some(x=>x.code==='MODEL_SHA_MISMATCH'));
});
test('HTTP integration is private, one use and never enables Shopify checkout',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'tj-o6-server-'));
 const app=await createLocalServer({dataDir:dir,shopifySnapshot:source.products});const addr=await app.listen(0);
 const base=`http://127.0.0.1:${addr.port}`;
 const post=async(path,body,ownerToken)=>{const r=await fetch(base+path,{method:'POST',headers:{'content-type':'application/json',...(ownerToken?{authorization:`Bearer ${ownerToken}`}:{})},body:JSON.stringify(body)});return {status:r.status,json:await r.json()};};
 try{
  const created=await post('/api/designs',{productManifestId:entry.manifest.id,layers:[layer]});assert.equal(created.status,201);
  const {reference,ownerToken}=created.json;
  const request={reference,expectedRevision:1,productGid:entry.product.id,variantGid};
  assert.equal((await post('/api/shopify/preview-capability',request)).status,403);
  const issued=await post('/api/shopify/preview-capability',request,ownerToken);
  assert.equal(issued.status,200);assert.equal(issued.json.checkoutEnabled,false);
  assert.ok(!JSON.stringify(issued.json).includes(ownerToken));
  const request2={...request,token:issued.json.token};
  assert.equal((await post('/api/shopify/consume-preview-capability',request2,'bad')).status,403);
  const used=await post('/api/shopify/consume-preview-capability',request2,ownerToken);
  assert.equal(used.status,200);assert.equal(used.json.checkoutEnabled,false);assert.equal(used.json.cartLine,null);
  assert.equal((await post('/api/shopify/consume-preview-capability',request2,ownerToken)).status,409);
  assert.equal((await post('/api/shopify/checkout',request2,ownerToken)).status,404);
 }finally{await new Promise(resolve=>app.server.close(resolve));await rm(dir,{recursive:true,force:true});}
});
test('malformed hostile manufacturing worksheet and design objects reject without crashing',()=>{
 const manifest=PRODUCT_MANIFESTS[0];
 for(const worksheet of [null,{}, {schema:'TJ-CALIBRATION-DRAFT-1',zones:{}},{schema:'TJ-CALIBRATION-DRAFT-1',zones:[null]}]){
  for(const design of [null,{layers:{}},{layers:[null]}]){
   const review=reviewManufacturingGeometry({manifest,worksheet,design});
   assert.equal(review.reviewReady,false);assert.equal(review.productionApproved,false);
  }
 }
});
test('tampering the local owner revision or artwork metadata prevents preview issuance',async()=>fixture(async({input,store,dir})=>{
 const a=auth();
 await writeFile(join(dir,'designs',input.reference,'1.json'),'not valid json');
 await assert.rejects(a.issue(input));
 // The locally corrupted record is deliberately not repaired or treated as a valid session.
}));
