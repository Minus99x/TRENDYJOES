import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createLocalMultiDesignReview} from '../src/preview-multidesign-review.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const entry=(i,revision=1)=>({reference:'TJ-'+i.toString(16).toUpperCase().padStart(24,'0'),revision,
 ownerToken:i.toString(16).padStart(64,'0'),productManifestId:'crew-shirt',productLabel:'Crew shirt',
 productGid:'gid://shopify/Product/123',variantGid:'gid://shopify/ProductVariant/456'});
const blockers=['CURRENT_CATALOG','ACTIVE_PURCHASABLE_VARIANT','AUTHORITATIVE_PRICE',
 'CUSTOMER_AUTHENTICATION','PRIVATE_ARTWORK_STORAGE','MANUFACTURING_APPROVAL','CHECKOUT_ORDER_RECONCILIATION'];
const checks=['LOCAL_DESIGN_OWNER','LOCAL_PRODUCT_VARIANT',...blockers].map((id,i)=>({id,
 status:i===0?'LOCAL_ONLY':i===1?'SNAPSHOT_ONLY':'BLOCKED',reason:'Not authorized for checkout'}));
const readiness=(x)=>({schema:'TJ-CUSTOMER-CART-READINESS-1',scope:'OFFLINE_PREVIEW_ONLY',
 reference:x.reference,revision:x.expectedRevision,productGid:x.productGid,variantGid:x.variantGid,
 compositionSha256:'a'.repeat(64),previewValid:true,localOwnerChecked:true,
 shopifyCustomerAuthenticated:false,catalogCurrent:false,priceApproved:false,
 productionReady:false,checkoutEnabled:false,cartLine:null,cartMutation:null,checkoutUrl:null,
 shopifyOrderId:null,blockers:[...blockers],checks:checks.map(x=>({...x}))});
const build=(readReadiness=async x=>readiness(x))=>createLocalMultiDesignReview({readReadiness});
const reject=async(p,code)=>assert.rejects(p,{code});
function pair(m){m.add(entry(1));m.add(entry(2));return m;}
test('35K two independent saved drafts produce only a non-authorizing preview',async()=>{
 let reads=0;const m=pair(build(async x=>{reads++;return readiness(x);}));const r=await m.review();
 assert.equal(reads,4);assert.equal(r.lineCount,2);assert.equal(r.outcome,'BLOCKED_FOR_COMMERCE');
 assert.equal(r.checkoutEnabled,false);assert.equal(r.cartLines,null);assert.equal(r.orderId,null);
 assert.equal(r.shopifyCustomerAuthenticated,false);assert.equal(r.productionApproved,false);
 assert.equal(r.lines[0].reference,entry(1).reference);
 assert.doesNotMatch(JSON.stringify(r),new RegExp(entry(1).ownerToken));
 assert.doesNotMatch(JSON.stringify(m.list()),new RegExp(entry(2).ownerToken));
 assert.equal(Object.isFrozen(r.lines[0]),true);
});
test('35K one draft cannot produce a multi-design review',()=>reject(build().review(),'MULTI_PREVIEW_NEEDS_TWO'));
test('35K selection changes line count and requires two selected',async()=>{
 const m=pair(build());m.select(entry(1).reference,false);await reject(m.review(),'MULTI_PREVIEW_NEEDS_TWO');
 m.select(entry(1).reference,true);assert.equal((await m.review()).lineCount,2);
});
test('35K removal and clear erase ephemeral capabilities',async()=>{
 const m=pair(build());m.remove(entry(1).reference);assert.equal(m.list().length,1);
 m.clear();assert.equal(m.list().length,0);await reject(m.review(),'MULTI_PREVIEW_NEEDS_TWO');
});
test('35K old revision capture cannot replace newer saved revision',()=>{
 const m=build();m.add(entry(1,3));assert.throws(()=>m.add(entry(1,2)),{code:'MULTI_PREVIEW_STALE_CAPTURE'});
 assert.equal(m.list()[0].revision,3);
});
test('35K updated revision replaces in-memory owner grant and invalidates old preview',async()=>{
 const m=pair(build());m.add(entry(1,2));assert.equal((await m.review()).lines[0].revision,2);
});
test('35K invalid reference, owner, variant and privilege fields fail closed',()=>{
 const m=build();for(const patch of [{reference:'../evil'},{ownerToken:'x'},
  {productGid:'gid://shopify/Customer/1'},{variantGid:'gid://shopify/ProductVariant/0'},
  {checkoutEnabled:true},{productLabel:'<'.repeat(121)}])
  assert.throws(()=>m.add({...entry(1),...patch}),{code:'MULTI_PREVIEW_ENTRY_INVALID'});
});
test('35K unrecognized selection and invalid boolean rejected',()=>{
 const m=build();assert.throws(()=>m.select(entry(1).reference,true),{code:'MULTI_PREVIEW_SELECTION_INVALID'});
 m.add(entry(1));assert.throws(()=>m.select(entry(1).reference,'true'),{code:'MULTI_PREVIEW_SELECTION_INVALID'});
});
test('35K caps queue at 25 distinct drafts',()=>{
 const m=build();for(let i=1;i<=25;i++)m.add(entry(i));
 assert.throws(()=>m.add(entry(26)),{code:'MULTI_PREVIEW_LIMIT'});
 assert.equal(m.list().length,25);
});
test('35K wrong variant and stale revision readiness fail closed',async()=>{
 for(const patch of [{variantGid:'gid://shopify/ProductVariant/999'},{revision:5},
  {productGid:'gid://shopify/Product/999'},{reference:entry(9).reference}]){
  const m=pair(build(async x=>({...readiness(x),...patch})));
  await reject(m.review(),'MULTI_PREVIEW_READINESS_UNTRUSTED');
 }
});
test('35K forged approval, checkout, missing blockers and extra fields fail closed',async()=>{
 for(const patch of [{checkoutEnabled:true},{shopifyCustomerAuthenticated:true},{priceApproved:true},
  {cartLine:{}},{checkoutUrl:'/checkout'},{blockers:[]},{ownerToken:'secret'},
  {checks:checks.slice(1)},{scope:'HOSTED'}]){
  const m=pair(build(async x=>({...readiness(x),...patch})));
  await reject(m.review(),'MULTI_PREVIEW_READINESS_UNTRUSTED');
 }
});
test('35K corrupted checks cannot imply production authorization',async()=>{
 const m=pair(build(async x=>({...readiness(x),checks:checks.map((c,i)=>i===2?{...c,status:'READY'}:c)})));
 await reject(m.review(),'MULTI_PREVIEW_READINESS_UNTRUSTED');
});
test('35K rejection of a single line blocks entire collection',async()=>{
 const m=pair(build(async x=>{if(x.reference===entry(2).reference)throw Error('private token '+x.ownerToken);return readiness(x);}));
 await reject(m.review(),'MULTI_PREVIEW_READINESS_REFUSED');
});
test('35K selection mutation during async revalidation invalidates result',async()=>{
 let release;const gate=new Promise(r=>release=r);let began;const begun=new Promise(r=>began=r);
 const m=pair(build(async x=>{began();await gate;return readiness(x);}));
 const pending=m.review();await begun;m.select(entry(2).reference,false);release();
 await reject(pending,'MULTI_PREVIEW_SELECTION_CHANGED');
});
test('35K revision update during async review invalidates result',async()=>{
 let release;const gate=new Promise(r=>release=r);let began;const begun=new Promise(r=>began=r);
 const m=pair(build(async x=>{began();await gate;return readiness(x);}));
 const pending=m.review();await begun;m.add(entry(1,2));release();
 await reject(pending,'MULTI_PREVIEW_SELECTION_CHANGED');
});
test('35K digest drift between first and second read rejects review',async()=>{
 let count=0;const m=pair(build(async x=>({...readiness(x),compositionSha256:++count>2?'b'.repeat(64):'a'.repeat(64)})));
 await reject(m.review(),'MULTI_PREVIEW_DESIGN_CHANGED');
});
test('35K no persistence, commerce or Shopify network path in preview module',async()=>{
 const code=await readFile(resolve(root,'src/preview-multidesign-review.mjs'),'utf8');
 assert.doesNotMatch(code,/fetch\(|https?:\/\/|localStorage|sessionStorage|checkout\.json|\/cart\/add/);
 assert.equal(build().localOnly,true);assert.equal(build().checkoutEnabled,false);
});
test('35K accessible review controls wired to local demo without enabling checkout',async()=>{
 const html=await readFile(resolve(root,'demo/index.html'),'utf8');
 const js=await readFile(resolve(root,'demo/studio.mjs'),'utf8');
 for(const id of ['multi-add','multi-list','multi-review','multi-status','multi-results','multi-clear']){
  assert.match(html,new RegExp(`id="${id}"`));assert.match(js,new RegExp(`\\$\\('${id}'\\)`));
 }
 assert.match(html,/aria-live="polite"/);assert.match(js,/createLocalMultiDesignReview/);
 assert.match(html,/disabled class="disabled-checkout"/);
 assert.doesNotMatch(html,/<form[^>]+action="\/cart/);
});

// Actual loopback API integration; synthetic fixtures, not Shopify network access.
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createLocalServer} from '../src/local-server.mjs';
import {createStagingRegistry} from '../src/shopify-bridge.mjs';
test('35K real local server: two independently owned saved designs revalidate without commerce',async t=>{
 const products=JSON.parse(await readFile(resolve(root,'fixtures/shopify-draft-manufacturing-2026-10-14.json'),'utf8')).products;
 const entries=createStagingRegistry(products).entries.filter(e=>e.manifest&&e.manifest.surfaces.length>0);
 assert.ok(entries.length>=2);
 const dir=await mkdtemp(join(tmpdir(),'tj-35k-local-'));
 const server=await createLocalServer({dataDir:dir,shopifySnapshot:products});
 const addr=await server.listen(0);const url=`http://127.0.0.1:${addr.port}`;
 t.after(async()=>{await new Promise(r=>server.server.close(r));await rm(dir,{recursive:true,force:true});});
 const post=async(path,body,ownerToken)=>{
  const res=await fetch(url+path,{method:'POST',headers:{'Content-Type':'application/json',
   ...(ownerToken?{Authorization:`Bearer ${ownerToken}`}:{})},body:JSON.stringify(body)});
  return {status:res.status,body:await res.json()};
 };
 const m=build(async input=>{
  const {ownerToken,...body}=input;
  const result=await post('/api/shopify/cart-readiness',body,ownerToken);
  if(result.status!==200)throw Error('LOCAL_REJECTED');
  return result.body;
 });
 const saved=[];
 for(const [i,e] of entries.slice(0,2).entries()){
  const design={productManifestId:e.manifest.id,layers:[{id:`local-text-${i}`,type:'text',surfaceId:e.manifest.surfaces[0].id,
   x:.25,y:.25,width:.3,height:.2,rotationDeg:0,value:`Synthetic preview ${i}`}]};
  const created=await post('/api/designs',design);assert.equal(created.status,201);
  const data=created.body;saved.push({e,design,data});
  m.add({reference:data.reference,revision:data.revision,ownerToken:data.ownerToken,
   productManifestId:e.manifest.id,productLabel:e.manifest.label,
   productGid:e.product.id,variantGid:e.product.variants[0].id});
 }
 const reviewed=await m.review();assert.equal(reviewed.lineCount,2);
 assert.equal(reviewed.outcome,'BLOCKED_FOR_COMMERCE');
 assert.equal(reviewed.cartLines,null);assert.equal(reviewed.orderId,null);
 for(const x of saved)assert.doesNotMatch(JSON.stringify(reviewed),new RegExp(x.data.ownerToken));
 // Cross-owner capability substitution is rejected by the real loopback API.
 const first=saved[0],second=saved[1];
 m.add({reference:first.data.reference,revision:1,ownerToken:second.data.ownerToken,
  productManifestId:first.e.manifest.id,productLabel:first.e.manifest.label,
  productGid:first.e.product.id,variantGid:first.e.product.variants[0].id});
 await reject(m.review(),'MULTI_PREVIEW_READINESS_REFUSED');
 m.add({reference:first.data.reference,revision:1,ownerToken:first.data.ownerToken,
  productManifestId:first.e.manifest.id,productLabel:first.e.manifest.label,
  productGid:first.e.product.id,variantGid:first.e.product.variants[0].id});
 assert.equal((await m.review()).lineCount,2);
 const x=saved[0];const revision=await post(`/api/designs/${x.data.reference}/revisions`,
  {...x.design,expectedRevision:1,layers:[{...x.design.layers[0],value:'Changed after queue'}]},x.data.ownerToken);
 assert.equal(revision.status,201);assert.equal(revision.body.revision,2);
 await reject(m.review(),'MULTI_PREVIEW_READINESS_REFUSED');
 m.add({reference:x.data.reference,revision:2,ownerToken:x.data.ownerToken,
  productManifestId:x.e.manifest.id,productLabel:x.e.manifest.label,
  productGid:x.e.product.id,variantGid:x.e.product.variants[0].id});
 assert.equal((await m.review()).lineCount,2);
 assert.equal((await post('/api/shopify/cart/add',{},x.data.ownerToken)).status,404);
});
