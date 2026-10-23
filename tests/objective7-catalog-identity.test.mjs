import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {assembleReadOnlyCatalog,createCatalogRefreshRegistry,validateCatalogTransition} from '../src/catalog-refresh.mjs';
import {resolveTrustedPrincipal} from '../src/customer-identity-contract.mjs';
import {createLocalServer} from '../src/local-server.mjs';

const fixture=JSON.parse(await readFile(new URL('../fixtures/shopify-draft-manufacturing-2026-10-14.json',import.meta.url),'utf8'));
const shop='gucgmp-bc.myshopify.com',now=1_800_000_000_000;
const fresh=()=>{
 const products=structuredClone(fixture.products);
 const pages=[products.slice(0,3),products.slice(3)].map((chunk,i)=>({requestAfter:i?'p3':null,
  edges:chunk.map((node,j)=>({cursor:'p'+(i*3+j+1),node:{...node,
   variantsCount:{count:node.variants.edges.length},variants:{...node.variants,pageInfo:{hasNextPage:false,endCursor:'v'+(i*3+j+1)}}}})),
  pageInfo:{hasNextPage:i===0,endCursor:i===0?'p3':'p6'}}));
 // Each first embedded variant edge requires a cursor.
 for(const page of pages)for(const edge of page.edges){const n=Number(edge.cursor.slice(1));edge.node.variants.edges[0].cursor='v'+n;}
 return {shop,expectedShop:shop,capturedAt:now-5000,now,scope:'MANUFACTURING_TEMPLATE_SUBSET',expectedCount:6,
  productPages:pages,variantPages:{}};
};
const assertReject=(capture,code)=>assert.throws(()=>assembleReadOnlyCatalog(capture),e=>e.code===code);

test('exhaustive paginated six-template subset compiles immutable, non-purchasable registry',()=>{
 const input=fresh();const {capture,registry}=createCatalogRefreshRegistry(input);
 assert.equal(capture.products.length,6);assert.equal(registry.entries.length,6);
 assert.equal(registry.entries.filter(e=>e.manifest).length,5);
 assert.equal(capture.scope,'MANUFACTURING_TEMPLATE_SUBSET');assert.equal(capture.sourceAuthenticated,false);
 assert.equal(capture.checkoutEnabled,false);assert.equal(capture.productionReady,false);
 assert.match(capture.digest,/^[a-f0-9]{64}$/);
 assert.throws(()=>capture.products[0].variants.edges.push({node:{}}),TypeError);
 assert.deepEqual(registry.entries.map(e=>e.issues),Array.from({length:6},()=>[]));
});
test('pagination rejects missing last page, duplicated page, cursor loops and reordered pages',()=>{
 for(const mutate of [
  x=>x.productPages.pop(),
  x=>x.productPages.push(structuredClone(x.productPages[1])),
  x=>x.productPages[1].requestAfter='wrong',
  x=>x.productPages[0].edges[1].cursor=x.productPages[0].edges[0].cursor,
  x=>x.productPages[0].pageInfo.endCursor='wrong',
  x=>x.productPages.reverse(),
 ]){const x=fresh();mutate(x);assert.throws(()=>assembleReadOnlyCatalog(x));}
});
test('incomplete product subset and claimed FULL_CATALOG with wrong count reject',()=>{
 const x=fresh();x.expectedCount=14;assertReject(x,'PRODUCT_COUNT_MISMATCH');
 const y=fresh();y.productPages[0].edges=[];assertReject(y,'PRODUCT_PAGINATION');
});
test('variant pages assemble all variants only with exact continuation and count',()=>{
 const x=fresh(),p=x.productPages[0].edges[0].node;
 p.variantsCount.count=2;p.variants.pageInfo.hasNextPage=true;
 const second={...p.variants.edges[0].node,id:'gid://shopify/ProductVariant/999999999',sku:'MTO-DTF-1002'};
 x.variantPages[p.id]=[{requestAfter:'v1',edges:[{cursor:'v1b',node:second}],pageInfo:{hasNextPage:false,endCursor:'v1b'}}];
 const {capture,registry}=createCatalogRefreshRegistry(x);
 assert.equal(capture.products[0].variants.edges.length,2);
 assert.equal(registry.entries[0].product.variants.length,2);
 const truncated=structuredClone(x);delete truncated.variantPages[p.id];assertReject(truncated,'VARIANT_INCOMPLETE');
 const badCount=structuredClone(x);badCount.productPages[0].edges[0].node.variantsCount.count=3;assertReject(badCount,'VARIANT_COUNT_MISMATCH');
 const badCursor=structuredClone(x);badCursor.variantPages[p.id][0].requestAfter='other';assertReject(badCursor,'VARIANT_PAGINATION');
});
test('cross-product duplicate variant GID, product duplication, and orphan continuation reject',()=>{
 const x=fresh();x.productPages[1].edges[0].node.variants.edges[0].node.id=x.productPages[0].edges[0].node.variants.edges[0].node.id;
 assertReject(x,'DUPLICATE_OR_INVALID_VARIANT');
 const y=fresh();y.productPages[1].edges[0].node.id=y.productPages[0].edges[0].node.id;assertReject(y,'DUPLICATE_OR_INVALID_PRODUCT');
 const z=fresh();z.variantPages['gid://shopify/Product/999999999']=[{requestAfter:null,edges:[],pageInfo:{hasNextPage:false,endCursor:null}}];assertReject(z,'ORPHAN_VARIANT_PAGE');
});
test('untrusted tenant, stale and future captures, missing timestamp or unsafe age reject',()=>{
 for(const change of [
  {shop:'another.myshopify.com'}, {capturedAt:now-30*60_000},{capturedAt:now+61_000},
  {capturedAt:'2026-10-14'}, {maxAgeMs:25*60*60_000},{expectedShop:'another.myshopify.com'}
 ]){const x={...fresh(),...change};assert.throws(()=>assembleReadOnlyCatalog(x));}
});
test('malformed nodes, missing variant count, invalid price and status fail closed',()=>{
 for(const mutate of [
  p=>delete p.variantsCount,
  p=>p.variants.edges[0].node.price='-0.01',
  p=>p.status='PUBLISHED',
  p=>p.variants.pageInfo.hasNextPage='false',
  p=>p.variants.edges[0].node.id='gid://shopify/ProductVariant/evil',
 ]){const x=fresh();mutate(x.productPages[0].edges[0].node);assert.throws(()=>assembleReadOnlyCatalog(x));}
});
test('snapshot digest changes on content edits; mutation of original pages cannot change capture',()=>{
 const x=fresh(),capture=assembleReadOnlyCatalog(x),digest=capture.digest;
 x.productPages[0].edges[0].node.title='Edited';
 assert.equal(capture.products[0].title,fixture.products[0].title);
 assert.notEqual(assembleReadOnlyCatalog(x).digest,digest);
});
test('local HTTP integration returns only offline evidence and does not create checkout route',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'tj-o7-'));
 const app=await createLocalServer({dataDir:dir,catalogCaptureOptions:fresh()});
 const addr=await app.listen(0);const url=`http://127.0.0.1:${addr.port}`;
 try{
  const evidence=await(await fetch(url+'/api/shopify/catalog-evidence')).json();
  assert.equal(evidence.shop,shop);assert.equal(evidence.sourceAuthenticated,false);assert.equal(evidence.checkoutEnabled,false);
  assert.equal(evidence.scope,'MANUFACTURING_TEMPLATE_SUBSET');
  const catalog=await(await fetch(url+'/api/shopify/staging-products')).json();
  assert.equal(catalog.entries.length,6);assert.equal(catalog.captureDigest,evidence.digest);
  assert.equal(catalog.checkoutEnabled,false);
  const checkout=await fetch(url+'/api/shopify/checkout',{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
  assert.equal(checkout.status,404);
 }finally{await new Promise(resolve=>app.server.close(resolve));await rm(dir,{recursive:true,force:true});}
});

const issuer='https://identity.example.test/verified',aud='tj-customer-app';
const claims=()=>({iss:issuer,aud,shop,sub:'gid://shopify/Customer/123456',kind:'customer',sid:'session_0123456789abc',
 jti:'token_0123456789abcdef',iat:now-1000,nbf:now-1000,exp:now+60_000});
const auth=({verifyBearer=async()=>claims(),...other}={})=>resolveTrustedPrincipal({authorizationHeader:'Bearer '+'x'.repeat(32),verifyBearer,
 expectedShop:shop,expectedIssuer:issuer,expectedAudience:aud,now,...other});
test('trusted identity adapter returns minimal immutable principal, not raw bearer or secrets',async()=>{
 const p=await auth();assert.equal(p.subject,'gid://shopify/Customer/123456');
 assert.equal(p.shop,shop);assert.equal(p.checkoutEnabled,false);assert.equal(p.productionReady,false);
 assert.ok(!JSON.stringify(p).includes('x'.repeat(32)));assert.equal(Object.isFrozen(p),true);
 const guestClaims={...claims(),sub:'guest:'+'a'.repeat(24),kind:'guest'};
 assert.equal((await auth({verifyBearer:async()=>guestClaims})).kind,'guest');
});
test('identity requires real injected verifier; caller-supplied verified flag is meaningless',async()=>{
 await assert.rejects(resolveTrustedPrincipal({authorizationHeader:'Bearer '+'x'.repeat(32),verified:true,
  expectedShop:shop,expectedIssuer:issuer,expectedAudience:aud,now}),/VERIFIER_NOT_CONFIGURED/);
 await assert.rejects(auth({verifyBearer:async()=>{throw Error('bad signature');}}),/TOKEN_VERIFICATION_FAILED/);
 for(const h of ['Bearer short','Basic '+'x'.repeat(32),'Bearer '+'.'.repeat(8200),'']){
  await assert.rejects(resolveTrustedPrincipal({authorizationHeader:h,verifyBearer:async()=>claims(),
   expectedShop:shop,expectedIssuer:issuer,expectedAudience:aud,now}),/BEARER_REQUIRED/);
 }
});
test('cross-shop, issuer, audience, subject, session, expired and future claims reject',async()=>{
 const variants=[{shop:'attacker.myshopify.com'},{iss:'https://attacker.test'},{aud:'other'},
  {kind:'guest',sub:'gid://shopify/Customer/123456'},{kind:'customer',sub:'guest:'+'b'.repeat(24)},
  {sid:'x'},{jti:'x'},{exp:now},{iat:now+120_000},{nbf:now+120_000},{exp:now+25*60*60_000}];
 for(const fields of variants){await assert.rejects(auth({verifyBearer:async()=>({...claims(),...fields})}),/UNTRUSTED_PRINCIPAL/);}
});
test('offline principal is not automatically a local design owner or checkout grant',async()=>{
 const p=await auth();
 assert.equal(Object.hasOwn(p,'ownerToken'),false);
 assert.equal(Object.hasOwn(p,'authorizationHeader'),false);
 assert.equal(Object.hasOwn(p,'token'),false);
 assert.equal(p.checkoutEnabled,false);
});

test('anti-rollback contract rejects old captures and same-timestamp equivocation',()=>{
 const x=fresh(),old=assembleReadOnlyCatalog(x);
 assert.equal(validateCatalogTransition(old,old).changed,false);
 const older=assembleReadOnlyCatalog({...fresh(),capturedAt:now-6000});
 assert.throws(()=>validateCatalogTransition(old,older),/CATALOG_ROLLBACK/);
 const edited=fresh();edited.productPages[0].edges[0].node.title='Changed in same second';
 const conflict=assembleReadOnlyCatalog(edited);
 assert.throws(()=>validateCatalogTransition(old,conflict),/CATALOG_EQUIVOCATION/);
 const newer=assembleReadOnlyCatalog({...edited,capturedAt:now-4000});
 assert.equal(validateCatalogTransition(old,newer).changed,true);
 assert.equal(createCatalogRefreshRegistry({...edited,capturedAt:now-4000,previousCapture:old}).capture.digest,newer.digest);
 assert.throws(()=>createCatalogRefreshRegistry({...fresh(),capturedAt:now-6000,previousCapture:old}),/CATALOG_ROLLBACK/);
});
test('catalog snapshot scope cannot silently switch between subset and full shop',()=>{
 const subset=assembleReadOnlyCatalog(fresh());
 const full=assembleReadOnlyCatalog({...fresh(),scope:'FULL_CATALOG'});
 assert.throws(()=>validateCatalogTransition(subset,full),/CATALOG_TRANSITION_IDENTITY/);
 assert.throws(()=>assembleReadOnlyCatalog({...fresh(),scope:'ANYTHING'}),/CATALOG_SCOPE/);
});
test('malformed variant continuation, repeated cursors and inflated counts are refused',()=>{
 const base=fresh(),p=base.productPages[0].edges[0].node;
 p.variantsCount.count=2;p.variants.pageInfo.hasNextPage=true;
 base.variantPages[p.id]=[{requestAfter:'v1',edges:[{cursor:'v1',node:{...p.variants.edges[0].node,id:'gid://shopify/ProductVariant/999999999'}}],pageInfo:{hasNextPage:false,endCursor:'v1'}}];
 assertReject(base,'VARIANT_EDGE');
 const inflated=fresh();inflated.productPages[0].edges[0].node.variantsCount.count=20001;assertReject(inflated,'VARIANT_COUNT_REQUIRED');
 const malformed=fresh();malformed.productPages[0].edges[0].node.variants.edges[0].cursor='../unsafe';assertReject(malformed,'VARIANT_EDGE');
});
