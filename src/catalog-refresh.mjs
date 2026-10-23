/** Offline-only Shopify catalog capture validation. No network, Admin API, checkout or writes.
 * Input pages MUST come from a separately authenticated, read-only Admin backend;
 * a successful validation does NOT attest their provenance or freshness on Shopify.
 */
import {createHash} from 'node:crypto';
import {createStagingRegistry,normalizeShopifyProduct} from './shopify-bridge.mjs';

const productGid=/^gid:\/\/shopify\/Product\/[1-9][0-9]*$/;
const variantGid=/^gid:\/\/shopify\/ProductVariant\/[1-9][0-9]*$/;
const shopPattern=/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/;
const validObject=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const reject=(code)=>{throw Object.assign(new Error(code),{code});};
const validCursor=c=>typeof c==='string'&&c.length>=1&&c.length<=512&&/^[A-Za-z0-9_+=:\/-]+$/.test(c);
const scopeSet=new Set(['FULL_CATALOG','MANUFACTURING_TEMPLATE_SUBSET']);

/** Enforce exact cursor continuity and termination. All pages are pre-fetched fixtures;
 * this module never executes requests or trusts client-supplied authorization.
 */
function readConnectionPages(pages,kind,initialAfter=null){
 if(!Array.isArray(pages)||!pages.length||pages.length>200)reject(`${kind}_PAGE_COUNT`);
 const nodes=[],seenCursors=new Set();let after=initialAfter;
 for(let i=0;i<pages.length;i++){
  const page=pages[i];
  if(!validObject(page)||page.requestAfter!==after||!Array.isArray(page.edges)||page.edges.length<1||page.edges.length>250||
   !validObject(page.pageInfo)||typeof page.pageInfo.hasNextPage!=='boolean')reject(`${kind}_PAGINATION`);
  for(const edge of page.edges){
   if(!validObject(edge)||!validCursor(edge.cursor)||!validObject(edge.node)||seenCursors.has(edge.cursor))reject(`${kind}_EDGE`);
   seenCursors.add(edge.cursor);nodes.push(structuredClone(edge.node));
  }
  const last=page.edges.at(-1).cursor;
  if(page.pageInfo.endCursor!==last)reject(`${kind}_END_CURSOR`);
  if(page.pageInfo.hasNextPage!==(i<pages.length-1))reject(`${kind}_INCOMPLETE`);
  after=last;
 }
 return nodes;
}

/** Assemble a complete, bounded, immutable read-only capture from explicit pages.
 * `expectedCount` is the count for the exact authorized query/scope, not necessarily
 * the whole shop. Captures do not authorize a cart, price, identity or manufacture.
 */
export function assembleReadOnlyCatalog({shop,expectedShop,capturedAt,now=Date.now(),maxAgeMs=15*60_000,
 scope,expectedCount,productPages,variantPages={}}={}){
 if(typeof shop!=='string'||!shopPattern.test(shop)||shop!==expectedShop||!shopPattern.test(expectedShop||''))reject('SHOP_IDENTITY');
 if(!Number.isSafeInteger(now)||now<0||!Number.isSafeInteger(capturedAt)||capturedAt<0||
  !Number.isSafeInteger(maxAgeMs)||maxAgeMs<1000||maxAgeMs>24*60*60_000||
  capturedAt>now+60_000||now-capturedAt>maxAgeMs)reject('CATALOG_CAPTURE_EXPIRED');
 if(!scopeSet.has(scope)||!Number.isSafeInteger(expectedCount)||expectedCount<1||expectedCount>50_000)reject('CATALOG_SCOPE');
 if(!validObject(variantPages))reject('VARIANT_PAGE_MAP');
 const products=readConnectionPages(productPages,'PRODUCT');
 if(products.length!==expectedCount)reject('PRODUCT_COUNT_MISMATCH');
 const seenProducts=new Set(),seenVariants=new Set();
 for(const product of products){
  if(!productGid.test(product.id||'')||seenProducts.has(product.id))reject('DUPLICATE_OR_INVALID_PRODUCT');
  seenProducts.add(product.id);
  if(!validObject(product.variants)||!Array.isArray(product.variants.edges)||
   !validObject(product.variants.pageInfo)||typeof product.variants.pageInfo.hasNextPage!=='boolean'||
   !Number.isSafeInteger(product.variantsCount?.count)||product.variantsCount.count<1||product.variantsCount.count>20_000)reject('VARIANT_COUNT_REQUIRED');
  const first={requestAfter:null,edges:product.variants.edges,pageInfo:product.variants.pageInfo};
  const more=variantPages[product.id]??[];
  if(!Array.isArray(more))reject('VARIANT_PAGE_MAP');
  // Variant page continuation starts at the cursor from the first embedded page.
  const variants=readConnectionPages([first,...more],'VARIANT');
  if(variants.length!==product.variantsCount.count)reject('VARIANT_COUNT_MISMATCH');
  for(const v of variants){
   if(!variantGid.test(v.id||'')||seenVariants.has(v.id))reject('DUPLICATE_OR_INVALID_VARIANT');
   seenVariants.add(v.id);
  }
  product.variants={edges:variants.map(node=>({node})),pageInfo:{hasNextPage:false}};
  const normalized=normalizeShopifyProduct(product);
  if(normalized.issues.length)reject(`PRODUCT_VALIDATION_${normalized.issues[0].code}`);
 }
 for(const key of Object.keys(variantPages))if(!seenProducts.has(key))reject('ORPHAN_VARIANT_PAGE');
 const digest=createHash('sha256').update(JSON.stringify({shop,scope,capturedAt,products})).digest('hex');
 const capture={schema:'TJ-READ-ONLY-CATALOG-CAPTURE-1',shop,scope,capturedAt,expectedCount,
  products,digest,sourceAuthenticated:false,checkoutEnabled:false,productionReady:false};
 const deepFreeze=obj=>{if(obj&&typeof obj==='object'&&!Object.isFrozen(obj)){Object.values(obj).forEach(deepFreeze);Object.freeze(obj);}return obj;};
 return deepFreeze(capture);
}

/** Pure anti-rollback check for a future durable, atomic snapshot store.
 * This does not persist state and is NOT a cross-process CAS implementation.
 */
export function validateCatalogTransition(previous,next){
 if(!previous||previous.schema!=='TJ-READ-ONLY-CATALOG-CAPTURE-1'||!next||next.schema!=='TJ-READ-ONLY-CATALOG-CAPTURE-1'||
  previous.shop!==next.shop||previous.scope!==next.scope||
  !Number.isSafeInteger(previous.capturedAt)||!Number.isSafeInteger(next.capturedAt)||
  !/^[a-f0-9]{64}$/.test(previous.digest||'')||!/^[a-f0-9]{64}$/.test(next.digest||''))reject('CATALOG_TRANSITION_IDENTITY');
 if(next.capturedAt<previous.capturedAt)reject('CATALOG_ROLLBACK');
 if(next.capturedAt===previous.capturedAt&&next.digest!==previous.digest)reject('CATALOG_EQUIVOCATION');
 return Object.freeze({canReplace:true,changed:next.digest!==previous.digest,checkoutEnabled:false});
}

export function createCatalogRefreshRegistry(options){
 const capture=assembleReadOnlyCatalog(options);
 if(options?.previousCapture)validateCatalogTransition(options.previousCapture,capture);
 const registry=createStagingRegistry(capture.products);
 if(registry.entries.some(e=>e.issues.some(x=>['PRODUCT_GID','VARIANT_GID','PARTIAL_VARIANTS','DUPLICATE_PRODUCT'].includes(x.code))))reject('REGISTRY_IDENTITY_REJECTED');
 return {capture,registry};
}
