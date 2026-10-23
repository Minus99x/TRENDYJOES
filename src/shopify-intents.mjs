/** Authenticated local design-to-Shopify identity bridge.
 * Emits NON-PURCHASABLE preview receipts. Cart and order operations remain disabled.
 */
import {createHash,createHmac,timingSafeEqual} from 'node:crypto';
import {inspectStagingDesign} from './shopify-bridge.mjs';
import {normalizePreviewSelection} from './preview-product-options.mjs';
const deny=(code,status=400)=>Object.assign(new Error(code),{code,status});
const h=val=>createHash('sha256').update(val).digest('hex');
const revisionOk=r=>Number.isSafeInteger(r)&&r>0;
/** Never store or expose ownerToken as a Shopify line item property. */
export async function prepareStagingBinding({store,registry,reference,ownerToken,expectedRevision,productGid,variantGid}){
 if(!revisionOk(expectedRevision))throw deny('INVALID_REVISION');
 // Authentication before any product lookup prevents leaking another design's contents.
 const record=await store.getDesign(reference,ownerToken);
 if(record.revision!==expectedRevision)throw deny('STALE_DESIGN_REVISION',409);
 const entry=registry.entries.find(e=>e.product.id===productGid);
 if(!entry)throw deny('UNKNOWN_SHOPIFY_PRODUCT',404);
 if(!entry.manifest||record.productManifestId!==entry.manifest.id)throw deny('DESIGN_PRODUCT_MISMATCH',409);
 if(!Array.isArray(record.layers)||record.layers.length===0)throw deny('EMPTY_CUSTOM_DESIGN');
 // Revalidate saved artwork bytes and checksum even if they were valid at upload time.
 for(const layer of record.layers){if(layer.type==='artwork')await store.assertArtworkIntegrity(layer.artworkId);}
 const review=inspectStagingDesign({entry,variantGid,design:{layers:record.layers}});
 if(!review.previewValid)throw deny('INVALID_SHOPIFY_DESIGN');
 const productManifest=store.manifests?.[record.productManifestId]??entry.manifest;
 const previewSelection=normalizePreviewSelection(productManifest,record.previewSelection);
 const digest=h(JSON.stringify({reference,revision:record.revision,productGid,variantGid,layers:record.layers,previewSelection}));
 return {schema:'TJ-SHOPIFY-STAGING-BINDING-1',reference,revision:record.revision,productGid,variantGid,compositionSha256:digest,
  previewValid:true,productionReady:false,checkoutEnabled:false,
  cartLine:null,shopifyOrderId:null,
  blockers:review.blockers.map(x=>x.code)};
}
/** Future backend contract: server-only HMAC attests immutable identity and revision.
 * For an externally verified production-ready checkout authorization ONLY.
 * The local staging server cannot issue this object. Not proof of payment or fulfillment.
 */
export function signOrderMetadata(binding,secret){
 if(!binding||binding.schema!=='TJ-SHOPIFY-AUTHORIZED-CHECKOUT-1'||binding.checkoutEnabled!==true||binding.productionReady!==true||!/^TJ-[A-F0-9]{24}$/.test(binding.reference)||!revisionOk(binding.revision)||!/^gid:\/\/shopify\/Product\/[1-9]\d*$/.test(binding.productGid)||!/^gid:\/\/shopify\/ProductVariant\/[1-9]\d*$/.test(binding.variantGid)||! /^[a-f0-9]{64}$/.test(binding.compositionSha256))throw deny('INVALID_BINDING');
 if(!Buffer.isBuffer(secret)||secret.length<32)throw deny('SERVER_SECRET_REQUIRED');
 const fields={"_TJ Design Reference":binding.reference,"_TJ Design Revision":String(binding.revision),"_TJ Product GID":binding.productGid,"_TJ Variant GID":binding.variantGid,"_TJ Composition SHA256":binding.compositionSha256};
 const message=Object.values(fields).join('\n');
 return {...fields,"_TJ Binding HMAC":createHmac('sha256',secret).update(message).digest('hex')};
}
export function verifyOrderMetadata(properties,secret,{productGid,variantGid}={}){
 if(!Buffer.isBuffer(secret)||secret.length<32)return false;
 const keys=['_TJ Design Reference','_TJ Design Revision','_TJ Product GID','_TJ Variant GID','_TJ Composition SHA256'];
 if(!properties||keys.some(k=>typeof properties[k]!=='string')||!/^[a-f0-9]{64}$/.test(properties['_TJ Binding HMAC']||''))return false;
 if(productGid&&properties['_TJ Product GID']!==productGid)return false;
 if(variantGid&&properties['_TJ Variant GID']!==variantGid)return false;
 const expected=createHmac('sha256',secret).update(keys.map(k=>properties[k]).join('\n')).digest();
 return timingSafeEqual(expected,Buffer.from(properties['_TJ Binding HMAC'],'hex'));
}
