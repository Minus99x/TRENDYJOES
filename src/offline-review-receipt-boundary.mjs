/** Objective 35H: a local, non-authorizing review -> synthetic receipt boundary.
 * A local owner capability is NOT a hosted Shopify customer identity. The
 * injected issuer MUST independently resolve a trusted principal and current
 * server-owned design; the receipt is never a checkout authorization.
 */
import {reviewCustomerCartReadiness} from './customer-cart-readiness.mjs';

const fail=code=>{throw Object.assign(new Error(code),{code,status:403});};
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const exact=(x,keys)=>object(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
const bindingKeys=['reference','revision','productGid','variantGid','compositionSha256'];
const inputKeys=['store','registry','reference','ownerToken','expectedRevision','productGid','variantGid','authContext'];
const requiredBlockers=['CURRENT_CATALOG','ACTIVE_PURCHASABLE_VARIANT','AUTHORITATIVE_PRICE',
 'CUSTOMER_AUTHENTICATION','PRIVATE_ARTWORK_STORAGE','MANUFACTURING_APPROVAL','CHECKOUT_ORDER_RECONCILIATION'];
const ref=/^TJ-[A-F0-9]{24}$/;
const gid=kind=>new RegExp(`^gid:\/\/shopify\/${kind}\/[1-9][0-9]*$`);
const hex=/^[a-f0-9]{64}$/;
const token=/^TJ2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/;
const same=(a,b)=>bindingKeys.every(k=>a[k]===b[k]);
function validBinding(b){return object(b)&&ref.test(b.reference)&&Number.isSafeInteger(b.revision)&&b.revision>0&&
 gid('Product').test(b.productGid)&&gid('ProductVariant').test(b.variantGid)&&hex.test(b.compositionSha256);}
function checkedReadiness(readiness,input){
 if(!object(readiness)||readiness.schema!=='TJ-CUSTOMER-CART-READINESS-1'||
 readiness.scope!=='OFFLINE_PREVIEW_ONLY'||!validBinding(readiness)||
 readiness.reference!==input.reference||readiness.revision!==input.expectedRevision||
 readiness.productGid!==input.productGid||readiness.variantGid!==input.variantGid||
 readiness.previewValid!==true||readiness.localOwnerChecked!==true||
 readiness.shopifyCustomerAuthenticated!==false||readiness.catalogCurrent!==false||
 readiness.priceApproved!==false||readiness.productionReady!==false||
 readiness.checkoutEnabled!==false||readiness.cartLine!==null||
 readiness.cartMutation!==null||readiness.checkoutUrl!==null||
 readiness.shopifyOrderId!==null||!Array.isArray(readiness.blockers)||
 requiredBlockers.some(k=>!readiness.blockers.includes(k)))fail('REVIEW_READINESS_UNTRUSTED');
 return Object.freeze(Object.fromEntries(bindingKeys.map(k=>[k,readiness[k]])));
}
function checkedReceipt(receipt){
 if(!object(receipt)||receipt.schema!=='TJ-OFFLINE-CART-METADATA-2'||
 !exact(receipt.properties,['_TJ Protocol','_TJ Cart Receipt'])||
 receipt.properties['_TJ Protocol']!=='TJ-OFFLINE-CART-2'||
 !token.test(receipt.properties['_TJ Cart Receipt'])||
 !Number.isSafeInteger(receipt.expiresAt)||receipt.expiresAt<1||
 receipt.checkoutEnabled!==false||receipt.productionApproved!==false||
 receipt.paymentVerified!==false||receipt.fulfillmentAuthorized!==false)
 fail('REVIEW_RECEIPT_UNTRUSTED');
 return Object.freeze({...receipt.properties});
}
/** The injected read adapter defaults to the real local saved-design readiness
 * contract. issueReceipt should be authority.issue from the synthetic V2
 * metadata authority; this code does not possess signing keys.
 */
export function createOfflineReviewReceiptBoundary({readReadiness=reviewCustomerCartReadiness,issueReceipt}={}){
 if(typeof readReadiness!=='function'||typeof issueReceipt!=='function')fail('REVIEW_BOUNDARY_CONFIGURATION');
 async function prepare(input){
  if(!exact(input,inputKeys)||!ref.test(input.reference)||
   !Number.isSafeInteger(input.expectedRevision)||input.expectedRevision<1||
   !gid('Product').test(input.productGid)||!gid('ProductVariant').test(input.variantGid)||
   typeof input.ownerToken!=='string'||! /^[a-f0-9]{64}$/.test(input.ownerToken))
   fail('REVIEW_INPUT_INVALID');
  const reviewInput=Object.freeze(Object.fromEntries(
   ['store','registry','reference','ownerToken','expectedRevision','productGid','variantGid'].map(k=>[k,input[k]])));
  let before;try{before=await readReadiness(reviewInput);}catch{fail('REVIEW_READINESS_REJECTED');}
  const binding=checkedReadiness(before,input);
  let issued;try{issued=await issueReceipt({authContext:input.authContext,binding});}
  catch{fail('REVIEW_RECEIPT_REJECTED');}
  const properties=checkedReceipt(issued);
  let after;try{after=await readReadiness(reviewInput);}catch{fail('REVIEW_CHANGED_DURING_ISSUE');}
  const final=checkedReadiness(after,input);
  if(!same(binding,final))fail('REVIEW_CHANGED_DURING_ISSUE');
  return Object.freeze({schema:'TJ-OFFLINE-REVIEW-RECEIPT-1',scope:'SYNTHETIC_OFFLINE_ONLY',
   ...binding,properties,expiresAt:issued.expiresAt,shopifyCustomerAuthenticated:false,
   priceApproved:false,checkoutEnabled:false,paymentVerified:false,
   productionApproved:false,fulfillmentAuthorized:false,cartLine:null,
   checkoutUrl:null,shopifyOrderId:null});
 }
 return Object.freeze({prepare,localOnly:true,checkoutEnabled:false});
}
