/** Objective 35I — offline-only multi-design review -> synthetic order observation.
 * Local owner tokens authenticate only local saved drafts; they are NEVER a
 * Shopify customer session, a cart credential or a manufacturing authorization.
 * The independently authenticated synthetic event and the durable ledger own
 * order identity and atomic nonce/design claims. No network or Shopify I/O.
 */
import {reviewCustomerCartReadiness} from './customer-cart-readiness.mjs';
import {isAuthenticatedSyntheticMultiLineEvent} from './offline-multiline-order.mjs';

const fail=code=>{throw Object.assign(new Error(code),{code,status:403});};
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const exact=(x,keys)=>object(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
const bindingKeys=['reference','revision','productGid','variantGid','compositionSha256'];
const requestKeys=['lineId','store','registry','reference','ownerToken','expectedRevision','productGid','variantGid'];
const requiredBlockers=['CURRENT_CATALOG','ACTIVE_PURCHASABLE_VARIANT','AUTHORITATIVE_PRICE',
 'CUSTOMER_AUTHENTICATION','PRIVATE_ARTWORK_STORAGE','MANUFACTURING_APPROVAL','CHECKOUT_ORDER_RECONCILIATION'];
const ref=/^TJ-[A-F0-9]{24}$/;
const gid=k=>new RegExp(`^gid:\/\/shopify\/${k}\/[1-9][0-9]*$`);
const hex=/^[a-f0-9]{64}$/;
const same=(a,b)=>bindingKeys.every(k=>a[k]===b[k]);
const reviewInput=x=>Object.freeze(Object.fromEntries(
 ['store','registry','reference','ownerToken','expectedRevision','productGid','variantGid'].map(k=>[k,x[k]])));
function checkReview(review,request,binding){
 if(!object(review)||review.schema!=='TJ-CUSTOMER-CART-READINESS-1'||
 review.scope!=='OFFLINE_PREVIEW_ONLY'||review.previewValid!==true||
 review.localOwnerChecked!==true||review.shopifyCustomerAuthenticated!==false||
 review.catalogCurrent!==false||review.priceApproved!==false||
 review.productionReady!==false||review.checkoutEnabled!==false||
 review.cartLine!==null||review.cartMutation!==null||review.checkoutUrl!==null||
 review.shopifyOrderId!==null||!Array.isArray(review.blockers)||
 requiredBlockers.some(k=>!review.blockers.includes(k))||
 !same(review,binding)||review.revision!==request.expectedRevision)
 fail('MULTI_REVIEW_CHANGED');
}
/** Trusted adapters are supplied by the offline server fixture. Each request
 * must contain exactly one private local capability, never exposed downstream.
 */
export function createOfflineMultiReviewObservation({reviewBoundary,readReadiness=reviewCustomerCartReadiness,lineage}={}){
 if(typeof reviewBoundary?.prepare!=='function'||typeof readReadiness!=='function'||
 typeof lineage?.transition!=='function')fail('MULTI_REVIEW_CONFIGURATION');
 async function observe({requests,verifiedEvent,authContext}={}){
  // Authenticity is checked BEFORE issuing any signed receipt. Checking a
  // plain event object's fields is insufficient: it could be forged.
  if(!isAuthenticatedSyntheticMultiLineEvent(verifiedEvent)||
   verifiedEvent.body.action!=='ORDER_OBSERVED')fail('MULTI_REVIEW_EVENT_UNTRUSTED');
  const lines=verifiedEvent.body.lines;
  if(!Array.isArray(requests)||requests.length<2||requests.length>25||
   requests.length!==lines.length||new Set(requests.map(r=>r?.lineId)).size!==requests.length||
   new Set(requests.map(r=>r?.reference)).size!==requests.length)
   fail('MULTI_REVIEW_REQUESTS_INVALID');
  for(let i=0;i<requests.length;i++){
   const r=requests[i],line=lines[i];
   if(!exact(r,requestKeys)||!Number.isSafeInteger(r.lineId)||r.lineId<1||
    !ref.test(r.reference)||!Number.isSafeInteger(r.expectedRevision)||r.expectedRevision<1||
    !gid('Product').test(r.productGid)||!gid('ProductVariant').test(r.variantGid)||
    typeof r.ownerToken!=='string'||!hex.test(r.ownerToken)||
    r.lineId!==line.lineId||r.reference!==line.reference||
    r.expectedRevision!==line.revision||r.productGid!==line.productGid||
    r.variantGid!==line.variantGid)
    fail('MULTI_REVIEW_REQUESTS_MISMATCH');
  }
  const items=[];
  for(let i=0;i<requests.length;i++){
   const r=requests[i],line=lines[i];let receipt;
   try{receipt=await reviewBoundary.prepare({...reviewInput(r),authContext});}
   catch{fail('MULTI_REVIEW_RECEIPT_REJECTED');}
   if(!object(receipt)||receipt.schema!=='TJ-OFFLINE-REVIEW-RECEIPT-1'||
    receipt.scope!=='SYNTHETIC_OFFLINE_ONLY'||!same(receipt,line)||
    !exact(receipt.properties,['_TJ Protocol','_TJ Cart Receipt'])||
    receipt.properties['_TJ Protocol']!=='TJ-OFFLINE-CART-2'||
    receipt.checkoutEnabled!==false||receipt.priceApproved!==false||
    receipt.paymentVerified!==false||receipt.productionApproved!==false||
    receipt.fulfillmentAuthorized!==false||receipt.shopifyCustomerAuthenticated!==false||
    receipt.cartLine!==null||receipt.checkoutUrl!==null||receipt.shopifyOrderId!==null)
    fail('MULTI_REVIEW_RECEIPT_UNTRUSTED');
   items.push(Object.freeze({lineId:r.lineId,properties:receipt.properties,
    expectedBinding:Object.freeze(Object.fromEntries(bindingKeys.map(k=>[k,line[k]])))}));
  }
  // Recheck ALL drafts after ALL asynchronous issuance: an earlier design
  // may change while a later line is being prepared. The trusted ledger
  // performs a separate atomic server-owned CAS at commit time.
  for(let i=0;i<requests.length;i++){
   let review;try{review=await readReadiness(reviewInput(requests[i]));}
   catch{fail('MULTI_REVIEW_CHANGED');}
   checkReview(review,requests[i],lines[i]);
  }
  let result;try{result=await lineage.transition({verifiedEvent,items,authContext});}
  catch{fail('MULTI_REVIEW_OBSERVATION_REJECTED');}
  if(!exact(result,['schema','shop','orderGid','lineCount','action','outcome','syntheticOnly',
   'checkoutEnabled','paymentVerified','productionApproved','fulfillmentAuthorized'])||
   result.schema!=='TJ-OFFLINE-MULTILINE-TRANSITION-1'||
   result.shop!==verifiedEvent.body.shop||result.orderGid!==verifiedEvent.body.orderGid||
   result.lineCount!==lines.length||result.action!=='ORDER_OBSERVED'||
   !['acquired','duplicate'].includes(result.outcome)||result.syntheticOnly!==true||
   result.checkoutEnabled!==false||result.paymentVerified!==false||
   result.productionApproved!==false||result.fulfillmentAuthorized!==false)
   fail('MULTI_REVIEW_OBSERVATION_UNTRUSTED');
  return Object.freeze({schema:result.schema,shop:result.shop,orderGid:result.orderGid,
   lineCount:result.lineCount,action:result.action,outcome:result.outcome,syntheticOnly:true,
   checkoutEnabled:false,paymentVerified:false,productionApproved:false,fulfillmentAuthorized:false});
 }
 return Object.freeze({observe,localOnly:true,checkoutEnabled:false});
}
