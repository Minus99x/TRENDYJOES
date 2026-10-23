/** Objective 12 — synthetic/offline cart-to-order lineage and observed transitions.
 * HMAC fixture events are NOT Shopify webhooks. Nothing here authorizes checkout,
 * payment, fulfillment, manufacturing, or a production order.
 */
import {createHmac,createHash,timingSafeEqual} from 'node:crypto';

const deny=code=>{throw Object.assign(new Error(code),{code,status:403});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const shopRe=/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/;
const gid=k=>new RegExp(`^gid://shopify/${k}/[1-9][0-9]*$`);
const refRe=/^TJ-[A-F0-9]{24}$/;
const hex=/^[a-f0-9]{64}$/;
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const checkoutRe=/^offline-checkout:[A-Za-z0-9_-]{16,80}$/;
const bindingKeys=['reference','revision','productGid','variantGid','compositionSha256'];
const bodyKeys=['schema','shop','action','checkoutId','orderGid','ownerSubject','sessionId','lineId',...bindingKeys,'occurredAt'];
const sha=x=>createHash('sha256').update(x).digest('hex');
const authenticated=new WeakSet();
const safeTime=x=>Number.isSafeInteger(x)&&x>=0;
function validBinding(b){return obj(b)&&Object.keys(b).length===bindingKeys.length&&refRe.test(b.reference)&&
 Number.isSafeInteger(b.revision)&&b.revision>0&&gid('Product').test(b.productGid)&&
 gid('ProductVariant').test(b.variantGid)&&hex.test(b.compositionSha256);}
function validBody(b){return obj(b)&&Object.keys(b).length===bodyKeys.length&&bodyKeys.every(k=>Object.hasOwn(b,k))&&
 b.schema==='TJ-SYNTHETIC-LINEAGE-EVENT-1'&&shopRe.test(b.shop)&&
 ['ORDER_OBSERVED','CANCELLATION_OBSERVED'].includes(b.action)&&checkoutRe.test(b.checkoutId)&&
 gid('Order').test(b.orderGid)&&gid('Customer').test(b.ownerSubject)&&
 typeof b.sessionId==='string'&&b.sessionId.length>=16&&b.sessionId.length<=160&&
 Number.isSafeInteger(b.lineId)&&b.lineId>0&&safeTime(b.occurredAt)&&
 validBinding(Object.fromEntries(bindingKeys.map(k=>[k,b[k]])));}
/** A trusted test adapter supplies raw bytes, domain-separated HMAC and event ID.
 * The object returned here is opaque to callers; copied/forged objects reject.
 */
export function authenticateSyntheticLineageEvent({rawBody,headers,secret,expectedShop}={}){
 if(!Buffer.isBuffer(secret)||secret.length<32||!shopRe.test(expectedShop||'')||
 !Buffer.isBuffer(rawBody)||rawBody.length<20||rawBody.length>4096||!obj(headers)||
 Object.keys(headers).length!==3||!uuid.test(headers['x-tj-event-id']||'')||
 headers['x-tj-shop']!==expectedShop||typeof headers['x-tj-signature']!=='string'||
 !/^[A-Za-z0-9_-]{43}$/.test(headers['x-tj-signature']))deny('LINEAGE_EVENT_ENVELOPE_INVALID');
 const signed=Buffer.concat([Buffer.from(`TJ-OFFLINE-LINEAGE-EVENT-1\0${expectedShop}\0${headers['x-tj-event-id'].toLowerCase()}\0`),rawBody]);
 const mac=createHmac('sha256',secret).update(signed).digest();
 const received=Buffer.from(headers['x-tj-signature'],'base64url');
 if(received.length!==mac.length||received.toString('base64url')!==headers['x-tj-signature']||
 !timingSafeEqual(mac,received))deny('LINEAGE_EVENT_HMAC_INVALID');
 let body;try{
  const raw=new TextDecoder('utf-8',{fatal:true}).decode(rawBody);
  body=JSON.parse(raw);
  // Strict canonical JSON also rejects duplicate keys, ambiguous whitespace and
  // encoded-key aliases; signed fixtures must use JSON.stringify canonical form.
  if(JSON.stringify(body)!==raw)deny('LINEAGE_EVENT_CANONICAL');
 }catch(e){if(e.code==='LINEAGE_EVENT_CANONICAL')throw e;deny('LINEAGE_EVENT_JSON_INVALID');}
 if(!validBody(body)||body.shop!==expectedShop)deny('LINEAGE_EVENT_BODY_INVALID');
 const verified=Object.freeze({schema:'TJ-AUTHENTICATED-SYNTHETIC-LINEAGE-1',
  shop:expectedShop,eventId:headers['x-tj-event-id'].toLowerCase(),bodySha256:sha(rawBody),
  body:Object.freeze(body),syntheticOnly:true,checkoutEnabled:false,paymentVerified:false,
  productionApproved:false,fulfillmentAuthorized:false});
 authenticated.add(verified);return verified;
}
/** resolveCheckout must verify a trusted synthetic checkout/session record.
 * verifyCartReceipt must be the real v2 authority.verify with expectedIdentity
 * enforcement; commitTransition must be a durable atomic server-owned ledger.
 */
export function createOfflineOrderLineage({verifyCartReceipt,resolveCheckout,commitTransition,lookupLineageEvent,clock=Date.now,
 prepareCartReceipt,commitAtomicObserved}={}){
 if(typeof verifyCartReceipt!=='function'||typeof resolveCheckout!=='function'||
 ((prepareCartReceipt===undefined)!==(commitAtomicObserved===undefined))||
 (prepareCartReceipt!==undefined&&typeof prepareCartReceipt!=='function')||
 (commitAtomicObserved!==undefined&&typeof commitAtomicObserved!=='function')||
 typeof commitTransition!=='function'||typeof lookupLineageEvent!=='function'||typeof clock!=='function')deny('LINEAGE_CONFIGURATION');
 async function transition({verifiedEvent,properties,authContext,expectedBinding}={}){
  if(!verifiedEvent||!authenticated.has(verifiedEvent)||verifiedEvent.syntheticOnly!==true)deny('LINEAGE_EVENT_UNTRUSTED');
  const b=verifiedEvent.body,t=clock();
  if(!safeTime(t)||b.occurredAt>t+60_000||t-b.occurredAt>5*60_000)deny('LINEAGE_EVENT_TIME_INVALID');
  if(b.action==='ORDER_OBSERVED'&&(!validBinding(expectedBinding)||
   bindingKeys.some(k=>expectedBinding[k]!==b[k])))deny('LINEAGE_EXPECTED_BINDING');
  let checkout;try{checkout=await resolveCheckout({checkoutId:b.checkoutId,shop:b.shop});}
  catch{deny('LINEAGE_CHECKOUT_UNAVAILABLE');}
  if(!obj(checkout)||checkout.schema!=='TJ-TRUSTED-OFFLINE-CHECKOUT-1'||
   checkout.shop!==b.shop||checkout.ownerSubject!==b.ownerSubject||
   checkout.sessionId!==b.sessionId||checkout.checkoutId!==b.checkoutId||
   checkout.status!=='BOUND_OFFLINE'||!safeTime(checkout.expiresAt)||
   checkout.checkoutEnabled!==false||checkout.paymentVerified!==false||
   (b.action==='ORDER_OBSERVED'&&checkout.expiresAt<=t))deny('LINEAGE_CHECKOUT_UNTRUSTED');
  let receipt;
  if(b.action==='ORDER_OBSERVED'){
   // A previously committed, authenticated event can be acknowledged again
   // without consuming a second one-use cart nonce. Never skip verification
   // for an event not durably recorded, or for a conflicting event identity.
   let old;try{old=await lookupLineageEvent({shop:b.shop,eventId:verifiedEvent.eventId});}
   catch{deny('LINEAGE_LEDGER_UNAVAILABLE');}
   if(old){
    if(old.bodySha256!==verifiedEvent.bodySha256||old.orderGid!==b.orderGid||old.action!==b.action)
     deny('LINEAGE_TRANSITION_CONFLICT');
    return Object.freeze({schema:'TJ-OFFLINE-LINEAGE-TRANSITION-1',shop:b.shop,
     orderGid:b.orderGid,reference:b.reference,revision:b.revision,action:b.action,
     outcome:'duplicate',syntheticOnly:true,checkoutEnabled:false,paymentVerified:false,
     productionApproved:false,fulfillmentAuthorized:false});
   }
   try{receipt=await (prepareCartReceipt||verifyCartReceipt)({properties,authContext,expectedBinding,
    expectedIdentity:{shop:b.shop,subject:b.ownerSubject,sessionId:b.sessionId}});}
   catch(e){deny('LINEAGE_CART_RECEIPT_REJECTED');}
   if(prepareCartReceipt){
    if(!obj(receipt)||receipt.schema!=='TJ-OFFLINE-PREPARED-CART-2'||
     receipt.shop!==b.shop||receipt.ownerSubject!==b.ownerSubject||
     bindingKeys.some(k=>receipt[k]!==b[k])||receipt.checkoutEnabled!==false||
     receipt.paymentVerified!==false||receipt.productionApproved!==false||
     receipt.fulfillmentAuthorized!==false)deny('LINEAGE_CART_RECEIPT_UNTRUSTED');
   }else if(!obj(receipt)||receipt.schema!=='TJ-OFFLINE-VERIFIED-CART-METADATA-2'||
    receipt.shop!==b.shop||bindingKeys.some(k=>receipt[k]!==b[k])||
    receipt.integrityVerified!==true||receipt.nonceConsumed!==true||
    receipt.checkoutEnabled!==false||receipt.paymentVerified!==false||
    receipt.productionApproved!==false||receipt.fulfillmentAuthorized!==false)deny('LINEAGE_CART_RECEIPT_UNTRUSTED');
  }else if(properties!==undefined||expectedBinding!==undefined||authContext!==undefined){
   deny('LINEAGE_CANCELLATION_CART_NOT_ALLOWED');
  }
  const binding=Object.fromEntries(bindingKeys.map(k=>[k,b[k]]));
  const sessionHash=sha(`TJ-LINEAGE-SESSION\0${b.shop}\0${b.ownerSubject}\0${b.sessionId}`);
  let outcome;try{outcome=await (b.action==='ORDER_OBSERVED'&&commitAtomicObserved?commitAtomicObserved:commitTransition)({shop:b.shop,eventId:verifiedEvent.eventId,
   bodySha256:verifiedEvent.bodySha256,action:b.action,orderGid:b.orderGid,
   checkoutId:b.checkoutId,ownerSubject:b.ownerSubject,sessionHash,lineId:b.lineId,binding,
   ...(b.action==='ORDER_OBSERVED'&&commitAtomicObserved?{preparedReceipt:receipt}:{})});}
  catch{deny('LINEAGE_LEDGER_UNAVAILABLE');}
  if(outcome==='conflict')deny('LINEAGE_TRANSITION_CONFLICT');
  if(!['acquired','duplicate'].includes(outcome))deny('LINEAGE_LEDGER_INVALID');
  return Object.freeze({schema:'TJ-OFFLINE-LINEAGE-TRANSITION-1',shop:b.shop,orderGid:b.orderGid,
   reference:b.reference,revision:b.revision,action:b.action,outcome,syntheticOnly:true,
   checkoutEnabled:false,paymentVerified:false,productionApproved:false,fulfillmentAuthorized:false});
 }
 return Object.freeze({transition,localOnly:true});
}
