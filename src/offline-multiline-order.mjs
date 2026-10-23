/** Objective 15: authenticated SYNTHETIC multi-line observations. No Shopify I/O. */
import {createHash,createHmac,timingSafeEqual} from 'node:crypto';
const deny=code=>{throw Object.assign(new Error(code),{code,status:403});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const shopRe=/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/;
const gid=k=>new RegExp(`^gid://shopify/${k}/[1-9][0-9]*$`);
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const checkoutRe=/^offline-checkout:[A-Za-z0-9_-]{16,80}$/;
const ref=/^TJ-[A-F0-9]{24}$/;
const hex=/^[a-f0-9]{64}$/;
const fields=['reference','revision','productGid','variantGid','compositionSha256'];
const lineFields=['lineId',...fields];
const bodyFields=['schema','shop','action','checkoutId','orderGid','ownerSubject','sessionId','lines','occurredAt'];
const sha=b=>createHash('sha256').update(b).digest('hex');
const safe=x=>Number.isSafeInteger(x)&&x>=0;
const same=(a,b,keys)=>keys.every(k=>a[k]===b[k]);
const exact=(x,keys)=>obj(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
function lineOk(x){return exact(x,lineFields)&&Number.isSafeInteger(x.lineId)&&x.lineId>0&&
 ref.test(x.reference)&&Number.isSafeInteger(x.revision)&&x.revision>0&&
 gid('Product').test(x.productGid)&&gid('ProductVariant').test(x.variantGid)&&hex.test(x.compositionSha256);}
function linesOk(lines){return Array.isArray(lines)&&lines.length>=2&&lines.length<=25&&lines.every(lineOk)&&
 new Set(lines.map(l=>l.lineId)).size===lines.length&&new Set(lines.map(l=>l.reference)).size===lines.length;}
function bodyOk(b){return exact(b,bodyFields)&&b.schema==='TJ-SYNTHETIC-MULTILINE-EVENT-1'&&
 shopRe.test(b.shop)&&['ORDER_OBSERVED','CANCELLATION_OBSERVED'].includes(b.action)&&
 checkoutRe.test(b.checkoutId)&&gid('Order').test(b.orderGid)&&gid('Customer').test(b.ownerSubject)&&
 typeof b.sessionId==='string'&&b.sessionId.length>=16&&b.sessionId.length<=160&&
 safe(b.occurredAt)&&linesOk(b.lines);}
const authenticated=new WeakSet();
/** Provenance predicate: a forged or cloned event cannot mint review receipts. */
export function isAuthenticatedSyntheticMultiLineEvent(event){return authenticated.has(event);}
export function authenticateSyntheticMultiLineEvent({rawBody,headers,secret,expectedShop}={}){
 if(!Buffer.isBuffer(secret)||secret.length<32||!shopRe.test(expectedShop||'')||
 !Buffer.isBuffer(rawBody)||rawBody.length<40||rawBody.length>16_384||!exact(headers,['x-tj-event-id','x-tj-shop','x-tj-signature'])||
 !uuid.test(headers['x-tj-event-id']||'')||headers['x-tj-shop']!==expectedShop||
 typeof headers['x-tj-signature']!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(headers['x-tj-signature']))deny('MULTI_ENVELOPE_INVALID');
 const eventId=headers['x-tj-event-id'].toLowerCase();
 const mac=createHmac('sha256',secret).update(Buffer.concat([
  Buffer.from(`TJ-OFFLINE-MULTILINE-EVENT-1\0${expectedShop}\0${eventId}\0`),rawBody])).digest();
 const received=Buffer.from(headers['x-tj-signature'],'base64url');
 if(received.length!==mac.length||received.toString('base64url')!==headers['x-tj-signature']||
 !timingSafeEqual(received,mac))deny('MULTI_HMAC_INVALID');
 let body;try{
  const decoded=new TextDecoder('utf-8',{fatal:true}).decode(rawBody);body=JSON.parse(decoded);
  if(JSON.stringify(body)!==decoded)deny('MULTI_CANONICAL_INVALID');
 }catch(e){if(e.code==='MULTI_CANONICAL_INVALID')throw e;deny('MULTI_JSON_INVALID');}
 if(!bodyOk(body)||body.shop!==expectedShop)deny('MULTI_BODY_INVALID');
 // Deep-copy/freeze every line; a caller cannot mutate an authenticated event after verification.
 const verified=Object.freeze({schema:'TJ-AUTHENTICATED-SYNTHETIC-MULTILINE-1',shop:expectedShop,
  eventId,bodySha256:sha(rawBody),body:Object.freeze({...body,
   lines:Object.freeze(body.lines.map(l=>Object.freeze({...l})))}),syntheticOnly:true,
  checkoutEnabled:false,paymentVerified:false,productionApproved:false,fulfillmentAuthorized:false});
 authenticated.add(verified);return verified;
}
/** All callbacks must be server-owned offline fixtures. A single durable ledger transaction
 * commits all receipt nonces + all design claims + one order event or none.
 */
export function createOfflineMultiLineage({prepareCartReceipt,resolveCheckout,commitObserved,
 commitCancellation,lookupEvent,inspectCommitted,clock=Date.now}={}){
 if([prepareCartReceipt,resolveCheckout,commitObserved,commitCancellation,lookupEvent,clock]
  .some(fn=>typeof fn!=='function'))deny('MULTI_CONFIGURATION');
 async function transition({verifiedEvent,items,authContext}={}){
  if(!authenticated.has(verifiedEvent)||verifiedEvent.syntheticOnly!==true)deny('MULTI_EVENT_UNTRUSTED');
  const b=verifiedEvent.body,t=clock();
  if(!safe(t)||b.occurredAt>t+60_000||t-b.occurredAt>300_000)deny('MULTI_EVENT_TIME_INVALID');
  let checkout;try{checkout=await resolveCheckout({checkoutId:b.checkoutId,shop:b.shop});}
  catch{deny('MULTI_CHECKOUT_UNAVAILABLE');}
  if(!obj(checkout)||checkout.schema!=='TJ-TRUSTED-OFFLINE-CHECKOUT-1'||
   checkout.shop!==b.shop||checkout.ownerSubject!==b.ownerSubject||checkout.sessionId!==b.sessionId||
   checkout.checkoutId!==b.checkoutId||checkout.status!=='BOUND_OFFLINE'||!safe(checkout.expiresAt)||
   checkout.checkoutEnabled!==false||checkout.paymentVerified!==false||
   (b.action==='ORDER_OBSERVED'&&checkout.expiresAt<=t))deny('MULTI_CHECKOUT_UNTRUSTED');
  if(b.action==='CANCELLATION_OBSERVED'&&(items!==undefined||authContext!==undefined))
   deny('MULTI_CANCEL_CART_NOT_ALLOWED');
  let old;try{old=await lookupEvent({shop:b.shop,eventId:verifiedEvent.eventId});}
  catch{deny('MULTI_LEDGER_UNAVAILABLE');}
  if(old){
   if(old.bodySha256!==verifiedEvent.bodySha256||old.orderGid!==b.orderGid||old.action!==b.action)
    deny('MULTI_EVENT_CONFLICT');
   return response(b,'duplicate');
  }
  const base={shop:b.shop,eventId:verifiedEvent.eventId,bodySha256:verifiedEvent.bodySha256,
   action:b.action,orderGid:b.orderGid,checkoutId:b.checkoutId,ownerSubject:b.ownerSubject,
   sessionHash:sha(`TJ-LINEAGE-SESSION\0${b.shop}\0${b.ownerSubject}\0${b.sessionId}`),
   lines:b.lines.map(l=>({...l}))};
  let outcome;
  if(b.action==='ORDER_OBSERVED'){
   if(!Array.isArray(items)||items.length!==b.lines.length||!items.every(x=>exact(x,['lineId','properties','expectedBinding']))||
    new Set(items.map(x=>x.lineId)).size!==items.length)deny('MULTI_ITEMS_INVALID');
   const proofs=[];
   for(let i=0;i<b.lines.length;i++){
    const line=b.lines[i],item=items[i];
    if(item.lineId!==line.lineId||!exact(item.expectedBinding,fields)||
     !same(item.expectedBinding,line,fields))deny('MULTI_ITEMS_MISMATCH');
    let proof;try{proof=await prepareCartReceipt({properties:item.properties,authContext,
     expectedBinding:item.expectedBinding,expectedIdentity:{shop:b.shop,subject:b.ownerSubject,sessionId:b.sessionId}});}
    catch{deny('MULTI_CART_RECEIPT_REJECTED');}
    if(!obj(proof)||proof.schema!=='TJ-OFFLINE-PREPARED-CART-2'||proof.shop!==b.shop||
     proof.ownerSubject!==b.ownerSubject||proof.sessionHash!==base.sessionHash||
     !same(proof,line,fields)||proof.checkoutEnabled!==false||proof.paymentVerified!==false||
     proof.productionApproved!==false||proof.fulfillmentAuthorized!==false)deny('MULTI_RECEIPT_UNTRUSTED');
    proofs.push(proof);
   }
   try{outcome=await commitObserved({...base,preparedReceipts:proofs});}
   catch{deny('MULTI_LEDGER_UNAVAILABLE');}
  }else{
   if(items!==undefined||authContext!==undefined)deny('MULTI_CANCEL_CART_NOT_ALLOWED');
   try{outcome=await commitCancellation(base);}catch{deny('MULTI_LEDGER_UNAVAILABLE');}
  }
  if(outcome==='conflict')deny('MULTI_EVENT_CONFLICT');
  if(!['acquired','duplicate'].includes(outcome))deny('MULTI_LEDGER_INVALID');
  return response(b,outcome);
 }
 /** Explicit post-crash recovery, not an automatic retry. An authenticated
  * synthetic event is necessary but insufficient: trusted checkout identity
  * and a single durable event/order/line snapshot must also match. The result
  * acknowledges an ALREADY committed offline observation only; it grants no
  * checkout, payment, production or fulfillment authority.
  */
 async function recoverCommitted({verifiedEvent}={}){
  if(!authenticated.has(verifiedEvent)||verifiedEvent.syntheticOnly!==true||
   verifiedEvent.body.action!=='ORDER_OBSERVED')deny('MULTI_RECOVERY_EVENT_UNTRUSTED');
  if(typeof inspectCommitted!=='function')deny('MULTI_RECOVERY_UNAVAILABLE');
  const b=verifiedEvent.body,t=clock();
  if(!safe(t)||b.occurredAt>t+60_000||t-b.occurredAt>300_000)
   deny('MULTI_RECOVERY_EVENT_TIME_INVALID');
  let checkout;try{checkout=await resolveCheckout({checkoutId:b.checkoutId,shop:b.shop});}
  catch{deny('MULTI_RECOVERY_CHECKOUT_UNAVAILABLE');}
  if(!obj(checkout)||checkout.schema!=='TJ-TRUSTED-OFFLINE-CHECKOUT-1'||
   checkout.shop!==b.shop||checkout.ownerSubject!==b.ownerSubject||
   checkout.sessionId!==b.sessionId||checkout.checkoutId!==b.checkoutId||
   checkout.status!=='BOUND_OFFLINE'||!safe(checkout.expiresAt)||
   checkout.checkoutEnabled!==false||checkout.paymentVerified!==false)
   deny('MULTI_RECOVERY_CHECKOUT_UNTRUSTED');
  const sessionHash=sha(`TJ-LINEAGE-SESSION\0${b.shop}\0${b.ownerSubject}\0${b.sessionId}`);
  let result;try{result=await inspectCommitted({shop:b.shop,eventId:verifiedEvent.eventId,
   bodySha256:verifiedEvent.bodySha256,action:b.action,orderGid:b.orderGid,
   checkoutId:b.checkoutId,ownerSubject:b.ownerSubject,sessionHash,
   lines:b.lines.map(l=>({...l}))});}
  catch{deny('MULTI_RECOVERY_LEDGER_UNAVAILABLE');}
  if(result==='absent')deny('MULTI_RECOVERY_NOT_COMMITTED');
  if(result!=='committed')deny('MULTI_RECOVERY_CONFLICT');
  return response(b,'duplicate');
 }
 function response(b,outcome){return Object.freeze({schema:'TJ-OFFLINE-MULTILINE-TRANSITION-1',
  shop:b.shop,orderGid:b.orderGid,lineCount:b.lines.length,action:b.action,outcome,syntheticOnly:true,
  checkoutEnabled:false,paymentVerified:false,productionApproved:false,fulfillmentAuthorized:false});}
 return Object.freeze({transition,recoverCommitted,localOnly:true});
}
