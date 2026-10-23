/** OFFLINE-only Shopify order webhook authentication/reconciliation contract.
 * No checkout, payment assertion, job dispatch, fulfillment or network I/O.
 * All signing secrets and design records MUST be supplied by a trusted backend.
 */
import {createHash,createHmac,timingSafeEqual} from 'node:crypto';
import {TextDecoder} from 'node:util';
import {verifyOrderMetadata} from './shopify-intents.mjs';

const deny=(code)=>{throw Object.assign(new Error(code),{code,status:403});};
const shopRe=/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/;
const uuidRe=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const gid=(kind)=>new RegExp(`^gid://shopify/${kind}/[1-9][0-9]*$`);
const hex=/^[a-f0-9]{64}$/;
const referenceRe=/^TJ-[A-F0-9]{24}$/;
const authenticatedWebhooks=new WeakSet();
function freezePayload(root){
 const stack=[root],seen=new WeakSet();let count=0;
 while(stack.length){const item=stack.pop();if(!item||typeof item!=='object'||seen.has(item))continue;
  if(++count>50000)deny('WEBHOOK_JSON_COMPLEXITY');seen.add(item);
  for(const value of Object.values(item))if(value&&typeof value==='object')stack.push(value);
  Object.freeze(item);
 }
 return root;
}
const metaKeys=['_TJ Design Reference','_TJ Design Revision','_TJ Product GID','_TJ Variant GID','_TJ Composition SHA256','_TJ Binding HMAC'];
const obj=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const id=v=>Number.isSafeInteger(v)&&v>0;
const gidId=(kind,v)=>gid(kind).test(v||'')?Number(v.split('/').at(-1)):NaN;

// JSON.parse alone silently accepts duplicate object keys. Refuse ambiguity before parsing.
function rejectDuplicateKeys(s){
 const stack=[];
 for(let i=0;i<s.length;i++){
  const ch=s[i];
  if(ch==='{')stack.push({kind:'object',keys:new Set()});
  else if(ch==='[')stack.push({kind:'array'});
  else if(ch==='}'||ch===']'){
   const top=stack.pop();if(!top||top.kind!==(ch==='}'?'object':'array'))deny('INVALID_JSON_STRUCTURE');
  }else if(ch==='"'){
   const start=i;let closed=false;
   for(i++;i<s.length;i++){
    if(s[i]==='\\'){i++;continue;}
    if(s[i]==='"'){closed=true;break;}
   }
   if(!closed)deny('INVALID_JSON_STRUCTURE');
   let next=i+1;while(/\s/.test(s[next]||'')&&next<s.length)next++;
   if(s[next]===':'){
    const top=stack.at(-1);if(!top||top.kind!=='object')deny('INVALID_JSON_STRUCTURE');
    const key=JSON.parse(s.slice(start,i+1));
    if(top.keys.has(key))deny('DUPLICATE_JSON_KEY');
    top.keys.add(key);
   }
  }
 }
 if(stack.length)deny('INVALID_JSON_STRUCTURE');
}

/** Verify Shopify's raw-body HMAC and transport identity BEFORE JSON interpretation.
 * Headers must be normalized by a trusted HTTP adapter (no duplicate headers).
 * This validates a fixture's cryptographic shape; no real Shopify connection exists.
 */
export function authenticateOfflineOrderWebhook({rawBody,headers,webhookSecret,expectedShop}={}){
 if(!Buffer.isBuffer(webhookSecret)||webhookSecret.length<32)deny('WEBHOOK_SECRET_REQUIRED');
 if(!shopRe.test(expectedShop||'')||!obj(headers))deny('WEBHOOK_CONFIGURATION');
 if(!Buffer.isBuffer(rawBody)||rawBody.length===0||rawBody.length>512*1024)deny('WEBHOOK_BODY_BOUNDS');
 const allowed=['x-shopify-hmac-sha256','x-shopify-shop-domain','x-shopify-topic','x-shopify-webhook-id'];
 if(Object.keys(headers).length!==allowed.length||Object.keys(headers).some(k=>!allowed.includes(k)))deny('WEBHOOK_HEADERS');
 if(headers['x-shopify-shop-domain']!==expectedShop||headers['x-shopify-topic']!=='orders/create'||
  !uuidRe.test(headers['x-shopify-webhook-id']||''))deny('WEBHOOK_IDENTITY');
 const signature=headers['x-shopify-hmac-sha256'];
 if(typeof signature!=='string'||! /^(?:[A-Za-z0-9+/]{43}=)$/.test(signature))deny('WEBHOOK_HMAC_FORMAT');
 const expected=createHmac('sha256',webhookSecret).update(rawBody).digest();
 const received=Buffer.from(signature,'base64');
 if(received.length!==expected.length||!timingSafeEqual(received,expected))deny('WEBHOOK_HMAC_INVALID');
 let body;
 try{
  const text=new TextDecoder('utf-8',{fatal:true}).decode(rawBody);
  rejectDuplicateKeys(text);
  body=JSON.parse(text);
 }catch(e){if(['DUPLICATE_JSON_KEY','INVALID_JSON_STRUCTURE'].includes(e?.code))throw e;deny('WEBHOOK_JSON_INVALID');}
 if(!obj(body))deny('WEBHOOK_ORDER_INVALID');
 freezePayload(body);
 const verified=Object.freeze({schema:'TJ-OFFLINE-VERIFIED-WEBHOOK-1',shop:expectedShop,
  topic:'orders/create',eventId:headers['x-shopify-webhook-id'].toLowerCase(),
  bodySha256:createHash('sha256').update(rawBody).digest('hex'),order:body,
  authenticatedFixture:true,checkoutEnabled:false,productionApproved:false});
 authenticatedWebhooks.add(verified);return verified;
}

function parseProperties(properties){
 if(!Array.isArray(properties)||properties.length!==metaKeys.length)deny('ORDER_METADATA_SHAPE');
 const out=Object.create(null);
 for(const p of properties){
  if(!obj(p)||typeof p.name!=='string'||typeof p.value!=='string'||!metaKeys.includes(p.name)||Object.hasOwn(out,p.name))deny('ORDER_METADATA_SHAPE');
  out[p.name]=p.value;
 }
 if(metaKeys.some(k=>!Object.hasOwn(out,k)))deny('ORDER_METADATA_SHAPE');
 return out;
}

/** The design lookup MUST return a current, server-authoritative record, not a
 * client-supplied preview or stale revision. Atomic claimOnce is a durable backend
 * contract: return 'acquired' | 'duplicate' | 'conflict'; never trust a local Map
 * as a distributed production replay ledger.
 */
export async function reconcileOfflineOrder({verifiedWebhook,metadataSecret,lookupDesign,claimOnce}={}){
 if(!verifiedWebhook||!authenticatedWebhooks.has(verifiedWebhook)||verifiedWebhook.schema!=='TJ-OFFLINE-VERIFIED-WEBHOOK-1'||verifiedWebhook.authenticatedFixture!==true||
  !shopRe.test(verifiedWebhook.shop||'')||!uuidRe.test(verifiedWebhook.eventId||'')||!hex.test(verifiedWebhook.bodySha256||'')||
  typeof lookupDesign!=='function'||typeof claimOnce!=='function'||!Buffer.isBuffer(metadataSecret)||metadataSecret.length<32)deny('RECONCILIATION_CONFIGURATION');
 const order=verifiedWebhook.order;
 if(!obj(order)||!gid('Order').test(order.admin_graphql_api_id||'')||!id(order.id)||
  gidId('Order',order.admin_graphql_api_id)!==order.id||!Array.isArray(order.line_items)||
  !order.line_items.length||order.line_items.length>250||!obj(order.customer)||!id(order.customer.id))deny('ORDER_SHAPE');
 const ownerSubject=`gid://shopify/Customer/${order.customer.id}`;
 const reconciled=[],seenLineIds=new Set(),seenDesigns=new Set();
 for(const line of order.line_items){
  if(!obj(line)||!id(line.id)||seenLineIds.has(line.id))deny('ORDER_LINE_IDENTITY');
  seenLineIds.add(line.id);
  const props=line.properties;
  if(!Array.isArray(props))deny('ORDER_LINE_PROPERTIES');
  const custom=props.some(p=>obj(p)&&typeof p.name==='string'&&p.name.startsWith('_TJ '));
  if(!custom){if(props.some(p=>!obj(p)||typeof p.name!=='string'))deny('ORDER_LINE_PROPERTIES');continue;}
  if(!id(line.product_id)||!id(line.variant_id)||!id(line.quantity)||line.quantity>1000)deny('ORDER_LINE_IDENTITY');
  const meta=parseProperties(props);
  const productGid=`gid://shopify/Product/${line.product_id}`;
  const variantGid=`gid://shopify/ProductVariant/${line.variant_id}`;
  if(meta['_TJ Product GID']!==productGid||meta['_TJ Variant GID']!==variantGid||
   !verifyOrderMetadata(meta,metadataSecret,{productGid,variantGid}))deny('ORDER_METADATA_AUTH');
  const reference=meta['_TJ Design Reference'],revision=Number(meta['_TJ Design Revision']);
  if(!referenceRe.test(reference)||!Number.isSafeInteger(revision)||revision<1||String(revision)!==meta['_TJ Design Revision']||
   !hex.test(meta['_TJ Composition SHA256'])||seenDesigns.has(reference))deny('ORDER_DESIGN_IDENTITY');
  seenDesigns.add(reference);
  let record;try{record=await lookupDesign({shop:verifiedWebhook.shop,reference});}catch{deny('DESIGN_LOOKUP_FAILED');}
  if(!obj(record)||record.shop!==verifiedWebhook.shop||record.ownerSubject!==ownerSubject||
   record.reference!==reference||record.revision!==revision||record.productGid!==productGid||
   record.variantGid!==variantGid||record.compositionSha256!==meta['_TJ Composition SHA256']||
   record.status!=='CURRENT')deny('DESIGN_RECORD_MISMATCH');
  reconciled.push(Object.freeze({reference,revision,productGid,variantGid,
   compositionSha256:record.compositionSha256,orderLineId:line.id,quantity:line.quantity}));
 }
 if(!reconciled.length)deny('NO_CUSTOM_DESIGN_LINES');
 const eventKey=`${verifiedWebhook.shop}:orders/create:${verifiedWebhook.eventId}`;
 // Must be an atomic, durable transaction in production. Offline tests inject a mock.
 let result;try{result=await claimOnce({eventKey,bodySha256:verifiedWebhook.bodySha256,orderGid:order.admin_graphql_api_id,matchedLines:reconciled});}
 catch{deny('REPLAY_LEDGER_UNAVAILABLE');}
 if(!['acquired','duplicate','conflict'].includes(result))deny('REPLAY_LEDGER_INVALID');
 if(result==='conflict')deny('WEBHOOK_REPLAY_CONFLICT');
 return Object.freeze({schema:'TJ-OFFLINE-ORDER-RECONCILIATION-1',shop:verifiedWebhook.shop,
  orderGid:order.admin_graphql_api_id,eventId:verifiedWebhook.eventId,
  idempotency:result,matchedLines:Object.freeze(reconciled),
  metadataReconciled:true,paymentVerified:false,checkoutEnabled:false,
  productionApproved:false,fulfillmentAuthorized:false,manufacturingJobs:[]});
}
