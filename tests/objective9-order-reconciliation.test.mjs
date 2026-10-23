import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,createHmac} from 'node:crypto';
import {authenticateOfflineOrderWebhook,reconcileOfflineOrder} from '../src/order-reconciliation.mjs';
import {signOrderMetadata} from '../src/shopify-intents.mjs';

const shop='gucgmp-bc.myshopify.com';
const webhookSecret=randomBytes(32),metadataSecret=randomBytes(32);
const productGid='gid://shopify/Product/123456789';
const variantGid='gid://shopify/ProductVariant/234567891';
const reference='TJ-'+'A'.repeat(24),compositionSha256='b'.repeat(64);
const eventId='123e4567-e89b-42d3-a456-426614174000';
const binding={schema:'TJ-SHOPIFY-AUTHORIZED-CHECKOUT-1',checkoutEnabled:true,productionReady:true,
 reference,revision:3,productGid,variantGid,compositionSha256};
const props=()=>Object.entries(signOrderMetadata(binding,metadataSecret)).map(([name,value])=>({name,value}));
const body=()=>({id:345678912,admin_graphql_api_id:'gid://shopify/Order/345678912',
 customer:{id:456789123},financial_status:'paid',
 line_items:[{id:567891234,product_id:123456789,variant_id:234567891,quantity:2,properties:props()}]});
const record=()=>({shop,ownerSubject:'gid://shopify/Customer/456789123',reference,revision:3,
 productGid,variantGid,compositionSha256,status:'CURRENT'});
function wire(value=body(),changes={}){
 const rawBody=Buffer.isBuffer(value)?value:Buffer.from(typeof value==='string'?value:JSON.stringify(value));
 const headers={'x-shopify-hmac-sha256':createHmac('sha256',webhookSecret).update(rawBody).digest('base64'),
  'x-shopify-shop-domain':shop,'x-shopify-topic':'orders/create','x-shopify-webhook-id':eventId,...changes};
 return {rawBody,headers,webhookSecret,expectedShop:shop};
}
function auth(value=body(),changes={}){return authenticateOfflineOrderWebhook(wire(value,changes));}
function ledger(){const records=new Map();return async({eventKey,bodySha256,orderGid})=>{
 const prev=records.get(eventKey);
 if(prev)return prev.bodySha256===bodySha256&&prev.orderGid===orderGid?'duplicate':'conflict';
 records.set(eventKey,{bodySha256,orderGid});return 'acquired';
};}
const reconcile=(verifiedWebhook=auth(),extra={})=>reconcileOfflineOrder({verifiedWebhook,metadataSecret,
 lookupDesign:async()=>record(),claimOnce:ledger(),...extra});
const fails=async(p,code)=>assert.rejects(p,e=>e?.code===code);

test('authenticated offline fixture reconciles exact order/customer/product/variant/revision and stays disabled',async()=>{
 const verified=auth();assert.equal(Object.isFrozen(verified.order.line_items[0].properties),true);
 const result=await reconcile(verified);
 assert.equal(result.idempotency,'acquired');assert.equal(result.matchedLines.length,1);
 assert.equal(result.matchedLines[0].quantity,2);assert.equal(result.matchedLines[0].reference,reference);
 assert.equal(result.paymentVerified,false);assert.equal(result.checkoutEnabled,false);
 assert.equal(result.productionApproved,false);assert.equal(result.fulfillmentAuthorized,false);
 assert.deepEqual(result.manufacturingJobs,[]);
});
test('no webhook secret or weak webhook secret fails closed',()=>{
 assert.throws(()=>authenticateOfflineOrderWebhook({...wire(),webhookSecret:undefined}),/WEBHOOK_SECRET_REQUIRED/);
 assert.throws(()=>authenticateOfflineOrderWebhook({...wire(),webhookSecret:Buffer.alloc(8)}),/WEBHOOK_SECRET_REQUIRED/);
});
test('HMAC mismatch and byte-level body tamper are rejected before parsing',()=>{
 const input=wire();input.rawBody=Buffer.from(input.rawBody);input.rawBody[5]^=1;
 assert.throws(()=>authenticateOfflineOrderWebhook(input),/WEBHOOK_HMAC_INVALID/);
 assert.throws(()=>authenticateOfflineOrderWebhook({...wire(),headers:{...wire().headers,'x-shopify-hmac-sha256':'A'.repeat(44)}}),/WEBHOOK_HMAC_FORMAT|WEBHOOK_HMAC_INVALID/);
});
test('cross-tenant, wrong topic, invalid event UUID, extra and duplicate-case headers reject',()=>{
 for(const change of [
  {'x-shopify-shop-domain':'other.myshopify.com'},
  {'x-shopify-topic':'orders/paid'},
  {'x-shopify-webhook-id':'not-uuid'},
  {'X-Shopify-Topic':'orders/create'},
  {'x-shopify-extra':'spoof'},
 ])assert.throws(()=>auth(body(),change));
});
test('webhook requires bounded raw bytes, rejects invalid UTF-8',()=>{
 assert.throws(()=>authenticateOfflineOrderWebhook(wire(Buffer.alloc(0))),/WEBHOOK_BODY_BOUNDS/);
 assert.throws(()=>authenticateOfflineOrderWebhook(wire(Buffer.alloc(512*1024+1))),/WEBHOOK_BODY_BOUNDS/);
 assert.throws(()=>auth(Buffer.from([0xff,0xfe])),/WEBHOOK_JSON_INVALID/);
});
test('valid-HMAC duplicate JSON keys reject even when JSON.parse would accept',()=>{
 const raw=JSON.stringify(body()).replace('"financial_status":"paid"','"financial_status":"pending","financial_status":"paid"');
 assert.throws(()=>auth(raw),/DUPLICATE_JSON_KEY/);
 const nested=JSON.stringify(body()).replace('"quantity":2','"quantity":1,"quantity":2');
 assert.throws(()=>auth(nested),/DUPLICATE_JSON_KEY/);
});
test('post-auth mutation cannot alter trusted order or line properties',()=>{
 const verified=auth();
 assert.throws(()=>{verified.order.customer.id=42;},TypeError);
 assert.throws(()=>{verified.order.line_items[0].properties[0].value='evil';},TypeError);
});
test('forged verifiedWebhook object cannot skip authentication',async()=>{
 const real=auth();await fails(reconcile({...real}), 'RECONCILIATION_CONFIGURATION');
 await fails(reconcile({...real,authenticatedFixture:true}), 'RECONCILIATION_CONFIGURATION');
});
test('order GID/numeric ID mismatch and missing customer reject',async()=>{
 for(const mutate of [x=>x.id++,x=>x.admin_graphql_api_id='gid://shopify/Order/9',x=>delete x.customer,
  x=>x.customer.id='123',x=>x.line_items=[]]){const x=body();mutate(x);await fails(reconcile(auth(x)),'ORDER_SHAPE');}
});
test('wrong product/variant, zero or negative quantity, repeated line id reject',async()=>{
 for(const mutate of [x=>x.line_items[0].product_id=9,x=>x.line_items[0].variant_id=9,
  x=>x.line_items[0].quantity=0,x=>x.line_items[0].quantity=-1,
  x=>x.line_items.push({...x.line_items[0]})]){
  const x=body();mutate(x);await assert.rejects(reconcile(auth(x)));
 }
});
test('metadata HMAC tamper, missing key, extra key and duplicated property reject',async()=>{
 for(const mutate of [p=>p[0].value='TJ-'+'B'.repeat(24),p=>p.pop(),
  p=>p.push({name:'_TJ Admin',value:'1'}),p=>p.push({...p[0]}),
  p=>p.find(x=>x.name==='_TJ Design Revision').value='4']){
  const x=body();mutate(x.line_items[0].properties);await assert.rejects(reconcile(auth(x)));
 }
});
test('cross-customer identity, stale revision, wrong tenant and wrong digest reject trusted lookup',async()=>{
 for(const fields of [{ownerSubject:'gid://shopify/Customer/1'},{revision:2},
  {shop:'other.myshopify.com'},{compositionSha256:'c'.repeat(64)},{status:'SUPERSEDED'},
  {variantGid:'gid://shopify/ProductVariant/999'}]){
  await fails(reconcile(auth(),{lookupDesign:async()=>({...record(),...fields})}),'DESIGN_RECORD_MISMATCH');
 }
});
test('missing server-side lookup, bad secret, missing atomic replay ledger reject',async()=>{
 await fails(reconcile(auth(),{lookupDesign:undefined}),'RECONCILIATION_CONFIGURATION');
 await fails(reconcile(auth(),{claimOnce:undefined}),'RECONCILIATION_CONFIGURATION');
 await fails(reconcile(auth(),{metadataSecret:Buffer.alloc(3)}),'RECONCILIATION_CONFIGURATION');
});
test('design lookup failures and ledger outage fail closed without manufacturing',async()=>{
 await fails(reconcile(auth(),{lookupDesign:async()=>{throw Error('offline');}}),'DESIGN_LOOKUP_FAILED');
 await fails(reconcile(auth(),{claimOnce:async()=>{throw Error('offline');}}),'REPLAY_LEDGER_UNAVAILABLE');
});
test('replay ledger acquired then duplicate for same event and payload',async()=>{
 const claimOnce=ledger(),verifiedWebhook=auth();
 const first=await reconcile(verifiedWebhook,{claimOnce});
 const second=await reconcile(verifiedWebhook,{claimOnce});
 assert.equal(first.idempotency,'acquired');assert.equal(second.idempotency,'duplicate');
 assert.equal(second.productionApproved,false);
});
test('same webhook ID with altered valid-HMAC body is a replay conflict',async()=>{
 const claimOnce=ledger();await reconcile(auth(),{claimOnce});
 const x=body();x.financial_status='refunded';
 await fails(reconcile(auth(x),{claimOnce}),'WEBHOOK_REPLAY_CONFLICT');
});
test('replay store returning malformed status rejects',async()=>{
 await fails(reconcile(auth(),{claimOnce:async()=>true}),'REPLAY_LEDGER_INVALID');
});
test('mixed ordinary and customized lines only reconcile signed customized lines',async()=>{
 const x=body();x.line_items.unshift({id:8888888,product_id:99,variant_id:100,quantity:1,properties:[]});
 const out=await reconcile(auth(x));assert.equal(out.matchedLines.length,1);
});
test('partial _TJ line, duplicate design reference, missing custom lines reject',async()=>{
 const partial=body();partial.line_items[0].properties=[{name:'_TJ Design Reference',value:reference}];
 await fails(reconcile(auth(partial)),'ORDER_METADATA_SHAPE');
 const duplicated=body();duplicated.line_items.push({...duplicated.line_items[0],id:77777777});
 await fails(reconcile(auth(duplicated)),'ORDER_DESIGN_IDENTITY');
 const empty=body();empty.line_items[0].properties=[];
 await fails(reconcile(auth(empty)),'NO_CUSTOM_DESIGN_LINES');
});
test('untrusted customer claims cannot substitute missing authenticated order customer',async()=>{
 const x=body();delete x.customer;x.ownerSubject=record().ownerSubject;
 await fails(reconcile(auth(x)),'ORDER_SHAPE');
});
test('simulated atomic ledger concurrent same event only one acquired',async()=>{
 const claimOnce=ledger(),verifiedWebhook=auth();
 const results=await Promise.all(Array.from({length:12},()=>reconcile(verifiedWebhook,{claimOnce})));
 assert.equal(results.filter(r=>r.idempotency==='acquired').length,1);
 assert.equal(results.filter(r=>r.idempotency==='duplicate').length,11);
});
