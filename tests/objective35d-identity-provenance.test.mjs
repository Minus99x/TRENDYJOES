import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolveTrustedPrincipal} from '../src/customer-identity-contract.mjs';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {createStaticPreviewState,updateStaticPreview,reviewStaticPreview} from '../src/static-preview-contract.mjs';

// Entirely synthetic offline verifier fixtures: no Shopify, accounts or secrets.
const now=1_800_000_000_000;
const claims=()=>({iss:'https://identity.example.test/verified',aud:'tj-customer-app',shop:'gucgmp-bc.myshopify.com',
 sub:'gid://shopify/Customer/123456',kind:'customer',sid:'session_0123456789abc',
 jti:'token_0123456789abcdef',iat:now-1000,nbf:now-1000,exp:now+60_000});
const bearer='Bearer '+'x'.repeat(32);
const verify=payload=>resolveTrustedPrincipal({authorizationHeader:bearer,verifyBearer:async()=>payload,
 expectedShop:claims().shop,expectedIssuer:claims().iss,expectedAudience:claims().aud,now});
const required=['iss','aud','shop','sub','kind','sid','jti','iat','nbf','exp'];
for(const field of required){
 test(`35D inherited ${field} cannot establish a trusted principal`,async()=>{
  const input=claims();const inherited=Object.create({[field]:input[field]});
  Object.assign(inherited,input);delete inherited[field];
  await assert.rejects(verify(inherited),/UNTRUSTED_PRINCIPAL/);
 });
}
test('35D inherited alternate subject cannot impersonate a customer',async()=>{
 const input=claims(),inherited=Object.create({sub:'gid://shopify/Customer/999999'});
 Object.assign(inherited,input);delete inherited.sub;
 await assert.rejects(verify(inherited),/UNTRUSTED_PRINCIPAL/);
});
for(const field of ['sub','exp','shop']){
 test(`35D ${field} getter exception never leaks private verifier text`,async()=>{
  const input=claims();Object.defineProperty(input,field,{enumerable:true,get(){throw Error('PRIVATE_VERIFIER_SECRET_123');}});
  await assert.rejects(verify(input),error=>error?.message==='UNTRUSTED_PRINCIPAL' &&
   !String(error?.message).includes('PRIVATE_VERIFIER_SECRET_123'));
 });
}
test('35D accessor returning plausible identity still rejects',async()=>{
 const input=claims();Object.defineProperty(input,'sub',{enumerable:true,get(){return 'gid://shopify/Customer/123456';}});
 await assert.rejects(verify(input),/UNTRUSTED_PRINCIPAL/);
});
test('35D throwing proxy descriptor rejects with a neutral error',async()=>{
 const input=new Proxy(claims(),{getOwnPropertyDescriptor(){throw Error('PRIVATE_PROXY_SECRET');}});
 await assert.rejects(verify(input),error=>error?.message==='UNTRUSTED_PRINCIPAL');
});
test('35D forged class-instance verifier result rejects instead of inheriting identity',async()=>{
 class Claims{constructor(){Object.assign(this,claims());}}
 await assert.rejects(verify(new Claims()),/UNTRUSTED_PRINCIPAL/);
});
test('35D plain own-data customer claims produce a frozen minimal non-commerce principal',async()=>{
 const result=await verify(claims());
 assert.equal(result.subject,claims().sub);assert.equal(result.checkoutEnabled,false);
 assert.equal(result.productionReady,false);assert.equal(Object.isFrozen(result),true);
 for(const key of ['token','authorizationHeader','jti','ownerToken','signature'])assert.equal(Object.hasOwn(result,key),false);
});
test('35D null-prototype and frozen own-data claims remain valid',async()=>{
 const input=Object.assign(Object.create(null),claims());
 assert.equal((await verify(input)).subject,claims().sub);
 assert.equal((await verify(Object.freeze(claims()))).kind,'customer');
});
test('35D guest verifier remains supported with exact own-data claims',async()=>{
 const input={...claims(),kind:'guest',sub:'guest:'+'a'.repeat(24)};
 const result=await verify(input);assert.equal(result.kind,'guest');assert.equal(result.subject,input.sub);
});
test('35D verifier rejection is sanitized independently of malformed claims',async()=>{
 await assert.rejects(resolveTrustedPrincipal({authorizationHeader:bearer,
  verifyBearer:async()=>{throw Error('PRIVATE_BAD_SIGNATURE');},expectedShop:claims().shop,
  expectedIssuer:claims().iss,expectedAudience:claims().aud,now}),error=>error?.message==='TOKEN_VERIFICATION_FAILED');
});
test('35D all eight merchandise concepts retain offline 2D/3D design review',()=>{
 for(const product of PRODUCT_MANIFESTS){
  let state=createStaticPreviewState('?product='+product.id);
  state=updateStaticPreview(state,{type:'ADD_TEXT',value:'TEST LETTERING'});
  state=updateStaticPreview(state,{type:'SET_MODE',mode:'2d'});
  assert.equal(reviewStaticPreview(state).layerCount,1,product.id);
  if(product.id==='concept-sneaker'){
   assert.throws(()=>updateStaticPreview(state,{type:'SET_MODE',mode:'3d'}),/INVALID_MODE/);
  }else{
   state=updateStaticPreview(state,{type:'SET_MODE',mode:'3d'});
   assert.equal(reviewStaticPreview(state).layerCount,1,product.id);
  }
 }
});
test('35D trusted principal adapter has no network, storage, cart or checkout operations',async()=>{
 const code=await readFile(new URL('../src/customer-identity-contract.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(code,/\bfetch\s*\(|\blocalStorage\b|\bsessionStorage\b|\bnew\s+(?:WebSocket|XMLHttpRequest)\b|\/cart\/add|checkoutUrl/);
});
test('35D object-coerced subject cannot become a trusted customer identity',async()=>{
 const input={...claims(),sub:{toString(){return 'gid://shopify/Customer/999999';}}};
 await assert.rejects(verify(input),/UNTRUSTED_PRINCIPAL/);
});
test('35D hostile subject coercion cannot expose a private exception',async()=>{
 const input={...claims(),sub:{toString(){throw Error('PRIVATE_CLAIM_SECRET_456');}}};
 await assert.rejects(verify(input),error=>error?.message==='UNTRUSTED_PRINCIPAL');
});
test('35D boxed string subject is not an identity claim',async()=>{
 await assert.rejects(verify({...claims(),sub:new String('gid://shopify/Customer/123456')}),/UNTRUSTED_PRINCIPAL/);
});
