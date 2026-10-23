/** Objective 11: offline, NON-AUTHORIZING versioned cart-metadata envelope.
 * This is a contract for a future trusted backend, not a Shopify checkout feature.
 * resolvePrincipal MUST perform real bearer/session verification; lookupDesign MUST
 * read server-owned current records; consumeNonce MUST be atomic and durable.
 * All adapters in this repository are synthetic/offline only.
 */
import {createHash,createHmac,randomBytes,timingSafeEqual} from 'node:crypto';

const fail=code=>{throw Object.assign(new Error(code),{code,status:403});};
const obj=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const shopRe=/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/;
const gid=kind=>new RegExp(`^gid://shopify/${kind}/[1-9][0-9]*$`);
const ownerRe=/^(?:gid:\/\/shopify\/Customer\/[1-9][0-9]*|guest:[A-Za-z0-9_-]{22,64})$/;
const refRe=/^TJ-[A-F0-9]{24}$/;
const hex=/^[a-f0-9]{64}$/;
const kidRe=/^[A-Za-z0-9_-]{3,48}$/;
const b64Re=/^[A-Za-z0-9_-]+$/;
const time=v=>Number.isSafeInteger(v)&&v>=0;
const fields=['version','purpose','kid','shop','ownerTag','sessionTag','reference','revision','productGid','variantGid','compositionSha256','nonce','issuedAt','expiresAt'];
const bindingFields=['reference','revision','productGid','variantGid','compositionSha256'];
const protocol='TJ-OFFLINE-CART-2';
const purpose='offline-cart-binding-only';
const prefix='TJ2';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const tag=(secret,label,value)=>createHmac('sha256',secret).update(`TJ-CART-V2:${label}\0${value}`).digest('hex');
const equalHex=(a,b)=>hex.test(a||'')&&hex.test(b||'')&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
function bindingOk(b){return obj(b)&&Object.keys(b).length===bindingFields.length&&
 refRe.test(b.reference)&&Number.isSafeInteger(b.revision)&&b.revision>0&&
 gid('Product').test(b.productGid)&&gid('ProductVariant').test(b.variantGid)&&hex.test(b.compositionSha256);}
function principalOk(p,now){return obj(p)&&p.schema==='TJ-TRUSTED-PRINCIPAL-1'&&shopRe.test(p.shop)&&
 ownerRe.test(p.subject)&&((p.kind==='customer'&&gid('Customer').test(p.subject))||(p.kind==='guest'&&p.subject.startsWith('guest:')))&&
 typeof p.sessionId==='string'&&p.sessionId.length>=16&&p.sessionId.length<=160&&
 time(p.expiresAt)&&p.expiresAt>now&&p.checkoutEnabled===false&&p.productionReady===false;}
function recordOk(r,p,b){return obj(r)&&r.shop===p.shop&&r.ownerSubject===p.subject&&
 r.status==='CURRENT'&&bindingFields.every(k=>r[k]===b[k]);}
function encode(payload,secret){const data=Buffer.from(JSON.stringify(payload),'utf8').toString('base64url');
 const signed=`${prefix}.${data}`;const mac=createHmac('sha256',secret).update(`TJ-OFFLINE-CART-METADATA-V2\0${signed}`).digest('base64url');
 return `${signed}.${mac}`;}
function decode(token){
 if(typeof token!=='string'||token.length>4096)fail('METADATA_TOKEN_FORMAT');
 const parts=token.split('.');if(parts.length!==3||parts[0]!==prefix||
 !b64Re.test(parts[1]||'')||!b64Re.test(parts[2]||'')||parts[2].length!==43)fail('METADATA_TOKEN_FORMAT');
 const raw=Buffer.from(parts[1],'base64url');
 if(raw.length<30||raw.length>2500||raw.toString('base64url')!==parts[1])fail('METADATA_CANONICAL');
 let payload;try{payload=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));}catch{fail('METADATA_JSON_INVALID');}
 if(!obj(payload)||Object.keys(payload).length!==fields.length||fields.some(k=>!Object.hasOwn(payload,k))||
 JSON.stringify(payload)!==raw.toString('utf8'))fail('METADATA_CANONICAL');
 if(payload.version!==2||payload.purpose!==purpose||!kidRe.test(payload.kid)||!shopRe.test(payload.shop)||
 !hex.test(payload.ownerTag)||!hex.test(payload.sessionTag)||!refRe.test(payload.reference)||
 !Number.isSafeInteger(payload.revision)||payload.revision<1||!gid('Product').test(payload.productGid)||
 !gid('ProductVariant').test(payload.variantGid)||!hex.test(payload.compositionSha256)||
 typeof payload.nonce!=='string'||!/^[A-Za-z0-9_-]{32}$/.test(payload.nonce)||
 !time(payload.issuedAt)||!time(payload.expiresAt)||payload.expiresAt<=payload.issuedAt||
 payload.expiresAt-payload.issuedAt>15*60_000)fail('METADATA_CLAIMS_INVALID');
 return {payload,signed:`${parts[0]}.${parts[1]}`,signature:parts[2]};
}
/** Key descriptors are server-private. ACTIVE signs+verifies; VERIFY_ONLY verifies;
 * REVOKED neither signs nor verifies. notBefore/verifyUntil bound key lifetime.
 * Secret Buffers are copied on initialization to prevent caller mutation.
 */
export function createOfflineVersionedMetadataAuthority({keys,activeKeyId=null,resolvePrincipal,lookupDesign,consumeNonce,
 clock=Date.now,nonceSource=()=>randomBytes(24).toString('base64url'),maxTtlMs=300_000}={}){
 if(!Array.isArray(keys)||keys.length<1||keys.length>12||typeof resolvePrincipal!=='function'||
 typeof lookupDesign!=='function'||typeof consumeNonce!=='function'||typeof clock!=='function'||
 typeof nonceSource!=='function'||!Number.isSafeInteger(maxTtlMs)||maxTtlMs<1||maxTtlMs>15*60_000)fail('METADATA_CONFIGURATION');
 const preparedReceipts=new WeakSet();
 const ring=new Map();
 for(const k of keys){
  if(!obj(k)||!kidRe.test(k.id)||ring.has(k.id)||!Buffer.isBuffer(k.secret)||k.secret.length<32||
   !['ACTIVE','VERIFY_ONLY','REVOKED'].includes(k.status)||!time(k.notBefore)||!time(k.verifyUntil)||k.verifyUntil<=k.notBefore)fail('METADATA_KEY_CONFIGURATION');
  ring.set(k.id,{secret:Buffer.from(k.secret),status:k.status,notBefore:k.notBefore,verifyUntil:k.verifyUntil});
 }
 if(activeKeyId!==null&&(!ring.has(activeKeyId)||ring.get(activeKeyId).status!=='ACTIVE'))fail('METADATA_ACTIVE_KEY');
 const now=()=>{const n=clock();if(!time(n))fail('METADATA_CLOCK_INVALID');return n;};
 async function principal(authContext,t){
  let p;try{p=await resolvePrincipal({authContext});}catch{fail('METADATA_IDENTITY_UNAVAILABLE');}
  if(!principalOk(p,t))fail('METADATA_IDENTITY_INVALID');return p;
 }
 async function current(p,b){
  let r;try{r=await lookupDesign({shop:p.shop,reference:b.reference});}catch{fail('METADATA_DESIGN_UNAVAILABLE');}
  if(!recordOk(r,p,b))fail('METADATA_DESIGN_STALE');
 }
 async function issue({authContext,binding,ttlMs=maxTtlMs}={}){
  const t=now();if(!bindingOk(binding))fail('METADATA_BINDING_INVALID');
  if(!Number.isSafeInteger(ttlMs)||ttlMs<1||ttlMs>maxTtlMs)fail('METADATA_TTL_INVALID');
  if(activeKeyId===null)fail('METADATA_SIGNING_DISABLED');
  const k=ring.get(activeKeyId);if(k.status!=='ACTIVE'||t<k.notBefore||t>=k.verifyUntil)fail('METADATA_SIGNING_DISABLED');
  const p=await principal(authContext,t);await current(p,binding);
  const expiresAt=Math.min(t+ttlMs,p.expiresAt,k.verifyUntil);
  if(expiresAt<=t)fail('METADATA_TTL_INVALID');
  let nonce;try{nonce=nonceSource();}catch{fail('METADATA_NONCE_UNAVAILABLE');}
  if(typeof nonce!=='string'||!/^[A-Za-z0-9_-]{32}$/.test(nonce))fail('METADATA_NONCE_INVALID');
  const payload={version:2,purpose,kid:activeKeyId,shop:p.shop,
   ownerTag:tag(k.secret,'owner',`${p.shop}|${p.subject}`),
   sessionTag:tag(k.secret,'session',`${p.shop}|${p.subject}|${p.sessionId}`),
   ...binding,nonce,issuedAt:t,expiresAt};
  return Object.freeze({schema:'TJ-OFFLINE-CART-METADATA-2',properties:Object.freeze({
   '_TJ Protocol':protocol,'_TJ Cart Receipt':encode(payload,k.secret)}),
   expiresAt,checkoutEnabled:false,productionApproved:false,paymentVerified:false,fulfillmentAuthorized:false});
 }
 async function checkedReceipt({properties,authContext,expectedBinding,expectedIdentity}={}){
  const t=now();if(!bindingOk(expectedBinding))fail('METADATA_EXPECTED_BINDING');
  if(!obj(properties)||Object.keys(properties).length!==2||properties['_TJ Protocol']!==protocol||
   typeof properties['_TJ Cart Receipt']!=='string')fail('METADATA_PROPERTIES_INVALID');
  const token=properties['_TJ Cart Receipt'];const {payload,signed,signature}=decode(token);
  const k=ring.get(payload.kid);if(!k||k.status==='REVOKED'||t<k.notBefore||t>=k.verifyUntil||
   payload.issuedAt<k.notBefore||payload.expiresAt>k.verifyUntil)fail('METADATA_KEY_UNTRUSTED');
  const mac=createHmac('sha256',k.secret).update(`TJ-OFFLINE-CART-METADATA-V2\0${signed}`).digest();
  const provided=Buffer.from(signature,'base64url');
  if(provided.length!==mac.length||provided.toString('base64url')!==signature||!timingSafeEqual(mac,provided))fail('METADATA_SIGNATURE_INVALID');
  if(payload.issuedAt>t||payload.expiresAt<=t)fail('METADATA_EXPIRED_OR_FUTURE');
  const p=await principal(authContext,t);
  // Optional trusted checkout seam: compare independently authenticated session
  // identity, never a client-provided identity or receipt claim.
  if(expectedIdentity!==undefined&&(!obj(expectedIdentity)||
   Object.keys(expectedIdentity).length!==3||expectedIdentity.shop!==p.shop||
   expectedIdentity.subject!==p.subject||expectedIdentity.sessionId!==p.sessionId))fail('METADATA_CHECKOUT_IDENTITY_MISMATCH');
  if(payload.shop!==p.shop||!equalHex(payload.ownerTag,tag(k.secret,'owner',`${p.shop}|${p.subject}`))||
   !equalHex(payload.sessionTag,tag(k.secret,'session',`${p.shop}|${p.subject}|${p.sessionId}`))||
   bindingFields.some(f=>payload[f]!==expectedBinding[f])||payload.expiresAt>p.expiresAt)fail('METADATA_CONTEXT_MISMATCH');
  await current(p,expectedBinding);
  const nonceKey=sha(Buffer.from(`TJ-NONCE-V2\0${payload.shop}\0${payload.kid}\0${payload.nonce}`));
  return {p,payload,nonceKey,receiptSha256:sha(token),
   expectedDesign:{shop:p.shop,ownerSubject:p.subject,...expectedBinding,status:'CURRENT'}};
 }
 async function verify(args={}){
  const {p,payload,nonceKey,receiptSha256,expectedDesign}=await checkedReceipt(args);
  let result;try{result=await consumeNonce({nonceKey,receiptSha256,expiresAt:payload.expiresAt,expectedDesign});}
  catch{fail('METADATA_NONCE_STORE_UNAVAILABLE');}
  if(result!=='acquired')fail(result==='duplicate'||result==='conflict'?'METADATA_REPLAY':'METADATA_NONCE_STORE_INVALID');
  return Object.freeze({schema:'TJ-OFFLINE-VERIFIED-CART-METADATA-2',shop:p.shop,
   reference:payload.reference,revision:payload.revision,productGid:payload.productGid,
   variantGid:payload.variantGid,compositionSha256:payload.compositionSha256,
   expiresAt:payload.expiresAt,integrityVerified:true,nonceConsumed:true,
   checkoutEnabled:false,paymentVerified:false,productionApproved:false,fulfillmentAuthorized:false});
 }
 /** Non-consuming verification for a trusted offline transaction adapter ONLY.
  * This proof must be committed atomically with lineage under the same ledger lock.
  * Never expose proof, validator or adapter directly to browser/cart clients.
  */
 async function prepareForAtomicLineage(args={}){
  const {p,payload,nonceKey,receiptSha256,expectedDesign}=await checkedReceipt(args);
  const proof=Object.freeze({schema:'TJ-OFFLINE-PREPARED-CART-2',shop:p.shop,
   ownerSubject:p.subject,sessionHash:sha(`TJ-LINEAGE-SESSION\0${p.shop}\0${p.subject}\0${p.sessionId}`),
   ...Object.fromEntries(bindingFields.map(f=>[f,payload[f]])),
   nonceKey,receiptSha256,expiresAt:payload.expiresAt,
   expectedDesign:Object.freeze({...expectedDesign}),checkoutEnabled:false,
   paymentVerified:false,productionApproved:false,fulfillmentAuthorized:false});
  preparedReceipts.add(proof);return proof;
 }
 function assertPreparedForAtomicLineage(proof){
  if(!obj(proof)||!preparedReceipts.has(proof)||proof.schema!=='TJ-OFFLINE-PREPARED-CART-2'||
   now()>=proof.expiresAt)fail('METADATA_PREPARED_UNTRUSTED');
  return proof;
 }
 return Object.freeze({issue,verify,prepareForAtomicLineage,assertPreparedForAtomicLineage});
}
