/** Offline-only, one-use preview receipt for an authenticated local design owner.
 * Possessing this receipt never authorizes checkout, price, production or fulfillment.
 * Replace local owner capabilities and in-memory replay locks with authenticated
 * customer sessions and durable atomic replay storage in any future hosted app.
 */
import {createHmac,randomBytes,timingSafeEqual} from 'node:crypto';
import {prepareStagingBinding} from './shopify-intents.mjs';

const reject=(code,status=400)=>Object.assign(new Error(code),{code,status});
const gidProduct=/^gid:\/\/shopify\/Product\/[1-9]\d*$/;
const gidVariant=/^gid:\/\/shopify\/ProductVariant\/[1-9]\d*$/;
const referencePattern=/^TJ-[A-F0-9]{24}$/;
const hex64=/^[a-f0-9]{64}$/;
const noncePattern=/^[a-f0-9]{48}$/;
const isTime=v=>Number.isSafeInteger(v)&&v>=0;
const revisionOk=v=>Number.isSafeInteger(v)&&v>0;
const exactKeys=(item,keys)=>item&&typeof item==='object'&&!Array.isArray(item)&&Object.keys(item).length===keys.length&&keys.every(k=>Object.hasOwn(item,k));
const payloadKeys=['version','purpose','nonce','issuedAt','expiresAt','reference','revision','productGid','variantGid','compositionSha256'];
function validPayload(p){
 return exactKeys(p,payloadKeys)&&p.version===1&&p.purpose==='PREVIEW_ONLY'&&noncePattern.test(p.nonce)&&
 isTime(p.issuedAt)&&isTime(p.expiresAt)&&p.expiresAt>p.issuedAt&&p.expiresAt-p.issuedAt<=15*60_000&&
 referencePattern.test(p.reference)&&revisionOk(p.revision)&&gidProduct.test(p.productGid)&&gidVariant.test(p.variantGid)&&hex64.test(p.compositionSha256);
}
function secretValid(secret){return Buffer.isBuffer(secret)&&secret.length>=32;}
function sameDigest(a,b){return hex64.test(a||'')&&hex64.test(b||'')&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));}

export class LocalPreviewCapabilityAuthority {
 constructor({secret=randomBytes(32),clock=()=>Date.now(),ttlMs=5*60_000}={}){
  if(!secretValid(secret))throw reject('CAPABILITY_SECRET_REQUIRED');
  if(typeof clock!=='function'||!Number.isSafeInteger(ttlMs)||ttlMs<1000||ttlMs>15*60_000)throw reject('INVALID_CAPABILITY_CONFIG');
  this.secret=Buffer.from(secret);this.clock=clock;this.ttlMs=ttlMs;
  // Process-local replay protection: deliberately NOT an eligible production backend.
  this.used=new Map();this.inFlight=new Set();
 }
 now(){const t=this.clock();if(!isTime(t))throw reject('INVALID_CLOCK');return t;}
 mac(content){return createHmac('sha256',this.secret).update(content).digest();}
 /** Only the authenticated owner may create a non-purchasable receipt. */
 async issue({store,registry,reference,ownerToken,expectedRevision,productGid,variantGid}){
  const binding=await prepareStagingBinding({store,registry,reference,ownerToken,expectedRevision,productGid,variantGid});
  if(binding.checkoutEnabled!==false||binding.productionReady!==false||binding.cartLine!==null)throw reject('PREVIEW_GATE_VIOLATION',409);
  const issuedAt=this.now();const payload={version:1,purpose:'PREVIEW_ONLY',nonce:randomBytes(24).toString('hex'),issuedAt,
   expiresAt:issuedAt+this.ttlMs,reference:binding.reference,revision:binding.revision,productGid:binding.productGid,
   variantGid:binding.variantGid,compositionSha256:binding.compositionSha256};
  const encoded=Buffer.from(JSON.stringify(payload)).toString('base64url');
  const token=`tjpreview1.${encoded}.${this.mac(`tjpreview1.${encoded}`).toString('base64url')}`;
  return {schema:'TJ-PREVIEW-CAPABILITY-1',token,expiresAt:payload.expiresAt,reference:payload.reference,
   previewOnly:true,checkoutEnabled:false,productionReady:false,cartLine:null,shopifyOrderId:null};
 }
 /** Authenticate the actual owner again, compare exact current server-side design,
  * lock the nonce through async checks, and burn it ONLY after successful validation.
  */
 async consume({store,registry,token,reference,ownerToken,expectedRevision,productGid,variantGid}){
  if(typeof token!=='string'||token.length>1800)throw reject('INVALID_PREVIEW_CAPABILITY',403);
  const parts=token.split('.');
  if(parts.length!==3||parts[0]!=='tjpreview1'||!/^[A-Za-z0-9_-]+$/.test(parts[1])||!/^[A-Za-z0-9_-]{43}$/.test(parts[2]))throw reject('INVALID_PREVIEW_CAPABILITY',403);
  const signed=`tjpreview1.${parts[1]}`;
  const actual=Buffer.from(parts[2],'base64url');
  if(actual.length!==32||!timingSafeEqual(actual,this.mac(signed)))throw reject('INVALID_PREVIEW_CAPABILITY',403);
  let payload;try{payload=JSON.parse(Buffer.from(parts[1],'base64url').toString('utf8'));}catch{throw reject('INVALID_PREVIEW_CAPABILITY',403);}
  if(!validPayload(payload))throw reject('INVALID_PREVIEW_CAPABILITY',403);
  const now=this.now();
  if(now<payload.issuedAt||now>=payload.expiresAt)throw reject('EXPIRED_PREVIEW_CAPABILITY',410);
  if(payload.reference!==reference||payload.revision!==expectedRevision||payload.productGid!==productGid||payload.variantGid!==variantGid)throw reject('PREVIEW_IDENTITY_MISMATCH',403);
  // Avoid unchecked memory growth; expired replay records can no longer be reused.
  for(const [nonce,expiry] of this.used){if(expiry<=now)this.used.delete(nonce);}
  if(this.used.has(payload.nonce)||this.inFlight.has(payload.nonce))throw reject('PREVIEW_REPLAY_BLOCKED',409);
  this.inFlight.add(payload.nonce);
  try{
   const live=await prepareStagingBinding({store,registry,reference,ownerToken,expectedRevision,productGid,variantGid});
   if(!sameDigest(live.compositionSha256,payload.compositionSha256))throw reject('PREVIEW_CONTENT_CHANGED',409);
   this.used.set(payload.nonce,payload.expiresAt);
   return {schema:'TJ-PREVIEW-VERIFIED-1',reference,revision:payload.revision,productGid,variantGid,
    compositionSha256:payload.compositionSha256,previewValid:true,previewOnly:true,
    checkoutEnabled:false,productionReady:false,cartLine:null,shopifyOrderId:null};
  }finally{this.inFlight.delete(payload.nonce);}
 }
}
