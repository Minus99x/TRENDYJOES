/**
 * Objectives 23–30 — OFFLINE single-host private revision and artwork fixture.
 * A local transaction contains immutable revision snapshots, exact PNG bytes,
 * revocations, and consumed operation IDs. Not hosted authentication, encrypted
 * hosting, multi-host locking, Shopify access, or manufacturing authorization.
 * HMAC protects integrity; an INDEPENDENT injected anchor detects rollback.
 */
import {createHash,createHmac,randomBytes,timingSafeEqual,verify as verifySignature,createCipheriv,createDecipheriv} from 'node:crypto';
import {constants as C} from 'node:fs';
import {mkdir,open,lstat,rename,rm,link} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {AsyncLocalStorage} from 'node:async_hooks';
import {join,resolve} from 'node:path';
import {computeArtworkDesignSha256,inspectVerifiedPng} from './manufacturing-artwork-evidence.mjs';

const fail=code=>{throw Object.assign(new Error(code),{code});};
const hex=/^[a-f0-9]{64}$/;
const safeId=/^[A-Za-z0-9_-]{8,120}$/;
const text=x=>typeof x==='string'&&x.length>=1&&x.length<=200&&x.trim()===x;
const snapshotFields=['schema','shop','productGid','variantGid','manifestId','ownerId','designId','revision','designSha256','status','design'];
const assetFields=['storageKey','artworkId','layerId','bytes'];
const recoverySchema='TJ-OFFLINE-PRIVATE-REGISTRY-RECOVERY-1';
const recoveryFields=['schema','registryId','authorizationId','issuedAt','expiresAt','expectedAnchor','targetAnchor','reason'];
const recoveryId=/^[A-Za-z0-9_-]{12,80}$/;
const mutationSchema='TJ-OFFLINE-PRIVATE-REGISTRY-MUTATION-1';
const mutationFields=['schema','registryId','action','opId','shop','ownerId','requestSha256','issuedAt','expiresAt'];
const mutationActions=['commit-revision','revoke-artwork','revoke-revision'];
const adminSchema='TJ-OFFLINE-PRIVATE-REGISTRY-ADMIN-1';
const adminActions=['migrate-plaintext','rotate-key'];
const adminFields=['schema','registryId','action','opId','operatorId','requestSha256','issuedAt','expiresAt'];
const backupSchema='TJ-OFFLINE-PRIVATE-REGISTRY-BACKUP-1';
const backupFields=['schema','registryId','anchor','sha256','byteLength','keyIds','revisionCount','assetCount','revocationCount','opIdCount','stateBase64'];
const backupActions=['export-backup','restore-backup','export-audit'];
const auditSchema='TJ-OFFLINE-PRIVATE-REGISTRY-AUDIT-SNAPSHOT-1';
const zeroMac='0'.repeat(64);
const encryptionSchema='TJ-OFFLINE-ARTWORK-AES256GCM-1';
const keyIdPattern=/^[A-Za-z0-9_-]{8,80}$/;
const authorizedArtworkFields=[...identityFieldsForAccess(),'revision','storageKey','artworkId','layerId'];
function identityFieldsForAccess(){return ['shop','productGid','variantGid','ownerId','designId'];}
function validateAuthorizedArtworkRequest(q){
 if(!exact(q,authorizedArtworkFields)||!/^[-a-z0-9]+\.myshopify\.com$/.test(q.shop||'')||
  !/^gid:\/\/shopify\/Product\/[1-9]\d*$/.test(q.productGid||'')||
  !/^gid:\/\/shopify\/ProductVariant\/[1-9]\d*$/.test(q.variantGid||'')||
  !text(q.ownerId)||!text(q.designId)||!safeId.test(q.storageKey||'')||
  !text(q.artworkId)||!text(q.layerId)||!Number.isSafeInteger(q.revision)||q.revision<1)
  fail('REGISTRY_ACCESS_DENIED');
}
function verifyPrincipalShape(principal,now){
 if(!exact(principal,['shop','ownerId','issuedAt','expiresAt'])||
  !/^[-a-z0-9]+\.myshopify\.com$/.test(principal.shop||'')||!text(principal.ownerId)||
  !Number.isSafeInteger(principal.issuedAt)||!Number.isSafeInteger(principal.expiresAt)||
  principal.issuedAt>now||principal.expiresAt<=now||
  principal.expiresAt<=principal.issuedAt||principal.expiresAt-principal.issuedAt>900_000)
  fail('REGISTRY_ACCESS_DENIED');
}

function encryptionConfig(config){
 if(config===undefined)return null;
 if(!isObj(config)||!exact(config,['activeKeyId','resolveKey'])||
  !keyIdPattern.test(config.activeKeyId||'')||typeof config.resolveKey!=='function')fail('REGISTRY_ENCRYPTION_CONFIGURATION');
 return config;
}
function encryptedAsset(a){return Object.hasOwn(a,'encryption');}
function associatedData(a,keyId){
 return Buffer.from(`${encryptionSchema}\0${JSON.stringify({storageKey:a.storageKey,artworkId:a.artworkId,layerId:a.layerId,identity:a.identity,revision:a.revision,sha256:a.sha256,byteLength:a.byteLength,keyId})}`);
}
function decodeStrict(value){const b=Buffer.from(value,'base64');if(b.toString('base64')!==value)fail('REGISTRY_ENCRYPTION_INVALID');return b;}

function recoveryConfig(x){
 if(x===undefined)return null;
 if(!isObj(x)||!exact(x,['registryId','publicKey'])||!recoveryId.test(x.registryId||'')||
  x.publicKey?.type!=='public'||x.publicKey?.asymmetricKeyType!=='ed25519')fail('REGISTRY_RECOVERY_CONFIGURATION');
 return {registryId:x.registryId,publicKey:x.publicKey};
}
function verifyRecoveryPermit(p,cfg,now){
 if(!exact(p,[...recoveryFields,'signature'])||p.schema!==recoverySchema||p.registryId!==cfg.registryId||
  !recoveryId.test(p.authorizationId||'')||!Number.isSafeInteger(p.issuedAt)||
  !Number.isSafeInteger(p.expiresAt)||p.issuedAt>now||p.expiresAt<=now||
  p.expiresAt<=p.issuedAt||p.expiresAt-p.issuedAt>900_000||
  typeof p.reason!=='string'||p.reason.length<8||p.reason.length>200||
  p.reason!==p.reason.trim()||/[\x00-\x1f\x7f]/.test(p.reason)||
  typeof p.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(p.signature))
  fail('REGISTRY_RECOVERY_AUTH_INVALID');
 if(p.expectedAnchor!==null)validateAnchor(p.expectedAnchor);
 validateAnchor(p.targetAnchor);
 if(p.targetAnchor===null)fail('REGISTRY_RECOVERY_AUTH_INVALID');
 const payload=Object.fromEntries(recoveryFields.map(k=>[k,p[k]]));
 const sig=Buffer.from(p.signature,'base64url');
 if(sig.length!==64||sig.toString('base64url')!==p.signature||
  !verifySignature(null,Buffer.from(`${recoverySchema}\0${JSON.stringify(payload)}`),cfg.publicKey,sig))
  fail('REGISTRY_RECOVERY_SIGNATURE');
 return payload;
}

const isObj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,fields)=>isObj(x)&&Object.keys(x).sort().join('|')===fields.slice().sort().join('|');
const copy=x=>{try{return structuredClone(x);}catch{fail('REGISTRY_INPUT');}};
const sha=b=>createHash('sha256').update(b).digest('hex');
const identityFields=['shop','productGid','variantGid','ownerId','designId'];
const same=(a,b)=>identityFields.every(k=>a[k]===b[k]);
const key=x=>JSON.stringify(identityFields.map(k=>x[k]));
const fresh=()=>({schema:'TJ-OFFLINE-PRIVATE-REGISTRY-1',sequence:0,previousMac:zeroMac,revisions:[],assets:[],revocations:[],opIds:[],mac:zeroMac});
const MAX_STATE=4*1024*1024, MAX_ASSET=512*1024;
function validateRecord(r){
 if(!exact(r,snapshotFields)||r.schema!=='TJ-CURRENT-IMMUTABLE-DESIGN-1'||
  r.status!=='CURRENT_IMMUTABLE'||!/^[-a-z0-9]+\.myshopify\.com$/.test(r.shop||'')||
  !/^gid:\/\/shopify\/Product\/[1-9]\d*$/.test(r.productGid||'')||
  !/^gid:\/\/shopify\/ProductVariant\/[1-9]\d*$/.test(r.variantGid||'')||
  !text(r.manifestId)||!text(r.ownerId)||!text(r.designId)||
  !Number.isSafeInteger(r.revision)||r.revision<1||!hex.test(r.designSha256||'')||
  !isObj(r.design)||!Array.isArray(r.design.layers)||r.design.layers.length<1||r.design.layers.length>100)
  fail('REGISTRY_REVISION_INVALID');
 let digest;try{digest=computeArtworkDesignSha256(r.design);}catch{fail('REGISTRY_REVISION_INVALID');}
 if(digest!==r.designSha256)fail('REGISTRY_DIGEST_MISMATCH');
 const layerIds=new Set(),artworkIds=new Set();
 for(const l of r.design.layers){
  if(!isObj(l)||!text(l.id)||layerIds.has(l.id))fail('REGISTRY_REVISION_INVALID');
  layerIds.add(l.id);
  if(l.type==='artwork'){
   if(!text(l.artworkId)||artworkIds.has(l.artworkId))fail('REGISTRY_REVISION_INVALID');
   artworkIds.add(l.artworkId);
  }
 }
}
/** Deterministic byte-bound request digest for a trusted offline permit issuer.
 * The issuer must inspect identity and artwork independently before signing.
 * A digest alone never authorizes a mutation. No tokens or keys are serialized.
 */
export function computePrivateRegistryMutationDigest(action,request){
 if(!mutationActions.includes(action)||!isObj(request))fail('REGISTRY_MUTATION_REQUEST');
 let payload;
 if(action==='commit-revision'){
  if(!exact(request,['record','artworks','expectedRevision','opId']))fail('REGISTRY_MUTATION_REQUEST');
  const r=copy(request.record);validateRecord(r);
  if(!Array.isArray(request.artworks)||request.artworks.length<1||request.artworks.length>100||
   !(request.expectedRevision===null||(Number.isSafeInteger(request.expectedRevision)&&request.expectedRevision>=1)))fail('REGISTRY_MUTATION_REQUEST');
  const layers=r.design.layers.filter(l=>l.type==='artwork');
  if(layers.length!==request.artworks.length)fail('REGISTRY_MUTATION_REQUEST');
  const summaries=request.artworks.map(a=>{
   if(!exact(a,assetFields)||!safeId.test(a.storageKey||'')||!text(a.artworkId)||!text(a.layerId)||
    !(Buffer.isBuffer(a.bytes)||a.bytes instanceof Uint8Array)||a.bytes.length>MAX_ASSET||
    !layers.some(l=>l.id===a.layerId&&l.artworkId===a.artworkId))fail('REGISTRY_MUTATION_REQUEST');
   const bytes=Buffer.from(a.bytes);
   try{inspectVerifiedPng(bytes);}catch{fail('REGISTRY_MUTATION_REQUEST');}
   return {storageKey:a.storageKey,artworkId:a.artworkId,layerId:a.layerId,sha256:sha(bytes),byteLength:bytes.length};
  });
  if(new Set(summaries.map(a=>a.storageKey)).size!==summaries.length||
   new Set(summaries.map(a=>a.artworkId)).size!==summaries.length)fail('REGISTRY_MUTATION_REQUEST');
  payload={action,opId:request.opId,record:r,expectedRevision:request.expectedRevision,artworks:summaries};
 }else if(action==='revoke-artwork'){
  if(!exact(request,[...authorizedArtworkFields,'opId']))fail('REGISTRY_MUTATION_REQUEST');
  validateAuthorizedArtworkRequest(Object.fromEntries(authorizedArtworkFields.map(k=>[k,request[k]])));
  payload={action,...request};
 }else{
  if(!exact(request,['identity','opId'])||!exact(request.identity,[...identityFields,'revision']))fail('REGISTRY_MUTATION_REQUEST');
  const i=request.identity;
  validateAuthorizedArtworkRequest({...i,storageKey:'ValidStorage0001',artworkId:'validation',layerId:'validation'});
  payload={action,identity:i,opId:request.opId};
 }
 if(!safeId.test(request.opId||''))fail('REGISTRY_OPERATION_ID');
 // Canonical object-key ordering eliminates signer/caller insertion-order ambiguity.
 const canonical=x=>Array.isArray(x)?x.map(canonical):isObj(x)?Object.fromEntries(Object.keys(x).sort().map(k=>[k,canonical(x[k])])):x;
 return sha(Buffer.from(`${mutationSchema}\0${JSON.stringify(canonical(payload))}`));
}
/** Deterministic signed admin-request digest; never a permission grant. The
 * operator must independently inspect the anchored registry and key inventory.
 */
export function computePrivateRegistryAdminDigest(action,request){
 if(!adminActions.includes(action)||!exact(request,['opId','expectedAnchor','targetKeyId','expectedAssetCount','sourceKeyIds'])||
  !safeId.test(request.opId||'')||!keyIdPattern.test(request.targetKeyId||'')||
  !Number.isSafeInteger(request.expectedAssetCount)||request.expectedAssetCount<1||request.expectedAssetCount>300||
  !Array.isArray(request.sourceKeyIds)||request.sourceKeyIds.length>300||
  request.sourceKeyIds.some(k=>typeof k!=='string'||!keyIdPattern.test(k))||
  request.sourceKeyIds.join('\0')!==[...new Set(request.sourceKeyIds)].sort().join('\0')||
  (action==='migrate-plaintext'&&request.sourceKeyIds.length!==0)||
  (action==='rotate-key'&&request.sourceKeyIds.length===0))fail('REGISTRY_ADMIN_REQUEST');
 if(request.expectedAnchor===null)fail('REGISTRY_ADMIN_REQUEST');
 try{validateAnchor(request.expectedAnchor);}catch{fail('REGISTRY_ADMIN_REQUEST');}
 return sha(Buffer.from(`${adminSchema}\0${JSON.stringify({action,opId:request.opId,expectedAnchor:{sequence:request.expectedAnchor.sequence,mac:request.expectedAnchor.mac},targetKeyId:request.targetKeyId,expectedAssetCount:request.expectedAssetCount,sourceKeyIds:request.sourceKeyIds})}`));
}
/** Signed offline operator request digest. Export is read-only; restore consumes
 * an opId in the new anchored registry state. No caller-supplied principal.
 */
export function computePrivateRegistryBackupDigest(action,request){
 if(!backupActions.includes(action)||!isObj(request)||
  !exact(request,action!=='restore-backup'?['opId','expectedAnchor']:['opId','expectedAnchor','backupSha256'])||
  !safeId.test(request.opId||'')||request.expectedAnchor===null||
  (action==='restore-backup'&&!hex.test(request.backupSha256||'')))fail('REGISTRY_BACKUP_REQUEST');
 try{validateAnchor(request.expectedAnchor);}catch{fail('REGISTRY_BACKUP_REQUEST');}
 return sha(Buffer.from(`${backupSchema}\0${JSON.stringify({action,opId:request.opId,expectedAnchor:request.expectedAnchor,...(action==='restore-backup'?{backupSha256:request.backupSha256}:{})})}`));
}
function adminConfig(cfg){
 if(cfg===undefined)return null;
 if(!exact(cfg,['registryId','publicKey','verifyOperator'])||!recoveryId.test(cfg.registryId||'')||
  cfg.publicKey?.type!=='public'||cfg.publicKey?.asymmetricKeyType!=='ed25519'||
  typeof cfg.verifyOperator!=='function')fail('REGISTRY_ADMIN_CONFIGURATION');
 return cfg;
}
function verifyAdminPermit(permit,cfg,action,request,digest,principal,now){
 if(!exact(permit,[...adminFields,'signature'])||permit.schema!==adminSchema||
  permit.registryId!==cfg.registryId||permit.action!==action||permit.opId!==request.opId||
  permit.operatorId!==principal.operatorId||permit.requestSha256!==digest||
  !Number.isSafeInteger(permit.issuedAt)||!Number.isSafeInteger(permit.expiresAt)||
  permit.issuedAt>now||permit.expiresAt<=now||permit.expiresAt<=permit.issuedAt||
  permit.expiresAt-permit.issuedAt>900_000||
  typeof permit.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(permit.signature))fail('REGISTRY_ADMIN_DENIED');
 const payload=Object.fromEntries(adminFields.map(k=>[k,permit[k]]));
 const sig=Buffer.from(permit.signature,'base64url');
 if(sig.length!==64||sig.toString('base64url')!==permit.signature||
  !verifySignature(null,Buffer.from(`${adminSchema}\0${JSON.stringify(payload)}`),cfg.publicKey,sig))fail('REGISTRY_ADMIN_DENIED');
}
function mutationConfig(cfg){
 if(cfg===undefined)return null;
 if(!exact(cfg,['registryId','publicKey'])||!recoveryId.test(cfg.registryId||'')||
  cfg.publicKey?.type!=='public'||cfg.publicKey?.asymmetricKeyType!=='ed25519')fail('REGISTRY_MUTATION_CONFIGURATION');
 return cfg;
}
function verifyMutationPermit(permit,cfg,action,opId,digest,identity,now){
 if(!exact(permit,[...mutationFields,'signature'])||permit.schema!==mutationSchema||
  permit.registryId!==cfg.registryId||permit.action!==action||permit.opId!==opId||
  permit.shop!==identity.shop||permit.ownerId!==identity.ownerId||permit.requestSha256!==digest||
  !Number.isSafeInteger(permit.issuedAt)||!Number.isSafeInteger(permit.expiresAt)||
  permit.issuedAt>now||permit.expiresAt<=now||permit.expiresAt<=permit.issuedAt||
  permit.expiresAt-permit.issuedAt>900_000||
  typeof permit.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(permit.signature))fail('REGISTRY_MUTATION_DENIED');
 const data=Object.fromEntries(mutationFields.map(k=>[k,permit[k]]));
 const sig=Buffer.from(permit.signature,'base64url');
 if(sig.length!==64||sig.toString('base64url')!==permit.signature||
  !verifySignature(null,Buffer.from(`${mutationSchema}\0${JSON.stringify(data)}`),cfg.publicKey,sig))fail('REGISTRY_MUTATION_DENIED');
}
function validateState(s){
 if(!(exact(s,['schema','sequence','previousMac','revisions','assets','revocations','opIds','mac'])||
       exact(s,['schema','sequence','revisions','assets','revocations','opIds','mac']))||
  (Object.hasOwn(s,'previousMac')&&!hex.test(s.previousMac))||
  s.schema!=='TJ-OFFLINE-PRIVATE-REGISTRY-1'||!Number.isSafeInteger(s.sequence)||s.sequence<1||
  !hex.test(s.mac)||!Array.isArray(s.revisions)||!Array.isArray(s.assets)||
  !Array.isArray(s.revocations)||!Array.isArray(s.opIds)||s.opIds.length>1000||
  s.revisions.length>100||s.assets.length>300||s.revocations.length>300)fail('REGISTRY_STATE_INVALID');
 const opSet=new Set();for(const id of s.opIds){if(!safeId.test(id)||opSet.has(id))fail('REGISTRY_STATE_INVALID');opSet.add(id);}
 const revisions=new Set(),assets=new Set(),revocations=new Set();
 for(const r of s.revisions){validateRecord(r);const k=`${key(r)}|${r.revision}`;if(revisions.has(k))fail('REGISTRY_STATE_INVALID');revisions.add(k);}
 for(const a of s.assets){
  if(!(exact(a,['storageKey','artworkId','layerId','identity','revision','sha256','byteLength','base64'])||
        exact(a,['storageKey','artworkId','layerId','identity','revision','sha256','byteLength','encryption']))||
   !safeId.test(a.storageKey)||!text(a.artworkId)||!text(a.layerId)||
   !isObj(a.identity)||!exact(a.identity,identityFields)||!Number.isSafeInteger(a.revision)||a.revision<1||
   !hex.test(a.sha256)||!Number.isSafeInteger(a.byteLength)||a.byteLength<60||a.byteLength>MAX_ASSET||
   assets.has(a.storageKey))fail('REGISTRY_STATE_INVALID');
  if(encryptedAsset(a)){
   const e=a.encryption;
   if(!exact(e,['schema','keyId','nonce','tag','ciphertext'])||e.schema!==encryptionSchema||
    !keyIdPattern.test(e.keyId||'')||typeof e.nonce!=='string'||!/^([A-Za-z0-9+/]{16})$/.test(e.nonce)||
    typeof e.tag!=='string'||!/^([A-Za-z0-9+/]{22}==)$/.test(e.tag)||
    typeof e.ciphertext!=='string'||e.ciphertext.length>MAX_ASSET*2||
    decodeStrict(e.nonce).length!==12||decodeStrict(e.tag).length!==16||
    decodeStrict(e.ciphertext).length!==a.byteLength)fail('REGISTRY_STATE_INVALID');
  }else{
   if(typeof a.base64!=='string')fail('REGISTRY_STATE_INVALID');
   const b=Buffer.from(a.base64,'base64');if(b.length!==a.byteLength||b.toString('base64')!==a.base64||sha(b)!==a.sha256)fail('REGISTRY_STATE_INVALID');
  }
  if(!revisions.has(`${key(a.identity)}|${a.revision}`))fail('REGISTRY_STATE_INVALID');
  assets.add(a.storageKey);
 }
 for(const r of s.revisions){
  const expected=r.design.layers.filter(l=>l.type==='artwork');
  const present=s.assets.filter(a=>same(a.identity,r)&&a.revision===r.revision);
  if(!expected.length||expected.length!==present.length||
   expected.some(l=>!present.some(a=>a.layerId===l.id&&a.artworkId===l.artworkId)))
   fail('REGISTRY_STATE_INVALID');
 }
 for(const v of s.revocations){
  if(!exact(v,['type','target'])||!['artwork','revision'].includes(v.type)||typeof v.target!=='string'||
   revocations.has(`${v.type}|${v.target}`))fail('REGISTRY_STATE_INVALID');
  if(v.type==='artwork'&&!assets.has(v.target))fail('REGISTRY_STATE_INVALID');
  if(v.type==='revision'&&!revisions.has(v.target))fail('REGISTRY_STATE_INVALID');
  revocations.add(`${v.type}|${v.target}`);
 }
}
function mac(secret,s){const {mac,...content}=s;return createHmac('sha256',secret).update('TJ-PRIVATE-REGISTRY-1\0'+JSON.stringify(content)).digest('hex');}
function validateAnchor(a){if(a===null)return;if(!exact(a,['sequence','mac'])||!Number.isSafeInteger(a.sequence)||a.sequence<1||!hex.test(a.mac))fail('REGISTRY_ANCHOR_INVALID');}

export function createOfflinePrivateRevisionRegistry({directory,secret,readAnchor,compareAndSetAnchor,lockTimeoutMs=1500,injectFault,recovery,encryption,verifyArtworkAccess,mutationAuthorization,adminAuthorization}={}){
 if(typeof directory!=='string'||!directory.trim()||!Buffer.isBuffer(secret)||secret.length<32||
  typeof readAnchor!=='function'||typeof compareAndSetAnchor!=='function'||
  !Number.isInteger(lockTimeoutMs)||lockTimeoutMs<0||lockTimeoutMs>10000||
  (injectFault!==undefined&&typeof injectFault!=='function')||process.platform!=='linux'||!C.O_NOFOLLOW)
  fail('REGISTRY_CONFIGURATION');
 const recoveryCfg=recoveryConfig(recovery);
 const encryptionCfg=encryptionConfig(encryption);
 if(verifyArtworkAccess!==undefined&&typeof verifyArtworkAccess!=='function')fail('REGISTRY_ACCESS_CONFIGURATION');
 const authenticatedAccess=verifyArtworkAccess||null;
 const mutationCfg=mutationConfig(mutationAuthorization);
 if(mutationCfg&&(!authenticatedAccess||!encryptionCfg))fail('REGISTRY_MUTATION_CONFIGURATION');
 const adminCfg=adminConfig(adminAuthorization);
 if(adminCfg&&!encryptionCfg)fail('REGISTRY_ADMIN_CONFIGURATION');
 async function authorizeAdmin(token,permit,action,request,digest){
  if(!adminCfg)fail('REGISTRY_AUTH_REQUIRED');
  if(typeof token!=='string'||token.length<16||token.length>512||/[\x00-\x1f\x7f]/.test(token))fail('REGISTRY_ADMIN_DENIED');
  let principal;try{principal=await adminCfg.verifyOperator(token,action);}catch{fail('REGISTRY_ADMIN_DENIED');}
  const now=Date.now();
  if(!exact(principal,['operatorId','issuedAt','expiresAt'])||!text(principal.operatorId)||
   !Number.isSafeInteger(principal.issuedAt)||!Number.isSafeInteger(principal.expiresAt)||
   principal.issuedAt>now||principal.expiresAt<=now||principal.expiresAt<=principal.issuedAt||
   principal.expiresAt-principal.issuedAt>900_000)fail('REGISTRY_ADMIN_DENIED');
  verifyAdminPermit(permit,adminCfg,action,request,digest,principal,now);
  return Math.min(principal.expiresAt,permit.expiresAt);
 }
 function adminEnvelope(envelope,action){
  if(!adminCfg)fail('REGISTRY_AUTH_REQUIRED');
  if(!exact(envelope,['operatorToken','permit','request']))fail('REGISTRY_ADMIN_DENIED');
  const digest=computePrivateRegistryAdminDigest(action,envelope.request);
  return {request:copy(envelope.request),authorize:()=>authorizeAdmin(envelope.operatorToken,envelope.permit,action,envelope.request,digest)};
 }
 function assertAdminState(s,request,action){
  if(s.sequence!==request.expectedAnchor.sequence||s.mac!==request.expectedAnchor.mac||
   s.assets.length!==request.expectedAssetCount||encryptionCfg.activeKeyId!==request.targetKeyId)fail('REGISTRY_ADMIN_STATE_MISMATCH');
  const source=[...new Set(s.assets.filter(encryptedAsset).map(a=>a.encryption.keyId))].sort();
  if(source.join('\0')!==request.sourceKeyIds.join('\0'))fail('REGISTRY_ADMIN_STATE_MISMATCH');
  if(action==='migrate-plaintext'&&s.assets.some(encryptedAsset))fail('REGISTRY_MIXED_ENCRYPTION');
  if(action==='rotate-key'&&s.assets.some(a=>!encryptedAsset(a)))fail('REGISTRY_ENCRYPTION_REQUIRED');
 }
 function checkAdminDeadline(until){if(!Number.isSafeInteger(until)||Date.now()>=until)fail('REGISTRY_ADMIN_DENIED');}

 async function authorizeMutation(sessionToken,permit,action,opId,digest,identity){
  if(!mutationCfg||!authenticatedAccess)fail('REGISTRY_AUTH_REQUIRED');
  if(typeof sessionToken!=='string'||sessionToken.length<16||sessionToken.length>512||
   /[\x00-\x1f\x7f]/.test(sessionToken))fail('REGISTRY_MUTATION_DENIED');
  let principal;
  try{principal=await authenticatedAccess(sessionToken);}catch{fail('REGISTRY_MUTATION_DENIED');}
  const now=Date.now();
  try{verifyPrincipalShape(principal,now);}catch{fail('REGISTRY_MUTATION_DENIED');}
  if(principal.shop!==identity.shop||principal.ownerId!==identity.ownerId)fail('REGISTRY_MUTATION_DENIED');
  verifyMutationPermit(permit,mutationCfg,action,opId,digest,identity,now);
  return Math.min(principal.expiresAt,permit.expiresAt);
 }
 function authenticatedEnvelope(envelope){
  if(!mutationCfg)fail('REGISTRY_AUTH_REQUIRED');
  if(!exact(envelope,['sessionToken','permit','request']))fail('REGISTRY_MUTATION_DENIED');
  return envelope;
 }

 function keyFor(keyId){
  if(!encryptionCfg)fail('REGISTRY_ENCRYPTION_REQUIRED');
  let key;try{key=encryptionCfg.resolveKey(keyId);}catch{fail('REGISTRY_KEY_UNAVAILABLE');}
  if(!Buffer.isBuffer(key)||key.length!==32)fail('REGISTRY_KEY_UNAVAILABLE');
  return Buffer.from(key);
 }
 function encryptAsset(a,bytes,keyId=encryptionCfg?.activeKeyId){
  const k=keyFor(keyId),nonce=randomBytes(12);
  try{
   const c=createCipheriv('aes-256-gcm',k,nonce);c.setAAD(associatedData(a,keyId));
   const ciphertext=Buffer.concat([c.update(bytes),c.final()]);
   const {base64:discard,...meta}=a;
   return {...meta,encryption:{schema:encryptionSchema,keyId,nonce:nonce.toString('base64'),tag:c.getAuthTag().toString('base64'),ciphertext:ciphertext.toString('base64')}};
  }finally{k.fill(0);}
 }
 function decryptAsset(a){
  if(!encryptedAsset(a)){
   if(encryptionCfg)fail('REGISTRY_ENCRYPTION_REQUIRED');
   return Buffer.from(a.base64,'base64');
  }
  const e=a.encryption,k=keyFor(e.keyId);
  try{
   const d=createDecipheriv('aes-256-gcm',k,decodeStrict(e.nonce));
   d.setAAD(associatedData(a,e.keyId));d.setAuthTag(decodeStrict(e.tag));
   let bytes;try{bytes=Buffer.concat([d.update(decodeStrict(e.ciphertext)),d.final()]);}catch{fail('REGISTRY_ARTWORK_AUTH_FAILED');}
   if(bytes.length!==a.byteLength||sha(bytes)!==a.sha256)fail('REGISTRY_ARTWORK_AUTH_FAILED');
   return bytes;
  }finally{k.fill(0);}
 }
 function checkEncryption(s,{allowPlaintext=false}={}){
  for(const a of s.assets){
   if(!encryptedAsset(a)&&encryptionCfg&&!allowPlaintext)fail('REGISTRY_ENCRYPTION_REQUIRED');
   if(encryptedAsset(a))decryptAsset(a);
  }
 }

 const dir=resolve(directory),file=join(dir,'private-registry.json'),lock=join(dir,'.private-registry-lock');
 const lockContext=new AsyncLocalStorage(); // Isolate lock ownership per asynchronous call.
 const hmacSecret=Buffer.from(secret);
 async function anchor(){let a;try{a=await readAnchor();validateAnchor(a);}catch{fail('REGISTRY_ANCHOR_UNAVAILABLE');}return a;}
 async function prepareDir(){
  await mkdir(dir,{recursive:true,mode:0o700});const st=await lstat(dir);
  if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==process.getuid()||(st.mode&0o077)!==0)
   fail('REGISTRY_DIRECTORY_UNSAFE');
 }
 async function locked(fn){
  await prepareDir();let h;
  try{
   const directoryStat=await lstat(dir);
   h=await open(lock,C.O_RDWR|C.O_CREAT|C.O_NOFOLLOW,0o600);
   const st=await h.stat(),ps=await lstat(lock);
   if(!st.isFile()||st.nlink!==1||(st.mode&0o077)!==0||st.ino!==ps.ino||st.dev!==ps.dev)fail('REGISTRY_LOCK_UNSAFE');
   await new Promise((ok,no)=>{const child=spawn('/usr/bin/flock',['-x','-w',(lockTimeoutMs/1000).toFixed(3),'3'],{stdio:['ignore','ignore','ignore',h.fd]});child.once('error',()=>no(Object.assign(Error('REGISTRY_LOCK_UNAVAILABLE'),{code:'REGISTRY_LOCK_UNAVAILABLE'})));child.once('close',code=>code===0?ok():no(Object.assign(Error('REGISTRY_LOCK_UNAVAILABLE'),{code:'REGISTRY_LOCK_UNAVAILABLE'})));});
   const after=await lstat(lock);if(after.ino!==st.ino||after.dev!==st.dev||after.nlink!==1)fail('REGISTRY_LOCK_UNSAFE');
   const currentDir=await lstat(dir);
   if(!currentDir.isDirectory()||currentDir.ino!==directoryStat.ino||currentDir.dev!==directoryStat.dev)fail('REGISTRY_DIRECTORY_UNSAFE');
   return await lockContext.run({directoryStat,lockStat:st},fn);
  }catch(e){if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('REGISTRY_LOCK_UNSAFE');throw e;}
  finally{if(h)await h.close();}
 }
 async function verifyHeldFilesystem(){
  const heldLock=lockContext.getStore();
  if(!heldLock)fail('REGISTRY_LOCK_UNSAFE');
  let d,l;try{[d,l]=await Promise.all([lstat(dir),lstat(lock)]);}catch{fail('REGISTRY_LOCK_UNSAFE');}
  if(!d.isDirectory()||d.ino!==heldLock.directoryStat.ino||d.dev!==heldLock.directoryStat.dev||
   !l.isFile()||l.ino!==heldLock.lockStat.ino||l.dev!==heldLock.lockStat.dev||l.nlink!==1)fail('REGISTRY_LOCK_UNSAFE');
 }
 async function load({recoveryRead=false,allowPlaintext=false}={}){
  let h,bytes;
  try{
   h=await open(file,C.O_RDONLY|C.O_NOFOLLOW);const st=await h.stat(),ps=await lstat(file);
   if(!st.isFile()||st.nlink!==1||(st.mode&0o077)!==0||st.ino!==ps.ino||st.dev!==ps.dev||st.size>MAX_STATE)fail('REGISTRY_FILE_UNSAFE');
   bytes=await h.readFile();
  }catch(e){
   if(e.code==='ENOENT'){if(recoveryRead)fail('REGISTRY_RECOVERY_STATE_MISSING');if(await anchor()!==null)fail('REGISTRY_ROLLBACK');return fresh();}
   if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('REGISTRY_FILE_UNSAFE');throw e;
  }finally{if(h)await h.close();}
  if(bytes.length>MAX_STATE)fail('REGISTRY_FILE_UNSAFE');
  let s;try{s=JSON.parse(bytes.toString('utf8'));}catch{fail('REGISTRY_STATE_INVALID');}
  validateState(s);
  const expected=mac(hmacSecret,s);
  if(!timingSafeEqual(Buffer.from(s.mac,'hex'),Buffer.from(expected,'hex')))fail('REGISTRY_TAMPERED');
  checkEncryption(s,{allowPlaintext});
  if(!recoveryRead){const a=await anchor();if(!a||a.sequence!==s.sequence||a.mac!==s.mac)fail('REGISTRY_ROLLBACK');}
  return s;
 }
 async function save(s,preRenameCheck,{createOnly=false}={}){
  const previous=s.sequence?{sequence:s.sequence,mac:s.mac}:null;
  s.previousMac=previous?.mac??zeroMac;s.sequence++;s.mac=mac(hmacSecret,s);validateState(s);
  const bytes=Buffer.from(JSON.stringify(s));if(bytes.length>MAX_STATE)fail('REGISTRY_CAPACITY');
  const temp=join(dir,'.pending-'+randomBytes(16).toString('hex'));let h;
  try{
   h=await open(temp,'wx',0o600);await h.writeFile(bytes);await h.sync();await h.close();h=null;
   if(injectFault)await injectFault('before-rename');
   await verifyHeldFilesystem(); // Detect lock or directory substitution before a durable write.
   if(preRenameCheck)await preRenameCheck(); // Last fail-closed authorization check before durable rename.
   await verifyHeldFilesystem(); // Recheck after async authorization/anchor callbacks.
   if(createOnly){
    try{await link(temp,file);}catch(e){if(e.code==='EEXIST')fail('REGISTRY_RESTORE_DESTINATION_EXISTS');throw e;}
    await rm(temp); // no-clobber creation; preserve any independently appearing file
   }else await rename(temp,file);
   const d=await open(dir,'r');try{await d.sync();}finally{await d.close();}
   if(injectFault)await injectFault('after-rename');
   await verifyHeldFilesystem(); // Fail closed if the lock/path changed before anchor CAS.
   let ok;try{ok=await compareAndSetAnchor(previous,{sequence:s.sequence,mac:s.mac});}catch{fail('REGISTRY_ANCHOR_UNAVAILABLE');}
   if(ok!==true)fail('REGISTRY_ANCHOR_CONFLICT');
   const a=await anchor();if(!a||a.sequence!==s.sequence||a.mac!==s.mac)fail('REGISTRY_ANCHOR_CONFLICT');
  }finally{if(h)await h.close();await rm(temp,{force:true}).catch(()=>{});}
 }
 async function mutate(opId,fn,authorize,expiryCode='REGISTRY_MUTATION_DENIED'){
  if(!safeId.test(opId||''))fail('REGISTRY_OPERATION_ID');
  return locked(async()=>{
   const authorizedUntil=authorize?await authorize():null;
   const s=await load();if(s.opIds.includes(opId))fail('REGISTRY_REPLAY');
   if(s.opIds.length>=1000)fail('REGISTRY_CAPACITY');
   const result=fn(s);s.opIds.push(opId);
   if(authorize&&(!Number.isSafeInteger(authorizedUntil)||Date.now()>=authorizedUntil))fail(expiryCode);
   await save(s,authorize?()=>{if(Date.now()>=authorizedUntil)fail(expiryCode);}:undefined);return result;
  });
 }
 const revisionKey=r=>`${key(r)}|${r.revision}`;
 function latest(s,identity){return s.revisions.filter(r=>same(r,identity)).sort((a,b)=>b.revision-a.revision)[0]||null;}
 function active(s,r){return r&&!s.revocations.some(v=>v.type==='revision'&&v.target===revisionKey(r));}
 async function commitRevisionCore({record,artworks,expectedRevision=null,opId}={},authorize){
  const r=copy(record);validateRecord(r);
  if(!Array.isArray(artworks))fail('REGISTRY_ASSETS_INVALID');
  const layers=r.design.layers.filter(l=>l?.type==='artwork');
  if(!layers.length||layers.length!==artworks.length)fail('REGISTRY_ASSETS_INVALID');
  const assets=artworks.map(a=>{
   if(!exact(a,assetFields)||!safeId.test(a.storageKey)||!text(a.artworkId)||!text(a.layerId)||
    !Buffer.isBuffer(a.bytes)&&!(a.bytes instanceof Uint8Array))fail('REGISTRY_ASSETS_INVALID');
   const layer=layers.find(l=>l.id===a.layerId&&l.artworkId===a.artworkId);
   if(!layer)fail('REGISTRY_ASSETS_INVALID');
   const bytes=Buffer.from(a.bytes);if(bytes.length>MAX_ASSET)fail('REGISTRY_ASSETS_INVALID');
   let inspection;try{inspection=inspectVerifiedPng(bytes);}catch{fail('REGISTRY_ASSETS_INVALID');}
   return {storageKey:a.storageKey,artworkId:a.artworkId,layerId:a.layerId,
    identity:Object.fromEntries(identityFields.map(k=>[k,r[k]])),revision:r.revision,
    sha256:inspection.sha256,byteLength:bytes.length,base64:bytes.toString('base64')};
  });
  if(new Set(assets.map(a=>a.storageKey)).size!==assets.length||new Set(assets.map(a=>a.artworkId)).size!==assets.length)
   fail('REGISTRY_ASSETS_INVALID');
  return mutate(opId,s=>{
   const prior=latest(s,r);
   if((prior?.revision??null)!==expectedRevision||r.revision!==(prior?prior.revision+1:1))fail('REGISTRY_STALE_REVISION');
   if(assets.some(a=>s.assets.some(b=>b.storageKey===a.storageKey)))fail('REGISTRY_STORAGE_KEY_REUSED');
   s.revisions.push(r);s.assets.push(...assets.map(a=>encryptionCfg?encryptAsset(a,Buffer.from(a.base64,'base64')):a));
   return {revision:r.revision,designSha256:r.designSha256,artworkCount:assets.length,productionApproved:false};
  },authorize);
 }
 async function commitRevision(args){
  if(mutationCfg)fail('REGISTRY_AUTH_REQUIRED');
  return commitRevisionCore(args);
 }
 async function commitAuthenticatedRevision(envelope){
  const {sessionToken,permit,request}=authenticatedEnvelope(envelope);
  const digest=computePrivateRegistryMutationDigest('commit-revision',request);
  const snapshot={record:copy(request.record),artworks:request.artworks.map(a=>({...a,bytes:Buffer.from(a.bytes)})),expectedRevision:request.expectedRevision,opId:request.opId};
  const identity=snapshot.record;
  return commitRevisionCore(snapshot,()=>authorizeMutation(sessionToken,permit,'commit-revision',snapshot.opId,digest,identity));
 }
 async function loadCurrentRevision(identity){
  return locked(async()=>{
   const s=await load(),r=latest(s,identity||{});
   return active(s,r)&&r.revision===identity?.revision?copy(r):null;
  });
 }
 /** Legacy local fixture read. Never expose this method as a hosted endpoint.
  * A configured trusted verifier disables this weaker compatibility method.
  */
 async function readPrivateArtwork({storageKey,ownerId,designId,revision,artworkId}={}){
  if(authenticatedAccess)fail('REGISTRY_AUTH_REQUIRED');
  return locked(async()=>{
   const s=await load(),a=s.assets.find(x=>x.storageKey===storageKey);
   if(!a||a.identity.ownerId!==ownerId||a.identity.designId!==designId||a.revision!==revision||
    a.artworkId!==artworkId||s.revocations.some(v=>v.type==='artwork'&&v.target===storageKey))fail('REGISTRY_ARTWORK_UNAVAILABLE');
   const r=latest(s,a.identity);
   if(!active(s,r)||r.revision!==revision)fail('REGISTRY_ARTWORK_UNAVAILABLE');
   const bytes=decryptAsset(a);
   if(sha(bytes)!==a.sha256||bytes.length!==a.byteLength)fail('REGISTRY_ARTWORK_CORRUPT');
   return Buffer.from(bytes);
  });
 }
 /** Trusted server-only integration seam. The caller supplies an opaque session
  * token; ONLY the independently injected verifier establishes the principal.
  * Never accept a principal supplied in the request or expose this as a public
  * unauthenticated API. All identity and asset coordinates must match exactly.
  */
 async function readAuthenticatedArtwork(envelope={}){
  if(!authenticatedAccess)fail('REGISTRY_AUTH_REQUIRED');
  if(!encryptionCfg)fail('REGISTRY_ENCRYPTION_REQUIRED');
  if(!exact(envelope,['sessionToken','request']))fail('REGISTRY_ACCESS_DENIED');
  const {sessionToken,request}=envelope;
  if(typeof sessionToken!=='string'||sessionToken.length<16||sessionToken.length>512||
   /[\x00-\x1f\x7f]/.test(sessionToken))fail('REGISTRY_ACCESS_DENIED');
  validateAuthorizedArtworkRequest(request);
  return locked(async()=>{
   let principal;
   try{principal=await authenticatedAccess(sessionToken);}catch{fail('REGISTRY_ACCESS_DENIED');}
   const now=Date.now();verifyPrincipalShape(principal,now);
   if(principal.shop!==request.shop||principal.ownerId!==request.ownerId)fail('REGISTRY_ACCESS_DENIED');
   const s=await load(),a=s.assets.find(x=>x.storageKey===request.storageKey);
   if(!a||!same(a.identity,request)||a.revision!==request.revision||
    a.artworkId!==request.artworkId||a.layerId!==request.layerId||
    s.revocations.some(v=>v.type==='artwork'&&v.target===request.storageKey))fail('REGISTRY_ARTWORK_UNAVAILABLE');
   const r=latest(s,a.identity);
   if(!active(s,r)||r.revision!==request.revision)fail('REGISTRY_ARTWORK_UNAVAILABLE');
   const bytes=decryptAsset(a);
   if(sha(bytes)!==a.sha256||bytes.length!==a.byteLength)fail('REGISTRY_ARTWORK_CORRUPT');
   return Buffer.from(bytes);
  });
 }
 /** Evidence only: does not retire or erase keys. ALL historical/revoked
  * assets count; external backups cannot be established by a local fixture.
  */
 async function inspectArtworkKeyRetirement({keyId}={}){
  if(!encryptionCfg)fail('REGISTRY_ENCRYPTION_REQUIRED');
  if(typeof keyId!=='string'||!keyIdPattern.test(keyId))fail('REGISTRY_KEY_ID_INVALID');
  return locked(async()=>{
   const s=await load();
   const referencedAssets=s.assets.filter(a=>encryptedAsset(a)&&a.encryption.keyId===keyId).length;
   const legacyPlaintextAssets=s.assets.filter(a=>!encryptedAsset(a)).length;
   const activeKey=keyId===encryptionCfg.activeKeyId;
   return Object.freeze({keyId,referencedAssets,legacyPlaintextAssets,activeKey,
    unusedInCurrentRegistry:referencedAssets===0&&!activeKey&&legacyPlaintextAssets===0,
    backupsVerified:false,safeToDestroy:false,productionApproved:false});
  });
 }
 async function revokeArtworkCore({storageKey,ownerId,designId,revision,opId}={},authorize,strict){
  return mutate(opId,s=>{
   const a=s.assets.find(x=>x.storageKey===storageKey);
   if(!a||a.identity.ownerId!==ownerId||a.identity.designId!==designId||a.revision!==revision||
    (strict&&(!same(a.identity,strict)||a.artworkId!==strict.artworkId||a.layerId!==strict.layerId)))
    fail('REGISTRY_ARTWORK_UNAVAILABLE');
   if(s.revocations.some(v=>v.type==='artwork'&&v.target===storageKey))fail('REGISTRY_ALREADY_REVOKED');
   s.revocations.push({type:'artwork',target:storageKey});return {revoked:true};
  },authorize);
 }
 async function revokeRevisionCore({identity,opId}={},authorize){
  return mutate(opId,s=>{
   const r=latest(s,identity||{});
   if(!r||r.revision!==identity?.revision||!active(s,r))fail('REGISTRY_REVISION_NOT_CURRENT');
   s.revocations.push({type:'revision',target:revisionKey(r)});return {revoked:true};
  },authorize);
 }

 async function revokeArtwork(args){
  if(mutationCfg)fail('REGISTRY_AUTH_REQUIRED');
  return revokeArtworkCore(args);
 }
 async function revokeRevision(args){
  if(mutationCfg)fail('REGISTRY_AUTH_REQUIRED');
  return revokeRevisionCore(args);
 }
 async function revokeAuthenticatedArtwork(envelope){
  const {sessionToken,permit,request}=authenticatedEnvelope(envelope);
  const digest=computePrivateRegistryMutationDigest('revoke-artwork',request),q=copy(request);
  return revokeArtworkCore(q,()=>authorizeMutation(sessionToken,permit,'revoke-artwork',q.opId,digest,q),q);
 }
 async function revokeAuthenticatedRevision(envelope){
  const {sessionToken,permit,request}=authenticatedEnvelope(envelope);
  const digest=computePrivateRegistryMutationDigest('revoke-revision',request),q=copy(request);
  return revokeRevisionCore(q,()=>authorizeMutation(sessionToken,permit,'revoke-revision',q.opId,digest,q.identity));
 }

 /** Explicit one-time legacy plaintext migration. No implicit plaintext reads when
  * encryption is enabled. A failed anchor CAS leaves the registry blocked.
  */
 async function migratePlaintextArtwork({opId}={}){
  if(mutationCfg||adminCfg)fail('REGISTRY_AUTH_REQUIRED'); // privileged offline operator path only
  if(!encryptionCfg)fail('REGISTRY_ENCRYPTION_REQUIRED');
  if(!safeId.test(opId||''))fail('REGISTRY_OPERATION_ID');
  return locked(async()=>{
   const s=await load({allowPlaintext:true});
   if(s.opIds.includes(opId))fail('REGISTRY_REPLAY');
   if(s.opIds.length>=1000)fail('REGISTRY_CAPACITY');
   if(!s.assets.length||s.assets.every(encryptedAsset))fail('REGISTRY_MIGRATION_NOT_REQUIRED');
   if(s.assets.some(encryptedAsset))fail('REGISTRY_MIXED_ENCRYPTION');
   s.assets=s.assets.map(a=>{
    const {base64,...meta}=a;
    return encryptAsset(meta,Buffer.from(base64,'base64'));
   });
   s.opIds.push(opId);await save(s);
   return {migrated:true,artworkCount:s.assets.length,productionApproved:false};
  });
 }
 /** Re-encrypt all ciphertexts with configured active key, under an atomic
  * new anchor sequence. Requires access to each historical key.
  */
 async function rotateArtworkKey({opId}={}){
  if(mutationCfg||adminCfg)fail('REGISTRY_AUTH_REQUIRED'); // privileged offline operator path only
  if(!encryptionCfg)fail('REGISTRY_ENCRYPTION_REQUIRED');
  return mutate(opId,s=>{
   if(!s.assets.length||s.assets.some(a=>!encryptedAsset(a)))fail('REGISTRY_ENCRYPTION_REQUIRED');
   if(s.assets.every(a=>a.encryption.keyId===encryptionCfg.activeKeyId))fail('REGISTRY_ROTATION_NOT_REQUIRED');
   s.assets=s.assets.map(a=>{
    const bytes=decryptAsset(a);
    const {encryption:discard,...meta}=a;
    return encryptAsset(meta,bytes);
   });
   return {rotated:true,artworkCount:s.assets.length,productionApproved:false};
  });
 }
 /** Signed, independently verified operator-only admin operations. The request
  * binds the exact pre-transaction anchor, key inventory and target key.
  * Never route this method through a customer-facing endpoint.
  */
 async function migrateAuthenticatedArtwork(envelope){
  const {request,authorize}=adminEnvelope(envelope,'migrate-plaintext');
  return locked(async()=>{
   const until=await authorize();
   const s=await load({allowPlaintext:true});
   if(s.opIds.includes(request.opId))fail('REGISTRY_REPLAY');
   if(s.opIds.length>=1000)fail('REGISTRY_CAPACITY');
   assertAdminState(s,request,'migrate-plaintext');
   if(!s.assets.length||s.assets.every(encryptedAsset))fail('REGISTRY_MIGRATION_NOT_REQUIRED');
   s.assets=s.assets.map(a=>{const {base64,...meta}=a;return encryptAsset(meta,Buffer.from(base64,'base64'));});
   s.opIds.push(request.opId);checkAdminDeadline(until);
   await save(s,()=>checkAdminDeadline(until));
   return {migrated:true,artworkCount:s.assets.length,productionApproved:false};
  });
 }
 async function rotateAuthenticatedArtworkKey(envelope){
  const {request,authorize}=adminEnvelope(envelope,'rotate-key');
  return mutate(request.opId,s=>{
   assertAdminState(s,request,'rotate-key');
   if(s.assets.every(a=>a.encryption.keyId===encryptionCfg.activeKeyId))fail('REGISTRY_ROTATION_NOT_REQUIRED');
   s.assets=s.assets.map(a=>{const bytes=decryptAsset(a);const {encryption:discard,...meta}=a;return encryptAsset(meta,bytes);});
   return {rotated:true,artworkCount:s.assets.length,productionApproved:false};
  },authorize,'REGISTRY_ADMIN_DENIED');
 }
 /** An operator-signed, read-only export of the exact anchored encrypted state.
  * The returned bytes are SENSITIVE ciphertext and metadata, not a hosted backup
  * or permission to delete keys. Caller must secure storage and retention.
  */
 async function exportAuthenticatedBackup(envelope){
  if(!adminCfg||!encryptionCfg)fail('REGISTRY_AUTH_REQUIRED');
  if(!exact(envelope,['operatorToken','permit','request']))fail('REGISTRY_BACKUP_DENIED');
  const request=copy(envelope.request),digest=computePrivateRegistryBackupDigest('export-backup',request);
  return locked(async()=>{
   const until=await authorizeAdmin(envelope.operatorToken,envelope.permit,'export-backup',request,digest);
   const s=await load();
   if(s.sequence!==request.expectedAnchor.sequence||s.mac!==request.expectedAnchor.mac)
    fail('REGISTRY_BACKUP_ANCHOR_MISMATCH');
   if(!s.assets.length||s.assets.some(a=>!encryptedAsset(a)))fail('REGISTRY_BACKUP_ENCRYPTION_REQUIRED');
   checkAdminDeadline(until);
   const bytes=Buffer.from(JSON.stringify(s));
   const keyIds=[...new Set(s.assets.map(a=>a.encryption.keyId))].sort();
   return Object.freeze({schema:backupSchema,registryId:adminCfg.registryId,
    anchor:{sequence:s.sequence,mac:s.mac},sha256:sha(bytes),byteLength:bytes.length,
    keyIds,revisionCount:s.revisions.length,assetCount:s.assets.length,
    revocationCount:s.revocations.length,opIdCount:s.opIds.length,
    stateBase64:bytes.toString('base64')});
  });
 }
 /** Read-only operator-signed snapshot of audit continuity, with NO event-log claim.
  * Anchored SHA-256 commitments permit offline comparison against separately
  * retained backup snapshots without disclosing op IDs or customer artwork.
  * It does not prove missing intermediate history or offsite retention.
  */
 async function exportAuthenticatedAudit(envelope){
  if(!adminCfg||!encryptionCfg)fail('REGISTRY_AUTH_REQUIRED');
  if(!exact(envelope,['operatorToken','permit','request']))fail('REGISTRY_AUDIT_DENIED');
  const request=copy(envelope.request),digest=computePrivateRegistryBackupDigest('export-audit',request);
  return locked(async()=>{
   const until=await authorizeAdmin(envelope.operatorToken,envelope.permit,'export-audit',request,digest);
   const s=await load();
   if(s.sequence!==request.expectedAnchor.sequence||s.mac!==request.expectedAnchor.mac)
    fail('REGISTRY_BACKUP_ANCHOR_MISMATCH');
   if(!s.assets.length||s.assets.some(a=>!encryptedAsset(a)))fail('REGISTRY_BACKUP_ENCRYPTION_REQUIRED');
   checkAdminDeadline(until);
   return Object.freeze({schema:auditSchema,registryId:adminCfg.registryId,
    anchor:{sequence:s.sequence,mac:s.mac},previousMac:s.previousMac??null,
    stateSha256:sha(Buffer.from(JSON.stringify(s))),
    revisionSha256:sha(Buffer.from(JSON.stringify(s.revisions))),
    artworkSha256:sha(Buffer.from(JSON.stringify(s.assets))),
    revocationSha256:sha(Buffer.from(JSON.stringify(s.revocations))),
    operationSha256:sha(Buffer.from(JSON.stringify(s.opIds))),
    revisionCount:s.revisions.length,artworkCount:s.assets.length,
    revocationCount:s.revocations.length,operationCount:s.opIds.length,
    historicalCoverage:'CURRENT_SNAPSHOT_ONLY',productionApproved:false});
  });
 }
 /** Restore only to a MISSING local registry from a complete encrypted snapshot
  * matching the independent CURRENT anchor. Never overwrite a local state or
  * accept an older backup. New signed opId is durably consumed on success.
  * If the anchor update is interrupted, separate signed recovery is required.
  */
 async function restoreAuthenticatedBackup(envelope){
  if(!adminCfg||!encryptionCfg)fail('REGISTRY_AUTH_REQUIRED');
  if(!exact(envelope,['operatorToken','permit','request','backup']))fail('REGISTRY_BACKUP_DENIED');
  const request=copy(envelope.request),digest=computePrivateRegistryBackupDigest('restore-backup',request);
  return locked(async()=>{
   const until=await authorizeAdmin(envelope.operatorToken,envelope.permit,'restore-backup',request,digest);
   const b=envelope.backup;
   if(!exact(b,backupFields)||b.schema!==backupSchema||b.registryId!==adminCfg.registryId||
    !hex.test(b.sha256||'')||b.sha256!==request.backupSha256||
    !Number.isSafeInteger(b.byteLength)||b.byteLength<100||b.byteLength>MAX_STATE||
    typeof b.stateBase64!=='string'||b.stateBase64.length>Math.ceil(MAX_STATE/3)*4+4||
    !Array.isArray(b.keyIds)||b.keyIds.length>300||
    b.keyIds.some(x=>typeof x!=='string'||!keyIdPattern.test(x))||
    b.keyIds.join('\0')!==[...new Set(b.keyIds)].sort().join('\0')||
    !['revisionCount','assetCount','revocationCount','opIdCount'].every(k=>Number.isSafeInteger(b[k])&&b[k]>=0))
    fail('REGISTRY_BACKUP_INVALID');
   let bytes,s;
   try{bytes=decodeStrict(b.stateBase64);}catch{fail('REGISTRY_BACKUP_INVALID');}
   if(bytes.length!==b.byteLength||sha(bytes)!==b.sha256)fail('REGISTRY_BACKUP_TAMPERED');
   try{s=JSON.parse(bytes.toString('utf8'));validateState(s);}catch{fail('REGISTRY_BACKUP_INVALID');}
   if(!exact(b.anchor,['sequence','mac'])||b.anchor.sequence!==s.sequence||b.anchor.mac!==s.mac||
    b.anchor.sequence!==request.expectedAnchor.sequence||b.anchor.mac!==request.expectedAnchor.mac||
    s.revisions.length!==b.revisionCount||s.assets.length!==b.assetCount||
    s.revocations.length!==b.revocationCount||s.opIds.length!==b.opIdCount||
    !s.assets.length||s.assets.some(a=>!encryptedAsset(a))||
    [...new Set(s.assets.map(a=>a.encryption.keyId))].sort().join('\0')!==b.keyIds.join('\0'))
    fail('REGISTRY_BACKUP_INVALID');
   if(!timingSafeEqual(Buffer.from(s.mac,'hex'),Buffer.from(mac(hmacSecret,s),'hex')))
    fail('REGISTRY_BACKUP_TAMPERED');
   checkEncryption(s); // all historical AND revoked ciphertext must authenticate
   const observed=await anchor();
   if(!observed||observed.sequence!==s.sequence||observed.mac!==s.mac)
    fail('REGISTRY_BACKUP_ANCHOR_MISMATCH');
   try{await lstat(file);fail('REGISTRY_RESTORE_DESTINATION_EXISTS');}
   catch(e){if(e.code!=='ENOENT')throw e;}
   if(s.opIds.includes(request.opId))fail('REGISTRY_REPLAY');
   if(s.opIds.length>=1000)fail('REGISTRY_CAPACITY');
   s.opIds.push(request.opId);
   checkAdminDeadline(until);
   await save(s,async()=>{
    checkAdminDeadline(until);
    const a=await anchor();
    if(!a||a.sequence!==request.expectedAnchor.sequence||a.mac!==request.expectedAnchor.mac)
     fail('REGISTRY_BACKUP_ANCHOR_MISMATCH');
   },{createOnly:true});
   return {restored:true,revisionCount:s.revisions.length,artworkCount:s.assets.length,
    revocationCount:s.revocations.length,productionApproved:false};
  });
 }
 /** Operator-authorized, exact one-step anchor catch-up for interrupted writes.
  * The independent operator MUST inspect trusted evidence before signing.
  * Never changes local revisions, bytes, revocations or replay IDs.
  * Legacy v0.23 states without a previousMac cannot prove the chain and
  * deliberately cannot be recovered through this method.
  */
 async function recoverInterruptedRegistry({authorization}={}){
  if(!recoveryCfg)fail('REGISTRY_RECOVERY_UNAVAILABLE');
  const permit=verifyRecoveryPermit(authorization,recoveryCfg,Date.now());
  return locked(async()=>{
   const s=await load({recoveryRead:true}); // HMAC and full structural checks, not anchor equality
   const target={sequence:s.sequence,mac:s.mac};
   if(target.sequence!==permit.targetAnchor.sequence||target.mac!==permit.targetAnchor.mac)
    fail('REGISTRY_RECOVERY_TARGET');
   const observed=await anchor();
   if(observed&&observed.sequence===target.sequence&&observed.mac===target.mac)
    return 'already-recovered';
   const prior=permit.expectedAnchor;
   if(!Object.hasOwn(s,'previousMac'))fail('REGISTRY_RECOVERY_LEGACY_UNPROVEN');
   if((observed===null)!==(prior===null)||
    (observed!==null&&(observed.sequence!==prior.sequence||observed.mac!==prior.mac))||
    target.sequence!==(prior?prior.sequence+1:1)||
    s.previousMac!==(prior?.mac??zeroMac))fail('REGISTRY_RECOVERY_CHAIN');
   let ok;try{ok=await compareAndSetAnchor(prior,target);}catch{fail('REGISTRY_ANCHOR_UNAVAILABLE');}
   if(ok!==true)fail('REGISTRY_ANCHOR_CONFLICT');
   const after=await anchor();
   if(!after||after.sequence!==target.sequence||after.mac!==target.mac)
    fail('REGISTRY_ANCHOR_CONFLICT');
   return 'recovered';
  });
 }
 return Object.freeze({commitRevision,commitAuthenticatedRevision,loadCurrentRevision,readPrivateArtwork,readAuthenticatedArtwork,inspectArtworkKeyRetirement,revokeArtwork,revokeRevision,revokeAuthenticatedArtwork,revokeAuthenticatedRevision,recoverInterruptedRegistry,migratePlaintextArtwork,rotateArtworkKey,migrateAuthenticatedArtwork,rotateAuthenticatedArtworkKey,exportAuthenticatedBackup,restoreAuthenticatedBackup,exportAuthenticatedAudit});
}
