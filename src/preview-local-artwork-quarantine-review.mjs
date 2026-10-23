/** Objective 35W: read-only, operator-reviewable artwork quarantine *intent*.
 * No filesystem mutation, deletion, quarantine, user authentication, or
 * production authorization. HMAC protects the serialized local review ticket
 * from substitution; a valid ticket is NEVER permission to mutate storage.
 */
import {createHmac,randomBytes,timingSafeEqual,createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {inspectLocalArtworkRetention} from './preview-local-artwork-retention.mjs';
const fail=(code,cause)=>Object.assign(new Error(code),{code,cause});
const hex64=/^[a-f0-9]{64}$/;
const hex32=/^[a-f0-9]{32}$/;
const artworkId=/^art_[a-f0-9]{32}$/;
const schema='trendyjoes.local-artwork-quarantine-review.v1';
const fields=['schema','operation','rootPin','referencePin','candidateArtworkIds','issuedAt','expiresAt','nonce','safeToAutoDelete'];
const exactKeys=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&
 Object.keys(value).length===keys.length&&keys.every(k=>Object.hasOwn(value,k));
const keyValid=key=>Buffer.isBuffer(key)&&key.length>=32&&key.length<=128;
const validClock=now=>Number.isSafeInteger(now)&&now>0;
const rootPin=root=>createHash('sha256').update(resolve(root)).digest('hex');
const sign=(body,key)=>createHmac('sha256',key).update(JSON.stringify(body)).digest('hex');
const sortedIds=ids=>Array.isArray(ids)&&ids.length<=10000&&ids.every(x=>typeof x==='string'&&artworkId.test(x))&&
 ids.every((x,i)=>i===0||ids[i-1]<x);
const optionsValid=({root,reviewKey,now})=>typeof root==='string'&&root.length>0&&keyValid(reviewKey)&&validClock(now);
function assertClean(scan){
 if(scan.referenceScanComplete!==true||scan.safeToAutoDelete!==false||
  scan.missingOrIncompleteReferencedArtworkIds.length||scan.incompleteArtworkIds.length||scan.pendingStageFiles.length)
  throw fail('LOCAL_QUARANTINE_REVIEW_UNCERTAIN_INVENTORY');
}
function bodyFor(root,scan,issuedAt,ttlMs,nonce){
 return {schema,operation:'REVIEW_ONLY',rootPin:rootPin(root),referencePin:scan.referencePin,
  candidateArtworkIds:[...scan.unreferencedCompleteArtworkIds],issuedAt,expiresAt:issuedAt+ttlMs,
  nonce,safeToAutoDelete:false};
}
/** The reviewKey is supplied by the caller and never persisted by this module. */
export async function createLocalArtworkQuarantineIntent(root,{reviewKey,now=Date.now(),ttlMs=300000,
 nonce=randomBytes(16).toString('hex'),io}={}){
 if(!optionsValid({root,reviewKey,now})||!Number.isSafeInteger(ttlMs)||ttlMs<1||ttlMs>3600000||
  !Number.isSafeInteger(now+ttlMs)||!hex32.test(nonce))throw fail('LOCAL_QUARANTINE_REVIEW_INVALID_OPTIONS');
 const scan=await inspectLocalArtworkRetention(root,{io});assertClean(scan);
 if(!hex64.test(scan.referencePin)||!sortedIds(scan.unreferencedCompleteArtworkIds))
  throw fail('LOCAL_QUARANTINE_REVIEW_UNCERTAIN_INVENTORY');
 const body=bodyFor(root,scan,now,ttlMs,nonce);
 return Object.freeze({...body,candidateArtworkIds:Object.freeze(body.candidateArtworkIds),mac:sign(body,reviewKey)});
}
/** Re-scans under the cooperative lease. Validity expires immediately when the
 * snapshot changes; even a positive result confers NO quarantine/delete rights.
 */
export async function verifyLocalArtworkQuarantineIntent(root,intent,{reviewKey,now=Date.now(),io}={}){
 if(!optionsValid({root,reviewKey,now})||!exactKeys(intent,[...fields,'mac']))
  throw fail('LOCAL_QUARANTINE_REVIEW_INVALID');
 const {mac,...body}=intent;
 if(body.schema!==schema||body.operation!=='REVIEW_ONLY'||body.safeToAutoDelete!==false||
  typeof body.rootPin!=='string'||typeof body.referencePin!=='string'||typeof mac!=='string'||
  !hex64.test(body.rootPin)||!hex64.test(body.referencePin)||!hex64.test(mac)||
  !sortedIds(body.candidateArtworkIds)||typeof body.nonce!=='string'||!hex32.test(body.nonce)||
  !validClock(body.issuedAt)||!validClock(body.expiresAt)||
  body.expiresAt<=body.issuedAt||body.expiresAt-body.issuedAt>3600000)
  throw fail('LOCAL_QUARANTINE_REVIEW_INVALID');
 const expected=Buffer.from(sign(body,reviewKey),'hex');
 if(!timingSafeEqual(Buffer.from(mac,'hex'),expected))throw fail('LOCAL_QUARANTINE_REVIEW_TAMPERED');
 if(body.rootPin!==rootPin(root))throw fail('LOCAL_QUARANTINE_REVIEW_WRONG_ROOT');
 if(now<body.issuedAt||now>=body.expiresAt)throw fail('LOCAL_QUARANTINE_REVIEW_EXPIRED');
 const scan=await inspectLocalArtworkRetention(root,{io});assertClean(scan);
 if(scan.referencePin!==body.referencePin||
  JSON.stringify(scan.unreferencedCompleteArtworkIds)!==JSON.stringify(body.candidateArtworkIds))
  throw fail('LOCAL_QUARANTINE_REVIEW_STALE');
 return Object.freeze({schema,verifiedReadOnly:true,referencePin:scan.referencePin,
  candidateArtworkIds:Object.freeze([...scan.unreferencedCompleteArtworkIds]),safeToAutoDelete:false,
  safeToQuarantine:false,reason:'LOCAL_SNAPSHOT_ONLY_NOT_AUTHORIZATION'});
}
