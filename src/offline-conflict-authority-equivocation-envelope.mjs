/** Objective 33F — portable, independently pinned, read-only signed fork evidence.
 * This is an offline evidence format, not a publication, replay database, trusted
 * clock, global consensus, repair, settlement, or production authorization.
 */
import {createHash,createPublicKey,KeyObject} from 'node:crypto';
import {TextDecoder} from 'node:util';
import {verifyOfflineConflictAuthorityObserverReconciliation} from './offline-conflict-authority-observer-reconciliation.mjs';

export const OFFLINE_CONFLICT_EQUIVOCATION_ENVELOPE_SCHEMA='TJ-OFFLINE-CONFLICT-EQUIVOCATION-ENVELOPE-1';
const HEX=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9_-]{8,64}$/;
const MAX_BYTES=2*1024*1024;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hex=x=>typeof x==='string'&&HEX.test(x);
const id=x=>typeof x==='string'&&ID.test(x);
const sha=b=>createHash('sha256').update(b).digest('hex');
const own=(o,k)=>Object.prototype.hasOwnProperty.call(o,k);
function exact(o,keys){
 if(o===null||typeof o!=='object'||Array.isArray(o)||
  ![Object.prototype,null].includes(Object.getPrototypeOf(o))||
  Reflect.ownKeys(o).length!==keys.length)return false;
 return keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value' in d&&d.enumerable;})&&
  Object.keys(o).every(k=>keys.includes(k));
}
function dense(a){
 if(!Array.isArray(a)||Object.getPrototypeOf(a)!==Array.prototype||
  a.length>50000||Reflect.ownKeys(a).length!==a.length+1)return false;
 for(let i=0;i<a.length;i++){
  const d=Object.getOwnPropertyDescriptor(a,String(i));
  if(!d||!('value' in d)||!d.enumerable)return false;
 }
 return true;
}
function base64Decode(value,limit){
 if(typeof value!=='string'||value.length>Math.ceil(limit*4/3)+4||
  !/^[A-Za-z0-9_-]+$/.test(value))fail('EXCHANGE33F_BINARY_ENCODING');
 const b=Buffer.from(value,'base64url');
 if(b.length>limit||b.toString('base64url')!==value)fail('EXCHANGE33F_BINARY_ENCODING');
 return b;
}
/** Canonical portable snapshot of plain data, byte buffers and public Ed25519 keys.
 * Accessors, cycles, prototype tricks, unsupported types and private keys fail closed.
 */
function portable(value){
 let nodes=0;const stack=new WeakSet();
 function walk(x,depth){
  if(++nodes>150000||depth>80)fail('EXCHANGE33F_COMPLEXITY_LIMIT');
  if(x===null||typeof x==='boolean')return x;
  if(typeof x==='string'){
   if(x.length>MAX_BYTES||/\uD800(?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(x))fail('EXCHANGE33F_STRING_INVALID');
   return x;
  }
  if(typeof x==='number'){
   if(!Number.isFinite(x)||Object.is(x,-0)||(!Number.isSafeInteger(x)&&Number.isInteger(x)))fail('EXCHANGE33F_NUMBER_INVALID');
   return x;
  }
  if(Buffer.isBuffer(x))return {$type:'bytes',value:x.toString('base64url')};
  if(x instanceof KeyObject){
   if(x.type!=='public'||x.asymmetricKeyType!=='ed25519')fail('EXCHANGE33F_KEY_INVALID');
   return {$type:'ed25519-spki',value:x.export({format:'der',type:'spki'}).toString('base64url')};
  }
  if(x===null||typeof x!=='object'||stack.has(x))fail('EXCHANGE33F_UNSUPPORTED_VALUE');
  stack.add(x);
  let result;
  if(Array.isArray(x)){
   if(!dense(x))fail('EXCHANGE33F_UNSAFE_ARRAY');
   result=x.map(v=>walk(v,depth+1));
  }else{
   const keys=Reflect.ownKeys(x);
   if(![Object.prototype,null].includes(Object.getPrototypeOf(x))||keys.length>1024||
    keys.some(k=>typeof k!=='string'||['__proto__','constructor','prototype','$type'].includes(k)))
    fail('EXCHANGE33F_UNSAFE_OBJECT');
   result={};
   for(const k of keys){
    const d=Object.getOwnPropertyDescriptor(x,k);
    if(!d||!('value' in d)||!d.enumerable)fail('EXCHANGE33F_UNSAFE_OBJECT');
    result[k]=walk(d.value,depth+1);
   }
  }
  stack.delete(x);return result;
 }
 return walk(value,0);
}
function revive(value){
 let nodes=0;
 function walk(x,depth){
  if(++nodes>150000||depth>80)fail('EXCHANGE33F_COMPLEXITY_LIMIT');
  if(x===null||typeof x==='boolean'||typeof x==='string'||typeof x==='number')return x;
  if(Array.isArray(x))return x.map(v=>walk(v,depth+1));
  if(!x||typeof x!=='object'||Array.isArray(x))fail('EXCHANGE33F_UNSAFE_OBJECT');
  if(own(x,'$type')){
   if(!exact(x,['$type','value']))fail('EXCHANGE33F_TYPED_VALUE_INVALID');
   if(x.$type==='bytes')return base64Decode(x.value,MAX_BYTES);
   if(x.$type==='ed25519-spki'){
    const der=base64Decode(x.value,256);
    let k;try{k=createPublicKey({key:der,format:'der',type:'spki'});}catch{fail('EXCHANGE33F_KEY_INVALID');}
    if(k.asymmetricKeyType!=='ed25519'||k.export({format:'der',type:'spki'}).toString('base64url')!==x.value)
     fail('EXCHANGE33F_KEY_INVALID');
    return k;
   }
   fail('EXCHANGE33F_TYPED_VALUE_INVALID');
  }
  const out={};
  for(const k of Object.keys(x)){
   if(['__proto__','constructor','prototype'].includes(k))fail('EXCHANGE33F_UNSAFE_OBJECT');
   out[k]=walk(x[k],depth+1);
  }
  return out;
 }
 return walk(value,0);
}
function canonicalJson(value){
 let nodes=0;
 function walk(x,depth){
  if(++nodes>150000||depth>80)fail('EXCHANGE33F_COMPLEXITY_LIMIT');
  if(x===null||typeof x==='boolean')return x;
  if(typeof x==='string'){
   if(x.length>MAX_BYTES||/\uD800(?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(x))fail('EXCHANGE33F_STRING_INVALID');
   return x;
  }
  if(typeof x==='number'){
   if(!Number.isFinite(x)||Object.is(x,-0)||(!Number.isSafeInteger(x)&&Number.isInteger(x)))fail('EXCHANGE33F_NUMBER_INVALID');
   return x;
  }
  if(Array.isArray(x)){
   if(!dense(x))fail('EXCHANGE33F_UNSAFE_ARRAY');
   return x.map(v=>walk(v,depth+1));
  }
  if(x===null||typeof x!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(x)))
   fail('EXCHANGE33F_UNSAFE_OBJECT');
  const keys=Reflect.ownKeys(x);
  if(keys.length>1024||keys.some(k=>typeof k!=='string'||['__proto__','constructor','prototype'].includes(k)))
   fail('EXCHANGE33F_UNSAFE_OBJECT');
  const out={};for(const k of keys){
   const d=Object.getOwnPropertyDescriptor(x,k);
   if(!d||!('value' in d)||!d.enumerable)fail('EXCHANGE33F_UNSAFE_OBJECT');
   out[k]=walk(d.value,depth+1);
  }
  return out;
 }
 return walk(value,0);
}
function encode(document){
 const json=JSON.stringify(canonicalJson(portable(document)));
 const bytes=Buffer.from(json,'utf8');
 if(bytes.length>MAX_BYTES)fail('EXCHANGE33F_ENVELOPE_TOO_LARGE');
 return bytes;
}
function metaValid(m){
 return exact(m,['schema','namespaceId','journalScopeDigest','nonce','issuedAt','expiresAt',
  'previousEnvelopeDigest','observerIds','attestationDigests','chainHeads','forkIndex',
  'leftTransitionDigest','rightTransitionDigest'])&&
  m.schema===OFFLINE_CONFLICT_EQUIVOCATION_ENVELOPE_SCHEMA&&id(m.namespaceId)&&
  hex(m.journalScopeDigest)&&id(m.nonce)&&Number.isSafeInteger(m.issuedAt)&&m.issuedAt>=0&&
  Number.isSafeInteger(m.expiresAt)&&m.expiresAt>m.issuedAt&&m.expiresAt-m.issuedAt<=3600000&&
  hex(m.previousEnvelopeDigest)&&dense(m.observerIds)&&m.observerIds.length===2&&
  m.observerIds.every(id)&&m.observerIds[0]<m.observerIds[1]&&
  dense(m.attestationDigests)&&m.attestationDigests.length===2&&m.attestationDigests.every(hex)&&
  dense(m.chainHeads)&&m.chainHeads.length===2&&m.chainHeads.every(hex)&&
  Number.isSafeInteger(m.forkIndex)&&m.forkIndex>=0&&m.forkIndex<8&&
  hex(m.leftTransitionDigest)&&hex(m.rightTransitionDigest)&&m.leftTransitionDigest!==m.rightTransitionDigest;
}
function checkReconciliation(doc){
 if(!exact(doc,['meta','reconciliationArgs','forkEvidence'])||!metaValid(doc.meta))
  fail('EXCHANGE33F_DOCUMENT_INVALID');
 const result=verifyOfflineConflictAuthorityObserverReconciliation(doc.reconciliationArgs);
 if(result.status!=='equivocation'||!result.evidence)fail('EXCHANGE33F_FORK_REQUIRED');
 const m=doc.meta,e=result.evidence;
 if(m.namespaceId!==doc.reconciliationArgs.expectedNamespaceId||
  m.journalScopeDigest!==doc.reconciliationArgs.expectedJournalScopeDigest||
  m.observerIds[0]!==result.observerIds[0]||m.observerIds[1]!==result.observerIds[1]||
  m.attestationDigests[0]!==result.attestationDigests[0]||
  m.attestationDigests[1]!==result.attestationDigests[1]||
  m.chainHeads[0]!==result.chainHeads[0]||m.chainHeads[1]!==result.chainHeads[1]||
  m.forkIndex!==e.forkIndex||m.leftTransitionDigest!==e.leftTransitionDigest||
  m.rightTransitionDigest!==e.rightTransitionDigest||
  JSON.stringify(canonicalJson(doc.forkEvidence))!==JSON.stringify(canonicalJson(e)))fail('EXCHANGE33F_FORK_BINDING_MISMATCH');
 return result;
}
/** Export from independently pinned and fully authenticated source histories. */
export function exportOfflineConflictAuthorityEquivocationEnvelope({reconciliationArgs,nonce,
 issuedAt,expiresAt,previousEnvelopeDigest}={}){
 const safeArgs=revive(portable(reconciliationArgs));
 const result=verifyOfflineConflictAuthorityObserverReconciliation(safeArgs);
 if(result.status!=='equivocation'||!result.evidence)fail('EXCHANGE33F_FORK_REQUIRED');
 const meta={schema:OFFLINE_CONFLICT_EQUIVOCATION_ENVELOPE_SCHEMA,
  namespaceId:reconciliationArgs.expectedNamespaceId,
  journalScopeDigest:reconciliationArgs.expectedJournalScopeDigest,nonce,issuedAt,expiresAt,
  previousEnvelopeDigest,observerIds:[...result.observerIds],
  attestationDigests:[...result.attestationDigests],chainHeads:[...result.chainHeads],
  forkIndex:result.evidence.forkIndex,leftTransitionDigest:result.evidence.leftTransitionDigest,
  rightTransitionDigest:result.evidence.rightTransitionDigest};
 if(!metaValid(meta))fail('EXCHANGE33F_DOCUMENT_INVALID');
 const bytes=encode({meta,reconciliationArgs:safeArgs,forkEvidence:result.evidence});
 // Prove the portable representation can be decoded and recursively verified.
 const decoded=JSON.parse(bytes.toString('utf8'));
 checkReconciliation({meta:decoded.meta,reconciliationArgs:revive(decoded.reconciliationArgs),
  forkEvidence:decoded.forkEvidence});
 return Object.freeze({bytes,digest:sha(Buffer.concat([Buffer.from('TJ-33F-EQUIVOCATION-ENVELOPE\0'),bytes])),
  length:bytes.length,readOnly:true,authorizesRepair:false,authorizesProduction:false});
}
/** Recheck independently retained pins and signed histories from untrusted bytes.
 * Replay history is caller-maintained; passing an empty history does not provide
 * persistent or global replay protection. No network or filesystem mutations.
 */
export function verifyOfflineConflictAuthorityEquivocationEnvelope({bytes,expectedDigest,
 expectedNonce,expectedPreviousEnvelopeDigest,expectedNamespaceId,expectedJournalScopeDigest,
 expectedObserverIds,expectedAttestationDigests,expectedChainHeads,seenEnvelopeDigests,nowMs}={}){
 if(!Buffer.isBuffer(bytes)||bytes.length===0||bytes.length>MAX_BYTES)
  fail('EXCHANGE33F_ENVELOPE_SIZE_INVALID');
 if(!hex(expectedDigest)||!id(expectedNonce)||!hex(expectedPreviousEnvelopeDigest)||
  !id(expectedNamespaceId)||!hex(expectedJournalScopeDigest)||
  !dense(expectedObserverIds)||expectedObserverIds.length!==2||!expectedObserverIds.every(id)||
  !dense(expectedAttestationDigests)||expectedAttestationDigests.length!==2||
  !expectedAttestationDigests.every(hex)||!dense(expectedChainHeads)||
  expectedChainHeads.length!==2||!expectedChainHeads.every(hex)||
  !dense(seenEnvelopeDigests)||seenEnvelopeDigests.length>4096||!seenEnvelopeDigests.every(hex)||
  !Number.isSafeInteger(nowMs)||nowMs<0)fail('EXCHANGE33F_EXTERNAL_PINS_REQUIRED');
 const digest=sha(Buffer.concat([Buffer.from('TJ-33F-EQUIVOCATION-ENVELOPE\0'),bytes]));
 if(digest!==expectedDigest)fail('EXCHANGE33F_ENVELOPE_DIGEST_MISMATCH');
 if(seenEnvelopeDigests.includes(digest))fail('EXCHANGE33F_REPLAY_DETECTED');
 let raw;try{raw=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{fail('EXCHANGE33F_UTF8_INVALID');}
 let doc;try{doc=JSON.parse(raw);}catch{fail('EXCHANGE33F_JSON_INVALID');}
 // Canonical re-encoding rejects duplicate keys, whitespace, reordered keys,
 // alternate escaping, numeric ambiguities and extra/truncated content.
 let canonical;try{canonical=Buffer.from(JSON.stringify(canonicalJson(doc)),'utf8');}catch(e){if(e?.code)throw e;fail('EXCHANGE33F_JSON_INVALID');}
 if(!canonical.equals(bytes))fail('EXCHANGE33F_NONCANONICAL_JSON');
 if(!exact(doc,['meta','reconciliationArgs','forkEvidence'])||!metaValid(doc.meta))
  fail('EXCHANGE33F_DOCUMENT_INVALID');
 const m=doc.meta;
 if(m.nonce!==expectedNonce||m.previousEnvelopeDigest!==expectedPreviousEnvelopeDigest||
  m.namespaceId!==expectedNamespaceId||m.journalScopeDigest!==expectedJournalScopeDigest||
  JSON.stringify(m.observerIds)!==JSON.stringify(expectedObserverIds)||
  JSON.stringify(m.attestationDigests)!==JSON.stringify(expectedAttestationDigests)||
  JSON.stringify(m.chainHeads)!==JSON.stringify(expectedChainHeads))
  fail('EXCHANGE33F_EXTERNAL_PIN_MISMATCH');
 if(nowMs<m.issuedAt||nowMs>m.expiresAt)fail('EXCHANGE33F_EXPIRED_OR_FUTURE');
 const result=checkReconciliation({...doc,reconciliationArgs:revive(doc.reconciliationArgs)});
 return Object.freeze({verified:true,readOnly:true,status:'equivocation',digest,
  previousEnvelopeDigest:m.previousEnvelopeDigest,nonce:m.nonce,
  observerIds:Object.freeze([...result.observerIds]),
  attestationDigests:Object.freeze([...result.attestationDigests]),
  forkIndex:result.evidence.forkIndex,
  leftTransitionDigest:result.evidence.leftTransitionDigest,
  rightTransitionDigest:result.evidence.rightTransitionDigest,
  independentlyPublished:false,globallyComplete:false,persistentReplayProtection:false,
  authorizesRepair:false,authorizesProduction:false,authorizesCheckout:false});
}
