/**
 * Objective 32K: portable offline checkpoint split-view conflict proofs.
 * Full historical evidence is retained, not just a claim of equivocation.
 * The caller MUST obtain the exact pin from an independent trust channel;
 * accepting a pin copied from the same untrusted bundle proves no publication.
 */
import {createHash,createPublicKey} from 'node:crypto';
import {verifyOfflineWitnessCheckpointSplitView} from './offline-witness-checkpoint-split-view.mjs';

export const OFFLINE_SPLIT_VIEW_CONFLICT_PROOF_SCHEMA='TJ-OFFLINE-SPLIT-VIEW-CONFLICT-PROOF-1';
export const OFFLINE_SPLIT_VIEW_CONFLICT_PIN_SCHEMA='TJ-OFFLINE-SPLIT-VIEW-CONFLICT-PIN-1';
const fail=code=>{throw Object.assign(new Error(code),{code});};
const sha=(domain,bytes)=>createHash('sha256').update(domain+'\0').update(bytes).digest('hex');
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const own=(x,k)=>Object.hasOwn(Object.getOwnPropertyDescriptor(x,k)||{},'value');
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|')&&keys.every(k=>own(x,k));
const canonical=x=>Buffer.from(JSON.stringify(x));
const MAX_BYTES=3*1024*1024;
function encodeValue(value,state,depth=0){
 if(++state.nodes>30000||depth>45)fail('CONFLICT32K_EVIDENCE_COMPLEXITY');
 if(value===null||typeof value==='boolean'||typeof value==='string'){
  if(typeof value==='string'&&value.length>MAX_BYTES)fail('CONFLICT32K_EVIDENCE_COMPLEXITY');
  return value;
 }
 if(typeof value==='number'){
  if(!Number.isSafeInteger(value))fail('CONFLICT32K_EVIDENCE_TYPE_INVALID');
  return value;
 }
 if(Buffer.isBuffer(value)){
  if(value.length>MAX_BYTES)fail('CONFLICT32K_EVIDENCE_COMPLEXITY');
  return {$tjType:'bytes',value:value.toString('base64url')};
 }
 if(value?.type==='public'&&value?.asymmetricKeyType==='ed25519'&&typeof value.export==='function'){
  const der=value.export({type:'spki',format:'der'});
  return {$tjType:'ed25519-spki',value:der.toString('base64url')};
 }
 if(Array.isArray(value)){
  if(Object.getPrototypeOf(value)!==Array.prototype||Object.keys(value).length!==value.length||value.length>4096)
   fail('CONFLICT32K_EVIDENCE_TYPE_INVALID');
  return Array.from({length:value.length},(_,i)=>{
   if(!own(value,String(i)))fail('CONFLICT32K_EVIDENCE_TYPE_INVALID');
   return encodeValue(value[i],state,depth+1);
  });
 }
 if(!plain(value)||state.seen.has(value))fail('CONFLICT32K_EVIDENCE_TYPE_INVALID');
 state.seen.add(value);
 // Preserve signed-object field order: upstream receipt digests bind JSON.stringify bytes.
 const keys=Object.keys(value);
 if(keys.length>1024||keys.some(k=>['__proto__','constructor','prototype','$tjType'].includes(k)))
  fail('CONFLICT32K_EVIDENCE_TYPE_INVALID');
 const out={};
 for(const k of keys){if(!own(value,k))fail('CONFLICT32K_EVIDENCE_TYPE_INVALID');out[k]=encodeValue(value[k],state,depth+1);}
 state.seen.delete(value);
 return out;
}
function decodeValue(value,state,depth=0){
 if(++state.nodes>30000||depth>45)fail('CONFLICT32K_EVIDENCE_COMPLEXITY');
 if(value===null||typeof value==='boolean'||typeof value==='string')return value;
 if(typeof value==='number'){if(!Number.isSafeInteger(value))fail('CONFLICT32K_EVIDENCE_TYPE_INVALID');return value;}
 if(Array.isArray(value))return value.map(v=>decodeValue(v,state,depth+1));
 if(!plain(value))fail('CONFLICT32K_EVIDENCE_TYPE_INVALID');
 if(Object.hasOwn(value,'$tjType')){
  if(!exact(value,['$tjType','value'])||typeof value.value!=='string'||
   !/^[A-Za-z0-9_-]+$/.test(value.value)||value.value.length>MAX_BYTES*2)
   fail('CONFLICT32K_EVIDENCE_TYPE_INVALID');
  const bytes=Buffer.from(value.value,'base64url');
  if(bytes.toString('base64url')!==value.value||bytes.length>MAX_BYTES)fail('CONFLICT32K_EVIDENCE_TYPE_INVALID');
  if(value.$tjType==='bytes')return bytes;
  if(value.$tjType==='ed25519-spki'){
   try{
    const key=createPublicKey({key:bytes,format:'der',type:'spki'});
    if(key.type!=='public'||key.asymmetricKeyType!=='ed25519'||
     !key.export({type:'spki',format:'der'}).equals(bytes))fail('CONFLICT32K_EVIDENCE_TYPE_INVALID');
    return key;
   }catch{fail('CONFLICT32K_EVIDENCE_TYPE_INVALID');}
  }
  fail('CONFLICT32K_EVIDENCE_TYPE_INVALID');
 }
 const keys=Object.keys(value);
 if(keys.some(k=>['__proto__','constructor','prototype'].includes(k)))fail('CONFLICT32K_EVIDENCE_TYPE_INVALID');
 const out=Object.create(null);
 for(const k of keys)out[k]=decodeValue(value[k],state,depth+1);
 return out;
}
function summary(result){
 if(!result.verified||!result.forkDetected||result.status!=='AUTHENTICATED_SPLIT_VIEW_DETECTED')
  fail('CONFLICT32K_SPLIT_VIEW_REQUIRED');
 return {status:result.status,sharedCheckpointCount:result.sharedCheckpointCount,
  leftCheckpointCount:result.leftCheckpointCount,rightCheckpointCount:result.rightCheckpointCount,
  conflict:result.conflict};
}
function inventory(root,branches,conflict){
 const manifest={rootDigest:sha('TJ-32K-ROOT',canonical(root)),
  leftDigest:sha('TJ-32K-BRANCH',canonical(branches[0])),
  rightDigest:sha('TJ-32K-BRANCH',canonical(branches[1])),
  conflictDigest:sha('TJ-32K-CONFLICT',canonical(conflict))};
 return {...manifest,inventoryDigest:sha('TJ-32K-INVENTORY',canonical(manifest))};
}
function checkedPin(pin){
 if(!exact(pin,['schema','rootDigest','leftDigest','rightDigest','conflictDigest','inventoryDigest'])||
  pin.schema!==OFFLINE_SPLIT_VIEW_CONFLICT_PIN_SCHEMA||
  !['rootDigest','leftDigest','rightDigest','conflictDigest','inventoryDigest'].every(k=>hex(pin[k])))
  fail('CONFLICT32K_EXTERNAL_PIN_REQUIRED');
 return pin;
}
function checkedBytes(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length===0||bytes.length>MAX_BYTES)
  fail('CONFLICT32K_BUNDLE_ENCODING_INVALID');
 let payload;try{payload=JSON.parse(bytes.toString('utf8'));}catch{fail('CONFLICT32K_BUNDLE_ENCODING_INVALID');}
 if(!exact(payload,['schema','root','branches','conflict','inventory'])||
  payload.schema!==OFFLINE_SPLIT_VIEW_CONFLICT_PROOF_SCHEMA||
  !Array.isArray(payload.branches)||payload.branches.length!==2||
  !exact(payload.inventory,['rootDigest','leftDigest','rightDigest','conflictDigest','inventoryDigest']))
  fail('CONFLICT32K_BUNDLE_SCHEMA_INVALID');
 if(!canonical(payload).equals(bytes))fail('CONFLICT32K_NONCANONICAL_BUNDLE');
 return payload;
}
function encodeEvidence(initialAnchor,observations){
 const state={nodes:0,seen:new WeakSet()};
 const root=encodeValue(initialAnchor,state);
 const branches=encodeValue(observations,state);
 if(!Array.isArray(branches)||branches.length!==2)fail('CONFLICT32K_TWO_BRANCHES_REQUIRED');
 return {root,branches};
}
/** Encode a portable *candidate* proof; returns a local pin candidate, not publication. */
export function encodeOfflineSplitViewConflictProof({initialAnchor,observations}={}){
 const result=verifyOfflineWitnessCheckpointSplitView({initialAnchor,observations});
 const conflict=summary(result),{root,branches}=encodeEvidence(initialAnchor,observations);
 const inv=inventory(root,branches,conflict);
 const bytes=canonical({schema:OFFLINE_SPLIT_VIEW_CONFLICT_PROOF_SCHEMA,root,branches,conflict,inventory:inv});
 if(bytes.length>MAX_BYTES)fail('CONFLICT32K_BUNDLE_TOO_LARGE');
 const pin=Object.freeze({schema:OFFLINE_SPLIT_VIEW_CONFLICT_PIN_SCHEMA,...inv});
 return Object.freeze({bytes,pinCandidate:pin,readOnly:true,independentlyPublished:false,
  externalPinPublicationVerified:false,authorizesCheckout:false,productionApproved:false});
}
/** Verify the entire evidence set against an exact caller-provided inventory pin. */
export function verifyOfflineSplitViewConflictProof({bytes,expectedPin}={}){
 const pin=checkedPin(expectedPin),bundle=checkedBytes(bytes);
 const recomputed=inventory(bundle.root,bundle.branches,bundle.conflict);
 for(const k of ['rootDigest','leftDigest','rightDigest','conflictDigest','inventoryDigest']){
  if(bundle.inventory[k]!==recomputed[k]||pin[k]!==recomputed[k])fail('CONFLICT32K_INVENTORY_PIN_MISMATCH');
 }
 const state={nodes:0};
 const initialAnchor=decodeValue(bundle.root,state),observations=decodeValue(bundle.branches,state);
 // Recompute authenticated fork status from every receipt, checkpoint and signer;
 // a consistent manifest alone is never accepted as cryptographic proof.
 const result=verifyOfflineWitnessCheckpointSplitView({initialAnchor,observations});
 const expected=summary(result);
 if(!canonical(expected).equals(canonical(bundle.conflict)))fail('CONFLICT32K_CONFLICT_CLAIM_MISMATCH');
 return Object.freeze({schema:OFFLINE_SPLIT_VIEW_CONFLICT_PROOF_SCHEMA,verified:true,readOnly:true,
  status:result.status,conflict:result.conflict,inventoryDigest:recomputed.inventoryDigest,
  independentlyPublished:false,externalPinPublicationVerified:false,globalUniquenessVerified:false,
  trustedTimestampVerified:false,authorizesCheckout:false,authorizesRemediation:false,productionApproved:false});
}
