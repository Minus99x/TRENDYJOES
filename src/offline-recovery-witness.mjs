/**
 * Objective 31E: independent signed witness contract and at-most-once recovery
 * reservation coordinator. Offline interfaces only; callers must arrange truly
 * independent witness custody, freshness, and durable permit-ledger retention.
 */
import {createHash,randomBytes,verify as verifySignature} from 'node:crypto';

export const OFFLINE_WITNESS_SCHEMA='TJ-OFFLINE-ANCHOR-WITNESS-1';
const ROOT='0'.repeat(64);
const HEX=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9_-]{12,80}$/;
const fields=['schema','witnessId','registryId','anchorType','eventCount','historyDigest','anchor','challenge','issuedAt','expiresAt'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>object(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const sha=x=>createHash('sha256').update(x).digest('hex');
function validAnchor(type,a){
 return a===null||(type==='registry'?exact(a,['sequence','mac'])&&Number.isSafeInteger(a.sequence)&&a.sequence>=1&&HEX.test(a.mac):
 exact(a,['index','digest'])&&Number.isSafeInteger(a.index)&&a.index>=1&&a.index<=10000&&HEX.test(a.digest));
}
function config({registryId,anchorType,witnesses,quorum}){
 if(!ID.test(registryId||'')||!['registry','journal'].includes(anchorType)||!Array.isArray(witnesses)||
    witnesses.length<2||witnesses.length>10||!Number.isSafeInteger(quorum)||
    quorum<=witnesses.length/2||quorum>witnesses.length)fail('WITNESS_CONFIGURATION');
 const ids=new Set(),keys=new Set();
 for(const w of witnesses){
  if(!exact(w,['id','publicKey','readLatest'])||!ID.test(w.id||'')||ids.has(w.id)||
    w.publicKey?.type!=='public'||w.publicKey?.asymmetricKeyType!=='ed25519'||typeof w.readLatest!=='function')fail('WITNESS_CONFIGURATION');
  const key=sha(w.publicKey.export({type:'spki',format:'der'}));
  if(keys.has(key))fail('WITNESS_CONFIGURATION');
  keys.add(key);ids.add(w.id);
 }
}
/** Every supplied signed receipt must agree; quorum cannot override equivocation. */
export function verifyOfflineWitnessQuorum({registryId,anchorType,witnesses,quorum,receipts,snapshot,challenge,now=Date.now()}={}){
 config({registryId,anchorType,witnesses,quorum});
 if(!Array.isArray(receipts)||receipts.length<quorum||receipts.length>witnesses.length||
    !Number.isSafeInteger(now)||typeof challenge!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(challenge)||Buffer.from(challenge,'base64url').toString('base64url')!==challenge||!exact(snapshot,['anchor','eventCount','historyDigest'])||
    !Number.isSafeInteger(snapshot.eventCount)||snapshot.eventCount<0||snapshot.eventCount>10000||
    !HEX.test(snapshot.historyDigest)||!validAnchor(anchorType,snapshot.anchor)||
    (snapshot.eventCount===0)!==(snapshot.anchor===null)||
    (snapshot.eventCount===0)!==(snapshot.historyDigest===ROOT))fail('WITNESS_SNAPSHOT_INVALID');
 const byId=new Map(witnesses.map(w=>[w.id,w])),seen=new Set();
 for(const r of receipts){
  if(!exact(r,[...fields,'signature'])||r.schema!==OFFLINE_WITNESS_SCHEMA||
     r.registryId!==registryId||r.anchorType!==anchorType||!byId.has(r.witnessId)||seen.has(r.witnessId)||
     !Number.isSafeInteger(r.eventCount)||r.eventCount!==snapshot.eventCount||
     r.historyDigest!==snapshot.historyDigest||!same(r.anchor,snapshot.anchor)||r.challenge!==challenge||
     !Number.isSafeInteger(r.issuedAt)||!Number.isSafeInteger(r.expiresAt)||
     r.issuedAt>now||r.expiresAt<=now||r.expiresAt<=r.issuedAt||r.expiresAt-r.issuedAt>300000||
     typeof r.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(r.signature))fail('WITNESS_RECEIPT_INVALID');
  const sig=Buffer.from(r.signature,'base64url');
  const body=Object.fromEntries(fields.map(k=>[k,r[k]]));
  if(sig.length!==64||sig.toString('base64url')!==r.signature||
     !verifySignature(null,Buffer.from(`${OFFLINE_WITNESS_SCHEMA}\0${JSON.stringify(body)}`),byId.get(r.witnessId).publicKey,sig))fail('WITNESS_SIGNATURE_INVALID');
  seen.add(r.witnessId);
 }
 return Object.freeze({verified:true,count:seen.size,required:quorum,productionApproved:false});
}

export function createOfflineWitnessedRecoveryGuard({adapter,ledger,registryId,anchorType,witnesses,quorum}={}){
 config({registryId,anchorType,witnesses,quorum});
 if(!adapter||['inspect','inspectRecoveryState','validateRecoveryAuthorization','recoverInterruptedCommit'].some(k=>typeof adapter[k]!=='function')||
    !ledger||typeof ledger.reserve!=='function'||typeof ledger.inspect!=='function')fail('WITNESS_CONFIGURATION');
 async function verifySnapshot(snapshot){
  // readLatest is an injected independent source; never accept caller-provided
  // receipts as proof of freshness. Errors from ANY witness fail closed.
  const challenge=randomBytes(32).toString('base64url');
  const receipts=await Promise.all(witnesses.map(w=>w.readLatest({challenge,registryId,anchorType}))); 
  return verifyOfflineWitnessQuorum({registryId,anchorType,witnesses,quorum,receipts,challenge,
   snapshot:{anchor:snapshot.anchor,eventCount:snapshot.eventCount,historyDigest:snapshot.historyDigest}});
 }
 async function readVerified(){
  const state=await adapter.inspect();await verifySnapshot(state);
  // Re-read under the adapter lock after network-like asynchronous witnesses;
  // reject a concurrent head change instead of returning a stale snapshot.
  const again=await adapter.inspect();
  if(!same(state,again))fail('WITNESS_CONCURRENT_ANCHOR_CHANGE');
  return Object.freeze({...structuredClone(state),witnessVerified:true,productionApproved:false});
 }
 async function recoverOnce({authorization}={}){
  // Invalid signatures are rejected before burning the one-time permit.
  adapter.validateRecoveryAuthorization(authorization);
  const state=await adapter.inspectRecoveryState();
  if(!state.pending||!same(state.anchor,authorization.expectedAnchor)||
     state.pendingDigest!==authorization.pendingDigest)fail('WITNESS_RECOVERY_STATE_MISMATCH');
  await verifySnapshot(state);
  const again=await adapter.inspectRecoveryState();
  if(!same(state,again))fail('WITNESS_CONCURRENT_ANCHOR_CHANGE');
  // Durable at-most-once reservation happens BEFORE any potentially
  // irreversible recovery. An ambiguous crash permanently burns the permit;
  // forensic review and a fresh authorization are required, never blind retry.
  const reservation=await ledger.reserve({authorizationId:authorization.authorizationId,
   permitDigest:sha(Buffer.from(JSON.stringify(authorization))),pendingDigest:authorization.pendingDigest});
  const result=await adapter.recoverInterruptedCommit({authorization});
  return Object.freeze({...result,reservationIndex:reservation.index,witnessVerifiedBeforeRecovery:true,productionApproved:false});
 }
 return Object.freeze({readVerified,recoverOnce});
}
