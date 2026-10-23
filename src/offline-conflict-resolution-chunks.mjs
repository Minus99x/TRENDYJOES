/**
 * Objective 32V: OFFLINE, read-only, bounded, session-bound chunk transport.
 * Pins, session identity, complete observer anchors and replay history MUST be
 * supplied independently. No network, durable replay database, or authority.
 * The original 32U signed JSON bytes are reassembled without normalization.
 */
import {createHash} from 'node:crypto';
import {TextDecoder} from 'node:util';
import {
 OFFLINE_CONFLICT_RESOLUTION_TRANSPORT_MAX_BYTES,
 offlineConflictResolutionTransportDigest,
 verifyOfflineConflictResolutionTransport
} from './offline-conflict-resolution-transport.mjs';

export const OFFLINE_CONFLICT_RESOLUTION_CHUNK_SCHEMA='TJ-OFFLINE-CONFLICT-RESOLUTION-CHUNKS-1';
export const OFFLINE_CONFLICT_RESOLUTION_CHUNK_MAX_COUNT=128;
export const OFFLINE_CONFLICT_RESOLUTION_CHUNK_MAX_MANIFEST_BYTES=16384;
const HEX=/^[0-9a-f]{64}$/;
const SESSION=/^[A-Za-z0-9_-]{16,96}$/;
const utf8=new TextDecoder('utf-8',{fatal:true});
const fail=code=>{throw Object.assign(new Error(code),{code});};
const digest=(domain,parts)=>{
 const hash=createHash('sha256').update(domain+'\0');
 for(const p of parts)hash.update(p);
 return hash.digest('hex');
};
const validHex=s=>typeof s==='string'&&HEX.test(s);
const validSession=s=>typeof s==='string'&&SESSION.test(s);
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 (Object.getPrototypeOf(o)===Object.prototype||Object.getPrototypeOf(o)===null)&&
 Reflect.ownKeys(o).length===keys.length&&keys.every(k=>{
  const d=Object.getOwnPropertyDescriptor(o,k);
  return d&&'value' in d&&d.enumerable;
 })&&Object.keys(o).every(k=>keys.includes(k));
function copyBytes(input,max,code){
 if(!(Buffer.isBuffer(input)||(input instanceof Uint8Array&&Object.getPrototypeOf(input)===Uint8Array.prototype)))fail(code);
 if(input.byteLength===0||input.byteLength>max)fail(code);
 return Buffer.from(input);
}
function checkChunkSize(size){
 if(!Number.isSafeInteger(size)||size<512||size>65536)fail('EXCHANGE32V_CHUNK_SIZE_INVALID');
}
export function offlineConflictResolutionChunkDigest({sessionId,index,bytes}={}){
 if(!validSession(sessionId)||!Number.isSafeInteger(index)||index<0||index>=OFFLINE_CONFLICT_RESOLUTION_CHUNK_MAX_COUNT)
  fail('EXCHANGE32V_CHUNK_INVALID');
 const copy=copyBytes(bytes,65536,'EXCHANGE32V_CHUNK_INVALID');
 return digest('TJ-32V-CHUNK',[sessionId,'\0',String(index),'\0',copy]);
}
export function offlineConflictResolutionChunkManifestDigest(manifestBytes){
 const bytes=copyBytes(manifestBytes,OFFLINE_CONFLICT_RESOLUTION_CHUNK_MAX_MANIFEST_BYTES,'EXCHANGE32V_MANIFEST_INVALID');
 return digest('TJ-32V-MANIFEST',[bytes]);
}
function validManifest(m){
 if(!exact(m,['schema','sessionId','transportDigest','byteLength','chunkSize','chunkCount','chunkDigests'])||
  m.schema!==OFFLINE_CONFLICT_RESOLUTION_CHUNK_SCHEMA||!validSession(m.sessionId)||!validHex(m.transportDigest)||
  !Number.isSafeInteger(m.byteLength)||m.byteLength<1||m.byteLength>OFFLINE_CONFLICT_RESOLUTION_TRANSPORT_MAX_BYTES)
  fail('EXCHANGE32V_MANIFEST_INVALID');
 checkChunkSize(m.chunkSize);
 const count=Math.ceil(m.byteLength/m.chunkSize);
 if(!Number.isSafeInteger(m.chunkCount)||count!==m.chunkCount||count>OFFLINE_CONFLICT_RESOLUTION_CHUNK_MAX_COUNT||
  !Array.isArray(m.chunkDigests)||Object.getPrototypeOf(m.chunkDigests)!==Array.prototype||
  Reflect.ownKeys(m.chunkDigests).length!==count+1||m.chunkDigests.length!==count)
  fail('EXCHANGE32V_MANIFEST_INVALID');
 for(let i=0;i<count;i++){
  const d=Object.getOwnPropertyDescriptor(m.chunkDigests,String(i));
  if(!d||!('value' in d)||!d.enumerable||!validHex(d.value))fail('EXCHANGE32V_MANIFEST_INVALID');
 }
}
function parseManifest(bytes){
 let text,m;
 try{
  text=utf8.decode(bytes);
  if(text.charCodeAt(0)===0xfeff)fail('EXCHANGE32V_MANIFEST_INVALID');
  m=JSON.parse(text);
 }catch{fail('EXCHANGE32V_MANIFEST_INVALID');}
 validManifest(m);
 // Fixed field order + exact compact bytes also reject duplicate JSON keys,
 // escaped key aliases, noncanonical numbers and trailing JSON/whitespace.
 if(JSON.stringify(m)!==text)fail('EXCHANGE32V_MANIFEST_INVALID');
 return m;
}
/** The encoder's pins are convenience output, NOT independently published pins. */
export function encodeOfflineConflictResolutionChunks({transportBytes,sessionId,chunkSize=16384}={}){
 if(!validSession(sessionId))fail('EXCHANGE32V_SESSION_INVALID');
 checkChunkSize(chunkSize);
 const bytes=copyBytes(transportBytes,OFFLINE_CONFLICT_RESOLUTION_TRANSPORT_MAX_BYTES,'EXCHANGE32V_TRANSPORT_INVALID');
 const count=Math.ceil(bytes.length/chunkSize);
 if(count>OFFLINE_CONFLICT_RESOLUTION_CHUNK_MAX_COUNT)fail('EXCHANGE32V_TOO_MANY_CHUNKS');
 const chunks=Array.from({length:count},(_,index)=>{
  const data=Buffer.from(bytes.subarray(index*chunkSize,Math.min(bytes.length,(index+1)*chunkSize)));
  return Object.freeze({sessionId,index,bytes:data});
 });
 const manifest={schema:OFFLINE_CONFLICT_RESOLUTION_CHUNK_SCHEMA,sessionId,
  transportDigest:offlineConflictResolutionTransportDigest(bytes),byteLength:bytes.length,
  chunkSize,chunkCount:count,chunkDigests:chunks.map(c=>offlineConflictResolutionChunkDigest(c))};
 const manifestBytes=Buffer.from(JSON.stringify(manifest),'utf8');
 if(manifestBytes.length>OFFLINE_CONFLICT_RESOLUTION_CHUNK_MAX_MANIFEST_BYTES)fail('EXCHANGE32V_MANIFEST_INVALID');
 const manifestDigest=offlineConflictResolutionChunkManifestDigest(manifestBytes);
 return Object.freeze({manifestBytes,manifestDigest,transportDigest:manifest.transportDigest,
  chunks:Object.freeze(chunks.map(c=>Object.freeze({...c,manifestDigest}))),
  independentlyPublished:false,authorizesProduction:false});
}
/**
 * `previouslyAcceptedManifestDigests` is an independently maintained snapshot.
 * Verification NEVER mutates it. A caller must persist acceptance atomically
 * elsewhere to guarantee single-use across processes/crashes.
 */
export function verifyOfflineConflictResolutionChunks({manifestBytes,expectedManifestDigest,
 expectedSessionId,expectedTransportDigest,previouslyAcceptedManifestDigests,chunks,
 anchors,expectedObserverIds,expectedUnionDigest,nowMs}={}){
 if(!validHex(expectedManifestDigest)||!validHex(expectedTransportDigest)||!validSession(expectedSessionId)||
  !(previouslyAcceptedManifestDigests instanceof Set)||
  Object.getPrototypeOf(previouslyAcceptedManifestDigests)!==Set.prototype)
  fail('EXCHANGE32V_EXTERNAL_PINS_REQUIRED');
 if(Set.prototype.has.call(previouslyAcceptedManifestDigests,expectedManifestDigest))
  fail('EXCHANGE32V_REPLAY_DETECTED');
 const manifestCopy=copyBytes(manifestBytes,OFFLINE_CONFLICT_RESOLUTION_CHUNK_MAX_MANIFEST_BYTES,'EXCHANGE32V_MANIFEST_INVALID');
 if(offlineConflictResolutionChunkManifestDigest(manifestCopy)!==expectedManifestDigest)
  fail('EXCHANGE32V_MANIFEST_PIN_MISMATCH');
 const manifest=parseManifest(manifestCopy);
 if(manifest.sessionId!==expectedSessionId||manifest.transportDigest!==expectedTransportDigest)
  fail('EXCHANGE32V_SESSION_OR_TRANSPORT_MISMATCH');
 if(!Array.isArray(chunks)||Object.getPrototypeOf(chunks)!==Array.prototype||
  chunks.length!==manifest.chunkCount||Reflect.ownKeys(chunks).length!==chunks.length+1)
  fail('EXCHANGE32V_CHUNK_COUNT_MISMATCH');
 const parts=[];
 for(let index=0;index<chunks.length;index++){
  const d=Object.getOwnPropertyDescriptor(chunks,String(index));
  if(!d||!('value' in d)||!d.enumerable||
   !exact(d.value,['sessionId','index','bytes','manifestDigest']))fail('EXCHANGE32V_CHUNK_INVALID');
  const chunk=d.value;
  if(chunk.sessionId!==manifest.sessionId||chunk.manifestDigest!==expectedManifestDigest||chunk.index!==index)
   fail('EXCHANGE32V_CHUNK_BINDING_MISMATCH');
  const bytes=copyBytes(chunk.bytes,manifest.chunkSize,'EXCHANGE32V_CHUNK_INVALID');
  const expectedLength=index===chunks.length-1?manifest.byteLength-index*manifest.chunkSize:manifest.chunkSize;
  if(bytes.length!==expectedLength)fail('EXCHANGE32V_CHUNK_LENGTH_MISMATCH');
  if(offlineConflictResolutionChunkDigest({sessionId:chunk.sessionId,index,bytes})!==manifest.chunkDigests[index])
   fail('EXCHANGE32V_CHUNK_DIGEST_MISMATCH');
  parts.push(bytes);
 }
 const joined=Buffer.concat(parts,manifest.byteLength);
 if(offlineConflictResolutionTransportDigest(joined)!==expectedTransportDigest)
  fail('EXCHANGE32V_TRANSPORT_PIN_MISMATCH');
 const verified=verifyOfflineConflictResolutionTransport({bytes:joined,expectedByteDigest:expectedTransportDigest,
  anchors,expectedObserverIds,expectedUnionDigest,nowMs});
 return Object.freeze({...verified,chunkManifestVerified:true,chunkCount:manifest.chunkCount,
  chunkManifestDigest:expectedManifestDigest,sessionId:expectedSessionId,
  replayCheckedAgainstCallerSnapshot:true,durableReplayProtection:false,
  independentlyPublished:false,authorizesProduction:false});
}
