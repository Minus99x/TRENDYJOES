/**
 * Objective 32U: bounded, exact-byte, offline-only transport for 32T evidence.
 * The byte pin, observer roster, per-observer anchors and union pin MUST arrive
 * over a separate trusted path. Transport never carries or generates trust.
 *
 * Wire normal form is compact JSON.stringify in ORIGINAL property order: 32S
 * signed proof digests depend on their existing serialized property order.
 * This is NOT a key-sorted or representation-independent JSON signature format.
 */
import {createHash} from 'node:crypto';
import {TextDecoder} from 'node:util';
import {verifyOfflineConflictResolutionInventories} from './offline-conflict-resolution-inventory.mjs';

export const OFFLINE_CONFLICT_RESOLUTION_TRANSPORT_SCHEMA='TJ-OFFLINE-CONFLICT-RESOLUTION-TRANSPORT-1';
export const OFFLINE_CONFLICT_RESOLUTION_TRANSPORT_MAX_BYTES=1048576;
const HEX=/^[0-9a-f]{64}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const utf8=new TextDecoder('utf-8',{fatal:true,ignoreBOM:false});
const object=o=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 (Object.getPrototypeOf(o)===Object.prototype||Object.getPrototypeOf(o)===null);

function safeTree(value,ancestors=new Set(),depth=0,budget={nodes:0}){
 if(++budget.nodes>100000||depth>64)fail('EXCHANGE32U_STRUCTURE_INVALID');
 if(value===null||typeof value==='boolean')return;
 if(typeof value==='string'){
  // UTF-8 replaces lone UTF-16 surrogates, which must never silently alias pins.
  if(/(?:[\uD800-\uDBFF](?![\uDC00-\uDFFF]))|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value))
   fail('EXCHANGE32U_STRUCTURE_INVALID');
  return;
 }
 if(typeof value==='number'){
  if(!Number.isSafeInteger(value))fail('EXCHANGE32U_STRUCTURE_INVALID');
  return;
 }
 if(!object(value)&&!Array.isArray(value))fail('EXCHANGE32U_STRUCTURE_INVALID');
 if(ancestors.has(value))fail('EXCHANGE32U_STRUCTURE_INVALID');
 ancestors.add(value);
 if(Array.isArray(value)){
  if(Object.getPrototypeOf(value)!==Array.prototype||value.length>100000||
   Reflect.ownKeys(value).length!==value.length+1)fail('EXCHANGE32U_STRUCTURE_INVALID');
  for(let i=0;i<value.length;i++){
   const d=Object.getOwnPropertyDescriptor(value,String(i));
   if(!d||!('value' in d)||!d.enumerable)fail('EXCHANGE32U_STRUCTURE_INVALID');
   safeTree(d.value,ancestors,depth+1,budget);
  }
 }else{
  const keys=Reflect.ownKeys(value);
  if(keys.length>128)fail('EXCHANGE32U_STRUCTURE_INVALID');
  for(const key of keys){
   if(typeof key!=='string'||key==='__proto__'||key==='constructor'||key==='prototype')
    fail('EXCHANGE32U_STRUCTURE_INVALID');
   safeTree(key,ancestors,depth+1,budget);
   const d=Object.getOwnPropertyDescriptor(value,key);
   if(!d||!('value' in d)||!d.enumerable)fail('EXCHANGE32U_STRUCTURE_INVALID');
   safeTree(d.value,ancestors,depth+1,budget);
  }
 }
 ancestors.delete(value);
}
function bytesCopy(input){
 if(!(Buffer.isBuffer(input)||(input instanceof Uint8Array&&Object.getPrototypeOf(input)===Uint8Array.prototype)))
  fail('EXCHANGE32U_BYTES_REQUIRED');
 if(input.byteLength===0||input.byteLength>OFFLINE_CONFLICT_RESOLUTION_TRANSPORT_MAX_BYTES)
  fail('EXCHANGE32U_SIZE_INVALID');
 return Buffer.from(input);
}
export function offlineConflictResolutionTransportDigest(input){
 const bytes=bytesCopy(input);
 return createHash('sha256').update('TJ-32U-RESOLUTION-TRANSPORT\0').update(bytes).digest('hex');
}
export function encodeOfflineConflictResolutionTransport(views){
 const envelope={schema:OFFLINE_CONFLICT_RESOLUTION_TRANSPORT_SCHEMA,views};
 safeTree(envelope);
 if(!Array.isArray(views)||views.length<2||views.length>8)fail('EXCHANGE32U_STRUCTURE_INVALID');
 const raw=Buffer.from(JSON.stringify(envelope),'utf8');
 const bytes=bytesCopy(raw);
 return Object.freeze({bytes,byteDigest:offlineConflictResolutionTransportDigest(bytes),
  byteLength:bytes.length,independentlyPublished:false,authorizesProduction:false});
}
/**
 * Preflight JSON grammar and duplicate decoded member names BEFORE JSON.parse.
 * JSON.parse alone silently accepts duplicate keys. Reject whitespace and all
 * non-normal JSON spellings via exact JSON.stringify roundtrip after parsing.
 */
function checkJSON(text){
 let pos=0,nodes=0;
 const bad=()=>fail('EXCHANGE32U_JSON_INVALID');
 const str=()=>{
  const start=pos;
  if(text[pos++]!=='"')bad();
  while(pos<text.length){
   const c=text.charCodeAt(pos++);
   if(c===34)return JSON.parse(text.slice(start,pos));
   if(c<32)bad();
   if(c===92){
    if(pos>=text.length)bad();
    const esc=text[pos++];
    if(esc==='u'){
     if(!/^[0-9a-fA-F]{4}$/.test(text.slice(pos,pos+4)))bad();
     pos+=4;
    }else if(!'"\\/bfnrt'.includes(esc))bad();
   }
  }
  bad();
 };
 const parse=(depth=0)=>{
  if(++nodes>100000||depth>64||pos>=text.length)bad();
  const c=text[pos];
  if(c==='"'){str();return;}
  if(c==='{'){
   pos++;const seen=new Set();let count=0;
   if(text[pos]==='}'){pos++;return;}
   while(pos<text.length){
    if(text[pos]!=='"'||++count>128)bad();
    const key=str();
    if(key==='__proto__'||key==='constructor'||key==='prototype'||seen.has(key))bad();
    seen.add(key);
    if(text[pos++]!==':')bad();
    parse(depth+1);
    if(text[pos]==='}'){pos++;return;}
    if(text[pos++]!==',')bad();
   }
   bad();
  }
  if(c==='['){
   pos++;let count=0;
   if(text[pos]===']'){pos++;return;}
   while(pos<text.length){
    if(++count>100000)bad();parse(depth+1);
    if(text[pos]===']'){pos++;return;}
    if(text[pos++]!==',')bad();
   }
   bad();
  }
  for(const literal of ['true','false','null']){
   if(text.startsWith(literal,pos)){pos+=literal.length;return;}
  }
  const match=/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(pos));
  if(!match)bad();pos+=match[0].length;
 };
 parse();if(pos!==text.length)bad();
}
export function verifyOfflineConflictResolutionTransport({bytes,expectedByteDigest,
 anchors,expectedObserverIds,expectedUnionDigest,nowMs}={}){
 if(typeof expectedByteDigest!=='string'||!HEX.test(expectedByteDigest))
  fail('EXCHANGE32U_EXTERNAL_BYTE_PIN_REQUIRED');
 const copy=bytesCopy(bytes);
 if(offlineConflictResolutionTransportDigest(copy)!==expectedByteDigest)
  fail('EXCHANGE32U_BYTE_PIN_MISMATCH');
 let text,parsed;
 try{
  if(copy.length>=3&&copy[0]===0xef&&copy[1]===0xbb&&copy[2]===0xbf)
   fail('EXCHANGE32U_JSON_INVALID');
  text=utf8.decode(copy);
  if(text.charCodeAt(0)===0xfeff)fail('EXCHANGE32U_JSON_INVALID');
  checkJSON(text);
  parsed=JSON.parse(text);
  safeTree(parsed);
  if(JSON.stringify(parsed)!==text)fail('EXCHANGE32U_NONCANONICAL_BYTES');
 }catch(e){if(e?.code?.startsWith('EXCHANGE32U_'))throw e;fail('EXCHANGE32U_JSON_INVALID');}
 if(!object(parsed)||Reflect.ownKeys(parsed).length!==2||
  Object.keys(parsed).join(',')!=='schema,views'||
  parsed.schema!==OFFLINE_CONFLICT_RESOLUTION_TRANSPORT_SCHEMA||
  !Object.hasOwn(parsed,'views'))fail('EXCHANGE32U_STRUCTURE_INVALID');
 const result=verifyOfflineConflictResolutionInventories({views:parsed.views,anchors,
  expectedObserverIds,expectedUnionDigest,nowMs});
 return Object.freeze({...result,transportBytesVerified:true,transportByteDigest:expectedByteDigest,
  transportByteLength:copy.length,independentlyPublished:false,authorizesProduction:false});
}
