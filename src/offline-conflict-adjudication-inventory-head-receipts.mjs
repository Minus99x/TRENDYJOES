/** Objective 33K: offline, read-only, externally pinned, signed inventory-head
 * observations. Signatures authenticate host assertions, NOT filesystem state,
 * independent time, actual cross-host networking, publication, or consensus.
 */
import {createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
import {offlineConflictAdjudicationInventoryGenesisHead,OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA} from './offline-conflict-adjudication-transcript-inventory.mjs';

export const OFFLINE_CONFLICT_INVENTORY_HEAD_RECEIPT_SCHEMA='TJ-OFFLINE-ADJUDICATION-INVENTORY-HEAD-RECEIPT-1';
const HEX=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9_-]{8,64}$/;
const BODY=['schema','inventorySchema','namespaceId','journalScopeDigest','hostId',
 'genesisHead','inventoryHead','observedAt','expiresAt','nonce'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value' in d&&d.enumerable;})&&
 Object.keys(o).every(k=>keys.includes(k));
const dense=(a,min,max)=>Array.isArray(a)&&Object.getPrototypeOf(a)===Array.prototype&&
 a.length>=min&&a.length<=max&&Reflect.ownKeys(a).length===a.length+1&&
 Array.from({length:a.length},(_,i)=>Object.getOwnPropertyDescriptor(a,String(i))).every(d=>d&&'value' in d&&d.enumerable);
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=256&&typeof h.headDigest==='string'&&HEX.test(h.headDigest);
const same=(a,b)=>a.count===b.count&&a.headDigest===b.headDigest;
const b64=x=>typeof x==='string'&&x.length>0&&x.length<256&&/^[A-Za-z0-9_-]+$/.test(x)&&Buffer.from(x,'base64url').toString('base64url')===x;
const sha=(domain,bytes)=>createHash('sha256').update(domain+'\0').update(bytes).digest('hex');
function validBody(b){
 if(!exact(b,BODY)||Object.keys(b).join('|')!==BODY.join('|')||
  b.schema!==OFFLINE_CONFLICT_INVENTORY_HEAD_RECEIPT_SCHEMA||
  b.inventorySchema!==OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA||
  typeof b.namespaceId!=='string'||!ID.test(b.namespaceId)||
  typeof b.journalScopeDigest!=='string'||!HEX.test(b.journalScopeDigest)||
  typeof b.hostId!=='string'||!ID.test(b.hostId)||!head(b.genesisHead)||!head(b.inventoryHead)||
  b.genesisHead.count!==0||!Number.isSafeInteger(b.observedAt)||b.observedAt<0||
  !Number.isSafeInteger(b.expiresAt)||b.expiresAt<=b.observedAt||
  b.expiresAt-b.observedAt>600000||typeof b.nonce!=='string'||!ID.test(b.nonce))
  fail('EXCHANGE33K_BODY_INVALID');
 const genesis=offlineConflictAdjudicationInventoryGenesisHead(b.namespaceId,b.journalScopeDigest);
 if(!same(b.genesisHead,genesis)||
  (b.inventoryHead.count===0&&!same(b.inventoryHead,genesis)))fail('EXCHANGE33K_GENESIS_MISMATCH');
}
export function offlineConflictInventoryHeadReceiptBodyBytes(body){
 validBody(body);
 return Buffer.from('TJ-33K-INVENTORY-HEAD-RECEIPT\0'+JSON.stringify(body));
}
function parse(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<50||bytes.length>4096)fail('EXCHANGE33K_BYTES_INVALID');
 let r;
 try{r=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
 catch{fail('EXCHANGE33K_BYTES_INVALID');}
 if(!exact(r,['body','signature'])||Object.keys(r).join('|')!=='body|signature'||
  !b64(r.signature)||Buffer.from(r.signature,'base64url').length!==64||
  !Buffer.from(JSON.stringify(r)).equals(bytes))fail('EXCHANGE33K_NONCANONICAL');
 validBody(r.body);
 return r;
}
function pinnedKey(encoded){
 if(!b64(encoded))fail('EXCHANGE33K_HOST_KEY_INVALID');
 let key;
 try{key=createPublicKey({key:Buffer.from(encoded,'base64url'),format:'der',type:'spki'});}
 catch{fail('EXCHANGE33K_HOST_KEY_INVALID');}
 if(key.asymmetricKeyType!=='ed25519'||key.export({format:'der',type:'spki'}).toString('base64url')!==encoded)
  fail('EXCHANGE33K_HOST_KEY_INVALID');
 return key;
}
/** A digest is an address for independently retained bytes, not a signature check. */
export function offlineConflictInventoryHeadReceiptDigest(bytes){
 parse(bytes);
 return sha('TJ-33K-SIGNED-INVENTORY-HEAD',bytes);
}
/** All host pins must come from an independent trust channel. No network/disk I/O. */
export function reconcileOfflineConflictInventoryHeadReceipts({receipts,hostPins,
 expectedNamespaceId,expectedJournalScopeDigest,expectedGenesisHead,nowMs,
 seenDigests=[],seenNonces=[]}={}){
 if(typeof expectedNamespaceId!=='string'||!ID.test(expectedNamespaceId)||
  typeof expectedJournalScopeDigest!=='string'||!HEX.test(expectedJournalScopeDigest)||
  !head(expectedGenesisHead)||expectedGenesisHead.count!==0||
  !same(expectedGenesisHead,offlineConflictAdjudicationInventoryGenesisHead(expectedNamespaceId,expectedJournalScopeDigest))||
  !Number.isSafeInteger(nowMs)||nowMs<0||!dense(receipts,2,8)||
  !dense(hostPins,2,8)||hostPins.length!==receipts.length||
  !dense(seenDigests,0,256)||seenDigests.some(x=>typeof x!=='string'||!HEX.test(x))||
  !dense(seenNonces,0,256)||seenNonces.some(x=>typeof x!=='string'||!ID.test(x)))
  fail('EXCHANGE33K_EXTERNAL_PINS_REQUIRED');
 const usedKeys=new Set(),usedNonces=new Set(),usedDigests=new Set();
 const heads=[];const raw=[];let previousId='';
 for(let i=0;i<hostPins.length;i++){
  const p=hostPins[i];
  if(!exact(p,['hostId','publicKey','expectedReceiptDigest','expectedInventoryHead'])||
   typeof p.hostId!=='string'||!ID.test(p.hostId)||p.hostId<=previousId||
   typeof p.expectedReceiptDigest!=='string'||!HEX.test(p.expectedReceiptDigest)||
   !head(p.expectedInventoryHead))fail('EXCHANGE33K_HOST_PINS_INVALID');
  previousId=p.hostId;
  const key=pinnedKey(p.publicKey),keyDigest=sha('TJ-33K-HOST-KEY',key.export({format:'der',type:'spki'}));
  if(usedKeys.has(keyDigest))fail('EXCHANGE33K_DUPLICATE_HOST_KEY');
  usedKeys.add(keyDigest);
  const bytes=receipts[i],r=parse(bytes),b=r.body;
  if(b.hostId!==p.hostId||b.namespaceId!==expectedNamespaceId||
   b.journalScopeDigest!==expectedJournalScopeDigest||!same(b.genesisHead,expectedGenesisHead)||
   !same(b.inventoryHead,p.expectedInventoryHead))fail('EXCHANGE33K_SCOPE_OR_HEAD_MISMATCH');
  if(nowMs<b.observedAt||nowMs>b.expiresAt)fail('EXCHANGE33K_EXPIRED');
  const digest=offlineConflictInventoryHeadReceiptDigest(bytes);
  if(digest!==p.expectedReceiptDigest)fail('EXCHANGE33K_RECEIPT_PIN_MISMATCH');
  if(usedNonces.has(b.nonce)||usedDigests.has(digest)||seenNonces.includes(b.nonce)||
   seenDigests.includes(digest))fail('EXCHANGE33K_REPLAY');
  usedNonces.add(b.nonce);usedDigests.add(digest);
  if(!verifySignature(null,offlineConflictInventoryHeadReceiptBodyBytes(b),key,
   Buffer.from(r.signature,'base64url')))fail('EXCHANGE33K_SIGNATURE_INVALID');
  heads.push(Object.freeze({...b.inventoryHead}));raw.push(bytes);
 }
 const sameCount=heads.every(h=>h.count===heads[0].count);
 const allSame=heads.every(h=>same(h,heads[0]));
 const status=allSame?'consistent-head':sameCount?'conflicting-same-height':'unresolved-different-heights';
 const evidenceDigest=sha('TJ-33K-RECONCILIATION',Buffer.from(JSON.stringify(raw.map(b=>b.toString('base64url')))));
 return Object.freeze({verified:true,status,hostIds:Object.freeze(hostPins.map(p=>p.hostId)),
  heads:Object.freeze(heads),evidenceDigest,independentlyWitnessedDisk:false,
  independentTimestamp:false,globallyComplete:false,provesAncestry:false,
  authorizesRepair:false,authorizesRecovery:false,authorizesCheckout:false,
  authorizesProduction:false});
}
