/** Objective 33P — offline verification of independently signed registry-head
 * publication assertions. Signatures authenticate assertions, not disk state,
 * timestamp, actual publication, global consistency, or remote acquisition.
 */
import {createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
export const OFFLINE_CONFLICT_ACQUISITION_HEAD_PUBLICATION_SCHEMA='TJ-OFFLINE-33P-ACQUISITION-HEAD-PUBLICATION-1';
const HEX=/^[0-9a-f]{64}$/,ID=/^[A-Za-z0-9_-]{8,64}$/,DEC=/^(0|[1-9][0-9]*)$/;
const BODY=['schema','namespaceId','journalScopeDigest','targetRegistryId','targetHostId',
 'publisherId','registryGenesisHead','registryHead','inventoryHead','registryDirectoryPin',
 'observedAtMs','expiresAtMs','nonce'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value'in d&&d.enumerable;})&&
 Object.keys(o).every(k=>keys.includes(k));
const dense=(a,min,max)=>Array.isArray(a)&&Object.getPrototypeOf(a)===Array.prototype&&
 a.length>=min&&a.length<=max&&Reflect.ownKeys(a).length===a.length+1&&
 Array.from({length:a.length},(_,i)=>Object.getOwnPropertyDescriptor(a,String(i))).every(d=>d&&'value'in d&&d.enumerable);
const head=(h,max)=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=max&&typeof h.headDigest==='string'&&HEX.test(h.headDigest);
const same=(a,b)=>a.count===b.count&&a.headDigest===b.headDigest;
const pin=p=>exact(p,['dev','ino'])&&DEC.test(p.dev)&&DEC.test(p.ino)&&p.ino!=='0';
const samePin=(a,b)=>a.dev===b.dev&&a.ino===b.ino;
const b64=x=>typeof x==='string'&&x.length>0&&x.length<256&&/^[A-Za-z0-9_-]+$/.test(x)&&Buffer.from(x,'base64url').toString('base64url')===x;
const digest=(domain,bytes)=>createHash('sha256').update(domain+'\0').update(bytes).digest('hex');
function validBody(b){
 if(!exact(b,BODY)||Object.keys(b).join('|')!==BODY.join('|')||
  b.schema!==OFFLINE_CONFLICT_ACQUISITION_HEAD_PUBLICATION_SCHEMA||
  ![b.namespaceId,b.targetRegistryId,b.targetHostId,b.publisherId,b.nonce].every(x=>typeof x==='string'&&ID.test(x))||
  typeof b.journalScopeDigest!=='string'||!HEX.test(b.journalScopeDigest)||
  !head(b.registryGenesisHead,64)||b.registryGenesisHead.count!==0||
  !head(b.registryHead,64)||!head(b.inventoryHead,256)||!pin(b.registryDirectoryPin)||
  !Number.isSafeInteger(b.observedAtMs)||b.observedAtMs<0||
  !Number.isSafeInteger(b.expiresAtMs)||b.expiresAtMs<=b.observedAtMs||
  b.expiresAtMs-b.observedAtMs>600000)fail('EXCHANGE33P_BODY_INVALID');
 if(b.registryHead.count===0&&!same(b.registryHead,b.registryGenesisHead))fail('EXCHANGE33P_GENESIS_MISMATCH');
 if(b.registryHead.count>b.inventoryHead.count)fail('EXCHANGE33P_HEAD_COUNT_MISMATCH');
}
export function offlineConflictAcquisitionHeadPublicationBodyBytes(body){
 validBody(body);return Buffer.from('TJ-33P-ACQUISITION-HEAD-PUBLICATION\0'+JSON.stringify(body));
}
function parse(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<80||bytes.length>4096)fail('EXCHANGE33P_BYTES_INVALID');
 let r;try{r=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
 catch{fail('EXCHANGE33P_BYTES_INVALID');}
 if(!exact(r,['body','signature'])||Object.keys(r).join('|')!=='body|signature'||
  !b64(r.signature)||Buffer.from(r.signature,'base64url').length!==64||
  !Buffer.from(JSON.stringify(r)).equals(bytes))fail('EXCHANGE33P_NONCANONICAL');
 validBody(r.body);return r;
}
function publicKey(encoded){
 if(!b64(encoded))fail('EXCHANGE33P_PUBLISHER_KEY_INVALID');
 let key;try{key=createPublicKey({key:Buffer.from(encoded,'base64url'),format:'der',type:'spki'});}
 catch{fail('EXCHANGE33P_PUBLISHER_KEY_INVALID');}
 if(key.asymmetricKeyType!=='ed25519'||key.export({format:'der',type:'spki'}).toString('base64url')!==encoded)
  fail('EXCHANGE33P_PUBLISHER_KEY_INVALID');
 return key;
}
export function offlineConflictAcquisitionHeadPublicationDigest(bytes){
 parse(bytes);return digest('TJ-33P-SIGNED-REGISTRY-HEAD',bytes);
}
/** Pins must be independently obtained and retained. No filesystem/network I/O.
 * minimumPinnedHead is an external rollback floor, NOT an ancestry proof.
 */
export function reconcileOfflineConflictAcquisitionHeadPublications({receipts,publisherPins,
 expectedNamespaceId,expectedJournalScopeDigest,expectedTargetRegistryId,expectedTargetHostId,
 expectedRegistryGenesisHead,expectedRegistryDirectoryPin,minimumPinnedHead,nowMs,
 seenDigests=[],seenNonces=[]}={}){
 if(![expectedNamespaceId,expectedTargetRegistryId,expectedTargetHostId].every(x=>typeof x==='string'&&ID.test(x))||
  typeof expectedJournalScopeDigest!=='string'||!HEX.test(expectedJournalScopeDigest)||
  !head(expectedRegistryGenesisHead,64)||expectedRegistryGenesisHead.count!==0||
  !pin(expectedRegistryDirectoryPin)||!head(minimumPinnedHead,64)||
  !Number.isSafeInteger(nowMs)||nowMs<0||!dense(receipts,2,8)||!dense(publisherPins,2,8)||
  publisherPins.length!==receipts.length||
  !dense(seenDigests,0,256)||seenDigests.some(x=>typeof x!=='string'||!HEX.test(x))||
  !dense(seenNonces,0,256)||seenNonces.some(x=>typeof x!=='string'||!ID.test(x)))
  fail('EXCHANGE33P_EXTERNAL_PINS_REQUIRED');
 if(minimumPinnedHead.count===0&&!same(minimumPinnedHead,expectedRegistryGenesisHead))
  fail('EXCHANGE33P_EXTERNAL_PINS_REQUIRED');
 const usedKeys=new Set(),usedNonces=new Set(),usedDigests=new Set(),heads=[],inventories=[],receiptBytes=[];
 let previousId='';
 for(let i=0;i<publisherPins.length;i++){
  const p=publisherPins[i];
  if(!exact(p,['publisherId','publicKey','expectedReceiptDigest'])||
   typeof p.publisherId!=='string'||!ID.test(p.publisherId)||p.publisherId<=previousId||
   typeof p.expectedReceiptDigest!=='string'||!HEX.test(p.expectedReceiptDigest))fail('EXCHANGE33P_PUBLISHER_PINS_INVALID');
  previousId=p.publisherId;
  const key=publicKey(p.publicKey),keyDigest=digest('TJ-33P-PUBLISHER-KEY',key.export({format:'der',type:'spki'}));
  if(usedKeys.has(keyDigest))fail('EXCHANGE33P_DUPLICATE_PUBLISHER_KEY');
  usedKeys.add(keyDigest);
  const bytes=receipts[i],r=parse(bytes),b=r.body;
  if(b.publisherId!==p.publisherId||b.namespaceId!==expectedNamespaceId||
   b.journalScopeDigest!==expectedJournalScopeDigest||b.targetRegistryId!==expectedTargetRegistryId||
   b.targetHostId!==expectedTargetHostId||!same(b.registryGenesisHead,expectedRegistryGenesisHead)||
   !samePin(b.registryDirectoryPin,expectedRegistryDirectoryPin))fail('EXCHANGE33P_SCOPE_OR_PIN_MISMATCH');
  if(nowMs<b.observedAtMs||nowMs>b.expiresAtMs)fail('EXCHANGE33P_EXPIRED');
  const d=offlineConflictAcquisitionHeadPublicationDigest(bytes);
  if(d!==p.expectedReceiptDigest)fail('EXCHANGE33P_RECEIPT_PIN_MISMATCH');
  if(usedNonces.has(b.nonce)||usedDigests.has(d)||seenNonces.includes(b.nonce)||seenDigests.includes(d))
   fail('EXCHANGE33P_REPLAY');
  usedNonces.add(b.nonce);usedDigests.add(d);
  if(!verifySignature(null,offlineConflictAcquisitionHeadPublicationBodyBytes(b),key,
   Buffer.from(r.signature,'base64url')))fail('EXCHANGE33P_SIGNATURE_INVALID');
  if(b.registryHead.count<minimumPinnedHead.count||
   (b.registryHead.count===minimumPinnedHead.count&&!same(b.registryHead,minimumPinnedHead)))
   fail('EXCHANGE33P_ROLLBACK_OR_FORK_AGAINST_PIN');
  heads.push(Object.freeze({...b.registryHead}));inventories.push(Object.freeze({...b.inventoryHead}));receiptBytes.push(bytes);
 }
 const equalCounts=heads.every(h=>h.count===heads[0].count);
 const equalHeads=heads.every(h=>same(h,heads[0]));
 const equalInventories=inventories.every(h=>same(h,inventories[0]));
 const status=!equalCounts?'unresolved-different-heights':!equalHeads?'conflicting-same-height':
  !equalInventories?'conflicting-inventory-claim':'consistent-head';
 return Object.freeze({verified:true,status,publisherIds:Object.freeze(publisherPins.map(p=>p.publisherId)),
  registryHeads:Object.freeze(heads),inventoryHeads:Object.freeze(inventories),
  evidenceDigest:digest('TJ-33P-RECONCILIATION',Buffer.from(JSON.stringify(receiptBytes.map(x=>x.toString('base64url'))))),
  provesRemoteFilesystemState:false,provesPublication:false,provesAncestry:false,
  independentlyWitnessed:false,trustedTimestamp:false,globallyComplete:false,
  authorizesRecovery:false,authorizesCheckout:false,authorizesProduction:false});
}
