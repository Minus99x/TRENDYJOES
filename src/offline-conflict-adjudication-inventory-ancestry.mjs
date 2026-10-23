/** Objective 33L — bounded, independently pinned, Ed25519-authenticated
 * predecessor ASSERTIONS between two 33K inventory-head receipts. A signed
 * assertion does not prove actual 33J record bytes or remote filesystem state.
 * No networking, storage writes, independent time, consensus or production use.
 */
import {createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
import {reconcileOfflineConflictInventoryHeadReceipts} from './offline-conflict-adjudication-inventory-head-receipts.mjs';

export const OFFLINE_CONFLICT_INVENTORY_ANCESTRY_LINK_SCHEMA='TJ-OFFLINE-ADJUDICATION-INVENTORY-ANCESTRY-LINK-1';
const HEX=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9_-]{8,64}$/;
const BODY=['schema','namespaceId','journalScopeDigest','higherHostId','lowerHostId',
 'fromHead','toHead','recordDigest','observedAt','expiresAt','nonce'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const sha=(domain,bytes)=>createHash('sha256').update(domain+'\0').update(bytes).digest('hex');
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value' in d&&d.enumerable;})&&
 Object.keys(o).every(k=>keys.includes(k));
const dense=(a,min,max)=>Array.isArray(a)&&Object.getPrototypeOf(a)===Array.prototype&&
 a.length>=min&&a.length<=max&&Reflect.ownKeys(a).length===a.length+1&&
 Array.from({length:a.length},(_,i)=>Object.getOwnPropertyDescriptor(a,String(i))).every(d=>d&&'value' in d&&d.enumerable);
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=256&&
 typeof h.headDigest==='string'&&HEX.test(h.headDigest);
const eq=(a,b)=>a.count===b.count&&a.headDigest===b.headDigest;
const b64=x=>typeof x==='string'&&x.length>0&&x.length<256&&/^[A-Za-z0-9_-]+$/.test(x)&&
 Buffer.from(x,'base64url').toString('base64url')===x;
function validBody(b){
 if(!exact(b,BODY)||Object.keys(b).join('|')!==BODY.join('|')||
  b.schema!==OFFLINE_CONFLICT_INVENTORY_ANCESTRY_LINK_SCHEMA||
  typeof b.namespaceId!=='string'||!ID.test(b.namespaceId)||
  typeof b.journalScopeDigest!=='string'||!HEX.test(b.journalScopeDigest)||
  typeof b.higherHostId!=='string'||!ID.test(b.higherHostId)||
  typeof b.lowerHostId!=='string'||!ID.test(b.lowerHostId)||b.higherHostId===b.lowerHostId||
  !head(b.fromHead)||!head(b.toHead)||b.toHead.count!==b.fromHead.count+1||
  typeof b.recordDigest!=='string'||!HEX.test(b.recordDigest)||b.toHead.headDigest!==b.recordDigest||
  !Number.isSafeInteger(b.observedAt)||b.observedAt<0||
  !Number.isSafeInteger(b.expiresAt)||b.expiresAt<=b.observedAt||
  b.expiresAt-b.observedAt>600000||typeof b.nonce!=='string'||!ID.test(b.nonce))fail('EXCHANGE33L_LINK_INVALID');
}
export function offlineConflictInventoryAncestryLinkBodyBytes(body){
 validBody(body);
 return Buffer.from('TJ-33L-INVENTORY-ANCESTRY-LINK\0'+JSON.stringify(body));
}
function parse(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<100||bytes.length>4096)fail('EXCHANGE33L_BYTES_INVALID');
 let r;
 try{r=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
 catch{fail('EXCHANGE33L_BYTES_INVALID');}
 if(!exact(r,['body','signature'])||Object.keys(r).join('|')!=='body|signature'||
  !b64(r.signature)||Buffer.from(r.signature,'base64url').length!==64||
  !Buffer.from(JSON.stringify(r)).equals(bytes))fail('EXCHANGE33L_NONCANONICAL');
 validBody(r.body);
 return r;
}
export function offlineConflictInventoryAncestryLinkDigest(bytes){
 parse(bytes);
 return sha('TJ-33L-SIGNED-INVENTORY-ANCESTRY-LINK',bytes);
}
function keyFromPin(encoded){
 if(!b64(encoded))fail('EXCHANGE33L_KEY_INVALID');
 let key;
 try{key=createPublicKey({key:Buffer.from(encoded,'base64url'),format:'der',type:'spki'});}
 catch{fail('EXCHANGE33L_KEY_INVALID');}
 if(key.asymmetricKeyType!=='ed25519'||key.export({format:'der',type:'spki'}).toString('base64url')!==encoded)
  fail('EXCHANGE33L_KEY_INVALID');
 return key;
}
/** Accepts exactly two independently pinned 33K receipts, and at most 32
 * consecutive signed links from the higher host. A missing chain stays
 * unresolved; a supplied incomplete or forged chain fails closed.
 */
export function reconcileOfflineConflictInventoryAncestry(args={}){
 if(!exact(args,['receiptArgs','links','linkPins']))fail('EXCHANGE33L_ARGUMENTS_INVALID');
 const {receiptArgs,links,linkPins}=args;
 if(!exact(receiptArgs,['receipts','hostPins','expectedNamespaceId','expectedJournalScopeDigest',
  'expectedGenesisHead','nowMs','seenDigests','seenNonces'])||
  !dense(receiptArgs.receipts,2,2)||!dense(receiptArgs.hostPins,2,2)||
  !dense(links,0,32)||!dense(linkPins,0,32))fail('EXCHANGE33L_ARGUMENTS_INVALID');
 const reconciled=reconcileOfflineConflictInventoryHeadReceipts(receiptArgs);
 const result=(status,digests=[])=>Object.freeze({verifiedSignedReceipts:true,status,
  receiptEvidenceDigest:reconciled.evidenceDigest,
  linkEvidenceDigest:sha('TJ-33L-ANCESTRY-RECONCILIATION',Buffer.from(JSON.stringify(digests))),
  signedPredecessorAssertions:status==='authenticated-signed-predecessor-claims',
  provesActualInventoryAncestry:false,independentlyWitnessedDisk:false,
  independentTimestamp:false,globallyComplete:false,authorizesRecovery:false,
  authorizesRepair:false,authorizesCheckout:false,authorizesProduction:false});
 if(reconciled.status!=='unresolved-different-heights'){
  if(links.length||linkPins.length)fail('EXCHANGE33L_UNEXPECTED_LINKS');
  return result(reconciled.status==='consistent-head'?'consistent-signed-heads':'conflicting-same-height');
 }
 const lowIndex=reconciled.heads[0].count<reconciled.heads[1].count?0:1;
 const highIndex=1-lowIndex;
 const low=reconciled.heads[lowIndex],high=reconciled.heads[highIndex];
 const delta=high.count-low.count;
 if(delta>32){if(links.length||linkPins.length)fail('EXCHANGE33L_GAP_EXCEEDS_BOUND');return result('unresolved-gap-exceeds-bound');}
 if(!links.length&&!linkPins.length)return result('unresolved-no-predecessor-evidence');
 if(links.length!==delta||linkPins.length!==delta)fail('EXCHANGE33L_MISSING_LINK');
 const upperPin=receiptArgs.hostPins[highIndex];
 const higherHostId=upperPin.hostId,lowerHostId=receiptArgs.hostPins[lowIndex].hostId;
 const upperReceipt=parseReceipt(receiptArgs.receipts[highIndex]);
 const key=keyFromPin(upperPin.publicKey);
 const usedNonces=new Set(),usedDigests=new Set(),digests=[];
 let current=low;
 for(let i=0;i<delta;i++){
  const p=linkPins[i];
  if(!exact(p,['expectedLinkDigest','expectedFromHead','expectedToHead'])||
   !HEX.test(p.expectedLinkDigest)||!head(p.expectedFromHead)||!head(p.expectedToHead))
   fail('EXCHANGE33L_EXTERNAL_LINK_PINS_REQUIRED');
  const r=parse(links[i]),b=r.body;
  if(b.namespaceId!==receiptArgs.expectedNamespaceId||
   b.journalScopeDigest!==receiptArgs.expectedJournalScopeDigest||
   b.higherHostId!==higherHostId||b.lowerHostId!==lowerHostId||
   !eq(b.fromHead,current)||!eq(b.fromHead,p.expectedFromHead)||
   !eq(b.toHead,p.expectedToHead))fail('EXCHANGE33L_CHAIN_MISMATCH');
  if(b.observedAt>upperReceipt.body.observedAt||b.observedAt>receiptArgs.nowMs||
   b.expiresAt<receiptArgs.nowMs)fail('EXCHANGE33L_LINK_EXPIRED');
  const digest=offlineConflictInventoryAncestryLinkDigest(links[i]);
  if(digest!==p.expectedLinkDigest)fail('EXCHANGE33L_LINK_PIN_MISMATCH');
  if(usedNonces.has(b.nonce)||usedDigests.has(digest))fail('EXCHANGE33L_LINK_REPLAY');
  usedNonces.add(b.nonce);usedDigests.add(digest);
  if(!verifySignature(null,offlineConflictInventoryAncestryLinkBodyBytes(b),key,
   Buffer.from(r.signature,'base64url')))fail('EXCHANGE33L_LINK_SIGNATURE_INVALID');
  digests.push(digest);current=b.toHead;
 }
 if(!eq(current,high))fail('EXCHANGE33L_FINAL_HEAD_MISMATCH');
 return result('authenticated-signed-predecessor-claims',digests);
}
function parseReceipt(bytes){
 // 33K already validated canonical bytes and their Ed25519 signature.
 // Here we only read the signed observation time for cross-evidence ordering.
 return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
}
