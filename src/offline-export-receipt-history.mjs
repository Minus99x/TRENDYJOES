/**
 * Objective 31T: portable, canonical, independently pinned OFFLINE receipt history.
 * Receipt signatures are checked for historical authenticity, not freshness.
 * Both branch pins MUST be supplied from an independent trust channel.
 * This module neither writes to disk nor authorizes checkout/manufacturing.
 */
import {createHash} from 'node:crypto';
import {OFFLINE_EXPORT_REGISTRY_SCHEMA,offlineExportReceiptPolicyDigest,verifyHistoricalOfflineExportReceipt} from './offline-acquisition-export-receipt-registry.mjs';

export const OFFLINE_EXPORT_RECEIPT_HISTORY_SCHEMA='TJ-OFFLINE-EXPORT-RECEIPT-HISTORY-1';
const ROOT='0'.repeat(64),HEX=/^[0-9a-f]{64}$/,ID=/^[A-Za-z0-9_-]{12,80}$/;
const MAX_BYTES=32*1024*1024,MAX_ENTRIES=2000;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>obj(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const sha=b=>createHash('sha256').update(b).digest('hex');
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=MAX_ENTRIES&&HEX.test(h.headDigest)&&(h.count===0)===(h.headDigest===ROOT);
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const recordDigest=body=>sha(Buffer.from(`${OFFLINE_EXPORT_REGISTRY_SCHEMA}\0${JSON.stringify(body)}`));
const copy=x=>JSON.parse(JSON.stringify(x));

function validateHistory(history,{expectedHead,registryId,witnesses,quorum}={}){
 if(!head(expectedHead)||!ID.test(registryId||''))fail('EXPORT_HISTORY_EXTERNAL_PIN_REQUIRED');
 const policyDigest=offlineExportReceiptPolicyDigest({witnesses,quorum});
 if(!exact(history,['schema','registryId','policyDigest','head','entries'])||history.schema!==OFFLINE_EXPORT_RECEIPT_HISTORY_SCHEMA||history.registryId!==registryId||history.policyDigest!==policyDigest||!head(history.head)||!same(history.head,expectedHead)||!Array.isArray(history.entries)||history.entries.length!==history.head.count||history.entries.length>MAX_ENTRIES)fail('EXPORT_HISTORY_INVALID_OR_UNPINNED');
 const exports=new Set(),acquisitions=new Set(),digests=new Set(),nonces=new Set();
 let previous=ROOT,previousIssuedAt=-1;
 for(let i=0;i<history.entries.length;i++){
  const e=history.entries[i];
  if(!exact(e,['schema','index','previousDigest','receipt','digest'])||e.schema!==OFFLINE_EXPORT_REGISTRY_SCHEMA||e.index!==i+1||e.previousDigest!==previous||!HEX.test(e.digest||''))fail('EXPORT_HISTORY_CHAIN_INVALID');
  const b=verifyHistoricalOfflineExportReceipt({receipt:e.receipt,witnesses,quorum,registryId}).body;
  if(b.sequence!==i+1||b.previousDigest!==previous||b.issuedAt<previousIssuedAt)fail('EXPORT_HISTORY_CHAIN_INVALID');
  if(exports.has(b.exportId)||acquisitions.has(b.acquisitionId)||digests.has(b.archiveDigest)||nonces.has(b.nonce))fail('EXPORT_HISTORY_REPLAY');
  const {digest,...body}=e;
  if(recordDigest(body)!==e.digest)fail('EXPORT_HISTORY_CHAIN_INVALID');
  exports.add(b.exportId);acquisitions.add(b.acquisitionId);digests.add(b.archiveDigest);nonces.add(b.nonce);
  previous=e.digest;previousIssuedAt=b.issuedAt;
 }
 if(previous!==history.head.headDigest)fail('EXPORT_HISTORY_PIN_MISMATCH');
 return Object.freeze({verified:true,registryId,policyDigest,head:Object.freeze({...history.head}),count:history.entries.length,readOnly:true,mayManufacture:false,mayAcknowledge:false,productionApproved:false});
}

export function encodeOfflineExportReceiptHistory({entries,expectedHead,registryId,witnesses,quorum}={}){
 if(!Array.isArray(entries)||entries.length>MAX_ENTRIES)fail('EXPORT_HISTORY_ENTRIES_INVALID');
 const history={schema:OFFLINE_EXPORT_RECEIPT_HISTORY_SCHEMA,registryId,policyDigest:offlineExportReceiptPolicyDigest({witnesses,quorum}),head:expectedHead,entries};
 validateHistory(history,{expectedHead,registryId,witnesses,quorum});
 const bytes=Buffer.from(JSON.stringify(history),'utf8');
 if(bytes.length>MAX_BYTES)fail('EXPORT_HISTORY_TOO_LARGE');
 return Buffer.from(bytes);
}

function parse(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<2||bytes.length>MAX_BYTES)fail('EXPORT_HISTORY_BYTES_INVALID');
 const raw=bytes.toString('utf8');
 if(!Buffer.from(raw,'utf8').equals(bytes))fail('EXPORT_HISTORY_ENCODING_INVALID');
 let value;try{value=JSON.parse(raw);}catch{fail('EXPORT_HISTORY_ENCODING_INVALID');}
 if(JSON.stringify(value)!==raw)fail('EXPORT_HISTORY_NOT_CANONICAL');
 return value;
}

export function verifyOfflineExportReceiptHistory({bytes,expectedHead,registryId,witnesses,quorum}={}){
 const history=parse(bytes);
 const verified=validateHistory(history,{expectedHead,registryId,witnesses,quorum});
 return Object.freeze({...verified,bundleDigest:sha(bytes)});
}

/**
 * Both histories must be independently pinned and fully verified. An extension
 * is not equivocation. Different valid signature subsets on an identical
 * receipt body are an encoding fork, not a contradictory signed assertion.
 * The returned evidence is informational; consumers MUST independently verify
 * both full bundles before trusting a reported conflict.
 */
export function compareOfflineExportReceiptHistories({leftBytes,rightBytes,leftExpectedHead,rightExpectedHead,registryId,witnesses,quorum}={}){
 const opts={registryId,witnesses,quorum};
 const left=verifyOfflineExportReceiptHistory({...opts,bytes:leftBytes,expectedHead:leftExpectedHead});
 const right=verifyOfflineExportReceiptHistory({...opts,bytes:rightBytes,expectedHead:rightExpectedHead});
 const a=parse(leftBytes).entries,b=parse(rightBytes).entries;
 let firstRecordDifference=-1,firstBodyDifference=-1;
 for(let i=0;i<Math.min(a.length,b.length);i++){
  if(firstRecordDifference<0&&a[i].digest!==b[i].digest)firstRecordDifference=i;
  if(firstBodyDifference<0&&!same(a[i].receipt.body,b[i].receipt.body))firstBodyDifference=i;
 }
 const shared=Math.min(a.length,b.length);
 let status;
 if(firstRecordDifference<0)status=a.length===b.length?'IDENTICAL':'CONSISTENT_PREFIX_EXTENSION';
 else status=firstBodyDifference>=0?'SIGNED_RECEIPT_EQUIVOCATION':'SIGNED_HISTORY_ENCODING_FORK';
 const index=firstBodyDifference>=0?firstBodyDifference:firstRecordDifference;
 const evidence=index>=0?Object.freeze({sequence:index+1,leftRecordDigest:a[index].digest,rightRecordDigest:b[index].digest,leftReceipt:copy(a[index].receipt),rightReceipt:copy(b[index].receipt),contradictorySignedBodies:firstBodyDifference>=0}):null;
 return Object.freeze({status,registryId,policyDigest:left.policyDigest,left:Object.freeze({head:left.head,bundleDigest:left.bundleDigest}),right:Object.freeze({head:right.head,bundleDigest:right.bundleDigest}),sharedPrefixCount:firstRecordDifference<0?shared:firstRecordDifference,conflictEvidence:evidence,readOnly:true,productionApproved:false});
}
