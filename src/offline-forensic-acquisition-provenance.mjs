/**
 * Objective 31L: independently signed, portable PRE/POST acquisition receipts.
 * The external receipt head, signer keys and forensic pins MUST be retained
 * outside the portable manifest. Receipts are evidence, never recovery grants.
 * This module has no filesystem, network, signing-key or Shopify side effects.
 */
import {createHash,verify as verifySignature} from 'node:crypto';
import {verifyOfflineForensicPortableReviewBundle} from './offline-forensic-portable-review.mjs';
import {recoveryReviewKeyDigest} from './offline-recovery-adjudication.mjs';

export const OFFLINE_ACQUISITION_RECEIPT_SCHEMA='TJ-OFFLINE-ACQUISITION-RECEIPT-1';
export const OFFLINE_ACQUISITION_MANIFEST_SCHEMA='TJ-OFFLINE-ACQUISITION-MANIFEST-1';
const ROOT='0'.repeat(64), HEX=/^[0-9a-f]{64}$/, ID=/^[A-Za-z0-9_-]{12,80}$/;
const BODY=['schema','registryId','anchorType','index','previousDigest','acquisitionId','phase','heads','bundleDigest','observedAt'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,fields)=>obj(x)&&Object.keys(x).sort().join('|')===fields.slice().sort().join('|');
const sha=b=>createHash('sha256').update(b).digest('hex');
const validHead=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=2000&&HEX.test(h.headDigest)&&(h.count===0)===(h.headDigest===ROOT);
const validHeads=h=>exact(h,['forensic','publication','outbox'])&&Object.values(h).every(validHead);
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const sigValid=s=>typeof s==='string'&&/^[A-Za-z0-9_-]{86}$/.test(s)&&Buffer.from(s,'base64url').length===64&&Buffer.from(s,'base64url').toString('base64url')===s;
function bodyValid(b){
 if(!exact(b,BODY)||b.schema!==OFFLINE_ACQUISITION_RECEIPT_SCHEMA||!ID.test(b.registryId||'')||!['registry','journal'].includes(b.anchorType)||!Number.isSafeInteger(b.index)||b.index<1||b.index>2000||!HEX.test(b.previousDigest)||!ID.test(b.acquisitionId||'')||!['PRE','POST'].includes(b.phase)||!validHeads(b.heads)||!HEX.test(b.bundleDigest)||!Number.isSafeInteger(b.observedAt)||b.observedAt<0||(b.phase==='PRE')!==(b.bundleDigest===ROOT))fail('ACQUISITION_RECEIPT_BODY_INVALID');
}
export function offlineAcquisitionReceiptSigningBytes(body){bodyValid(body);return Buffer.from(`${OFFLINE_ACQUISITION_RECEIPT_SCHEMA}\0${JSON.stringify(body)}`);}
/** Assemble a signed receipt without possessing private keys. */
export function createOfflineAcquisitionReceipt({body,signatures}={}){
 offlineAcquisitionReceiptSigningBytes(body);
 if(!Array.isArray(signatures)||signatures.length<1||signatures.length>10)fail('ACQUISITION_RECEIPT_SIGNATURE_INVALID');
 const unsigned={...body,signatures};
 return structuredClone({...unsigned,digest:sha(Buffer.from(`${OFFLINE_ACQUISITION_RECEIPT_SCHEMA}\0${JSON.stringify(unsigned)}`))});
}
function members(trust){
 if(!exact(trust,['registryId','anchorType','retentionWitnesses','retentionQuorum'])||!ID.test(trust.registryId||'')||!['registry','journal'].includes(trust.anchorType)||!Array.isArray(trust.retentionWitnesses)||trust.retentionWitnesses.length<2||trust.retentionWitnesses.length>10||!Number.isSafeInteger(trust.retentionQuorum)||trust.retentionQuorum<=trust.retentionWitnesses.length/2||trust.retentionQuorum>trust.retentionWitnesses.length)fail('ACQUISITION_RETENTION_TRUST_INVALID');
 const byId=new Map(),keys=new Set();
 for(const w of trust.retentionWitnesses){
  if(!exact(w,['id','publicKey'])||!ID.test(w.id||'')||byId.has(w.id)||w.publicKey?.type!=='public'||w.publicKey?.asymmetricKeyType!=='ed25519')fail('ACQUISITION_RETENTION_TRUST_INVALID');
  const k=recoveryReviewKeyDigest(w.publicKey);if(keys.has(k))fail('ACQUISITION_RETENTION_TRUST_INVALID');
  byId.set(w.id,w.publicKey);keys.add(k);
 }
 return byId;
}
/** Pure independent verification. `expectedHead` is NOT taken from history. */
export function verifyOfflineAcquisitionRetentionHistory({history,expectedHead,trust}={}){
 const byId=members(trust);
 if(!Array.isArray(history)||history.length>2000||history.length%2!==0||!validHead(expectedHead)||history.length!==expectedHead.count)fail('ACQUISITION_RETENTION_PIN_INVALID');
 let previous=ROOT,prior=null,priorTime=-1;const acquisitionIds=new Set();let previousPostHeads=null;
 for(let i=0;i<history.length;i++){
  const r=history[i];
  if(!exact(r,[...BODY,'signatures','digest']))fail('ACQUISITION_RECEIPT_RECORD_INVALID');
  const body=Object.fromEntries(BODY.map(k=>[k,r[k]]));bodyValid(body);
  if(body.registryId!==trust.registryId||body.anchorType!==trust.anchorType||body.index!==i+1||body.previousDigest!==previous||body.observedAt<=priorTime||body.phase!==(i%2===0?'PRE':'POST'))fail('ACQUISITION_RECEIPT_CHAIN_INVALID');
  if(i%2===1&&(!prior||body.acquisitionId!==prior.acquisitionId||!same(body.heads,prior.heads)||body.bundleDigest===ROOT))fail('ACQUISITION_SNAPSHOT_RACE_OR_REPLAY');
  if(i%2===0){
   if(acquisitionIds.has(body.acquisitionId))fail('ACQUISITION_SNAPSHOT_RACE_OR_REPLAY');
   acquisitionIds.add(body.acquisitionId);
   if(previousPostHeads)for(const k of ['forensic','publication','outbox']){
    const old=previousPostHeads[k],next=body.heads[k];
    if(next.count<old.count||(next.count===old.count&&next.headDigest!==old.headDigest))fail('ACQUISITION_SNAPSHOT_RACE_OR_REPLAY');
   }
  }
  if(!Array.isArray(r.signatures)||r.signatures.length<trust.retentionQuorum||r.signatures.length>byId.size)fail('ACQUISITION_RECEIPT_SIGNATURE_INVALID');
  const bytes=offlineAcquisitionReceiptSigningBytes(body),seen=new Set();
  for(const s of r.signatures){
   if(!exact(s,['witnessId','signature'])||!byId.has(s.witnessId)||seen.has(s.witnessId)||!sigValid(s.signature)||!verifySignature(null,bytes,byId.get(s.witnessId),Buffer.from(s.signature,'base64url')))fail('ACQUISITION_RECEIPT_SIGNATURE_INVALID');
   seen.add(s.witnessId);
  }
  const {digest,...unsigned}=r;
  if(!HEX.test(digest)||sha(Buffer.from(`${OFFLINE_ACQUISITION_RECEIPT_SCHEMA}\0${JSON.stringify(unsigned)}`))!==digest)fail('ACQUISITION_RECEIPT_DIGEST_INVALID');
  previous=digest;prior=body;priorTime=body.observedAt;if(body.phase==='POST')previousPostHeads=body.heads;
 }
 if(previous!==expectedHead.headDigest)fail('ACQUISITION_RETENTION_PIN_INVALID');
 return Object.freeze({verified:true,count:history.length,headDigest:previous,lastAcquisitionId:prior?.acquisitionId??null,readOnly:true,productionApproved:false});
}
/** Manifest copies are untrusted transport objects; no embedded keys/pins. */
export function createOfflineForensicAcquisitionManifest({acquisitionId,envelope,receiptHistory}={}){
 if(!ID.test(acquisitionId||'')||!obj(envelope)||!Array.isArray(receiptHistory)||receiptHistory.length<2||receiptHistory.length>2000)fail('ACQUISITION_MANIFEST_INVALID');
 const m={schema:OFFLINE_ACQUISITION_MANIFEST_SCHEMA,acquisitionId,envelope,receiptHistory};
 const bytes=Buffer.from(JSON.stringify(m));if(bytes.length>12*1024*1024)fail('ACQUISITION_MANIFEST_SIZE_INVALID');
 return structuredClone(m);
}
/** This is a diagnostic review result, NEVER authority to retry/release. */
export function verifyOfflineForensicAcquisitionManifest({manifest,independentPins,forensicTrust,retentionTrust,independentRetentionHead}={}){
 if(!exact(manifest,['schema','acquisitionId','envelope','receiptHistory'])||manifest.schema!==OFFLINE_ACQUISITION_MANIFEST_SCHEMA||!ID.test(manifest.acquisitionId||'')||!Array.isArray(manifest.receiptHistory)||manifest.receiptHistory.length<2||!validHeads(independentPins))fail('ACQUISITION_MANIFEST_INVALID');
 // Independent retention cannot reuse a forensic witness/reviewer signing key.
 const retentionKeys=new Set(retentionTrust?.retentionWitnesses?.map(w=>recoveryReviewKeyDigest(w.publicKey))??[]);
 const forensicKeys=[...(forensicTrust?.witnesses??[]),...(forensicTrust?.reviewerPolicies??[]).flatMap(p=>p.reviewers??[])];
 for(const w of forensicKeys)if(retentionKeys.has(recoveryReviewKeyDigest(w.publicKey)))fail('ACQUISITION_RETENTION_NOT_INDEPENDENT');
 const r=verifyOfflineAcquisitionRetentionHistory({history:manifest.receiptHistory,expectedHead:independentRetentionHead,trust:retentionTrust});
 const pre=manifest.receiptHistory.at(-2),post=manifest.receiptHistory.at(-1);
 if(pre.acquisitionId!==manifest.acquisitionId||post.acquisitionId!==manifest.acquisitionId||!same(pre.heads,independentPins)||!same(post.heads,independentPins)||post.bundleDigest!==manifest.envelope?.transportDigest)fail('ACQUISITION_MANIFEST_BINDING_INVALID');
 const forensic=verifyOfflineForensicPortableReviewBundle({envelope:manifest.envelope,independentPins,trust:forensicTrust});
 return Object.freeze({verified:true,classification:forensic.classification,retentionCount:r.count,acquisitionId:manifest.acquisitionId,readOnly:true,mayRetry:false,mayAcknowledge:false,mayDeletePending:false,productionApproved:false});
}
