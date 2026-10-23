/**
 * Objective 31O: portable, independently signed acquisition-index head receipts
 * and cross-branch structural equivocation review. OFFLINE DIAGNOSTICS ONLY.
 * Witness public keys, time, and anchor must originate independently of the
 * machine under review. No production permission or evidence-retention service.
 */
import {createHash,verify as verifySignature} from 'node:crypto';
import {OFFLINE_ACQUISITION_INDEX_SCHEMA} from './offline-acquisition-cross-session-index.mjs';

export const OFFLINE_ACQUISITION_ATTESTATION_SCHEMA='TJ-OFFLINE-ACQUISITION-INDEX-ATTESTATION-1';
const ROOT='0'.repeat(64),HEX=/^[0-9a-f]{64}$/,ID=/^[A-Za-z0-9_-]{12,80}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>obj(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const sha=b=>createHash('sha256').update(b).digest('hex');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=2000&&HEX.test(h.headDigest)&&(h.count===0)===(h.headDigest===ROOT);
const zero=()=>({count:0,headDigest:ROOT});
const validHeads=h=>exact(h,['forensic','publication','outbox'])&&Object.values(h).every(head);
const signature=s=>typeof s==='string'&&/^[A-Za-z0-9_-]{86}$/.test(s)&&Buffer.from(s,'base64url').length===64&&Buffer.from(s,'base64url').toString('base64url')===s;
const digestRecord=b=>sha(Buffer.from(`${OFFLINE_ACQUISITION_INDEX_SCHEMA}\0${JSON.stringify(b)}`));

function policy(witnesses,quorum){
 if(!Array.isArray(witnesses)||witnesses.length<2||witnesses.length>12||!Number.isSafeInteger(quorum)||quorum<=witnesses.length/2||quorum>witnesses.length)fail('INDEX_ATTESTATION_POLICY_INVALID');
 const ids=new Set(),keys=new Set(),members=[];
 for(const w of witnesses){
  if(!exact(w,['id','publicKey'])||!ID.test(w.id||'')||ids.has(w.id)||w.publicKey?.type!=='public'||w.publicKey?.asymmetricKeyType!=='ed25519')fail('INDEX_ATTESTATION_POLICY_INVALID');
  const keyDigest=sha(w.publicKey.export({format:'der',type:'spki'}));
  if(keys.has(keyDigest))fail('INDEX_ATTESTATION_DUPLICATE_KEY');
  ids.add(w.id);keys.add(keyDigest);members.push({id:w.id,publicKey:w.publicKey,keyDigest});
 }
 const digest=sha(Buffer.from(`${OFFLINE_ACQUISITION_ATTESTATION_SCHEMA}-POLICY\0${JSON.stringify({quorum,witnesses:members.map(m=>({id:m.id,keyDigest:m.keyDigest})).sort((a,b)=>a.id.localeCompare(b.id,'en'))})}`));
 return {digest,members:new Map(members.map(m=>[m.id,m.publicKey])),quorum};
}
export function offlineAcquisitionIndexAttestationPolicyDigest({witnesses,quorum}={}){return policy(witnesses,quorum).digest;}
function checkBody(b){
 if(!exact(b,['schema','registryId','head','previousHead','issuedAt','expiresAt','nonce','policyDigest'])||b.schema!==OFFLINE_ACQUISITION_ATTESTATION_SCHEMA||!ID.test(b.registryId||'')||!ID.test(b.nonce||'')||!head(b.head)||!head(b.previousHead)||b.head.count<1||b.previousHead.count!==b.head.count-1||!HEX.test(b.policyDigest||'')||!Number.isSafeInteger(b.issuedAt)||b.issuedAt<0||!Number.isSafeInteger(b.expiresAt)||b.expiresAt<=b.issuedAt||b.expiresAt-b.issuedAt>7*24*3600*1000)fail('INDEX_ATTESTATION_BODY_INVALID');
}
export function offlineAcquisitionIndexAttestationSigningBytes(body){checkBody(body);return Buffer.from(`${OFFLINE_ACQUISITION_ATTESTATION_SCHEMA}\0${JSON.stringify(body)}`);}
export function verifyOfflineAcquisitionIndexHeadAttestation({attestation,witnesses,quorum,registryId,nowMs}={}){
 const p=policy(witnesses,quorum);
 if(!exact(attestation,['body','signatures'])||!ID.test(registryId||'')||!Number.isSafeInteger(nowMs)||nowMs<0)fail('INDEX_ATTESTATION_REQUEST_INVALID');
 const b=attestation.body,bytes=offlineAcquisitionIndexAttestationSigningBytes(b);
 if(b.registryId!==registryId||b.policyDigest!==p.digest)fail('INDEX_ATTESTATION_POLICY_MISMATCH');
 if(nowMs<b.issuedAt||nowMs>=b.expiresAt)fail('INDEX_ATTESTATION_EXPIRED_OR_FUTURE');
 if(!Array.isArray(attestation.signatures)||attestation.signatures.length<p.quorum||attestation.signatures.length>p.members.size)fail('INDEX_ATTESTATION_QUORUM_INVALID');
 let last='';const signerIds=[];
 for(const s of attestation.signatures){
  if(!exact(s,['witnessId','signature'])||!p.members.has(s.witnessId)||s.witnessId<=last||!signature(s.signature)||!verifySignature(null,bytes,p.members.get(s.witnessId),Buffer.from(s.signature,'base64url')))fail('INDEX_ATTESTATION_SIGNATURE_INVALID');
  last=s.witnessId;signerIds.push(last);
 }
 return Object.freeze({verified:true,head:structuredClone(b.head),previousHead:structuredClone(b.previousHead),signerIds:Object.freeze(signerIds),readOnly:true,mayRetry:false,mayAcknowledge:false,productionApproved:false});
}
function payload(p){
 return exact(p,['acquisitionId','sessionHead','previousRetentionHead','retentionHead','forensicHeads','manifestDigest'])&&ID.test(p.acquisitionId||'')&&head(p.sessionHead)&&p.sessionHead.count===3&&head(p.previousRetentionHead)&&head(p.retentionHead)&&p.retentionHead.count===p.previousRetentionHead.count+2&&p.retentionHead.count%2===0&&validHeads(p.forensicHeads)&&HEX.test(p.manifestDigest||'');
}
/** Pure portable structural history check. Does NOT verify original 31L/31M signatures. */
export function verifyOfflineAcquisitionIndexPortableHistory({history,expectedHead,trustedAnchor}={}){
 if(!Array.isArray(history)||history.length>2000||!head(expectedHead)||!head(trustedAnchor)||history.length!==expectedHead.count||trustedAnchor.count>expectedHead.count)fail('INDEX_ATTESTATION_HISTORY_REQUEST_INVALID');
 let prev=ROOT,previous=null;const seen=new Set(),heads=[zero()];
 for(let i=0;i<history.length;i++){
  const e=history[i];
  if(!exact(e,['schema','index','previousDigest','payload','digest'])||e.schema!==OFFLINE_ACQUISITION_INDEX_SCHEMA||e.index!==i+1||e.previousDigest!==prev||!HEX.test(e.digest||'')||!payload(e.payload))fail('INDEX_ATTESTATION_HISTORY_INVALID');
  const {digest,...body}=e;
  if(digestRecord(body)!==digest)fail('INDEX_ATTESTATION_HISTORY_INVALID');
  const p=e.payload;
  if(seen.has(p.acquisitionId)||!same(p.previousRetentionHead,previous?.retentionHead??zero()))fail('INDEX_ATTESTATION_HISTORY_CONTINUITY');
  if(previous)for(const k of ['forensic','publication','outbox']){
   const a=previous.forensicHeads[k],b=p.forensicHeads[k];
   if(b.count<a.count||(b.count===a.count&&b.headDigest!==a.headDigest))fail('INDEX_ATTESTATION_HISTORY_CONTINUITY');
  }
  seen.add(p.acquisitionId);previous=p;prev=digest;heads.push({count:i+1,headDigest:prev});
 }
 if(!same(heads.at(-1),expectedHead)||!same(heads[trustedAnchor.count],trustedAnchor))fail('INDEX_ATTESTATION_ANCHOR_MISMATCH');
 return Object.freeze({verifiedStructuralHistory:true,head:structuredClone(expectedHead),trustedAnchor:structuredClone(trustedAnchor),readOnly:true,signaturesOfSessionsVerified:false,productionApproved:false});
}
/**
 * Requires full histories back to genesis AND an externally pinned common
 * anchor. Two quorum-signed incompatible branches are equivocation evidence;
 * compatible prefixes are consistent only to the extent of provided evidence.
 */
export function reviewOfflineAcquisitionIndexBranches({branches,witnesses,quorum,registryId,nowMs,trustedAnchor}={}){
 if(!Array.isArray(branches)||branches.length<2||branches.length>10||!head(trustedAnchor))fail('INDEX_ATTESTATION_REVIEW_INVALID');
 const checked=[],unique=new Set();
 for(const branch of branches){
  if(!exact(branch,['attestation','history']))fail('INDEX_ATTESTATION_REVIEW_INVALID');
  const v=verifyOfflineAcquisitionIndexHeadAttestation({attestation:branch.attestation,witnesses,quorum,registryId,nowMs});
  verifyOfflineAcquisitionIndexPortableHistory({history:branch.history,expectedHead:v.head,trustedAnchor});
  const expectedPrevious=branch.history.length===1?zero():{count:branch.history.length-1,headDigest:branch.history.at(-2).digest};
  if(!same(v.previousHead,expectedPrevious))fail('INDEX_ATTESTATION_PREDECESSOR_MISMATCH');
  const id=JSON.stringify(branch.attestation);
  if(unique.has(id))fail('INDEX_ATTESTATION_REPLAY');unique.add(id);
  checked.push({history:branch.history,head:v.head,signers:v.signerIds,nonce:branch.attestation.body.nonce});
 }
 let conflict=null;
 for(let i=0;i<checked.length;i++)for(let j=i+1;j<checked.length;j++){
  const a=checked[i],b=checked[j],length=Math.min(a.history.length,b.history.length);
  for(let k=0;k<length;k++)if(a.history[k].digest!==b.history[k].digest){
   const found={branchA:i,branchB:j,firstConflictingIndex:k+1,headA:a.head,headB:b.head,commonSigners:a.signers.filter(s=>b.signers.includes(s))};
   if(!conflict||found.firstConflictingIndex<conflict.firstConflictingIndex)conflict=found;
   break;
  }
 }
 return Object.freeze({classification:conflict?'SIGNED_BRANCH_EQUIVOCATION_EVIDENCE':'CONSISTENT_SIGNED_PREFIXES_ONLY',conflict,reviewedBranches:checked.length,externallyPinnedAnchor:structuredClone(trustedAnchor),readOnly:true,mayRetry:false,mayAcknowledge:false,productionApproved:false});
}
