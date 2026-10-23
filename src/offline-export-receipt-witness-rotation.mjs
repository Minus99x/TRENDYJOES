/**
 * Objective 31U: independently pinned, OFFLINE receipt-history witness rotation.
 * Caller supplies trusted Ed25519 public keys, policy/head/transition pins and
 * observation time. No key discovery, filesystem writes or operational authority.
 * Historic receipt and transition expiry is NOT fresh authorization.
 */
import {createHash,verify as cryptoVerify} from 'node:crypto';
import {OFFLINE_EXPORT_REGISTRY_SCHEMA,offlineExportReceiptPolicyDigest,verifyHistoricalOfflineExportReceipt} from './offline-acquisition-export-receipt-registry.mjs';
export const OFFLINE_EXPORT_WITNESS_TRANSITION_SCHEMA='TJ-OFFLINE-EXPORT-RECEIPT-WITNESS-TRANSITION-1';
export const OFFLINE_EXPORT_ROTATED_HISTORY_SCHEMA='TJ-OFFLINE-EXPORT-RECEIPT-ROTATED-HISTORY-1';
const ROOT='0'.repeat(64),HEX=/^[0-9a-f]{64}$/,ID=/^[A-Za-z0-9_-]{12,80}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>obj(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const sha=b=>createHash('sha256').update(b).digest('hex');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=2000&&HEX.test(h.headDigest)&&(h.count===0)===(h.headDigest===ROOT);
const signature=s=>typeof s==='string'&&/^[A-Za-z0-9_-]{86}$/.test(s)&&Buffer.from(s,'base64url').length===64&&Buffer.from(s,'base64url').toString('base64url')===s;
const recordDigest=body=>sha(Buffer.from(`${OFFLINE_EXPORT_REGISTRY_SCHEMA}\0${JSON.stringify(body)}`));
const keyDigest=k=>sha(k.export({format:'der',type:'spki'}));
const pin=entries=>({count:entries.length,headDigest:entries.length?entries.at(-1).digest:ROOT});
function normalize(policy){
 if(!exact(policy,['witnesses','quorum']))fail('EXPORT_ROTATION_POLICY_INVALID');
 const digest=offlineExportReceiptPolicyDigest(policy),members=new Map(policy.witnesses.map(w=>[w.id,w.publicKey]));
 return {...policy,digest,members};
}
function bodyValid(b){
 if(!exact(b,['schema','registryId','fromEpoch','toEpoch','fromPolicyDigest','toPolicyDigest','anchorHead','issuedAt','expiresAt','nonce'])||
 b.schema!==OFFLINE_EXPORT_WITNESS_TRANSITION_SCHEMA||!ID.test(b.registryId||'')||!ID.test(b.nonce||'')||
 !Number.isSafeInteger(b.fromEpoch)||b.fromEpoch<0||b.fromEpoch>19||b.toEpoch!==b.fromEpoch+1||
 !HEX.test(b.fromPolicyDigest||'')||!HEX.test(b.toPolicyDigest||'')||b.fromPolicyDigest===b.toPolicyDigest||
 !head(b.anchorHead)||b.anchorHead.count<1||!Number.isSafeInteger(b.issuedAt)||b.issuedAt<0||
 !Number.isSafeInteger(b.expiresAt)||b.expiresAt<=b.issuedAt||b.expiresAt-b.issuedAt>7*86400000)fail('EXPORT_ROTATION_BODY_INVALID');
}
export function offlineExportWitnessTransitionSigningBytes(body){bodyValid(body);return Buffer.from(`${OFFLINE_EXPORT_WITNESS_TRANSITION_SCHEMA}\0${JSON.stringify(body)}`);}
export function offlineExportWitnessTransitionPossessionBytes(body,witnessId){
 const bytes=offlineExportWitnessTransitionSigningBytes(body);
 if(!ID.test(witnessId||''))fail('EXPORT_ROTATION_PROOF_INVALID');
 return Buffer.concat([Buffer.from(`${OFFLINE_EXPORT_WITNESS_TRANSITION_SCHEMA}-POP\0`),bytes,Buffer.from(`\0${witnessId}`)]);
}
function signedSet(sigs,members,minimum,bytes,code){
 if(!Array.isArray(sigs)||sigs.length<minimum||sigs.length>members.size)fail(code);
 let prev='';
 for(const s of sigs){
  if(!exact(s,['witnessId','signature'])||typeof s.witnessId!=='string'||s.witnessId<=prev||!members.has(s.witnessId)||!signature(s.signature)||
  !cryptoVerify(null,bytes(s.witnessId),members.get(s.witnessId),Buffer.from(s.signature,'base64url')))fail(code);
  prev=s.witnessId;
 }
}
export function offlineExportWitnessTransitionChainDigest({transitions}={}){
 if(!Array.isArray(transitions)||transitions.length<1||transitions.length>20)fail('EXPORT_ROTATION_REQUEST_INVALID');
 return sha(Buffer.from(`${OFFLINE_EXPORT_WITNESS_TRANSITION_SCHEMA}-CHAIN\0${JSON.stringify(transitions)}`));
}
function verifyChain({policies,transitions,registryId,nowMs,expectedGenesisPolicyDigest,expectedFinalPolicyDigest,expectedFinalEpoch,expectedTransitionDigest}){
 if(!Array.isArray(policies)||!Array.isArray(transitions)||transitions.length<1||transitions.length>20||policies.length!==transitions.length+1||
 !ID.test(registryId||'')||!Number.isSafeInteger(nowMs)||nowMs<0||!HEX.test(expectedGenesisPolicyDigest||'')||
 !HEX.test(expectedFinalPolicyDigest||'')||!HEX.test(expectedTransitionDigest||'')||
 !Number.isSafeInteger(expectedFinalEpoch)||expectedFinalEpoch!==transitions.length)fail('EXPORT_ROTATION_REQUEST_INVALID');
 const ps=policies.map(normalize),usedIds=new Set(),usedKeys=new Set();
 for(const p of ps)for(const w of p.witnesses){
  const kd=keyDigest(w.publicKey);
  if(usedIds.has(w.id)||usedKeys.has(kd))fail('EXPORT_ROTATION_RETIRED_KEY_REUSE');
  usedIds.add(w.id);usedKeys.add(kd);
 }
 if(ps[0].digest!==expectedGenesisPolicyDigest||ps.at(-1).digest!==expectedFinalPolicyDigest||
 offlineExportWitnessTransitionChainDigest({transitions})!==expectedTransitionDigest)fail('EXPORT_ROTATION_EXTERNAL_PIN_MISMATCH');
 let prevCount=0,prevTime=-1;const nonces=new Set(),anchors=[],times=[];
 for(let i=0;i<transitions.length;i++){
  const t=transitions[i];
  if(!exact(t,['body','outgoingSignatures','incomingProofs']))fail('EXPORT_ROTATION_CERTIFICATE_INVALID');
  const b=t.body,bytes=offlineExportWitnessTransitionSigningBytes(b);
  if(b.registryId!==registryId||b.fromEpoch!==i||b.toEpoch!==i+1||b.fromPolicyDigest!==ps[i].digest||b.toPolicyDigest!==ps[i+1].digest)fail('EXPORT_ROTATION_POLICY_MISMATCH');
  if(b.anchorHead.count<=prevCount||b.issuedAt<=prevTime||b.issuedAt>nowMs||nonces.has(b.nonce))fail('EXPORT_ROTATION_TIME_OR_REPLAY');
  signedSet(t.outgoingSignatures,ps[i].members,ps[i].quorum,()=>bytes,'EXPORT_ROTATION_OUTGOING_SIGNATURE_INVALID');
  if(!Array.isArray(t.incomingProofs)||t.incomingProofs.length!==ps[i+1].members.size)fail('EXPORT_ROTATION_PROOF_INVALID');
  signedSet(t.incomingProofs,ps[i+1].members,ps[i+1].members.size,id=>offlineExportWitnessTransitionPossessionBytes(b,id),'EXPORT_ROTATION_PROOF_INVALID');
  nonces.add(b.nonce);anchors.push(b.anchorHead);times.push(b.issuedAt);prevCount=b.anchorHead.count;prevTime=b.issuedAt;
 }
 return {ps,anchors,times,transitionDigest:expectedTransitionDigest};
}
function parse(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<2||bytes.length>32*1024*1024)fail('EXPORT_ROTATION_BYTES_INVALID');
 const raw=bytes.toString('utf8');if(!Buffer.from(raw,'utf8').equals(bytes))fail('EXPORT_ROTATION_ENCODING_INVALID');
 let value;try{value=JSON.parse(raw);}catch{fail('EXPORT_ROTATION_ENCODING_INVALID');}
 if(JSON.stringify(value)!==raw)fail('EXPORT_ROTATION_NOT_CANONICAL');
 return value;
}
/** Verify all historic signed receipts against their correct retired/active epoch. */
export function verifyOfflineExportRotatedReceiptHistory({bytes,expectedHead,policies,transitions,registryId,nowMs,expectedGenesisPolicyDigest,expectedFinalPolicyDigest,expectedFinalEpoch,expectedTransitionDigest}={}){
 if(!head(expectedHead))fail('EXPORT_ROTATION_EXTERNAL_HEAD_REQUIRED');
 const chain=verifyChain({policies,transitions,registryId,nowMs,expectedGenesisPolicyDigest,expectedFinalPolicyDigest,expectedFinalEpoch,expectedTransitionDigest});
 const history=parse(bytes);
 if(!exact(history,['schema','registryId','head','entries'])||history.schema!==OFFLINE_EXPORT_ROTATED_HISTORY_SCHEMA||history.registryId!==registryId||
 !head(history.head)||!same(history.head,expectedHead)||!Array.isArray(history.entries)||history.entries.length!==history.head.count||history.entries.length>2000||
 history.entries.length<=chain.anchors.at(-1).count)fail('EXPORT_ROTATION_HISTORY_INVALID');
 let previous=ROOT,previousTime=-1,epoch=0;
 const exports=new Set(),acquisitions=new Set(),digests=new Set(),nonces=new Set();
 for(let i=0;i<history.entries.length;i++){
  const e=history.entries[i];
  if(!exact(e,['schema','index','previousDigest','receipt','digest'])||e.schema!==OFFLINE_EXPORT_REGISTRY_SCHEMA||e.index!==i+1||e.previousDigest!==previous||!HEX.test(e.digest||''))fail('EXPORT_ROTATION_CHAIN_INVALID');
  while(epoch<chain.anchors.length&&i>=chain.anchors[epoch].count){
   if(previous!==chain.anchors[epoch].headDigest)fail('EXPORT_ROTATION_ANCHOR_MISMATCH');
   epoch++;
  }
  const p=chain.ps[epoch],b=verifyHistoricalOfflineExportReceipt({receipt:e.receipt,witnesses:p.witnesses,quorum:p.quorum,registryId}).body;
  const earliest=epoch?chain.times[epoch-1]:0,latest=chain.times[epoch]??Infinity;
  if(b.sequence!==i+1||b.previousDigest!==previous||b.issuedAt<previousTime||b.issuedAt<earliest||b.issuedAt>=latest||b.issuedAt>nowMs)fail('EXPORT_ROTATION_EPOCH_OR_CHAIN_INVALID');
  if(exports.has(b.exportId)||acquisitions.has(b.acquisitionId)||digests.has(b.archiveDigest)||nonces.has(b.nonce))fail('EXPORT_ROTATION_REPLAY');
  const {digest,...record}=e;if(recordDigest(record)!==e.digest)fail('EXPORT_ROTATION_CHAIN_INVALID');
  exports.add(b.exportId);acquisitions.add(b.acquisitionId);digests.add(b.archiveDigest);nonces.add(b.nonce);
  previous=e.digest;previousTime=b.issuedAt;
 }
 if(previous!==expectedHead.headDigest)fail('EXPORT_ROTATION_HEAD_MISMATCH');
 return Object.freeze({verified:true,registryId,head:Object.freeze({...expectedHead}),count:history.entries.length,epoch:chain.ps.length-1,
  transitionDigest:chain.transitionDigest,bundleDigest:sha(bytes),readOnly:true,mayManufacture:false,mayAcknowledge:false,productionApproved:false});
}
/** Encoding is allowed only after full independent verification of caller's pins. */
export function encodeOfflineExportRotatedReceiptHistory({entries,...options}={}){
 if(!Array.isArray(entries)||entries.length>2000)fail('EXPORT_ROTATION_HISTORY_INVALID');
 const bytes=Buffer.from(JSON.stringify({schema:OFFLINE_EXPORT_ROTATED_HISTORY_SCHEMA,registryId:options.registryId,head:options.expectedHead,entries}));
 if(bytes.length>32*1024*1024)fail('EXPORT_ROTATION_BYTES_INVALID');
 verifyOfflineExportRotatedReceiptHistory({bytes,...options});return bytes;
}
/** Compare two independently verified branches; no trust in embedded policies. */
export function compareOfflineExportRotatedReceiptHistories({left,right,registryId,nowMs}={}){
 if(!obj(left)||!obj(right))fail('EXPORT_ROTATION_COMPARISON_INVALID');
 const a=verifyOfflineExportRotatedReceiptHistory({...left,registryId,nowMs});
 const b=verifyOfflineExportRotatedReceiptHistory({...right,registryId,nowMs});
 if(a.epoch!==b.epoch||left.expectedGenesisPolicyDigest!==right.expectedGenesisPolicyDigest)fail('EXPORT_ROTATION_COMPARISON_INCOMPATIBLE');
 const la=parse(left.bytes).entries,rb=parse(right.bytes).entries;
 let bodyDiff=-1,recordDiff=-1;
 for(let i=0;i<Math.min(la.length,rb.length);i++){
  if(recordDiff<0&&la[i].digest!==rb[i].digest)recordDiff=i;
  if(bodyDiff<0&&!same(la[i].receipt.body,rb[i].receipt.body))bodyDiff=i;
 }
 let policyDiff=-1;
 for(let i=0;i<left.transitions.length;i++)if(!same(left.transitions[i].body,right.transitions[i].body)){policyDiff=i;break;}
 let status;
 if(bodyDiff>=0)status='SIGNED_RECEIPT_EQUIVOCATION';
 else if(policyDiff>=0)status='SIGNED_POLICY_EQUIVOCATION';
 else if(recordDiff>=0)status='SIGNED_HISTORY_ENCODING_FORK';
 else if(a.transitionDigest!==b.transitionDigest)status='SIGNED_POLICY_CERTIFICATE_ENCODING_FORK';
 else status=la.length===rb.length?'IDENTICAL':'CONSISTENT_PREFIX_EXTENSION';
 return Object.freeze({status,registryId,firstConflictingReceiptSequence:bodyDiff<0?null:bodyDiff+1,firstConflictingPolicyEpoch:policyDiff<0?null:policyDiff,
  left:Object.freeze({head:a.head,transitionDigest:a.transitionDigest}),right:Object.freeze({head:b.head,transitionDigest:b.transitionDigest}),
  readOnly:true,mayManufacture:false,productionApproved:false});
}
