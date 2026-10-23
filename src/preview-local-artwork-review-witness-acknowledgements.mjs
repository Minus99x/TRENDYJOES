/** Objective 35AF: OFFLINE witness-signed checkpoint observations and portable
 * split-view evidence. All pins, trusted clock, and atomic replay store must be
 * supplied independently. This module neither hosts witnesses nor stores keys.
 * No Shopify, production authorization, or network access.
 */
import {createHash,createPublicKey,sign,verify,timingSafeEqual} from 'node:crypto';
import {inspectOfflineLocalReviewPolicySplitView} from './preview-local-artwork-review-policy-cas.mjs';
import {LOCAL_REVIEW_RETAINED_HEAD_SCHEMA} from './preview-local-artwork-review-policy-checkpoints.mjs';

export const OFFLINE_WITNESS_ACK_SCHEMA='TJ-LOCAL-POLICY-WITNESS-ACK-35AF-1';
export const OFFLINE_WITNESSED_FORK_SCHEMA='TJ-LOCAL-POLICY-WITNESSED-FORK-35AF-1';
const DOMAIN='TRENDYJOES_LOCAL_POLICY_WITNESS_ACK_35AF_V1\n';
const HEX=/^[a-f0-9]{64}$/;
const SIG=/^[A-Za-z0-9_-]{86}$/;
const MAX_TTL=300000;
const BODY=['schema','witnessId','witnessKeyFingerprint','rootPin','registryId',
 'policySignerFingerprint','parentCheckpointSha256','parentRevision',
 'candidateCheckpointSha256','candidateRevision','challenge','audience',
 'issuedAtMs','expiresAtMs','authority'];
const SIGNED=[...BODY,'signature'];
const HEAD=['schema','rootPin','registryId','signerFingerprint','checkpointSha256','revision'];
const FORK=['schema','rootPin','registryId','policySignerFingerprint',
 'parentCheckpointSha256','parentRevision','forkRevision','audience',
 'leftCheckpointBytesBase64url','rightCheckpointBytesBase64url',
 'leftReceiptBase64url','rightReceiptBase64url','evidenceSha256'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const sha=x=>createHash('sha256').update(x).digest('hex');
const hex=x=>typeof x==='string'&&HEX.test(x);
const equal=(a,b)=>hex(a)&&hex(b)&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
const key=(k,t)=>k?.type===t&&k?.asymmetricKeyType==='ed25519';
const fingerprint=k=>sha(k.export({type:'spki',format:'der'}));
const exact=(x,fields)=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(x))&&
 Reflect.ownKeys(x).length===fields.length&&fields.every(k=>{
  const d=Object.getOwnPropertyDescriptor(x,k);return d&&'value'in d&&d.enumerable;
 });
function snapshot(b,code,max=16384){
 if(!Buffer.isBuffer(b)||b.length<2||b.length>max)fail(code);
 return Buffer.from(b);
}
function strictB64(s,code){
 if(typeof s!=='string'||s.length<3||s.length>24000||!/^[A-Za-z0-9_-]+$/.test(s))fail(code);
 const b=Buffer.from(s,'base64url');
 if(b.toString('base64url')!==s)fail(code);
 return snapshot(b,code);
}
function headValid(h){
 if(!exact(h,HEAD)||h.schema!==LOCAL_REVIEW_RETAINED_HEAD_SCHEMA||
  !hex(h.rootPin)||!hex(h.registryId)||!hex(h.signerFingerprint)||
  !hex(h.checkpointSha256)||!Number.isSafeInteger(h.revision)||h.revision<1)
  fail('OFFLINE_WITNESS_INVALID_HEAD');
 return {...h};
}
function bodyValid(b){
 if(!exact(b,BODY)||b.schema!==OFFLINE_WITNESS_ACK_SCHEMA||
  ![b.witnessId,b.witnessKeyFingerprint,b.rootPin,b.registryId,
   b.policySignerFingerprint,b.parentCheckpointSha256,
   b.candidateCheckpointSha256,b.challenge,b.audience].every(hex)||
  !Number.isSafeInteger(b.parentRevision)||b.parentRevision<1||
  !Number.isSafeInteger(b.candidateRevision)||b.candidateRevision!==b.parentRevision+1||
  equal(b.parentCheckpointSha256,b.candidateCheckpointSha256)||
  !Number.isSafeInteger(b.issuedAtMs)||b.issuedAtMs<0||
  !Number.isSafeInteger(b.expiresAtMs)||b.expiresAtMs<=b.issuedAtMs||
  b.expiresAtMs-b.issuedAtMs>MAX_TTL||b.authority!=='NONE')
  fail('OFFLINE_WITNESS_INVALID_BODY');
}
function pinned(b,p){
 const comparisons=[['witnessId','expectedWitnessId'],['witnessKeyFingerprint','expectedWitnessKeyFingerprint'],
  ['rootPin','expectedRootPin'],['registryId','expectedRegistryId'],
  ['policySignerFingerprint','expectedPolicySignerFingerprint'],
  ['parentCheckpointSha256','expectedParentCheckpointSha256'],
  ['candidateCheckpointSha256','expectedCandidateSha256'],
  ['challenge','expectedChallenge'],['audience','expectedAudience']];
 if(comparisons.some(([a,c])=>!equal(b[a],p[c]))||
  b.parentRevision!==p.expectedParentRevision||
  b.candidateRevision!==p.expectedCandidateRevision)
  fail('OFFLINE_WITNESS_PIN_MISMATCH');
}
/** Signing helper for an offline fixture; not evidence of an external observer. */
export function createOfflineWitnessAcknowledgement({signingKey,witnessId,head,
 candidateCheckpointSha256,challenge,audience,issuedAtMs,expiresAtMs}={}){
 if(!key(signingKey,'private'))fail('OFFLINE_WITNESS_INVALID_SIGNER');
 const h=headValid(head),pub=createPublicKey(signingKey);
 const b={schema:OFFLINE_WITNESS_ACK_SCHEMA,witnessId,
  witnessKeyFingerprint:fingerprint(pub),rootPin:h.rootPin,registryId:h.registryId,
  policySignerFingerprint:h.signerFingerprint,
  parentCheckpointSha256:h.checkpointSha256,parentRevision:h.revision,
  candidateCheckpointSha256,candidateRevision:h.revision+1,challenge,audience,
  issuedAtMs,expiresAtMs,authority:'NONE'};
 bodyValid(b);
 const signature=sign(null,Buffer.from(DOMAIN+JSON.stringify(b)),signingKey).toString('base64url');
 const bytes=Buffer.from(JSON.stringify({...b,signature}));
 if(bytes.length>4096)fail('OFFLINE_WITNESS_INVALID_BYTES');
 return Object.freeze({bytes,sha256:sha(bytes),witnessId,
  independentlyWitnessed:false,authorizesProduction:false});
}
/** An external trusted atomic consumeOnce(token) is mandatory; this callback
 * must durably arbitrate concurrent callers. Local in-memory Sets do not prove
 * cross-host replay protection. No automatic retry on uncertain results.
 */
export async function verifyOfflineWitnessAcknowledgement({receiptBytes,witnessPublicKey,
 expectedWitnessId,expectedWitnessKeyFingerprint,expectedRootPin,expectedRegistryId,
 expectedPolicySignerFingerprint,expectedParentCheckpointSha256,expectedParentRevision,
 expectedCandidateSha256,expectedCandidateRevision,expectedChallenge,expectedAudience,
 trustedNowMs,consumeOnce}={}){
 const bytes=snapshot(receiptBytes,'OFFLINE_WITNESS_INVALID_BYTES',4096);
 if(!key(witnessPublicKey,'public')||!hex(expectedWitnessKeyFingerprint)||
  !equal(fingerprint(witnessPublicKey),expectedWitnessKeyFingerprint)||
  !Number.isSafeInteger(trustedNowMs)||trustedNowMs<0||typeof consumeOnce!=='function')
  fail('OFFLINE_WITNESS_INVALID_TRUST_BOUNDARY');
 let parsed;
 try{parsed=JSON.parse(bytes.toString('utf8'));}catch{fail('OFFLINE_WITNESS_MALFORMED');}
 if(!exact(parsed,SIGNED)||!Object.keys(parsed).every((k,i)=>k===SIGNED[i])||
  !Buffer.from(JSON.stringify(parsed)).equals(bytes))
  fail('OFFLINE_WITNESS_MALFORMED');
 const b=Object.fromEntries(BODY.map(k=>[k,parsed[k]]));
 bodyValid(b);
 pinned(b,{expectedWitnessId,expectedWitnessKeyFingerprint,expectedRootPin,
  expectedRegistryId,expectedPolicySignerFingerprint,expectedParentCheckpointSha256,
  expectedParentRevision,expectedCandidateSha256,expectedCandidateRevision,
  expectedChallenge,expectedAudience});
 if(typeof parsed.signature!=='string'||!SIG.test(parsed.signature))
  fail('OFFLINE_WITNESS_MALFORMED');
 const signature=Buffer.from(parsed.signature,'base64url');
 if(signature.length!==64||signature.toString('base64url')!==parsed.signature)
  fail('OFFLINE_WITNESS_MALFORMED');
 if(!verify(null,Buffer.from(DOMAIN+JSON.stringify(b)),witnessPublicKey,signature))
  fail('OFFLINE_WITNESS_BAD_SIGNATURE');
 if(trustedNowMs<b.issuedAtMs)fail('OFFLINE_WITNESS_NOT_YET_VALID');
 if(trustedNowMs>=b.expiresAtMs)fail('OFFLINE_WITNESS_EXPIRED');
 const token=sha(Buffer.from(`${DOMAIN}REPLAY\n${sha(bytes)}\n${b.witnessId}\n${b.audience}\n${b.challenge}`));
 let consumed;
 try{consumed=await consumeOnce(token);}catch{fail('OFFLINE_WITNESS_REPLAY_STORE_UNAVAILABLE');}
 if(consumed!==true){if(consumed===false)fail('OFFLINE_WITNESS_REPLAY');
  fail('OFFLINE_WITNESS_REPLAY_STORE_UNCERTAIN');}
 return Object.freeze({witnessId:b.witnessId,receiptSha256:sha(bytes),
  candidateCheckpointSha256:b.candidateCheckpointSha256,
  candidateRevision:b.candidateRevision,signatureVerified:true,replayTokenConsumed:true,
  externalCustodyVerified:false,globalConsensusVerified:false,
  authorizesProduction:false,shopifyWritesAllowed:false});
}
/** Verifies both signer-valid checkpoint branches AND two distinct pinned
 * witness signatures. The returned evidence is portable but NOT proof that
 * observer keys or replay storage are independently controlled.
 */
export async function inspectOfflineWitnessedPolicyFork({leftCheckpointBytes,
 rightCheckpointBytes,pinnedHead,policySignerPublicKey,leftReceiptBytes,
 rightReceiptBytes,leftWitness,rightWitness,expectedAudience,trustedNowMs,
 consumeOnce}={}){
 const h=headValid(pinnedHead);
 const observer=w=>exact(w,['witnessId','challenge','publicKey'])?
  Object.freeze({witnessId:w.witnessId,challenge:w.challenge,publicKey:w.publicKey}):null;
 const wl=observer(leftWitness),wr=observer(rightWitness);
 if(!wl||!wr||!hex(wl.witnessId)||
  !hex(wr.witnessId)||equal(wl.witnessId,wr.witnessId)||
  !hex(wl.challenge)||!hex(wr.challenge)||
  equal(wl.challenge,wr.challenge)||
  !key(wl.publicKey,'public')||!key(wr.publicKey,'public')||
  equal(fingerprint(wl.publicKey),fingerprint(wr.publicKey)))
  fail('OFFLINE_WITNESS_DISTINCT_OBSERVERS_REQUIRED');
 // Snapshot all attacker-owned byte arrays before the first await.
 const chain=(input)=>{
  if(!Array.isArray(input)||input.length!==2||Reflect.ownKeys(input).length!==3)
   fail('OFFLINE_WITNESS_INVALID_CHAIN');
  return [snapshot(input[0],'OFFLINE_WITNESS_INVALID_CHAIN'),
   snapshot(input[1],'OFFLINE_WITNESS_INVALID_CHAIN')];
 };
 const left=chain(leftCheckpointBytes),right=chain(rightCheckpointBytes);
 const a=snapshot(leftReceiptBytes,'OFFLINE_WITNESS_INVALID_BYTES',4096);
 const b=snapshot(rightReceiptBytes,'OFFLINE_WITNESS_INVALID_BYTES',4096);
 const fork=await inspectOfflineLocalReviewPolicySplitView({leftCheckpointBytes:left,
  rightCheckpointBytes:right,pinnedHead:h,signerPublicKey:policySignerPublicKey,
  expectedRootPin:h.rootPin,expectedRegistryId:h.registryId,
  expectedSignerFingerprint:h.signerFingerprint});
 const common={expectedRootPin:h.rootPin,expectedRegistryId:h.registryId,
  expectedPolicySignerFingerprint:h.signerFingerprint,
  expectedParentCheckpointSha256:h.checkpointSha256,
  expectedParentRevision:h.revision,expectedCandidateRevision:h.revision+1,
  expectedAudience,trustedNowMs,consumeOnce};
 // A valid left receipt can be consumed before right fails: fail closed.
 const leftVerified=await verifyOfflineWitnessAcknowledgement({...common,
  receiptBytes:a,witnessPublicKey:wl.publicKey,
  expectedWitnessId:wl.witnessId,
  expectedWitnessKeyFingerprint:fingerprint(wl.publicKey),
  expectedChallenge:wl.challenge,
  expectedCandidateSha256:sha(left[1])});
 const rightVerified=await verifyOfflineWitnessAcknowledgement({...common,
  receiptBytes:b,witnessPublicKey:wr.publicKey,
  expectedWitnessId:wr.witnessId,
  expectedWitnessKeyFingerprint:fingerprint(wr.publicKey),
  expectedChallenge:wr.challenge,
  expectedCandidateSha256:sha(right[1])});
 const body={schema:OFFLINE_WITNESSED_FORK_SCHEMA,rootPin:h.rootPin,
  registryId:h.registryId,policySignerFingerprint:h.signerFingerprint,
  parentCheckpointSha256:h.checkpointSha256,parentRevision:h.revision,
  forkRevision:h.revision+1,audience:expectedAudience,
  leftCheckpointBytesBase64url:left[1].toString('base64url'),
  rightCheckpointBytesBase64url:right[1].toString('base64url'),
  leftReceiptBase64url:a.toString('base64url'),
  rightReceiptBase64url:b.toString('base64url')};
 const portableEvidence=Object.freeze({...body,evidenceSha256:sha(Buffer.from(JSON.stringify(body)))});
 return Object.freeze({...portableEvidence,portableEvidence,
  observerSignaturesVerified:true,policySignaturesVerified:fork.signerValidForksDetected,
  receiptDigests:Object.freeze([leftVerified.receiptSha256,rightVerified.receiptSha256]),
  externallyWitnessed:false,globalForkPreventionVerified:false,
  authorizesProduction:false,shopifyWritesAllowed:false});
}
/** Portable exchange is reverified against independently supplied original
 * parent bytes and observer pins. Self-declared evidence digests are not trust. */
export async function verifyPortableOfflineWitnessedPolicyForkEvidence({evidence,
 parentCheckpointBytes,pinnedHead,policySignerPublicKey,leftWitness,rightWitness,
 expectedAudience,trustedNowMs,consumeOnce}={}){
 if(!exact(evidence,FORK)||!Object.keys(evidence).every((k,i)=>k===FORK[i]))
  fail('OFFLINE_WITNESS_INVALID_EVIDENCE');
 const {evidenceSha256,...body}=evidence;
 if(body.schema!==OFFLINE_WITNESSED_FORK_SCHEMA||!hex(evidenceSha256)||
  !equal(sha(Buffer.from(JSON.stringify(body))),evidenceSha256))
  fail('OFFLINE_WITNESS_EVIDENCE_DIGEST_MISMATCH');
 const h=headValid(pinnedHead);
 if(!equal(body.rootPin,h.rootPin)||!equal(body.registryId,h.registryId)||
  !equal(body.policySignerFingerprint,h.signerFingerprint)||
  !equal(body.parentCheckpointSha256,h.checkpointSha256)||
  body.parentRevision!==h.revision||body.forkRevision!==h.revision+1||
  !equal(body.audience,expectedAudience))fail('OFFLINE_WITNESS_PIN_MISMATCH');
 const parent=snapshot(parentCheckpointBytes,'OFFLINE_WITNESS_INVALID_CHAIN');
 const checked=await inspectOfflineWitnessedPolicyFork({
  leftCheckpointBytes:[parent,strictB64(body.leftCheckpointBytesBase64url,'OFFLINE_WITNESS_INVALID_EVIDENCE')],
  rightCheckpointBytes:[parent,strictB64(body.rightCheckpointBytesBase64url,'OFFLINE_WITNESS_INVALID_EVIDENCE')],
  leftReceiptBytes:strictB64(body.leftReceiptBase64url,'OFFLINE_WITNESS_INVALID_EVIDENCE'),
  rightReceiptBytes:strictB64(body.rightReceiptBase64url,'OFFLINE_WITNESS_INVALID_EVIDENCE'),
  pinnedHead:h,policySignerPublicKey,leftWitness,rightWitness,
  expectedAudience,trustedNowMs,consumeOnce});
 if(!equal(checked.evidenceSha256,evidenceSha256))
  fail('OFFLINE_WITNESS_EVIDENCE_DIGEST_MISMATCH');
 return checked;
}
