/** Objective 35Y: signed, challenge-bound operator review evidence for LOCAL
 * artwork retention snapshots. Read-only: neither this module nor a valid
 * signature authorizes quarantine, deletion, Shopify operations, or printing.
 * The caller holds keys/challenges; there is no hosted trust or trusted clock.
 */
import {createHash, sign as edSign, verify as edVerify} from 'node:crypto';
import {verifyLocalArtworkQuarantineIntent} from './preview-local-artwork-quarantine-review.mjs';

const fail=(code,cause)=>Object.assign(new Error(code),{code,cause});
const schema='trendyjoes.local-artwork-review-evidence.v1';
const purpose='OPERATOR_READ_ONLY_ARTWORK_REVIEW';
const domain='TRENDYJOES_OFFLINE_ARTWORK_REVIEW_EVIDENCE_V1\n';
const hex64=/^[a-f0-9]{64}$/;
const hex32=/^[a-f0-9]{32}$/;
const idPattern=/^art_[a-f0-9]{32}$/;
const keyIdPattern=/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const signaturePattern=/^[A-Za-z0-9_-]{86}$/;
const fields=['schema','purpose','keyId','rootPin','referencePin','ticketDigest',
 'candidateArtworkIds','candidateCount','observedAt','expiresAt','challenge',
 'referenceScanComplete','authority','safeToAutoDelete','safeToQuarantine',
 'shopifyWritesAllowed','reason'];
const allFields=[...fields,'signature'];
const exactKeys=(value,keys)=>value!==null&&typeof value==='object'&&!Array.isArray(value)&&
 (Object.getPrototypeOf(value)===Object.prototype||Object.getPrototypeOf(value)===null)&&
 Object.keys(value).length===keys.length&&keys.every(k=>Object.hasOwn(value,k));
const clock=now=>Number.isSafeInteger(now)&&now>0&&now<=8640000000000000;
const validKey=(key,type)=>key?.type===type&&key?.asymmetricKeyType==='ed25519';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const ticketHash=ticket=>sha(JSON.stringify(ticket));
const validCandidates=(ids,maxCandidates)=>{
 if(!Array.isArray(ids)||ids.length>maxCandidates||Object.keys(ids).length!==ids.length)return false;
 for(let i=0;i<ids.length;i++){
  const id=ids[i];
  if(!Object.hasOwn(ids,i)||typeof id!=='string'||!idPattern.test(id)||
   (i>0&&ids[i-1]>=id))return false;
 }
 return true;
};
const message=body=>Buffer.from(domain+JSON.stringify(body),'utf8');
const positiveLimit=(value,max)=>Number.isSafeInteger(value)&&value>0&&value<=max;
function validatedBody(record,maxCandidates){
 if(!exactKeys(record,allFields))throw fail('LOCAL_REVIEW_EVIDENCE_INVALID');
 const body=Object.fromEntries(fields.map(k=>[k,record[k]]));
 if(body.schema!==schema||body.purpose!==purpose||typeof body.keyId!=='string'||!keyIdPattern.test(body.keyId)||
  typeof body.rootPin!=='string'||!hex64.test(body.rootPin)||
  typeof body.referencePin!=='string'||!hex64.test(body.referencePin)||
  typeof body.ticketDigest!=='string'||!hex64.test(body.ticketDigest)||
  !validCandidates(body.candidateArtworkIds,maxCandidates)||body.candidateCount!==body.candidateArtworkIds.length||
  !clock(body.observedAt)||!clock(body.expiresAt)||body.expiresAt<=body.observedAt||
  body.expiresAt-body.observedAt>300000||typeof body.challenge!=='string'||!hex32.test(body.challenge)||
  body.referenceScanComplete!==true||body.authority!=='NONE'||body.safeToAutoDelete!==false||
  body.safeToQuarantine!==false||body.shopifyWritesAllowed!==false||
  body.reason!=='LOCAL_SNAPSHOT_ONLY_NOT_MUTATION_AUTHORITY'||
  typeof record.signature!=='string'||!signaturePattern.test(record.signature))
  throw fail('LOCAL_REVIEW_EVIDENCE_INVALID');
 return body;
}
function validateLimits({maxCandidates,maxEvidenceBytes}){
 if(!positiveLimit(maxCandidates,1024)||!positiveLimit(maxEvidenceBytes,131072))
  throw fail('LOCAL_REVIEW_EVIDENCE_INVALID_OPTIONS');
}
function enforceSize(value,maxEvidenceBytes){
 if(Buffer.byteLength(JSON.stringify(value),'utf8')>maxEvidenceBytes)
  throw fail('LOCAL_REVIEW_EVIDENCE_TOO_LARGE');
}
/** A reviewer supplies an unpredictable, single-session challenge out of band.
 * The signer never persists the private key or evidence; review of the local
 * snapshot must succeed before signing. The signature is NOT an authorization.
 */
export async function createLocalArtworkReviewEvidence(root,ticket,{
 reviewKey,signingKey,keyId,challenge,now=Date.now(),ttlMs=120000,io,
 maxCandidates=1024,maxEvidenceBytes=65536
}={}){
 validateLimits({maxCandidates,maxEvidenceBytes});
 if(!validKey(signingKey,'private')||typeof keyId!=='string'||!keyIdPattern.test(keyId)||
  typeof challenge!=='string'||!hex32.test(challenge)||!clock(now)||
  !positiveLimit(ttlMs,300000))throw fail('LOCAL_REVIEW_EVIDENCE_INVALID_OPTIONS');
 const verified=await verifyLocalArtworkQuarantineIntent(root,ticket,{reviewKey,now,io});
 if(!validCandidates(verified.candidateArtworkIds,maxCandidates))throw fail('LOCAL_REVIEW_EVIDENCE_TOO_MANY_CANDIDATES');
 const expiresAt=Math.min(now+ttlMs,ticket.expiresAt);
 if(!clock(expiresAt)||expiresAt<=now)throw fail('LOCAL_REVIEW_EVIDENCE_EXPIRED');
 const body={schema,purpose,keyId,rootPin:ticket.rootPin,referencePin:verified.referencePin,
  ticketDigest:ticketHash(ticket),candidateArtworkIds:[...verified.candidateArtworkIds],
  candidateCount:verified.candidateArtworkIds.length,observedAt:now,expiresAt,challenge,
  referenceScanComplete:true,authority:'NONE',safeToAutoDelete:false,
  safeToQuarantine:false,shopifyWritesAllowed:false,
  reason:'LOCAL_SNAPSHOT_ONLY_NOT_MUTATION_AUTHORITY'};
 const evidence={...body,signature:edSign(null,message(body),signingKey).toString('base64url')};
 enforceSize(evidence,maxEvidenceBytes);
 return Object.freeze({...evidence,candidateArtworkIds:Object.freeze(evidence.candidateArtworkIds)});
}
/** Historical signature authentication ONLY. This deliberately does not check
 * current expiry, the live artwork snapshot, ticket HMAC, or reviewer-session
 * freshness. The caller MUST supply trusted historical signer-key resolution
 * and an independently retained journal head. Never treat this as approval.
 */
export async function verifyHistoricalLocalArtworkReviewSignature(evidence,{
 resolvePublicKey,maxCandidates=1024,maxEvidenceBytes=65536
}={}){
 validateLimits({maxCandidates,maxEvidenceBytes});
 if(typeof resolvePublicKey!=='function')throw fail('LOCAL_REVIEW_EVIDENCE_INVALID_OPTIONS');
 const body=validatedBody(evidence,maxCandidates);
 enforceSize(evidence,maxEvidenceBytes);
 let publicKey;
 try{publicKey=await resolvePublicKey(body.keyId);}catch(error){throw fail('LOCAL_REVIEW_EVIDENCE_UNTRUSTED_SIGNER',error);}
 if(!validKey(publicKey,'public'))throw fail('LOCAL_REVIEW_EVIDENCE_UNTRUSTED_SIGNER');
 const sig=Buffer.from(evidence.signature,'base64url');
 if(sig.length!==64||sig.toString('base64url')!==evidence.signature||
  !edVerify(null,message(body),publicKey,sig))throw fail('LOCAL_REVIEW_EVIDENCE_BAD_SIGNATURE');
 return Object.freeze({historicalSignatureVerified:true,evidenceDigest:sha(JSON.stringify(evidence)),
  rootPin:body.rootPin,referencePin:body.referencePin,ticketDigest:body.ticketDigest,
  challenge:body.challenge,keyId:body.keyId,observedAt:body.observedAt,expiresAt:body.expiresAt,
  authority:'NONE',safeToAutoDelete:false,safeToQuarantine:false,shopifyWritesAllowed:false,
  liveSnapshotVerified:false,currentFreshnessVerified:false,independentlyWitnessed:false});
}
/** The public key MUST come from trusted caller configuration, not evidence.
 * A challenge mismatch rejects a replay in another reviewer session. A replay
 * within the same challenge/TTL remains possible: no durable nonce registry.
 */
export async function verifyLocalArtworkReviewEvidence(root,evidence,ticket,{
 reviewKey,resolvePublicKey,expectedChallenge,now=Date.now(),io,
 maxCandidates=1024,maxEvidenceBytes=65536
}={}){
 validateLimits({maxCandidates,maxEvidenceBytes});
 if(!clock(now)||typeof expectedChallenge!=='string'||!hex32.test(expectedChallenge)||
  typeof resolvePublicKey!=='function')throw fail('LOCAL_REVIEW_EVIDENCE_INVALID_OPTIONS');
 const body=validatedBody(evidence,maxCandidates);
 enforceSize(evidence,maxEvidenceBytes);
 if(body.challenge!==expectedChallenge)throw fail('LOCAL_REVIEW_EVIDENCE_WRONG_CHALLENGE');
 if(now<body.observedAt||now>=body.expiresAt)throw fail('LOCAL_REVIEW_EVIDENCE_EXPIRED');
 let publicKey;
 try{publicKey=await resolvePublicKey(body.keyId);}catch(error){throw fail('LOCAL_REVIEW_EVIDENCE_UNTRUSTED_SIGNER',error);}
 if(!validKey(publicKey,'public'))throw fail('LOCAL_REVIEW_EVIDENCE_UNTRUSTED_SIGNER');
 const sig=Buffer.from(evidence.signature,'base64url');
 if(sig.length!==64||sig.toString('base64url')!==evidence.signature||
  !edVerify(null,message(body),publicKey,sig))throw fail('LOCAL_REVIEW_EVIDENCE_BAD_SIGNATURE');
 // Compare only after authenticating the signature; do not read storage for
 // malformed/forged evidence. The ticket verifier performs a fresh lease scan.
 if(!ticket||typeof ticket!=='object'||Array.isArray(ticket))throw fail('LOCAL_REVIEW_EVIDENCE_WRONG_TICKET');
 if(ticketHash(ticket)!==body.ticketDigest||ticket.rootPin!==body.rootPin||
  ticket.referencePin!==body.referencePin||ticket.expiresAt<body.expiresAt||
  ticket.issuedAt>body.observedAt||
  JSON.stringify(ticket.candidateArtworkIds)!==JSON.stringify(body.candidateArtworkIds))
  throw fail('LOCAL_REVIEW_EVIDENCE_WRONG_TICKET');
 const scan=await verifyLocalArtworkQuarantineIntent(root,ticket,{reviewKey,now,io});
 if(scan.referencePin!==body.referencePin||
  JSON.stringify(scan.candidateArtworkIds)!==JSON.stringify(body.candidateArtworkIds))
  throw fail('LOCAL_REVIEW_EVIDENCE_STALE');
 const evidenceDigest=sha(JSON.stringify(evidence));
 const report=[
  'TRENDYJOES — LOCAL ARTWORK REVIEW EVIDENCE (READ ONLY)',
  'Signature: VERIFIED against caller-trusted Ed25519 public key',
  `Signer key ID: ${body.keyId}`,
  `Evidence SHA-256: ${evidenceDigest}`,
  `Root pin: ${body.rootPin}`,
  `Content/reference pin: ${body.referencePin}`,
  `Issued: ${new Date(body.observedAt).toISOString()}`,
  `Expires: ${new Date(body.expiresAt).toISOString()}`,
  `Review challenge: ${body.challenge}`,
  `Unreferenced complete artwork candidates (${body.candidateCount}):`,
  ...body.candidateArtworkIds.map(id=>`  ${id}`),
  'AUTHORITY: NONE. NO DELETE. NO QUARANTINE. NO SHOPIFY WRITES.',
  'Snapshot may change after verification. No production writer fence.',
 ].join('\n')+'\n';
 if(Buffer.byteLength(report,'utf8')>maxEvidenceBytes)throw fail('LOCAL_REVIEW_EVIDENCE_TOO_LARGE');
 return Object.freeze({schema,verifiedReadOnly:true,evidenceDigest,
  referencePin:body.referencePin,candidateCount:body.candidateCount,
  operatorReport:report,safeToAutoDelete:false,safeToQuarantine:false,
  shopifyWritesAllowed:false,reason:'LOCAL_SNAPSHOT_ONLY_NOT_MUTATION_AUTHORITY'});
}
