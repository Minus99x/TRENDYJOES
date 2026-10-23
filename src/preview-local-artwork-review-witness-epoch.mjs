/** Objective 35AH: offline, externally pinned roster-epoch transition and
 * issuer-signed challenge tickets. NOT hosted identity, external key custody,
 * cross-host replay consensus, or production authority. No Shopify I/O. */
import {createHash,createPublicKey,sign,verify,timingSafeEqual} from 'node:crypto';
import {verifyOfflinePinnedWitnessRoster,verifyOfflineWitnessWithPinnedRoster} from './preview-local-artwork-review-witness-roster-ledger.mjs';

export const OFFLINE_WITNESS_EPOCH_SCHEMA='TJ-LOCAL-WITNESS-EPOCH-35AH-1';
export const OFFLINE_WITNESS_ISSUANCE_SCHEMA='TJ-LOCAL-WITNESS-ISSUANCE-35AH-1';
const EPOCH_DOMAIN='TRENDYJOES_LOCAL_WITNESS_EPOCH_35AH_V1\n';
const ISSUE_DOMAIN='TRENDYJOES_LOCAL_WITNESS_ISSUANCE_35AH_V1\n';
const HEX=/^[0-9a-f]{64}$/;
const SIG=/^[A-Za-z0-9_-]{86}$/;
const MAX_TTL=300000;
const TRANSITION_FIELDS=['schema','rootPin','registryId','policySignerFingerprint','audience','previousRosterSha256','nextRosterSha256','previousEpoch','nextEpoch','cutoverMs','issuerKeyFingerprint','authority'];
const TICKET_FIELDS=['schema','rootPin','registryId','audience','rosterSha256','epoch','transitionSha256','witnessId','challenge','parentCheckpointSha256','parentRevision','candidateCheckpointSha256','candidateRevision','issuedAtMs','expiresAtMs','issuerKeyFingerprint','authority'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const sha=x=>createHash('sha256').update(x).digest('hex');
const hex=x=>typeof x==='string'&&HEX.test(x);
const eq=(a,b)=>hex(a)&&hex(b)&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
const key=(k,type)=>k?.type===type&&k?.asymmetricKeyType==='ed25519';
const fingerprint=k=>sha(k.export({type:'spki',format:'der'}));
const integer=x=>Number.isSafeInteger(x)&&x>=0;
const exact=(o,fields)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===fields.length&&
 fields.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value'in d&&d.enumerable;});
function parseSigned(input,fields,code){
 if(!Buffer.isBuffer(input)||input.length<2||input.length>4096)fail(code);
 const bytes=Buffer.from(input);
 let parsed;try{parsed=JSON.parse(bytes.toString('utf8'));}catch{fail(code);}
 const signed=[...fields,'signature'];
 if(!exact(parsed,signed)||!Object.keys(parsed).every((k,i)=>k===signed[i])||
  !Buffer.from(JSON.stringify(parsed)).equals(bytes)||!SIG.test(parsed.signature))fail(code);
 const sig=Buffer.from(parsed.signature,'base64url');
 if(sig.length!==64||sig.toString('base64url')!==parsed.signature)fail(code);
 return {body:Object.fromEntries(fields.map(k=>[k,parsed[k]])),signature:sig,bytes};
}
function signedBytes(body,fields,domain,signingKey,code){
 if(!key(signingKey,'private')||!exact(body,fields))fail(code);
 const signature=sign(null,Buffer.from(domain+JSON.stringify(body)),signingKey).toString('base64url');
 const bytes=Buffer.from(JSON.stringify({...body,signature}));
 if(bytes.length>4096)fail(code);
 return Object.freeze({bytes,sha256:sha(bytes),authorizesProduction:false});
}
function validateTransition(t){
 if(t.schema!==OFFLINE_WITNESS_EPOCH_SCHEMA||t.authority!=='NONE'||
  ![t.rootPin,t.registryId,t.policySignerFingerprint,t.audience,
   t.previousRosterSha256,t.nextRosterSha256,t.issuerKeyFingerprint].every(hex)||
  eq(t.previousRosterSha256,t.nextRosterSha256)||!integer(t.previousEpoch)||
  !integer(t.nextEpoch)||t.nextEpoch!==t.previousEpoch+1||!integer(t.cutoverMs))
  fail('OFFLINE_EPOCH_INVALID_TRANSITION');
}
/** Fixture signer only. Caller must pin the signer, previous head, and bytes externally. */
export function createOfflineWitnessRosterEpochTransition({signingKey,rootPin,registryId,
 policySignerFingerprint,audience,previousRosterSha256,nextRosterSha256,previousEpoch,
 nextEpoch,cutoverMs}={}){
 if(!key(signingKey,'private'))fail('OFFLINE_EPOCH_INVALID_SIGNER');
 const issuerKeyFingerprint=fingerprint(createPublicKey(signingKey));
 const body={schema:OFFLINE_WITNESS_EPOCH_SCHEMA,rootPin,registryId,policySignerFingerprint,
  audience,previousRosterSha256,nextRosterSha256,previousEpoch,nextEpoch,cutoverMs,
  issuerKeyFingerprint,authority:'NONE'};
 validateTransition(body);
 return signedBytes(body,TRANSITION_FIELDS,EPOCH_DOMAIN,signingKey,'OFFLINE_EPOCH_INVALID_TRANSITION');
}
function checkedSignature({bytes,fields,domain,publicKey,expectedKeyFingerprint,expectedSha256,code}){
 if(!key(publicKey,'public')||!hex(expectedKeyFingerprint)||
  !eq(fingerprint(publicKey),expectedKeyFingerprint)||!hex(expectedSha256))fail('OFFLINE_EPOCH_MISSING_EXTERNAL_PINS');
 const parsed=parseSigned(bytes,fields,code);
 if(!eq(sha(parsed.bytes),expectedSha256))fail('OFFLINE_EPOCH_DIGEST_MISMATCH');
 if(!eq(parsed.body.issuerKeyFingerprint,expectedKeyFingerprint))fail('OFFLINE_EPOCH_SIGNER_SUBSTITUTION');
 if(!verify(null,Buffer.from(domain+JSON.stringify(parsed.body)),publicKey,parsed.signature))
  fail('OFFLINE_EPOCH_BAD_SIGNATURE');
 return parsed.body;
}
/** External epoch head must be independently retained; no self-advancing trust. */
export function verifyOfflineWitnessRosterEpochTransition({transitionBytes,
 expectedTransitionSha256,issuerPublicKey,expectedIssuerKeyFingerprint,
 previousRosterBytes,nextRosterBytes,expectedPreviousRosterSha256,
 expectedNextRosterSha256,expectedRootPin,expectedRegistryId,
 expectedPolicySignerFingerprint,expectedAudience,expectedPreviousEpoch,
 expectedNextEpoch,trustedNowMs}={}){
 if(!integer(trustedNowMs)||!integer(expectedPreviousEpoch)||!integer(expectedNextEpoch)||
  expectedNextEpoch!==expectedPreviousEpoch+1||
  ![expectedPreviousRosterSha256,expectedNextRosterSha256,expectedRootPin,
    expectedRegistryId,expectedPolicySignerFingerprint,expectedAudience].every(hex))
  fail('OFFLINE_EPOCH_MISSING_EXTERNAL_PINS');
 const t=checkedSignature({bytes:transitionBytes,fields:TRANSITION_FIELDS,
  domain:EPOCH_DOMAIN,publicKey:issuerPublicKey,
  expectedKeyFingerprint:expectedIssuerKeyFingerprint,
  expectedSha256:expectedTransitionSha256,code:'OFFLINE_EPOCH_MALFORMED_TRANSITION'});
 validateTransition(t);
 if(!eq(t.rootPin,expectedRootPin)||!eq(t.registryId,expectedRegistryId)||
  !eq(t.policySignerFingerprint,expectedPolicySignerFingerprint)||
  !eq(t.audience,expectedAudience)||
  !eq(t.previousRosterSha256,expectedPreviousRosterSha256)||
  !eq(t.nextRosterSha256,expectedNextRosterSha256)||
  t.previousEpoch!==expectedPreviousEpoch||t.nextEpoch!==expectedNextEpoch)
  fail('OFFLINE_EPOCH_HEAD_MISMATCH');
 if(trustedNowMs<t.cutoverMs)fail('OFFLINE_EPOCH_NOT_YET_ACTIVE');
 // Historical validity is checked at the instant immediately before cutover.
 // This does not require the superseded roster to be currently valid.
 if(!integer(t.cutoverMs)||t.cutoverMs<1)fail('OFFLINE_EPOCH_INVALID_TRANSITION');
 const previous=verifyOfflinePinnedWitnessRoster({rosterBytes:previousRosterBytes,
  expectedRosterSha256:expectedPreviousRosterSha256,expectedRootPin,expectedRegistryId,
  expectedPolicySignerFingerprint,expectedAudience,trustedNowMs:t.cutoverMs-1});
 const next=verifyOfflinePinnedWitnessRoster({rosterBytes:nextRosterBytes,
  expectedRosterSha256:expectedNextRosterSha256,expectedRootPin,expectedRegistryId,
  expectedPolicySignerFingerprint,expectedAudience,trustedNowMs});
 if(next.validFromMs>t.cutoverMs||previous.validUntilMs<t.cutoverMs||
  next.validFromMs<=previous.validFromMs)fail('OFFLINE_EPOCH_INVALID_CUTOVER');
 return Object.freeze({epoch:t.nextEpoch,rosterSha256:next.rosterSha256,
  transitionSha256:sha(transitionBytes),cutoverMs:t.cutoverMs,
  authorizesProduction:false,independentCustodyVerified:false});
}
function validateTicket(t){
 if(t.schema!==OFFLINE_WITNESS_ISSUANCE_SCHEMA||t.authority!=='NONE'||
  ![t.rootPin,t.registryId,t.audience,t.rosterSha256,t.transitionSha256,
    t.witnessId,t.challenge,t.parentCheckpointSha256,
    t.candidateCheckpointSha256,t.issuerKeyFingerprint].every(hex)||
  !integer(t.epoch)||!integer(t.parentRevision)||t.parentRevision<1||
  !integer(t.candidateRevision)||t.candidateRevision!==t.parentRevision+1||
  eq(t.parentCheckpointSha256,t.candidateCheckpointSha256)||
  !integer(t.issuedAtMs)||!integer(t.expiresAtMs)||t.expiresAtMs<=t.issuedAtMs||
  t.expiresAtMs-t.issuedAtMs>MAX_TTL)fail('OFFLINE_ISSUANCE_INVALID_TICKET');
}
/** Offline fixture issuance; signing does not establish hosted challenge delivery. */
export function createOfflineWitnessChallengeTicket({signingKey,...input}={}){
 if(!key(signingKey,'private'))fail('OFFLINE_EPOCH_INVALID_SIGNER');
 const body={schema:OFFLINE_WITNESS_ISSUANCE_SCHEMA,...Object.fromEntries(TICKET_FIELDS.slice(1,-2).map(k=>[k,input[k]])),
  issuerKeyFingerprint:fingerprint(createPublicKey(signingKey)),authority:'NONE'};
 validateTicket(body);
 return signedBytes(body,TICKET_FIELDS,ISSUE_DOMAIN,signingKey,'OFFLINE_ISSUANCE_INVALID_TICKET');
}
/** Verifies issuer signature, independently pinned epoch/roster and challenge
 * before delegating witness signature + durable replay to Objective 35AG. */
export async function verifyOfflineIssuedWitnessAcknowledgement({ticketBytes,
 expectedTicketSha256,issuerPublicKey,expectedIssuerKeyFingerprint,
 epochTransitionBytes,expectedTransitionSha256,previousRosterBytes,
 nextRosterBytes,expectedPreviousRosterSha256,expectedNextRosterSha256,
 expectedPreviousEpoch,expectedNextEpoch,expectedRootPin,expectedRegistryId,
 expectedPolicySignerFingerprint,expectedAudience,trustedNowMs,
 witnessId,witnessPublicKey,receiptBytes,ledger}={}){
 // Snapshot mutable caller-owned bytes before any asynchronous replay-store operation.
 const transitionSnapshot=Buffer.isBuffer(epochTransitionBytes)?Buffer.from(epochTransitionBytes):epochTransitionBytes;
 const ticketSnapshot=Buffer.isBuffer(ticketBytes)?Buffer.from(ticketBytes):ticketBytes;
 const previousSnapshot=Buffer.isBuffer(previousRosterBytes)?Buffer.from(previousRosterBytes):previousRosterBytes;
 const nextSnapshot=Buffer.isBuffer(nextRosterBytes)?Buffer.from(nextRosterBytes):nextRosterBytes;
 const receiptSnapshot=Buffer.isBuffer(receiptBytes)?Buffer.from(receiptBytes):receiptBytes;
 const epoch=verifyOfflineWitnessRosterEpochTransition({transitionBytes:transitionSnapshot,
  expectedTransitionSha256,issuerPublicKey,expectedIssuerKeyFingerprint,
  previousRosterBytes:previousSnapshot,nextRosterBytes:nextSnapshot,expectedPreviousRosterSha256,
  expectedNextRosterSha256,expectedRootPin,expectedRegistryId,
  expectedPolicySignerFingerprint,expectedAudience,expectedPreviousEpoch,
  expectedNextEpoch,trustedNowMs});
 const t=checkedSignature({bytes:ticketSnapshot,fields:TICKET_FIELDS,
  domain:ISSUE_DOMAIN,publicKey:issuerPublicKey,
  expectedKeyFingerprint:expectedIssuerKeyFingerprint,
  expectedSha256:expectedTicketSha256,code:'OFFLINE_ISSUANCE_MALFORMED_TICKET'});
 validateTicket(t);
 if(!eq(t.rootPin,expectedRootPin)||!eq(t.registryId,expectedRegistryId)||
  !eq(t.audience,expectedAudience)||!eq(t.rosterSha256,epoch.rosterSha256)||
  !eq(t.transitionSha256,epoch.transitionSha256)||t.epoch!==epoch.epoch||
  !eq(t.witnessId,witnessId))fail('OFFLINE_ISSUANCE_PIN_MISMATCH');
 if(t.issuedAtMs<epoch.cutoverMs)fail('OFFLINE_ISSUANCE_PRE_CUTOVER');
 if(trustedNowMs<t.issuedAtMs)fail('OFFLINE_ISSUANCE_NOT_YET_VALID');
 if(trustedNowMs>=t.expiresAtMs)fail('OFFLINE_ISSUANCE_EXPIRED');
 const roster=verifyOfflinePinnedWitnessRoster({rosterBytes:nextSnapshot,
  expectedRosterSha256:expectedNextRosterSha256,expectedRootPin,expectedRegistryId,
  expectedPolicySignerFingerprint,expectedAudience,trustedNowMs});
 if(t.expiresAtMs>roster.validUntilMs)fail('OFFLINE_ISSUANCE_OUTLIVES_ROSTER');
 // Fail closed BEFORE consuming the one-time challenge if receipt dates do not
 // belong to this signed issuance window. The underlying 35AF verifier checks
 // canonical form, binding and signature before writing the replay receipt.
 let receipt;try{if(!Buffer.isBuffer(receiptSnapshot))throw Error();
  receipt=JSON.parse(receiptSnapshot.toString('utf8'));}catch{fail('OFFLINE_ISSUANCE_INVALID_RECEIPT');}
 if(!integer(receipt.issuedAtMs)||receipt.issuedAtMs<t.issuedAtMs||
  !integer(receipt.expiresAtMs)||receipt.expiresAtMs>t.expiresAtMs)
  fail('OFFLINE_ISSUANCE_RECEIPT_WINDOW_MISMATCH');
 const checked=await verifyOfflineWitnessWithPinnedRoster({rosterBytes:nextSnapshot,
  expectedRosterSha256:expectedNextRosterSha256,expectedRootPin,expectedRegistryId,
  expectedPolicySignerFingerprint,expectedAudience,trustedNowMs,witnessId,
  witnessPublicKey,challenge:t.challenge,receiptBytes:receiptSnapshot,
  expectedParentCheckpointSha256:t.parentCheckpointSha256,
  expectedParentRevision:t.parentRevision,
  expectedCandidateSha256:t.candidateCheckpointSha256,
  expectedCandidateRevision:t.candidateRevision,ledger});
 return Object.freeze({...checked,epoch:epoch.epoch,challengeTicketSha256:sha(ticketSnapshot),
  authorizesProduction:false,shopifyWritesAllowed:false});
}
