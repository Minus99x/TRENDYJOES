/** Objective 35AG — offline, externally pinned witness roster and single-host
 * durable challenge ledger. Local filesystem atomicity is NOT cross-host
 * consensus or rollback-resistant external custody. No Shopify integration. */
import {createHash,timingSafeEqual} from 'node:crypto';
import {open,readFile,lstat,realpath} from 'node:fs/promises';
import {isAbsolute,join,resolve} from 'node:path';
import {verifyOfflineWitnessAcknowledgement} from './preview-local-artwork-review-witness-acknowledgements.mjs';

export const OFFLINE_WITNESS_ROSTER_SCHEMA='TJ-LOCAL-WITNESS-ROSTER-35AG-1';
export const OFFLINE_WITNESS_LEDGER_SCHEMA='TJ-LOCAL-WITNESS-LEDGER-35AG-1';
const DOMAIN='TRENDYJOES_OFFLINE_WITNESS_CHALLENGE_35AG_V1\n';
const HEX=/^[0-9a-f]{64}$/;
const ROSTER_FIELDS=['schema','rootPin','registryId','policySignerFingerprint','audience','validFromMs','validUntilMs','witnesses','authority'];
const WITNESS_FIELDS=['witnessId','publicKeyFingerprint','status'];
const RECEIPT_FIELDS=['schema','namespacePin','challengeKey','witnessId','challenge','audience','registryId','receiptReplayToken'];
const MARKER='.tj-witness-namespace.json';
const MAX_ROSTER_BYTES=16384;
const adapters=new WeakSet();
const fail=code=>{throw Object.assign(new Error(code),{code});};
const sha=x=>createHash('sha256').update(x).digest('hex');
const hex=x=>typeof x==='string'&&HEX.test(x);
const eq=(a,b)=>hex(a)&&hex(b)&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
const exact=(x,fields)=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(x))&&
 Reflect.ownKeys(x).length===fields.length&&fields.every(k=>{
  const d=Object.getOwnPropertyDescriptor(x,k);return d&&'value'in d&&d.enumerable;
 });
function strictBytes(b,max,code){
 if(!Buffer.isBuffer(b)||b.length<2||b.length>max)fail(code);
 return Buffer.from(b);
}
function canonicalParse(bytes,fields,code){
 let obj;try{obj=JSON.parse(bytes.toString('utf8'));}catch{fail(code);}
 if(!exact(obj,fields)||!Object.keys(obj).every((k,i)=>k===fields[i])||
  !Buffer.from(JSON.stringify(obj)).equals(bytes))fail(code);
 return obj;
}
function validateRoster(bytes,{expectedRosterSha256,expectedRootPin,expectedRegistryId,
 expectedPolicySignerFingerprint,expectedAudience,trustedNowMs}){
 if(!hex(expectedRosterSha256)||!hex(expectedRootPin)||!hex(expectedRegistryId)||
  !hex(expectedPolicySignerFingerprint)||!hex(expectedAudience)||
  !Number.isSafeInteger(trustedNowMs)||trustedNowMs<0)fail('OFFLINE_ROSTER_MISSING_EXTERNAL_PINS');
 const b=strictBytes(bytes,MAX_ROSTER_BYTES,'OFFLINE_ROSTER_INVALID_BYTES');
 if(!eq(sha(b),expectedRosterSha256))fail('OFFLINE_ROSTER_PIN_MISMATCH');
 const r=canonicalParse(b,ROSTER_FIELDS,'OFFLINE_ROSTER_NONCANONICAL');
 if(r.schema!==OFFLINE_WITNESS_ROSTER_SCHEMA||r.authority!=='NONE'||
  !eq(r.rootPin,expectedRootPin)||!eq(r.registryId,expectedRegistryId)||
  !eq(r.policySignerFingerprint,expectedPolicySignerFingerprint)||
  !eq(r.audience,expectedAudience)||
  !Number.isSafeInteger(r.validFromMs)||r.validFromMs<0||
  !Number.isSafeInteger(r.validUntilMs)||r.validUntilMs<=r.validFromMs||
  !Array.isArray(r.witnesses)||r.witnesses.length<2||r.witnesses.length>32)
  fail('OFFLINE_ROSTER_INVALID_POLICY');
 if(trustedNowMs<r.validFromMs||trustedNowMs>=r.validUntilMs)
  fail('OFFLINE_ROSTER_OUTSIDE_VALIDITY');
 const ids=new Set(),keys=new Set();let last='';
 for(const w of r.witnesses){
  if(!exact(w,WITNESS_FIELDS)||!hex(w.witnessId)||!hex(w.publicKeyFingerprint)||
   !['active','revoked'].includes(w.status)||w.witnessId<=last||
   ids.has(w.witnessId)||keys.has(w.publicKeyFingerprint))fail('OFFLINE_ROSTER_INVALID_WITNESSES');
  last=w.witnessId;ids.add(w.witnessId);keys.add(w.publicKeyFingerprint);
 }
 return Object.freeze({...r,witnesses:Object.freeze(r.witnesses.map(w=>Object.freeze({...w}))),rosterSha256:sha(b),independentCustodyVerified:false,authorizesProduction:false});
}
/** The SHA-256 pin MUST be obtained from an independently retained trusted source. */
export function verifyOfflinePinnedWitnessRoster({rosterBytes,...pins}={}){
 return validateRoster(rosterBytes,pins);
}
/** Fixture serializer. This does not authenticate a roster or generate a trust pin. */
export function serializeOfflineWitnessRoster({rootPin,registryId,policySignerFingerprint,
 audience,validFromMs,validUntilMs,witnesses}={}){
 const bytes=Buffer.from(JSON.stringify({schema:OFFLINE_WITNESS_ROSTER_SCHEMA,
  rootPin,registryId,policySignerFingerprint,audience,validFromMs,validUntilMs,
  witnesses,authority:'NONE'}));
 if(bytes.length>MAX_ROSTER_BYTES)fail('OFFLINE_ROSTER_INVALID_BYTES');
 return Object.freeze({bytes,sha256:sha(bytes),independentCustodyVerified:false});
}
async function checkedDirectory(directory){
 if(typeof directory!=='string'||!isAbsolute(directory)||resolve(directory)!==directory)
  fail('OFFLINE_LEDGER_INVALID_DIRECTORY');
 let st,real;
 try{st=await lstat(directory);real=await realpath(directory);}catch{fail('OFFLINE_LEDGER_UNAVAILABLE');}
 if(!st.isDirectory()||st.isSymbolicLink()||real!==directory||
  (st.mode&0o077)!==0||(typeof process.getuid==='function'&&st.uid!==process.getuid()))
  fail('OFFLINE_LEDGER_UNSAFE_DIRECTORY');
 return directory;
}
async function fsyncDirectory(directory){
 let h;try{h=await open(directory,'r');await h.sync();}
 catch{fail('OFFLINE_LEDGER_DURABILITY_UNCERTAIN');}
 finally{await h?.close().catch(()=>{});}
}
const markerBytes=pin=>Buffer.from(JSON.stringify({schema:OFFLINE_WITNESS_LEDGER_SCHEMA,namespacePin:pin}));
/** Explicit initialization: missing/partial namespace markers are never repaired
 * automatically by open/consume, so crash ambiguity remains fail-closed. */
export async function initializeOfflineWitnessChallengeLedger({directory,namespacePin}={}){
 if(!hex(namespacePin))fail('OFFLINE_LEDGER_INVALID_NAMESPACE');
 await checkedDirectory(directory);
 const path=join(directory,MARKER),bytes=markerBytes(namespacePin);
 let handle;
 try{handle=await open(path,'wx',0o600);await handle.writeFile(bytes);await handle.sync();}
 catch(e){if(e?.code!=='EEXIST')fail('OFFLINE_LEDGER_INITIALIZATION_UNCERTAIN');}
 finally{await handle?.close().catch(()=>{});}
 await fsyncDirectory(directory);
 let existing;try{existing=await readFile(path);}catch{fail('OFFLINE_LEDGER_UNAVAILABLE');}
 const markerStat=await lstat(path);
 if(!markerStat.isFile()||markerStat.isSymbolicLink()||markerStat.nlink!==1||
  (markerStat.mode&0o077)!==0||
  (typeof process.getuid==='function'&&markerStat.uid!==process.getuid()))
  fail('OFFLINE_LEDGER_NAMESPACE_MISMATCH');
 if(!existing.equals(bytes))fail('OFFLINE_LEDGER_NAMESPACE_MISMATCH');
 return Object.freeze({namespacePin,initialized:true,independentCustodyVerified:false});
}
async function assertNamespace(directory,namespacePin){
 await checkedDirectory(directory);
 let st,bytes;try{st=await lstat(join(directory,MARKER));bytes=await readFile(join(directory,MARKER));}
 catch{fail('OFFLINE_LEDGER_UNAVAILABLE');}
 if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||(st.mode&0o077)!==0||
  (typeof process.getuid==='function'&&st.uid!==process.getuid())||
  !bytes.equals(markerBytes(namespacePin)))
  fail('OFFLINE_LEDGER_NAMESPACE_MISMATCH');
}
function challengeKey({namespacePin,witnessId,challenge,audience,registryId}){
 if(![namespacePin,witnessId,challenge,audience,registryId].every(hex))
  fail('OFFLINE_LEDGER_INVALID_CHALLENGE');
 return sha(Buffer.from(`${DOMAIN}${namespacePin}\n${witnessId}\n${challenge}\n${audience}\n${registryId}`));
}
function receiptBytes(args){
 const challengeKeyValue=challengeKey(args);
 if(!hex(args.receiptReplayToken))fail('OFFLINE_LEDGER_INVALID_CHALLENGE');
 return {challengeKey:challengeKeyValue,bytes:Buffer.from(JSON.stringify({
  schema:OFFLINE_WITNESS_LEDGER_SCHEMA,namespacePin:args.namespacePin,
  challengeKey:challengeKeyValue,witnessId:args.witnessId,challenge:args.challenge,
  audience:args.audience,registryId:args.registryId,receiptReplayToken:args.receiptReplayToken}))};
}
/** Atomic single-host O_EXCL create; ambiguous partial files permanently block
 * reuse. Durable once only on a trustworthy filesystem; no cross-host guarantee. */
export async function openOfflineWitnessChallengeLedger({directory,namespacePin,
 pinnedRetainedReceipts=[]}={}){
 if(!hex(namespacePin))fail('OFFLINE_LEDGER_INVALID_NAMESPACE');
 await assertNamespace(directory,namespacePin);
 if(!Array.isArray(pinnedRetainedReceipts)||pinnedRetainedReceipts.length>256||
  Reflect.ownKeys(pinnedRetainedReceipts).length!==pinnedRetainedReceipts.length+1)
  fail('OFFLINE_LEDGER_INVALID_RETENTION_PINS');
 const retained=pinnedRetainedReceipts.map(p=>{
  if(!exact(p,['witnessId','challenge','audience','registryId','receiptReplayToken','expectedReceiptSha256'])||
   !hex(p.expectedReceiptSha256))fail('OFFLINE_LEDGER_INVALID_RETENTION_PINS');
  receiptBytes({namespacePin,...p});return Object.freeze({...p});
 });
 const ledger=Object.freeze({namespacePin,independentCustodyVerified:false,
  async consumeOnce({witnessId,challenge,audience,registryId,receiptReplayToken}={}){
   await assertNamespace(directory,namespacePin);
   for(const pin of retained)await ledger.assertRetainedReceipt(pin);
   const {challengeKey:key,bytes}=receiptBytes({namespacePin,witnessId,challenge,audience,registryId,receiptReplayToken});
   const path=join(directory,`c-${key}.json`);
   let h;
   try{h=await open(path,'wx',0o600);}
   catch(e){if(e?.code==='EEXIST')return false;fail('OFFLINE_LEDGER_WRITE_UNCERTAIN');}
   try{await h.writeFile(bytes);await h.sync();}
   catch{fail('OFFLINE_LEDGER_WRITE_UNCERTAIN');}
   finally{await h.close().catch(()=>{});}
   await fsyncDirectory(directory);
   return true;
  },
  /** Caller MUST retain expected SHA outside this directory. Missing, altered,
   * or partial receipt fails closed; no self-repair or rollback acceptance. */
  async assertRetainedReceipt({witnessId,challenge,audience,registryId,receiptReplayToken,expectedReceiptSha256}={}){
   if(!hex(expectedReceiptSha256))fail('OFFLINE_LEDGER_EXTERNAL_PIN_REQUIRED');
   await assertNamespace(directory,namespacePin);
   const {challengeKey:key,bytes}=receiptBytes({namespacePin,witnessId,challenge,audience,registryId,receiptReplayToken});
   let actual,st;try{const path=join(directory,`c-${key}.json`);st=await lstat(path);actual=await readFile(path);}
   catch{fail('OFFLINE_LEDGER_RETENTION_MISSING');}
   if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||(st.mode&0o077)!==0||
    (typeof process.getuid==='function'&&st.uid!==process.getuid())||
    !actual.equals(bytes)||
    !eq(sha(actual),expectedReceiptSha256))fail('OFFLINE_LEDGER_RETENTION_MISMATCH');
   return Object.freeze({challengeKey:key,receiptSha256:sha(actual),retained:true,independentCustodyVerified:false});
  }
 });
 adapters.add(ledger);
 for(const pin of retained)await ledger.assertRetainedReceipt(pin);
 return ledger;
}
/** Pin roster before using the existing signature/expiry verification contract.
 * The durable ledger consumes one challenge per witness+registry+audience,
 * including differently signed receipts for the same challenge. */
export async function verifyOfflineWitnessWithPinnedRoster({rosterBytes,expectedRosterSha256,
 expectedRootPin,expectedRegistryId,expectedPolicySignerFingerprint,expectedAudience,
 trustedNowMs,witnessId,witnessPublicKey,challenge,receiptBytes,
 expectedParentCheckpointSha256,expectedParentRevision,expectedCandidateSha256,
 expectedCandidateRevision,ledger}={}){
 const roster=validateRoster(rosterBytes,{expectedRosterSha256,expectedRootPin,
  expectedRegistryId,expectedPolicySignerFingerprint,expectedAudience,trustedNowMs});
 if(!adapters.has(ledger)||!eq(ledger.namespacePin,roster.rosterSha256))
  fail('OFFLINE_LEDGER_TRUST_BOUNDARY');
 const w=roster.witnesses.find(x=>eq(x.witnessId,witnessId));
 if(!w||w.status!=='active')fail('OFFLINE_ROSTER_WITNESS_NOT_ACTIVE');
 return verifyOfflineWitnessAcknowledgement({receiptBytes,witnessPublicKey,
  expectedWitnessId:witnessId,expectedWitnessKeyFingerprint:w.publicKeyFingerprint,
  expectedRootPin,expectedRegistryId,expectedPolicySignerFingerprint,
  expectedParentCheckpointSha256,expectedParentRevision,expectedCandidateSha256,
  expectedCandidateRevision,expectedChallenge:challenge,expectedAudience,trustedNowMs,
  consumeOnce:receiptReplayToken=>ledger.consumeOnce({witnessId,challenge,
   audience:expectedAudience,registryId:expectedRegistryId,receiptReplayToken})});
}
/** Deterministic receipt pin for separately retained checkpoint evidence. */
export function deriveOfflineWitnessChallengeReceiptPin({namespacePin,witnessId,challenge,
 audience,registryId,receiptReplayToken}={}){
 const {challengeKey:key,bytes}=receiptBytes({namespacePin,witnessId,challenge,audience,registryId,receiptReplayToken});
 return Object.freeze({challengeKey:key,receiptSha256:sha(bytes),independentCustodyVerified:false});
}
