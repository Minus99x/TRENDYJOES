/** Objective 35AJ: portable offline epoch-chain evidence and observer signatures.
 * Observer keys, challenges, clocks, retained hashes, and custody are supplied
 * independently by the caller. This module provides NO consensus or authority. */
import {createHash,createPublicKey,sign,verify,timingSafeEqual} from 'node:crypto';
import {OFFLINE_EPOCH_HEAD_SCHEMA} from './preview-local-artwork-review-epoch-head-registry.mjs';
export const OFFLINE_EPOCH_CHAIN_EVIDENCE_SCHEMA='TJ-LOCAL-EPOCH-CHAIN-EVIDENCE-35AJ-1';
export const OFFLINE_EPOCH_OBSERVER_SCHEMA='TJ-LOCAL-EPOCH-OBSERVER-35AJ-1';
const DOMAIN='TRENDYJOES_LOCAL_EPOCH_OBSERVER_35AJ_V1\n';
const HEX=/^[0-9a-f]{64}$/;
const SIG=/^[A-Za-z0-9_-]{86}$/;
const ZERO='0'.repeat(64);
const MAX_RECORDS=256,MAX_EVIDENCE=600000,MAX_TTL=300000;
const RECORD=['schema','namespacePin','rootPin','registryId','epoch','rosterSha256','transitionSha256','previousRecordSha256','authority'];
const HEAD=['epoch','rosterSha256','recordSha256'];
const EVIDENCE=['schema','namespacePin','rootPin','registryId','genesisSha256','records','head','authority'];
const BODY=['schema','observerId','observerKeyFingerprint','namespacePin','rootPin','registryId','audience','challenge','evidenceSha256','headEpoch','headRecordSha256','issuedAtMs','expiresAtMs','authority'];
const SIGNED=[...BODY,'signature'];
const PIN=['observerId','observerKeyFingerprint','receiptSha256','challenge','expectedHead'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const sha=b=>createHash('sha256').update(b).digest('hex');
const hex=s=>typeof s==='string'&&HEX.test(s);
const eq=(a,b)=>hex(a)&&hex(b)&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
const integer=n=>Number.isSafeInteger(n)&&n>=0&&n<1e15;
const exact=(o,fields)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===fields.length&&
 fields.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d?.enumerable&&'value'in d;});
const key=(k,type)=>k?.type===type&&k?.asymmetricKeyType==='ed25519';
const fp=k=>sha(k.export({type:'spki',format:'der'}));
function bytes(b,max,code){if(!Buffer.isBuffer(b)||b.length<2||b.length>max)fail(code);return Buffer.from(b);}
function parse(b,fields,code){let o;try{o=JSON.parse(b.toString('utf8'));}catch{fail(code);}
 if(!exact(o,fields)||!Object.keys(o).every((k,i)=>k===fields[i])||
 !Buffer.from(JSON.stringify(o)).equals(b))fail(code);return o;}
function b64(b){return b.toString('base64url');}
function unb64(s){if(typeof s!=='string'||s.length<3||s.length>4096||!/^[A-Za-z0-9_-]+$/.test(s))
 fail('OFFLINE_EPOCH_EVIDENCE_INVALID_RECORD');
 const b=Buffer.from(s,'base64url');if(b64(b)!==s)return fail('OFFLINE_EPOCH_EVIDENCE_INVALID_RECORD');
 return bytes(b,2048,'OFFLINE_EPOCH_EVIDENCE_INVALID_RECORD');}
function head(h){if(!exact(h,HEAD)||!integer(h.epoch)||!hex(h.rosterSha256)||!hex(h.recordSha256))
 fail('OFFLINE_EPOCH_EVIDENCE_MISSING_PIN');return {...h};}
function inspectRecordChain(recordBytes,{expectedNamespacePin,expectedRootPin,expectedRegistryId,expectedGenesisSha256,expectedHead}){
 if(!Array.isArray(recordBytes)||recordBytes.length<1||recordBytes.length>MAX_RECORDS||
 Reflect.ownKeys(recordBytes).length!==recordBytes.length+1||
 ![expectedNamespacePin,expectedRootPin,expectedRegistryId,expectedGenesisSha256].every(hex))
 fail('OFFLINE_EPOCH_EVIDENCE_MISSING_PIN');
 const pinned=head(expectedHead);let previous=null;const records=[];
 for(let i=0;i<recordBytes.length;i++){
  const raw=bytes(recordBytes[i],2048,'OFFLINE_EPOCH_EVIDENCE_INVALID_RECORD');
  const r=parse(raw,RECORD,'OFFLINE_EPOCH_EVIDENCE_NONCANONICAL');
  if(r.schema!==OFFLINE_EPOCH_HEAD_SCHEMA||r.authority!=='NONE'||
   !integer(r.epoch)||![r.namespacePin,r.rootPin,r.registryId,r.rosterSha256,r.transitionSha256,r.previousRecordSha256].every(hex)||
   !eq(r.namespacePin,expectedNamespacePin)||!eq(r.rootPin,expectedRootPin)||!eq(r.registryId,expectedRegistryId))
   fail('OFFLINE_EPOCH_EVIDENCE_INVALID_RECORD');
  const digest=sha(raw);
  if(i===0){if(!eq(digest,expectedGenesisSha256)||r.previousRecordSha256!==ZERO||r.transitionSha256!==ZERO)
   fail('OFFLINE_EPOCH_EVIDENCE_GENESIS_MISMATCH');}
  else if(r.epoch!==previous.epoch+1||!eq(r.previousRecordSha256,previous.sha256)||
   eq(r.rosterSha256,previous.rosterSha256)||r.transitionSha256===ZERO)
   fail('OFFLINE_EPOCH_EVIDENCE_CHAIN_MISMATCH');
  previous={epoch:r.epoch,rosterSha256:r.rosterSha256,sha256:digest};
  records.push(Object.freeze({...previous,bytes:raw}));
 }
 if(previous.epoch!==pinned.epoch||!eq(previous.rosterSha256,pinned.rosterSha256)||
 !eq(previous.sha256,pinned.recordSha256))fail('OFFLINE_EPOCH_EVIDENCE_HEAD_MISMATCH');
 return Object.freeze(records);
}
/** Caller must supply independently retained genesis/head pins; source bytes
 * are snapshots, not authenticated solely by the archive that contains them. */
export function createOfflineEpochChainEvidence({recordBytes,namespacePin,rootPin,registryId,
 expectedGenesisSha256,expectedHead}={}){
 const records=inspectRecordChain(recordBytes,{expectedNamespacePin:namespacePin,
  expectedRootPin:rootPin,expectedRegistryId:registryId,expectedGenesisSha256,expectedHead});
 const body={schema:OFFLINE_EPOCH_CHAIN_EVIDENCE_SCHEMA,namespacePin,rootPin,registryId,
  genesisSha256:expectedGenesisSha256,records:records.map(r=>b64(r.bytes)),head:head(expectedHead),authority:'NONE'};
 const result=Buffer.from(JSON.stringify(body));if(result.length>MAX_EVIDENCE)fail('OFFLINE_EPOCH_EVIDENCE_TOO_LARGE');
 return Object.freeze({bytes:result,sha256:sha(result),recordCount:records.length,
  independentCustodyVerified:false,transitionSignaturesVerified:false,authorizesProduction:false});
}
export function verifyOfflineEpochChainEvidence({evidenceBytes,expectedNamespacePin,expectedRootPin,
 expectedRegistryId,expectedGenesisSha256,expectedHead,expectedEvidenceSha256}={}){
 if(![expectedNamespacePin,expectedRootPin,expectedRegistryId,expectedGenesisSha256,expectedEvidenceSha256].every(hex))
 fail('OFFLINE_EPOCH_EVIDENCE_MISSING_PIN');
 const raw=bytes(evidenceBytes,MAX_EVIDENCE,'OFFLINE_EPOCH_EVIDENCE_INVALID_BYTES');
 if(!eq(sha(raw),expectedEvidenceSha256))fail('OFFLINE_EPOCH_EVIDENCE_DIGEST_MISMATCH');
 const b=parse(raw,EVIDENCE,'OFFLINE_EPOCH_EVIDENCE_NONCANONICAL');
 const pinned=head(expectedHead);
 if(b.schema!==OFFLINE_EPOCH_CHAIN_EVIDENCE_SCHEMA||b.authority!=='NONE'||
  !eq(b.namespacePin,expectedNamespacePin)||!eq(b.rootPin,expectedRootPin)||
  !eq(b.registryId,expectedRegistryId)||!eq(b.genesisSha256,expectedGenesisSha256)||
  !exact(b.head,HEAD)||!eq(b.head.rosterSha256,pinned.rosterSha256)||
  !eq(b.head.recordSha256,pinned.recordSha256)||b.head.epoch!==pinned.epoch||
  !Array.isArray(b.records)||Reflect.ownKeys(b.records).length!==b.records.length+1)
 fail('OFFLINE_EPOCH_EVIDENCE_PIN_MISMATCH');
 const records=inspectRecordChain(b.records.map(unb64),{expectedNamespacePin,expectedRootPin,
  expectedRegistryId,expectedGenesisSha256,expectedHead:pinned});
 return Object.freeze({head:Object.freeze(pinned),recordDigests:Object.freeze(records.map(r=>Object.freeze({epoch:r.epoch,sha256:r.sha256}))),
  evidenceSha256:sha(raw),recordCount:records.length,chainHashesVerified:true,
  transitionSignaturesVerified:false,independentCustodyVerified:false,authorizesProduction:false});
}
function validObservation(b){if(!exact(b,BODY)||b.schema!==OFFLINE_EPOCH_OBSERVER_SCHEMA||b.authority!=='NONE'||
 ![b.observerId,b.observerKeyFingerprint,b.namespacePin,b.rootPin,b.registryId,b.audience,b.challenge,
 b.evidenceSha256,b.headRecordSha256].every(hex)||!integer(b.headEpoch)||
 !integer(b.issuedAtMs)||!integer(b.expiresAtMs)||b.expiresAtMs<=b.issuedAtMs||
 b.expiresAtMs-b.issuedAtMs>MAX_TTL)fail('OFFLINE_EPOCH_OBSERVER_INVALID_BODY');}
/** Offline fixture signer; does not prove an independently controlled observer. */
export function createOfflineEpochObserverReceipt({signingKey,observerId,namespacePin,rootPin,registryId,
 audience,challenge,evidenceSha256,headEpoch,headRecordSha256,issuedAtMs,expiresAtMs}={}){
 if(!key(signingKey,'private'))fail('OFFLINE_EPOCH_OBSERVER_INVALID_SIGNER');
 const b={schema:OFFLINE_EPOCH_OBSERVER_SCHEMA,observerId,
  observerKeyFingerprint:fp(createPublicKey(signingKey)),namespacePin,rootPin,registryId,audience,
  challenge,evidenceSha256,headEpoch,headRecordSha256,issuedAtMs,expiresAtMs,authority:'NONE'};
 validObservation(b);
 const signature=b64(sign(null,Buffer.from(DOMAIN+JSON.stringify(b)),signingKey));
 const result=Buffer.from(JSON.stringify({...b,signature}));
 return Object.freeze({bytes:result,sha256:sha(result),independentCustodyVerified:false,authorizesProduction:false});
}
export function verifyOfflineEpochObserverReceipt({receiptBytes,observerPublicKey,expectedObserverId,
 expectedObserverKeyFingerprint,expectedReceiptSha256,expectedNamespacePin,expectedRootPin,
 expectedRegistryId,expectedAudience,expectedChallenge,expectedEvidenceSha256,expectedHead,
 trustedNowMs}={}){
 if(!key(observerPublicKey,'public')||![expectedObserverId,expectedObserverKeyFingerprint,
  expectedReceiptSha256,expectedNamespacePin,expectedRootPin,expectedRegistryId,expectedAudience,
  expectedChallenge,expectedEvidenceSha256].every(hex)||!integer(trustedNowMs)||
  !eq(fp(observerPublicKey),expectedObserverKeyFingerprint))fail('OFFLINE_EPOCH_OBSERVER_MISSING_PINS');
 const pinned=head(expectedHead),raw=bytes(receiptBytes,4096,'OFFLINE_EPOCH_OBSERVER_INVALID_BYTES');
 if(!eq(sha(raw),expectedReceiptSha256))fail('OFFLINE_EPOCH_OBSERVER_RECEIPT_PIN_MISMATCH');
 const b=parse(raw,SIGNED,'OFFLINE_EPOCH_OBSERVER_NONCANONICAL');
 const body=Object.fromEntries(BODY.map(k=>[k,b[k]]));validObservation(body);
 if(!eq(b.observerId,expectedObserverId)||!eq(b.observerKeyFingerprint,expectedObserverKeyFingerprint)||
  !eq(b.namespacePin,expectedNamespacePin)||!eq(b.rootPin,expectedRootPin)||
  !eq(b.registryId,expectedRegistryId)||!eq(b.audience,expectedAudience)||
  !eq(b.challenge,expectedChallenge)||!eq(b.evidenceSha256,expectedEvidenceSha256)||
  b.headEpoch!==pinned.epoch||!eq(b.headRecordSha256,pinned.recordSha256))
 fail('OFFLINE_EPOCH_OBSERVER_PIN_MISMATCH');
 if(typeof b.signature!=='string'||!SIG.test(b.signature))fail('OFFLINE_EPOCH_OBSERVER_BAD_SIGNATURE');
 const sig=Buffer.from(b.signature,'base64url');
 if(sig.length!==64||b64(sig)!==b.signature||
 !verify(null,Buffer.from(DOMAIN+JSON.stringify(body)),observerPublicKey,sig))
 fail('OFFLINE_EPOCH_OBSERVER_BAD_SIGNATURE');
 if(trustedNowMs<body.issuedAtMs)fail('OFFLINE_EPOCH_OBSERVER_NOT_YET_VALID');
 if(trustedNowMs>=body.expiresAtMs)fail('OFFLINE_EPOCH_OBSERVER_EXPIRED');
 return Object.freeze({observerId:body.observerId,head:pinned,receiptSha256:sha(raw),signatureVerified:true,
  replayConsumed:false,independentCustodyVerified:false,authorizesProduction:false});
}
/** Compare separately pinned observer receipts. Fork evidence is informative,
 * never an authorization to accept either branch. */
export function inspectOfflineEpochObserverViews({views,observerPins,expectedNamespacePin,
 expectedRootPin,expectedRegistryId,expectedGenesisSha256,expectedAudience,trustedNowMs}={}){
 if(!Array.isArray(views)||views.length<2||views.length>16||
  !Array.isArray(observerPins)||observerPins.length!==views.length||
  ![expectedNamespacePin,expectedRootPin,expectedRegistryId,expectedGenesisSha256,expectedAudience].every(hex)||
  !integer(trustedNowMs))fail('OFFLINE_EPOCH_OBSERVER_INVALID_VIEWS');
 const ids=new Set(),keys=new Set(),challenges=new Set(),verified=[];
 for(let i=0;i<views.length;i++){
  const v=views[i],p=observerPins[i];
  if(!exact(v,['evidenceBytes','receiptBytes','observerPublicKey'])||!exact(p,PIN)||
   ![p.observerId,p.observerKeyFingerprint,p.receiptSha256,p.challenge].every(hex)||
   ids.has(p.observerId)||keys.has(p.observerKeyFingerprint)||challenges.has(p.challenge))
   fail('OFFLINE_EPOCH_OBSERVER_DISTINCT_PINS_REQUIRED');
  ids.add(p.observerId);keys.add(p.observerKeyFingerprint);challenges.add(p.challenge);
  const evidenceRaw=bytes(v.evidenceBytes,MAX_EVIDENCE,'OFFLINE_EPOCH_EVIDENCE_INVALID_BYTES');
  const evidenceSha256=sha(evidenceRaw);
  const chain=verifyOfflineEpochChainEvidence({evidenceBytes:evidenceRaw,expectedNamespacePin,
   expectedRootPin,expectedRegistryId,expectedGenesisSha256,expectedHead:p.expectedHead,
   expectedEvidenceSha256:evidenceSha256});
  verifyOfflineEpochObserverReceipt({receiptBytes:v.receiptBytes,observerPublicKey:v.observerPublicKey,
   expectedObserverId:p.observerId,expectedObserverKeyFingerprint:p.observerKeyFingerprint,
   expectedReceiptSha256:p.receiptSha256,expectedNamespacePin,expectedRootPin,expectedRegistryId,
   expectedAudience,expectedChallenge:p.challenge,expectedEvidenceSha256:evidenceSha256,
   expectedHead:p.expectedHead,trustedNowMs});
  verified.push(Object.freeze({observerId:p.observerId,head:chain.head,
   recordDigests:chain.recordDigests,evidenceSha256,receiptSha256:p.receiptSha256}));
 }
 let fork=null;
 for(let i=0;i<verified.length;i++)for(let j=i+1;j<verified.length;j++){
  const a=verified[i],b=verified[j];const byEpoch=new Map(a.recordDigests.map(r=>[r.epoch,r.sha256]));
  for(const r of b.recordDigests){const prior=byEpoch.get(r.epoch);
   if(prior&&!eq(prior,r.sha256)){
    const [left,right]=a.observerId<b.observerId?
     [{id:a.observerId,digest:prior},{id:b.observerId,digest:r.sha256}]:
     [{id:b.observerId,digest:r.sha256},{id:a.observerId,digest:prior}];
    const candidate={epoch:r.epoch,leftObserverId:left.id,rightObserverId:right.id,
     leftRecordSha256:left.digest,rightRecordSha256:right.digest};
    if(!fork||candidate.epoch<fork.epoch||(candidate.epoch===fork.epoch&&
     candidate.leftObserverId+candidate.rightObserverId<fork.leftObserverId+fork.rightObserverId))fork=candidate;
   }
  }
 }
 const digest=sha(Buffer.from(JSON.stringify({schema:OFFLINE_EPOCH_OBSERVER_SCHEMA,
  views:verified.map(v=>({observerId:v.observerId,evidenceSha256:v.evidenceSha256,
   receiptSha256:v.receiptSha256})).sort((a,b)=>a.observerId.localeCompare(b.observerId)),
  fork})));
 return Object.freeze({relationship:fork?'FORK':verified.every(v=>v.head.recordSha256===verified[0].head.recordSha256)?'AGREEMENT':'PREFIX',
  fork:fork?Object.freeze(fork):null,evidenceDigestSha256:digest,observerCount:verified.length,
  observerSignaturesVerified:true,chainHashesVerified:true,transitionSignaturesVerified:false,
  replayConsumed:false,independentCustodyVerified:false,crossHostConsensusVerified:false,authorizesProduction:false});
}
