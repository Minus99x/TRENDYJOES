import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {offlineConflictRecoveryReceiptGenesisHead} from '../src/offline-conflict-exchange-recovery-receipts.mjs';
import {offlineConflictExchangeRecoveryReviewerPolicyDigest} from '../src/offline-conflict-exchange-recovery.mjs';
import {OFFLINE_CONFLICT_RECOVERY_POLICY_EPOCH_SCHEMA,offlineConflictRecoveryPolicyEpochGenesisDigest,
 offlineConflictRecoveryPolicyTransitionBytes,offlineConflictRecoveryPolicyTransitionDigest} from '../src/offline-conflict-recovery-policy-epochs.mjs';
import {OFFLINE_CONFLICT_RECOVERY_CUTOVER_SCHEMA,offlineConflictRecoveryCutoverDigest} from '../src/offline-conflict-recovery-policy-cutover.mjs';
import {OFFLINE_CONFLICT_CUTOVER_ADJUDICATION_SCHEMA,offlineConflictCutoverAdjudicationBytes,
 offlineConflictCutoverAdjudicationDigest} from '../src/offline-conflict-recovery-cutover-adjudication.mjs';
import {OFFLINE_CONFLICT_CUTOVER_RESOLUTION_PROOF_SCHEMA,offlineConflictCutoverResolutionProofDigest} from '../src/offline-conflict-cutover-resolution-proof.mjs';
import {OFFLINE_CONFLICT_RESOLUTION_INVENTORY_SCHEMA,OFFLINE_CONFLICT_RESOLUTION_UNION_SCHEMA,
 offlineConflictResolutionInventoryDigest,offlineConflictResolutionUnionDigest,
 verifyOfflineConflictResolutionInventories} from '../src/offline-conflict-resolution-inventory.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const now=1792200000000;
const signers=(seed,role)=>[1,2,3].map(i=>({reviewerId:`${role}_review_${seed}_${i}`,...generateKeyPairSync('ed25519')}));
const pub=g=>g.map(x=>({reviewerId:x.reviewerId,publicKey:x.publicKey.export({format:'pem',type:'spki'})}));
const policy=g=>offlineConflictExchangeRecoveryReviewerPolicyDigest(pub(g));
const signatures=(body,g,fn)=>g.slice(0,2).map(k=>({reviewerId:k.reviewerId,signature:sign(null,fn(body),k.privateKey).toString('base64url')}));
const signerCache=new Map();
function fixture(seed,action='abort'){
 if(!signerCache.has(seed))signerCache.set(seed,{old:signers(seed,'old'),next:signers(seed,'next')});
 const genesisExchangeDigest=sha('32t-'+seed),{old,next}=signerCache.get(seed);
 const receiptHead=offlineConflictRecoveryReceiptGenesisHead(genesisExchangeDigest);
 const transitionBody={schema:OFFLINE_CONFLICT_RECOVERY_POLICY_EPOCH_SCHEMA,sequence:1,
  previousTransitionDigest:offlineConflictRecoveryPolicyEpochGenesisDigest({genesisExchangeDigest,initialPolicyDigest:policy(old)}),
  genesisExchangeDigest,fromPolicyDigest:policy(old),toPolicyDigest:policy(next),receiptHead,
  issuedAt:now-1000,expiresAt:now+30000,nonce:`epoch_nonce_${seed}_01`};
 const transition={body:transitionBody,outgoingSignatures:signatures(transitionBody,old,offlineConflictRecoveryPolicyTransitionBytes),
  incomingSignatures:signatures(transitionBody,next,offlineConflictRecoveryPolicyTransitionBytes)};
 const transitionHead={count:1,headDigest:offlineConflictRecoveryPolicyTransitionDigest({transition})};
 const history={genesisExchangeDigest,reviewerPolicies:[pub(old),pub(next)],transitions:[transition],segments:[[],[]],
  expectedTransitionHead:transitionHead,expectedFinalReceiptHead:receiptHead,expectedFinalPolicyDigest:policy(next),nowMs:now};
 const cutoverBody={schema:OFFLINE_CONFLICT_RECOVERY_CUTOVER_SCHEMA,genesisExchangeDigest,
  previousPolicyDigest:policy(old),activePolicyDigest:policy(next),transitionHead,receiptHead,activatedAt:now};
 const cutoverDigest=offlineConflictRecoveryCutoverDigest(cutoverBody);
 const cutoverMarker={...cutoverBody,cutoverDigest};
 const pending=Buffer.from(JSON.stringify(cutoverMarker)),pendingBytesDigest=sha(pending);
 const exchangeJournalHead={count:0,headDigest:sha('journal-'+seed)};
 const body={schema:OFFLINE_CONFLICT_CUTOVER_ADJUDICATION_SCHEMA,action,genesisExchangeDigest,
  cutoverDigest,pendingBytesDigest,previousPolicyDigest:policy(old),activePolicyDigest:policy(next),
  exchangeJournalHead,receiptHead,issuedAt:now-500,expiresAt:now+10000,nonce:`resolution_nonce_${seed}_${action}`};
 const decision={body,outgoingSignatures:signatures(body,old,offlineConflictCutoverAdjudicationBytes),
  incomingSignatures:signatures(body,next,offlineConflictCutoverAdjudicationBytes)};
 const decisionDigest=offlineConflictCutoverAdjudicationDigest(decision);
 const receiptBody={schema:'TJ-OFFLINE-CONFLICT-CUTOVER-RESOLUTION-1',action,genesisExchangeDigest,
  cutoverDigest,pendingBytesDigest,decisionDigest,resolvedAt:now};
 const resolutionReceipt={...receiptBody,receiptDigest:sha('TJ-32R-RESOLUTION-RECEIPT\0'+JSON.stringify(receiptBody))};
 const proof={schema:OFFLINE_CONFLICT_CUTOVER_RESOLUTION_PROOF_SCHEMA,history,cutoverMarker,
  pendingMarkerBase64url:pending.toString('base64url'),decision,resolutionReceipt};
 const pins={proofDigest:offlineConflictCutoverResolutionProofDigest(proof),decisionDigest,
  resolutionDigest:resolutionReceipt.receiptDigest,cutoverDigest,pendingBytesDigest,genesisExchangeDigest,
  transitionHead,receiptHead,finalPolicyDigest:policy(next),exchangeJournalHead};
 const entry={genesisExchangeDigest,cutoverDigest,resolutionDigest:pins.resolutionDigest,
  decisionDigest,proofDigest:pins.proofDigest,action};
 return {proof,pins,entry};
}
const f1=fixture('a'),f2=fixture('b');
const key=e=>[e.genesisExchangeDigest,e.cutoverDigest,e.resolutionDigest,e.decisionDigest,e.proofDigest,e.action].join(':');
const sorted=entries=>entries.sort((a,b)=>key(a)<key(b)?-1:key(a)>key(b)?1:0);
function build(entries=[f1,f2],ids=['observer_alpha','observer_beta']){
 const views=[],anchors=[];
 for(const observerId of ids){
  const ordered=sorted(entries.map(f=>f.entry));
  const manifest={schema:OFFLINE_CONFLICT_RESOLUTION_INVENTORY_SCHEMA,observerId,entries:structuredClone(ordered)};
  const lookup=new Map(entries.map(f=>[f.entry.proofDigest,f]));
  views.push({manifest,proofs:ordered.map(e=>({proof:structuredClone(lookup.get(e.proofDigest).proof)}))});
  anchors.push({observerId,inventoryDigest:offlineConflictResolutionInventoryDigest(manifest),
   proofPins:ordered.map(e=>({proofDigest:e.proofDigest,pins:structuredClone(lookup.get(e.proofDigest).pins)}))});
 }
 const union={schema:OFFLINE_CONFLICT_RESOLUTION_UNION_SCHEMA,entries:structuredClone(sorted(entries.map(f=>f.entry)))};
 return {views,anchors,expectedObserverIds:[...ids].sort(),expectedUnionDigest:offlineConflictResolutionUnionDigest(union),nowMs:now+100000};
}

import {OFFLINE_CONFLICT_RESOLUTION_TRANSPORT_SCHEMA, OFFLINE_CONFLICT_RESOLUTION_TRANSPORT_MAX_BYTES,
 encodeOfflineConflictResolutionTransport, offlineConflictResolutionTransportDigest,
 verifyOfflineConflictResolutionTransport} from '../src/offline-conflict-resolution-transport.mjs';

const t=(name,fn)=>test('32U '+name,fn);
const reject=(f,code)=>assert.throws(()=>verifyOfflineConflictResolutionTransport(f),e=>e?.code===code);
function packed(f=build()){
 const {bytes,byteDigest,byteLength}=encodeOfflineConflictResolutionTransport(f.views);
 return {...f,bytes,expectedByteDigest:byteDigest,byteLength};
}
function replaceAndRepin(f,replace){
 f.bytes=Buffer.from(replace(f.bytes.toString('utf8')),'utf8');
 f.expectedByteDigest=offlineConflictResolutionTransportDigest(f.bytes);
 return f;
}

t('valid two-observer signed proof roundtrip verifies all 32T history',()=>{
 const f=packed(),r=verifyOfflineConflictResolutionTransport(f);
 assert.equal(r.verified,true);assert.equal(r.authenticatedAttemptCount,2);
 assert.equal(r.transportBytesVerified,true);assert.equal(r.transportByteDigest,f.expectedByteDigest);
 assert.equal(r.transportByteLength,f.byteLength);
 assert.equal(r.independentlyPublished,false);assert.equal(r.authorizesProduction,false);
});
t('valid three observers roundtrip preserves historical Ed25519 verification',()=>{
 const r=verifyOfflineConflictResolutionTransport(packed(build([f1],['observer_alpha','observer_beta','observer_gamma'])));
 assert.equal(r.observerCount,3);assert.equal(r.authenticatedAttemptCount,1);
});
t('encoding preserves nested signed proof property order',()=>{
 const f=packed();const parsed=JSON.parse(f.bytes.toString('utf8'));
 assert.deepEqual(parsed.views,f.views);
 assert.equal(offlineConflictResolutionTransportDigest(f.bytes),f.expectedByteDigest);
});
t('transport digest is domain-separated from raw SHA256',()=>{
 const f=packed();assert.notEqual(f.expectedByteDigest,sha(f.bytes));
});
t('missing independent byte pin rejected',()=>{const f=packed();delete f.expectedByteDigest;reject(f,'EXCHANGE32U_EXTERNAL_BYTE_PIN_REQUIRED');});
t('uppercase independent byte pin rejected',()=>{const f=packed();f.expectedByteDigest=f.expectedByteDigest.toUpperCase();reject(f,'EXCHANGE32U_EXTERNAL_BYTE_PIN_REQUIRED');});
t('invalid pin type rejected without coercion',()=>{const f=packed();f.expectedByteDigest={toString(){throw Error('should not coerce');}};reject(f,'EXCHANGE32U_EXTERNAL_BYTE_PIN_REQUIRED');});
t('wrong independent byte pin rejected',()=>{const f=packed();f.expectedByteDigest=sha('substituted');reject(f,'EXCHANGE32U_BYTE_PIN_MISMATCH');});
t('missing byte body rejected',()=>{const f=packed();delete f.bytes;reject(f,'EXCHANGE32U_BYTES_REQUIRED');});
t('string byte body rejected',()=>{const f=packed();f.bytes=f.bytes.toString('utf8');reject(f,'EXCHANGE32U_BYTES_REQUIRED');});
t('ordinary array body rejected',()=>{const f=packed();f.bytes=[...f.bytes];reject(f,'EXCHANGE32U_BYTES_REQUIRED');});
t('Uint8Array input accepted',()=>{const f=packed();f.bytes=new Uint8Array(f.bytes);assert.equal(verifyOfflineConflictResolutionTransport(f).verified,true);});
t('empty bytes rejected',()=>{const f=packed();f.bytes=Buffer.alloc(0);reject(f,'EXCHANGE32U_SIZE_INVALID');});
t('overlarge byte input rejected before parsing',()=>{const f=packed();f.bytes=Buffer.alloc(OFFLINE_CONFLICT_RESOLUTION_TRANSPORT_MAX_BYTES+1);reject(f,'EXCHANGE32U_SIZE_INVALID');});
t('truncation of JSON tail fails closed with re-pinned bytes',()=>{const f=packed();f.bytes=f.bytes.subarray(0,-1);f.expectedByteDigest=offlineConflictResolutionTransportDigest(f.bytes);reject(f,'EXCHANGE32U_JSON_INVALID');});
t('truncation in signed evidence fails closed with re-pinned bytes',()=>{
 const f=packed();f.bytes=f.bytes.subarray(0,Math.floor(f.bytes.length/2));f.expectedByteDigest=offlineConflictResolutionTransportDigest(f.bytes);reject(f,'EXCHANGE32U_JSON_INVALID');
});
t('bitflip in signed proof without re-pin rejected at byte boundary',()=>{
 const f=packed();f.bytes=Buffer.from(f.bytes);f.bytes[200]^=1;reject(f,'EXCHANGE32U_BYTE_PIN_MISMATCH');
});
t('trailing JSON object rejected after byte repin',()=>{
 const f=packed();replaceAndRepin(f,s=>s+'{}');reject(f,'EXCHANGE32U_JSON_INVALID');
});
t('leading whitespace is rejected as noncanonical',()=>{
 const f=packed();replaceAndRepin(f,s=>' '+s);reject(f,'EXCHANGE32U_JSON_INVALID');
});
t('trailing newline rejected',()=>{
 const f=packed();replaceAndRepin(f,s=>s+'\n');reject(f,'EXCHANGE32U_JSON_INVALID');
});
t('whitespace inside JSON rejected',()=>{
 const f=packed();replaceAndRepin(f,s=>s.replace('"views":','"views": '));reject(f,'EXCHANGE32U_JSON_INVALID');
});
t('invalid UTF8 rejected after byte re-pin',()=>{
 const f=packed();f.bytes=Buffer.concat([f.bytes.subarray(0,10),Buffer.from([0xff]),f.bytes.subarray(11)]);
 f.expectedByteDigest=offlineConflictResolutionTransportDigest(f.bytes);reject(f,'EXCHANGE32U_JSON_INVALID');
});
t('UTF8 BOM rejected after re-pin',()=>{
 const f=packed();f.bytes=Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),f.bytes]);
 f.expectedByteDigest=offlineConflictResolutionTransportDigest(f.bytes);reject(f,'EXCHANGE32U_JSON_INVALID');
});
t('duplicate top-level key rejected even with new byte pin',()=>{
 const f=packed();replaceAndRepin(f,s=>s.replace('{"schema":','{"schema":"extra","schema":'));
 reject(f,'EXCHANGE32U_JSON_INVALID');
});
t('duplicate nested proof key rejected before JSON.parse',()=>{
 const f=packed();replaceAndRepin(f,s=>s.replace('"history":','"history":null,"history":'));
 reject(f,'EXCHANGE32U_JSON_INVALID');
});
t('escaped alias duplicate key rejected',()=>{
 const f=packed();replaceAndRepin(f,s=>s.replace('{"schema":','{"\\u0073chema":"extra","schema":'));
 reject(f,'EXCHANGE32U_JSON_INVALID');
});
t('noncanonical ASCII unicode escape rejected',()=>{
 const f=packed();replaceAndRepin(f,s=>s.replace('"schema":','"\\u0073chema":'));
 reject(f,'EXCHANGE32U_NONCANONICAL_BYTES');
});
t('noncanonical escaped slash rejected',()=>{
 const f=packed();replaceAndRepin(f,s=>s.replace('-----BEGIN PUBLIC KEY-----','-----BEGIN PUBLIC KEY-----\\/'));
 reject(f,'EXCHANGE32U_NONCANONICAL_BYTES');
});
t('noncanonical -0 numeric representation rejected',()=>{
 const f=packed();replaceAndRepin(f,s=>s.replace('"count":0','"count":-0'));
 reject(f,'EXCHANGE32U_NONCANONICAL_BYTES');
});
t('noncanonical 1e0 numeric representation rejected',()=>{
 const f=packed();replaceAndRepin(f,s=>s.replace('"count":1','"count":1e0'));
 reject(f,'EXCHANGE32U_NONCANONICAL_BYTES');
});
t('malformed unicode escape rejected',()=>{
 const f=packed();replaceAndRepin(f,s=>s.replace('"schema":','"\\uZZZZ":'));
 reject(f,'EXCHANGE32U_JSON_INVALID');
});
t('invalid escape rejected',()=>{
 const f=packed();replaceAndRepin(f,s=>s.replace('"schema":','"\\x73chema":'));
 reject(f,'EXCHANGE32U_JSON_INVALID');
});
t('prototype pollution key rejected',()=>{
 const f=packed();replaceAndRepin(f,s=>s.replace('{"schema":','{"__proto__":{},"schema":'));
 reject(f,'EXCHANGE32U_JSON_INVALID');
});
t('constructor key rejected',()=>{
 const f=packed();replaceAndRepin(f,s=>s.replace('{"schema":','{"constructor":{},"schema":'));
 reject(f,'EXCHANGE32U_JSON_INVALID');
});
t('unknown production approval claim rejected after repin',()=>{
 const f=packed();replaceAndRepin(f,s=>s.replace('{"schema":','{"productionApproved":true,"schema":'));
 reject(f,'EXCHANGE32U_STRUCTURE_INVALID');
});
t('missing schema rejected',()=>{
 const f=packed();replaceAndRepin(f,s=>s.replace('{"schema":"'+OFFLINE_CONFLICT_RESOLUTION_TRANSPORT_SCHEMA+'",','{'));
 reject(f,'EXCHANGE32U_STRUCTURE_INVALID');
});
t('substituted schema rejected',()=>{
 const f=packed();replaceAndRepin(f,s=>s.replace(OFFLINE_CONFLICT_RESOLUTION_TRANSPORT_SCHEMA,'TJ-FAKE-SCHEMA'));
 reject(f,'EXCHANGE32U_STRUCTURE_INVALID');
});
t('omitted view with independently re-pinned bytes rejected by observer roster',()=>{
 const f=packed();f.views.pop();const e=encodeOfflineConflictResolutionTransport(f.views.concat([f.views[0]]));
 // Both bytes and hash are valid, but two duplicate observers cannot masquerade as a complete roster.
 f.bytes=e.bytes;f.expectedByteDigest=e.byteDigest;assert.throws(()=>verifyOfflineConflictResolutionTransport(f),e=>e?.code==='EXCHANGE32T_OBSERVER_UNTRUSTED');
});
t('one observer is rejected even with valid byte pin',()=>{
 const f=packed();const b=Buffer.from(JSON.stringify({schema:OFFLINE_CONFLICT_RESOLUTION_TRANSPORT_SCHEMA,views:[f.views[0]]}));
 f.bytes=b;f.expectedByteDigest=offlineConflictResolutionTransportDigest(b);
 reject(f,'EXCHANGE32T_EXTERNAL_PINS_REQUIRED');
});
t('modified signed evidence with re-pinned bytes fails 32T/32S cryptographic checks',()=>{
 const f=packed();replaceAndRepin(f,s=>s.replace('"resolvedAt":'+now,'"resolvedAt":'+(now+1)));
 assert.throws(()=>verifyOfflineConflictResolutionTransport(f),e=>e?.code?.startsWith('EXCHANGE32S_'));
});
t('missing historical proof with re-pinned bytes rejected by 32T',()=>{
 const f=packed();f.views[0].proofs.pop();const e=encodeOfflineConflictResolutionTransport(f.views);
 f.bytes=e.bytes;f.expectedByteDigest=e.byteDigest;reject(f,'EXCHANGE32T_EVIDENCE_OMITTED');
});
t('missing independently pinned observer anchors rejected',()=>{
 const f=packed();f.anchors.pop();reject(f,'EXCHANGE32T_EXTERNAL_PINS_REQUIRED');
});
t('missing independent union pin rejected',()=>{
 const f=packed();delete f.expectedUnionDigest;reject(f,'EXCHANGE32T_EXTERNAL_PINS_REQUIRED');
});
t('missing external observer roster rejected',()=>{
 const f=packed();delete f.expectedObserverIds;reject(f,'EXCHANGE32T_EXTERNAL_PINS_REQUIRED');
});
t('encoder rejects getters without invoking',()=>{
 const f=build();Object.defineProperty(f.views[0],'danger',{enumerable:true,get(){throw Error('getter called');}});
 assert.throws(()=>encodeOfflineConflictResolutionTransport(f.views),e=>e?.code==='EXCHANGE32U_STRUCTURE_INVALID');
});
t('encoder rejects hidden symbols',()=>{
 const f=build();f.views[0][Symbol('claim')]=true;
 assert.throws(()=>encodeOfflineConflictResolutionTransport(f.views),e=>e?.code==='EXCHANGE32U_STRUCTURE_INVALID');
});
t('encoder rejects sparse arrays',()=>{
 const f=build();delete f.views[0].proofs[0];
 assert.throws(()=>encodeOfflineConflictResolutionTransport(f.views),e=>e?.code==='EXCHANGE32U_STRUCTURE_INVALID');
});
t('encoder rejects nonfinite numeric claims',()=>{
 const f=build();f.views[0].manifest.entries[0].n=NaN;
 assert.throws(()=>encodeOfflineConflictResolutionTransport(f.views),e=>e?.code==='EXCHANGE32U_STRUCTURE_INVALID');
});
t('encoder rejects cyclic evidence graphs',()=>{
 const f=build();f.views[0].self=f.views[0];
 assert.throws(()=>encodeOfflineConflictResolutionTransport(f.views),e=>e?.code==='EXCHANGE32U_STRUCTURE_INVALID');
});
t('encoder rejects object prototype poisoning',()=>{
 const f=build();Object.setPrototypeOf(f.views[0],new Date());
 assert.throws(()=>encodeOfflineConflictResolutionTransport(f.views),e=>e?.code==='EXCHANGE32U_STRUCTURE_INVALID');
});
t('encoder rejects lone surrogate strings',()=>{
 const f=build();f.views[0].manifest.observerId='bad\ud800';
 assert.throws(()=>encodeOfflineConflictResolutionTransport(f.views),e=>e?.code==='EXCHANGE32U_STRUCTURE_INVALID');
});
t('encoder rejects array custom properties',()=>{
 const f=build();f.views[0].proofs.extra=true;
 assert.throws(()=>encodeOfflineConflictResolutionTransport(f.views),e=>e?.code==='EXCHANGE32U_STRUCTURE_INVALID');
});
t('verified transport is read-only and does not mutate inputs',()=>{
 const f=packed();const before=structuredClone(f.views),raw=Buffer.from(f.bytes);
 verifyOfflineConflictResolutionTransport(f);
 assert.deepEqual(f.views,before);assert.deepEqual(f.bytes,raw);
});
t('max nesting fails closed before recursive stack overflow',()=>{
 const f=packed();const b=Buffer.from('{"schema":"'+OFFLINE_CONFLICT_RESOLUTION_TRANSPORT_SCHEMA+'","views":'+ '['.repeat(66)+'0'+']'.repeat(66)+'}');
 f.bytes=b;f.expectedByteDigest=offlineConflictResolutionTransportDigest(b);
 reject(f,'EXCHANGE32U_JSON_INVALID');
});
t('transport encoder refuses single observer without pretending to certify it',()=>{
 const f=build();assert.throws(()=>encodeOfflineConflictResolutionTransport([f.views[0]]),e=>e?.code==='EXCHANGE32U_STRUCTURE_INVALID');
});
