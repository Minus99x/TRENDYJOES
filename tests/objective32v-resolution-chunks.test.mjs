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

import {encodeOfflineConflictResolutionTransport,offlineConflictResolutionTransportDigest} from '../src/offline-conflict-resolution-transport.mjs';
import {OFFLINE_CONFLICT_RESOLUTION_CHUNK_SCHEMA,OFFLINE_CONFLICT_RESOLUTION_CHUNK_MAX_COUNT,
 OFFLINE_CONFLICT_RESOLUTION_CHUNK_MAX_MANIFEST_BYTES,encodeOfflineConflictResolutionChunks,
 verifyOfflineConflictResolutionChunks,offlineConflictResolutionChunkManifestDigest,
 offlineConflictResolutionChunkDigest} from '../src/offline-conflict-resolution-chunks.mjs';

const sessionA='session_32v_unique_A_001',sessionB='session_32v_unique_B_002';
const t=(name,fn)=>test('32V '+name,fn);
const fixturePack=(sessionId=sessionA,chunkSize=2048)=>{
 const f=build(),transport=encodeOfflineConflictResolutionTransport(f.views);
 const encoded=encodeOfflineConflictResolutionChunks({transportBytes:transport.bytes,sessionId,chunkSize});
 return {...f,manifestBytes:encoded.manifestBytes,expectedManifestDigest:encoded.manifestDigest,
  expectedTransportDigest:encoded.transportDigest,expectedSessionId:sessionId,
  chunks:encoded.chunks,previouslyAcceptedManifestDigests:new Set(),transportBytes:transport.bytes};
};
const verify=f=>verifyOfflineConflictResolutionChunks(f);
const rejects=(f,code)=>assert.throws(()=>verify(f),e=>e?.code===code);
const editManifest=(f,fn,repin=true)=>{
 const m=JSON.parse(f.manifestBytes.toString('utf8'));fn(m);
 f.manifestBytes=Buffer.from(JSON.stringify(m));
 if(repin)f.expectedManifestDigest=offlineConflictResolutionChunkManifestDigest(f.manifestBytes);
 f.chunks=f.chunks.map(c=>({...c,manifestDigest:f.expectedManifestDigest}));
 return f;
};
const editChunk=(f,i,fn)=>{
 f.chunks=f.chunks.map(c=>({...c,bytes:Buffer.from(c.bytes)}));fn(f.chunks[i]);return f;
};

t('valid signed two-observer roundtrip across multiple chunks',()=>{
 const f=fixturePack();assert.ok(f.chunks.length>1);
 const r=verify(f);assert.equal(r.verified,true);assert.equal(r.authenticatedAttemptCount,2);
 assert.equal(r.chunkManifestVerified,true);assert.equal(r.chunkCount,f.chunks.length);
 assert.equal(r.sessionId,sessionA);assert.equal(r.durableReplayProtection,false);
 assert.equal(r.authorizesProduction,false);assert.equal(r.independentlyPublished,false);
});
t('single chunk is valid with sufficiently large size',()=>{
 const f=fixturePack(sessionA,65536);assert.equal(f.chunks.length,1);assert.equal(verify(f).verified,true);
});
t('Uint8Array inputs are supported and copied',()=>{
 const f=fixturePack();f.manifestBytes=new Uint8Array(f.manifestBytes);
 f.chunks=f.chunks.map(c=>({...c,bytes:new Uint8Array(c.bytes)}));assert.equal(verify(f).verified,true);
});
t('original 32U bytes preserved exactly through reassembly',()=>{
 const f=fixturePack();assert.deepEqual(Buffer.concat(f.chunks.map(c=>c.bytes)),f.transportBytes);
 assert.equal(offlineConflictResolutionTransportDigest(f.transportBytes),f.expectedTransportDigest);
});
t('domain separation for chunk and manifest pins',()=>{
 const f=fixturePack();assert.notEqual(f.expectedManifestDigest,sha(f.manifestBytes));
 assert.notEqual(offlineConflictResolutionChunkDigest(f.chunks[0]),sha(f.chunks[0].bytes));
});
t('encoder requires explicit session id',()=>{
 const f=fixturePack();assert.throws(()=>encodeOfflineConflictResolutionChunks({transportBytes:f.transportBytes}),{code:'EXCHANGE32V_SESSION_INVALID'});
});
t('encoder rejects short or unicode session',()=>{
 const f=fixturePack();for(const sessionId of ['a','é'.repeat(20),'session with spaces 000'])
  assert.throws(()=>encodeOfflineConflictResolutionChunks({transportBytes:f.transportBytes,sessionId}),{code:'EXCHANGE32V_SESSION_INVALID'});
});
t('encoder rejects bad chunk sizes',()=>{
 const f=fixturePack();for(const chunkSize of [0,511,65537,NaN,1.5,'2048'])
  assert.throws(()=>encodeOfflineConflictResolutionChunks({transportBytes:f.transportBytes,sessionId:sessionA,chunkSize}),{code:'EXCHANGE32V_CHUNK_SIZE_INVALID'});
});
t('encoder rejects empty and oversized transports',()=>{
 for(const transportBytes of [Buffer.alloc(0),Buffer.alloc(1048577)])
  assert.throws(()=>encodeOfflineConflictResolutionChunks({transportBytes,sessionId:sessionA}),{code:'EXCHANGE32V_TRANSPORT_INVALID'});
});
t('encoder rejects excessive chunk count',()=>{
 assert.throws(()=>encodeOfflineConflictResolutionChunks({transportBytes:Buffer.alloc(100000),sessionId:sessionA,chunkSize:512}),{code:'EXCHANGE32V_TOO_MANY_CHUNKS'});
});
t('no independently pinned manifest rejected',()=>{const f=fixturePack();delete f.expectedManifestDigest;rejects(f,'EXCHANGE32V_EXTERNAL_PINS_REQUIRED');});
t('no independently pinned session rejected',()=>{const f=fixturePack();delete f.expectedSessionId;rejects(f,'EXCHANGE32V_EXTERNAL_PINS_REQUIRED');});
t('no independently pinned transport rejected',()=>{const f=fixturePack();delete f.expectedTransportDigest;rejects(f,'EXCHANGE32V_EXTERNAL_PINS_REQUIRED');});
t('no caller-supplied replay snapshot rejected',()=>{const f=fixturePack();delete f.previouslyAcceptedManifestDigests;rejects(f,'EXCHANGE32V_EXTERNAL_PINS_REQUIRED');});
t('invalid replay snapshot rejected',()=>{const f=fixturePack();f.previouslyAcceptedManifestDigests=[];rejects(f,'EXCHANGE32V_EXTERNAL_PINS_REQUIRED');});
t('caller replay snapshot prevents accepted manifest reuse',()=>{
 const f=fixturePack();assert.equal(verify(f).verified,true);
 f.previouslyAcceptedManifestDigests.add(f.expectedManifestDigest);rejects(f,'EXCHANGE32V_REPLAY_DETECTED');
});
t('verifier never mutates caller replay snapshot',()=>{
 const f=fixturePack();verify(f);assert.equal(f.previouslyAcceptedManifestDigests.size,0);
});
t('manifest byte pin substitution rejected',()=>{
 const f=fixturePack();f.manifestBytes=Buffer.from(f.manifestBytes);f.manifestBytes[5]^=1;
 rejects(f,'EXCHANGE32V_MANIFEST_PIN_MISMATCH');
});
t('cross-session manifest reuse rejected',()=>{
 const f=fixturePack();f.expectedSessionId=sessionB;rejects(f,'EXCHANGE32V_SESSION_OR_TRANSPORT_MISMATCH');
});
t('cross-transport digest pin mismatch rejected',()=>{
 const f=fixturePack();f.expectedTransportDigest=sha('wrong');rejects(f,'EXCHANGE32V_SESSION_OR_TRANSPORT_MISMATCH');
});
t('reordered chunks rejected, not silently sorted',()=>{
 const f=fixturePack();f.chunks=[...f.chunks];[f.chunks[0],f.chunks[1]]=[f.chunks[1],f.chunks[0]];
 rejects(f,'EXCHANGE32V_CHUNK_BINDING_MISMATCH');
});
t('omitted chunk rejected',()=>{const f=fixturePack();f.chunks=f.chunks.slice(1);rejects(f,'EXCHANGE32V_CHUNK_COUNT_MISMATCH');});
t('duplicated chunk rejected',()=>{
 const f=fixturePack();f.chunks=[...f.chunks];f.chunks[1]=f.chunks[0];rejects(f,'EXCHANGE32V_CHUNK_BINDING_MISMATCH');
});
t('extra chunk rejected',()=>{const f=fixturePack();f.chunks=[...f.chunks,f.chunks.at(-1)];rejects(f,'EXCHANGE32V_CHUNK_COUNT_MISMATCH');});
t('sparse chunk array rejected',()=>{const f=fixturePack();f.chunks=[...f.chunks];delete f.chunks[1];rejects(f,'EXCHANGE32V_CHUNK_COUNT_MISMATCH');});
t('chunk accessor rejected without invoking it',()=>{
 const f=fixturePack();f.chunks=[...f.chunks];Object.defineProperty(f.chunks,'0',{get(){throw Error('accessor invoked');},enumerable:true});
 rejects(f,'EXCHANGE32V_CHUNK_INVALID');
});
t('chunk extra property rejected',()=>{const f=fixturePack();f.chunks=f.chunks.map(c=>({...c}));f.chunks[0].extra=true;rejects(f,'EXCHANGE32V_CHUNK_INVALID');});
t('chunk session substitution rejected',()=>{
 const f=fixturePack();f.chunks=f.chunks.map(c=>({...c}));f.chunks[0].sessionId=sessionB;rejects(f,'EXCHANGE32V_CHUNK_BINDING_MISMATCH');
});
t('chunk from different manifest rejected',()=>{
 const f=fixturePack(),g=fixturePack(sessionB);f.chunks=[...f.chunks];f.chunks[0]=g.chunks[0];rejects(f,'EXCHANGE32V_CHUNK_BINDING_MISMATCH');
});
t('chunk index substitution rejected',()=>{
 const f=fixturePack();f.chunks=f.chunks.map(c=>({...c}));f.chunks[0].index=1;rejects(f,'EXCHANGE32V_CHUNK_BINDING_MISMATCH');
});
t('truncated chunk rejected',()=>{
 const f=fixturePack();editChunk(f,0,c=>c.bytes=c.bytes.subarray(0,-1));rejects(f,'EXCHANGE32V_CHUNK_LENGTH_MISMATCH');
});
t('chunk extension rejected',()=>{
 const f=fixturePack();editChunk(f,0,c=>c.bytes=Buffer.concat([c.bytes,Buffer.from([0])]));rejects(f,'EXCHANGE32V_CHUNK_INVALID');
});
t('bitflipped chunk rejected with manifest unchanged',()=>{
 const f=fixturePack();editChunk(f,0,c=>c.bytes[0]^=1);rejects(f,'EXCHANGE32V_CHUNK_DIGEST_MISMATCH');
});
t('re-pinned malicious chunk rejected by independently pinned manifest',()=>{
 const f=fixturePack();editChunk(f,0,c=>c.bytes[0]^=1);
 editManifest(f,m=>m.chunkDigests[0]=offlineConflictResolutionChunkDigest(f.chunks[0]),false);
 rejects(f,'EXCHANGE32V_MANIFEST_PIN_MISMATCH');
});
t('re-pinned malicious manifest rejected by independently pinned transport digest',()=>{
 const f=fixturePack();editChunk(f,0,c=>c.bytes[0]^=1);
 editManifest(f,m=>m.chunkDigests[0]=offlineConflictResolutionChunkDigest(f.chunks[0]));
 rejects(f,'EXCHANGE32V_TRANSPORT_PIN_MISMATCH');
});
t('manifest duplicate key rejected even with re-pin',()=>{
 const f=fixturePack(),s=f.manifestBytes.toString('utf8');
 f.manifestBytes=Buffer.from(s.replace('"schema":','"schema":"duplicate","schema":'));
 f.expectedManifestDigest=offlineConflictResolutionChunkManifestDigest(f.manifestBytes);
 rejects(f,'EXCHANGE32V_MANIFEST_INVALID');
});
t('manifest escaped duplicate key rejected even with re-pin',()=>{
 const f=fixturePack(),s=f.manifestBytes.toString('utf8');
 f.manifestBytes=Buffer.from(s.replace('"schema":','"\\u0073chema":"duplicate","schema":'));
 f.expectedManifestDigest=offlineConflictResolutionChunkManifestDigest(f.manifestBytes);
 rejects(f,'EXCHANGE32V_MANIFEST_INVALID');
});
t('manifest trailing bytes rejected even with re-pin',()=>{
 const f=fixturePack();f.manifestBytes=Buffer.concat([f.manifestBytes,Buffer.from(' ')]);
 f.expectedManifestDigest=offlineConflictResolutionChunkManifestDigest(f.manifestBytes);rejects(f,'EXCHANGE32V_MANIFEST_INVALID');
});
t('manifest invalid UTF8 rejected even with re-pin',()=>{
 const f=fixturePack();f.manifestBytes=Buffer.concat([f.manifestBytes,Buffer.from([0xff])]);
 f.expectedManifestDigest=offlineConflictResolutionChunkManifestDigest(f.manifestBytes);rejects(f,'EXCHANGE32V_MANIFEST_INVALID');
});
t('manifest count alteration rejected even with re-pin',()=>{
 const f=fixturePack();editManifest(f,m=>m.chunkCount++);rejects(f,'EXCHANGE32V_MANIFEST_INVALID');
});
t('manifest missing chunk digest rejected even with re-pin',()=>{
 const f=fixturePack();editManifest(f,m=>m.chunkDigests.pop());rejects(f,'EXCHANGE32V_MANIFEST_INVALID');
});
t('manifest extra key rejected even with re-pin',()=>{
 const f=fixturePack();editManifest(f,m=>m.productionAuthorized=true);rejects(f,'EXCHANGE32V_MANIFEST_INVALID');
});
t('manifest session substitution rejected by independent session pin',()=>{
 const f=fixturePack();editManifest(f,m=>m.sessionId=sessionB);rejects(f,'EXCHANGE32V_SESSION_OR_TRANSPORT_MISMATCH');
});
t('manifest size limit enforced',()=>{
 const f=fixturePack();f.manifestBytes=Buffer.alloc(OFFLINE_CONFLICT_RESOLUTION_CHUNK_MAX_MANIFEST_BYTES+1);
 rejects(f,'EXCHANGE32V_MANIFEST_INVALID');
});
t('manifest schema change rejected even with re-pin',()=>{
 const f=fixturePack();editManifest(f,m=>m.schema='NOT_32V');rejects(f,'EXCHANGE32V_MANIFEST_INVALID');
});
t('manifest chunk digest changed with re-pin but unchanged chunks rejected',()=>{
 const f=fixturePack();editManifest(f,m=>m.chunkDigests[0]=sha('false'));
 rejects(f,'EXCHANGE32V_CHUNK_DIGEST_MISMATCH');
});
t('cross-session chunks from same bytes rejected',()=>{
 const f=fixturePack(),g=fixturePack(sessionB);f.chunks=[...g.chunks];rejects(f,'EXCHANGE32V_CHUNK_BINDING_MISMATCH');
});
t('unsigned altered proof fails historical signature check after complete re-pin',()=>{
 const f=fixturePack();
 const altered=Buffer.from(f.transportBytes.toString('utf8').replace('resolution_nonce_a_abort','resolution_nonce_a_forged'));
 const e=encodeOfflineConflictResolutionChunks({transportBytes:altered,sessionId:sessionA,chunkSize:2048});
 f.manifestBytes=e.manifestBytes;f.expectedManifestDigest=e.manifestDigest;
 f.expectedTransportDigest=e.transportDigest;f.chunks=e.chunks;
 assert.throws(()=>verify(f),e=>e?.code?.startsWith('EXCHANGE32')&&e?.code!=='EXCHANGE32V_TRANSPORT_PIN_MISMATCH');
});
t('independent observer roster remains mandatory',()=>{
 const f=fixturePack();delete f.expectedObserverIds;
 assert.throws(()=>verify(f),e=>e?.code==='EXCHANGE32T_EXTERNAL_PINS_REQUIRED');
});
t('independent evidence anchors remain mandatory',()=>{
 const f=fixturePack();delete f.anchors;
 assert.throws(()=>verify(f),e=>e?.code==='EXCHANGE32T_EXTERNAL_PINS_REQUIRED');
});
t('caller-provided expected union remains mandatory',()=>{
 const f=fixturePack();delete f.expectedUnionDigest;
 assert.throws(()=>verify(f),e=>e?.code==='EXCHANGE32T_EXTERNAL_PINS_REQUIRED');
});
