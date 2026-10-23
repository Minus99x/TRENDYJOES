import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {offlineConflictRecoveryReceiptGenesisHead} from '../../src/offline-conflict-exchange-recovery-receipts.mjs';
import {offlineConflictExchangeRecoveryReviewerPolicyDigest} from '../../src/offline-conflict-exchange-recovery.mjs';
import {OFFLINE_CONFLICT_RECOVERY_POLICY_EPOCH_SCHEMA,offlineConflictRecoveryPolicyEpochGenesisDigest,
 offlineConflictRecoveryPolicyTransitionBytes,offlineConflictRecoveryPolicyTransitionDigest} from '../../src/offline-conflict-recovery-policy-epochs.mjs';
import {OFFLINE_CONFLICT_RECOVERY_CUTOVER_SCHEMA,offlineConflictRecoveryCutoverDigest} from '../../src/offline-conflict-recovery-policy-cutover.mjs';
import {OFFLINE_CONFLICT_CUTOVER_ADJUDICATION_SCHEMA,offlineConflictCutoverAdjudicationBytes,
 offlineConflictCutoverAdjudicationDigest} from '../../src/offline-conflict-recovery-cutover-adjudication.mjs';
import {OFFLINE_CONFLICT_CUTOVER_RESOLUTION_PROOF_SCHEMA,offlineConflictCutoverResolutionProofDigest} from '../../src/offline-conflict-cutover-resolution-proof.mjs';
import {OFFLINE_CONFLICT_RESOLUTION_INVENTORY_SCHEMA,OFFLINE_CONFLICT_RESOLUTION_UNION_SCHEMA,
 offlineConflictResolutionInventoryDigest,offlineConflictResolutionUnionDigest,
 verifyOfflineConflictResolutionInventories} from '../../src/offline-conflict-resolution-inventory.mjs';

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


import {encodeOfflineConflictResolutionTransport} from '../../src/offline-conflict-resolution-transport.mjs';
import {encodeOfflineConflictResolutionChunks} from '../../src/offline-conflict-resolution-chunks.mjs';
export function fixturePack(sessionId='session_32w_unique_A_001',chunkSize=2048,seed='a'){
 const f=build(seed==='a'?[f1,f2]:[fixture('c'),fixture('d')]),transport=encodeOfflineConflictResolutionTransport(f.views);
 const encoded=encodeOfflineConflictResolutionChunks({transportBytes:transport.bytes,sessionId,chunkSize});
 return {...f,manifestBytes:encoded.manifestBytes,expectedManifestDigest:encoded.manifestDigest,
  expectedTransportDigest:encoded.transportDigest,expectedSessionId:sessionId,
  chunks:encoded.chunks,previouslyAcceptedManifestDigests:new Set(),transportBytes:transport.bytes};
}
