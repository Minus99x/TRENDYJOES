/**
 * Objective 32F: portable, read-only replay audit evidence and offline witness
 * receipt verification. No publication, network I/O, key custody, or actions.
 */
import {createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
import {verifyOfflineReplayHeadCheckpoint} from './offline-supervisor-replay-checkpoint.mjs';

export const OFFLINE_PORTABLE_REPLAY_AUDIT_SCHEMA='TJ-OFFLINE-PORTABLE-REPLAY-AUDIT-1';
export const OFFLINE_PORTABLE_REPLAY_WITNESS_SCHEMA='TJ-OFFLINE-PORTABLE-REPLAY-WITNESS-1';
const HEX=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9_-]{12,80}$/;
const sha=b=>createHash('sha256').update(b).digest('hex');
const fail=code=>{throw Object.assign(new Error(code),{code});};
const plain=o=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&[Object.prototype,null].includes(Object.getPrototypeOf(o));
const exact=(o,fields)=>plain(o)&&Object.keys(o).sort().join('|')===fields.slice().sort().join('|');
const cmp=(a,b)=>a<b?-1:a>b?1:0;
function checkData(x,depth=0){
 if(depth>48)fail('PORTABLE32F_CANONICAL_INVALID');
 if(x===null||typeof x==='string'||typeof x==='boolean'||typeof x==='number'&&Number.isFinite(x))return;
 if(!Array.isArray(x)&&!plain(x))fail('PORTABLE32F_CANONICAL_INVALID');
 if(Array.isArray(x)&&Object.keys(x).length!==x.length)fail('PORTABLE32F_CANONICAL_INVALID');
 for(const [k,d] of Object.entries(Object.getOwnPropertyDescriptors(x))){
  if(k==='__proto__'||k==='constructor'||k==='prototype'||!Object.hasOwn(d,'value'))fail('PORTABLE32F_CANONICAL_INVALID');
  checkData(d.value,depth+1);
 }
}
function canonical(x){
 checkData(x);
 let s;try{s=JSON.stringify(x);}catch{fail('PORTABLE32F_CANONICAL_INVALID');}
 if(typeof s!=='string'||Buffer.byteLength(s)>32*1024*1024)fail('PORTABLE32F_CANONICAL_INVALID');
 return Buffer.from(s,'utf8');
}
function decode64(s,max=32*1024*1024){
 if(typeof s!=='string'||s.length>max*2||!/^[A-Za-z0-9_-]+$/.test(s))fail('PORTABLE32F_ENCODING_INVALID');
 const b=Buffer.from(s,'base64url');
 if(b.length>max||b.toString('base64url')!==s)fail('PORTABLE32F_ENCODING_INVALID');
 return b;
}
function portableKey({id,publicKey}){
 if(!ID.test(id||'')||publicKey?.type!=='public'||publicKey?.asymmetricKeyType!=='ed25519')fail('PORTABLE32F_KEY_INVALID');
 return {id,spki:publicKey.export({format:'der',type:'spki'}).toString('base64url')};
}
function hydrateKey(x){
 if(!exact(x,['id','spki'])||!ID.test(x.id||''))fail('PORTABLE32F_KEY_INVALID');
 const der=decode64(x.spki,2048);let publicKey;
 try{publicKey=createPublicKey({key:der,format:'der',type:'spki'});}catch{fail('PORTABLE32F_KEY_INVALID');}
 if(publicKey.asymmetricKeyType!=='ed25519'||!publicKey.export({format:'der',type:'spki'}).equals(der))fail('PORTABLE32F_KEY_INVALID');
 return {id:x.id,publicKey};
}
const ITEM_FIELDS=['record','report','expectedPins','decision','reviewers','quorum','expectedReviewerPolicyDigest','observedAtMs'];
function serializeItem(item){
 if(!exact(item,ITEM_FIELDS)||!Array.isArray(item.reviewers))fail('PORTABLE32F_ITEM_INVALID');
 return {record:item.record,report:item.report,expectedPins:item.expectedPins,decision:item.decision,
  reviewers:item.reviewers.map(portableKey),quorum:item.quorum,
  expectedReviewerPolicyDigest:item.expectedReviewerPolicyDigest,observedAtMs:item.observedAtMs};
}
function hydrateItem(item){
 if(!exact(item,ITEM_FIELDS)||!Array.isArray(item.reviewers))fail('PORTABLE32F_ITEM_INVALID');
 return {...item,reviewers:item.reviewers.map(hydrateKey)};
}
const itemDigest=item=>sha(Buffer.concat([Buffer.from(`${OFFLINE_PORTABLE_REPLAY_AUDIT_SCHEMA}-ITEM\0`),canonical(item)]));
const inventoryDigest=digests=>sha(Buffer.from(`${OFFLINE_PORTABLE_REPLAY_AUDIT_SCHEMA}-INVENTORY\0${JSON.stringify(digests)}`));
const BUNDLE_FIELDS=['schema','registryId','genesisBase64','expectedGenesisDigest','items','inventory','checkpoint','auditors',
 'auditorQuorum','expectedAuditorPolicyDigest','expectedCheckpointDigest','expectedPreviousCheckpointDigest','expectedSequence'];
function checkedBundle(b){
 if(!exact(b,BUNDLE_FIELDS)||b.schema!==OFFLINE_PORTABLE_REPLAY_AUDIT_SCHEMA||!ID.test(b.registryId||'')||
  !Array.isArray(b.items)||b.items.length>4096||!Array.isArray(b.auditors)||b.auditors.length>12||
  !exact(b.inventory,['count','itemDigests','inventoryDigest'])||
  !Number.isSafeInteger(b.inventory.count)||b.inventory.count!==b.items.length||
  !Array.isArray(b.inventory.itemDigests)||b.inventory.itemDigests.length!==b.items.length||
  !b.inventory.itemDigests.every(d=>HEX.test(d||''))||!HEX.test(b.inventory.inventoryDigest||''))fail('PORTABLE32F_INVENTORY_INVALID');
 const actual=b.items.map(itemDigest);
 if(actual.some((d,i)=>d!==b.inventory.itemDigests[i])||inventoryDigest(actual)!==b.inventory.inventoryDigest)
  fail('PORTABLE32F_INVENTORY_MISMATCH');
 return b;
}
export function encodeOfflinePortableReplayAuditBundle(args={}){
 // Verify all signed historical evidence against independently supplied pins BEFORE packaging.
 verifyOfflineReplayHeadCheckpoint(args);
 const items=args.items.map(serializeItem),digests=items.map(itemDigest);
 const b={schema:OFFLINE_PORTABLE_REPLAY_AUDIT_SCHEMA,registryId:args.registryId,
  genesisBase64:args.genesisBytes.toString('base64url'),expectedGenesisDigest:args.expectedGenesisDigest,
  items,inventory:{count:items.length,itemDigests:digests,inventoryDigest:inventoryDigest(digests)},
  checkpoint:args.checkpoint,auditors:args.auditors.map(portableKey),auditorQuorum:args.auditorQuorum,
  expectedAuditorPolicyDigest:args.expectedAuditorPolicyDigest,expectedCheckpointDigest:args.expectedCheckpointDigest,
  expectedPreviousCheckpointDigest:args.expectedPreviousCheckpointDigest,expectedSequence:args.expectedSequence};
 checkedBundle(b);return canonical(b);
}
export function offlinePortableReplayAuditBundleDigest(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length===0||bytes.length>32*1024*1024)fail('PORTABLE32F_BUNDLE_BYTES_INVALID');
 return sha(Buffer.concat([Buffer.from(`${OFFLINE_PORTABLE_REPLAY_AUDIT_SCHEMA}-BUNDLE\0`),bytes]));
}
const RECEIPT_FIELDS=['schema','registryId','bundleDigest','checkpointDigest','historyDigest','genesisDigest','commitCount',
 'previousWitnessReceiptDigest','sequence','issuedAt','witnessPolicyDigest'];
function checkedReceiptBody(b){
 if(!exact(b,RECEIPT_FIELDS)||b.schema!==OFFLINE_PORTABLE_REPLAY_WITNESS_SCHEMA||!ID.test(b.registryId||'')||
  ![b.bundleDigest,b.checkpointDigest,b.historyDigest,b.genesisDigest,b.previousWitnessReceiptDigest,b.witnessPolicyDigest].every(x=>HEX.test(x||''))||
  !Number.isSafeInteger(b.commitCount)||b.commitCount<0||b.commitCount>4096||
  !Number.isSafeInteger(b.sequence)||b.sequence<1||!Number.isSafeInteger(b.issuedAt)||b.issuedAt<0)
  fail('PORTABLE32F_RECEIPT_BODY_INVALID');
}
export function offlinePortableReplayWitnessSigningBytes(body){
 checkedReceiptBody(body);return Buffer.concat([Buffer.from(`${OFFLINE_PORTABLE_REPLAY_WITNESS_SCHEMA}\0`),canonical(body)]);
}
export function offlinePortableReplayWitnessReceiptDigest(receipt){
 if(!exact(receipt,['body','signatures']))fail('PORTABLE32F_RECEIPT_INVALID');
 offlinePortableReplayWitnessSigningBytes(receipt.body);
 return sha(Buffer.concat([Buffer.from(`${OFFLINE_PORTABLE_REPLAY_WITNESS_SCHEMA}-SIGNED\0`),canonical(receipt)]));
}
function checkedWitnessPolicy(witnesses,quorum){
 if(!Array.isArray(witnesses)||witnesses.length<2||witnesses.length>12||!Number.isSafeInteger(quorum)||quorum<=witnesses.length/2||quorum>witnesses.length)
  fail('PORTABLE32F_WITNESS_POLICY_INVALID');
 const ids=new Set(),keys=new Set(),members=[];
 for(const w of witnesses){
  if(!exact(w,['id','publicKey'])||!ID.test(w.id||'')||ids.has(w.id)||w.publicKey?.type!=='public'||w.publicKey?.asymmetricKeyType!=='ed25519')
   fail('PORTABLE32F_WITNESS_POLICY_INVALID');
  const keyDigest=sha(w.publicKey.export({format:'der',type:'spki'}));
  if(keys.has(keyDigest))fail('PORTABLE32F_WITNESS_POLICY_INVALID');
  ids.add(w.id);keys.add(keyDigest);members.push({id:w.id,keyDigest,publicKey:w.publicKey});
 }
 const sorted=members.slice().sort((a,b)=>cmp(a.id,b.id));
 const digest=sha(Buffer.from(`${OFFLINE_PORTABLE_REPLAY_WITNESS_SCHEMA}-POLICY\0${JSON.stringify({quorum,witnesses:sorted.map(({id,keyDigest})=>({id,keyDigest}))})}`));
 return {digest,quorum,members:new Map(members.map(w=>[w.id,w.publicKey])),keys};
}
export function offlinePortableReplayWitnessPolicyDigest({witnesses,quorum}={}){return checkedWitnessPolicy(witnesses,quorum).digest;}
export function verifyOfflinePortableReplayAuditBundle({bundleBytes,expectedBundleDigest,witnessReceipt,witnesses,witnessQuorum,
 expectedWitnessPolicyDigest,expectedWitnessReceiptDigest,expectedPreviousWitnessReceiptDigest,expectedWitnessSequence,
 expectedGenesisDigest,expectedCheckpointDigest,expectedPreviousCheckpointDigest,expectedSequence,expectedAuditorPolicyDigest}={}){
 if(!Buffer.isBuffer(bundleBytes)||bundleBytes.length===0||bundleBytes.length>32*1024*1024||!HEX.test(expectedBundleDigest||'')||
  offlinePortableReplayAuditBundleDigest(bundleBytes)!==expectedBundleDigest)fail('PORTABLE32F_EXTERNAL_BUNDLE_PIN_REQUIRED');
 let b;try{b=JSON.parse(bundleBytes.toString('utf8'));}catch{fail('PORTABLE32F_BUNDLE_INVALID');}
 if(!canonical(b).equals(bundleBytes))fail('PORTABLE32F_NONCANONICAL_BUNDLE');
 checkedBundle(b);
 if(![expectedGenesisDigest,expectedCheckpointDigest,expectedPreviousCheckpointDigest,expectedAuditorPolicyDigest].every(x=>HEX.test(x||''))||
  !Number.isSafeInteger(expectedSequence)||expectedSequence<1||b.expectedGenesisDigest!==expectedGenesisDigest||
  b.expectedCheckpointDigest!==expectedCheckpointDigest||b.expectedPreviousCheckpointDigest!==expectedPreviousCheckpointDigest||
  b.expectedAuditorPolicyDigest!==expectedAuditorPolicyDigest||b.expectedSequence!==expectedSequence)
  fail('PORTABLE32F_CHECKPOINT_PINS_MISMATCH');
 const auditors=b.auditors.map(hydrateKey),items=b.items.map(hydrateItem);
 const result=verifyOfflineReplayHeadCheckpoint({registryId:b.registryId,genesisBytes:decode64(b.genesisBase64,1024*1024),
  expectedGenesisDigest,items,checkpoint:b.checkpoint,auditors,auditorQuorum:b.auditorQuorum,
  expectedAuditorPolicyDigest,expectedCheckpointDigest,expectedPreviousCheckpointDigest,expectedSequence});
 if(!exact(witnessReceipt,['body','signatures']))fail('PORTABLE32F_RECEIPT_INVALID');
 const body=witnessReceipt.body,signBytes=offlinePortableReplayWitnessSigningBytes(body);
 if(!HEX.test(expectedWitnessReceiptDigest||'')||!HEX.test(expectedPreviousWitnessReceiptDigest||'')||
  !Number.isSafeInteger(expectedWitnessSequence)||expectedWitnessSequence<1||
  offlinePortableReplayWitnessReceiptDigest(witnessReceipt)!==expectedWitnessReceiptDigest||
  body.previousWitnessReceiptDigest!==expectedPreviousWitnessReceiptDigest||body.sequence!==expectedWitnessSequence)
  fail('PORTABLE32F_EXTERNAL_RECEIPT_PIN_REQUIRED');
 const policy=checkedWitnessPolicy(witnesses,witnessQuorum);
 if(!HEX.test(expectedWitnessPolicyDigest||'')||expectedWitnessPolicyDigest!==policy.digest||body.witnessPolicyDigest!==policy.digest)
  fail('PORTABLE32F_WITNESS_POLICY_PIN_MISMATCH');
 // Witness policy must not simply reuse auditor or historical reviewer signing keys.
 const historicalKeys=new Set([...auditors,...items.flatMap(i=>i.reviewers)].map(k=>sha(k.publicKey.export({format:'der',type:'spki'}))));
 if([...policy.keys].some(k=>historicalKeys.has(k)))fail('PORTABLE32F_WITNESS_NOT_INDEPENDENT');
 if(body.registryId!==b.registryId||body.bundleDigest!==expectedBundleDigest||
  body.checkpointDigest!==expectedCheckpointDigest||body.historyDigest!==b.checkpoint.body.historyDigest||
  body.genesisDigest!==expectedGenesisDigest||body.commitCount!==items.length||body.issuedAt<b.checkpoint.body.issuedAt)
  fail('PORTABLE32F_RECEIPT_BINDING_MISMATCH');
 if(!Array.isArray(witnessReceipt.signatures)||witnessReceipt.signatures.length<policy.quorum||witnessReceipt.signatures.length>policy.members.size)
  fail('PORTABLE32F_WITNESS_QUORUM_INVALID');
 let last='';for(const s of witnessReceipt.signatures){
  if(!exact(s,['witnessId','signature'])||typeof s.witnessId!=='string'||s.witnessId<=last||!policy.members.has(s.witnessId)||
   typeof s.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(s.signature)||
   Buffer.from(s.signature,'base64url').toString('base64url')!==s.signature||
   !verifySignature(null,signBytes,policy.members.get(s.witnessId),Buffer.from(s.signature,'base64url')))
   fail('PORTABLE32F_WITNESS_SIGNATURE_INVALID');
  last=s.witnessId;
 }
 return Object.freeze({verified:true,portableEvidenceVerified:true,historyVerified:result.historicalSignaturesVerified,
  commitCount:items.length,headDigest:result.headDigest,bundleDigest:expectedBundleDigest,witnessReceiptDigest:expectedWitnessReceiptDigest,
  independentlyPublished:false,externalPinPublicationVerified:false,trustedTimestampVerified:false,
  readOnly:true,authorizesRemediation:false,authorizesCheckout:false,productionApproved:false});
}
