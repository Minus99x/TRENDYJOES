import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,readdir,writeFile,unlink,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {fixturePack} from './support/objective32w-fixture.mjs';
import {createOfflineConflictManifestJournal,offlineConflictManifestJournalGenesisHead} from '../src/offline-conflict-resolution-manifest-journal.mjs';
import {offlineConflictExchangeRecoveryReviewerPolicyDigest} from '../src/offline-conflict-exchange-recovery.mjs';
import {OFFLINE_CONFLICT_MANIFEST_CLAIM_ADJUDICATION_SCHEMA,offlineConflictManifestClaimDecisionBytes,offlineConflictManifestClaimDecisionDigest} from '../src/offline-conflict-manifest-claim-adjudication.mjs';
import {OFFLINE_CONFLICT_MANIFEST_CLAIM_TRANSCRIPT_SCHEMA,OFFLINE_CONFLICT_MANIFEST_CLAIM_TRANSCRIPT_MAX_BYTES,
 offlineConflictManifestClaimSnapshotDigest,offlineConflictManifestClaimTranscriptDigest,
 verifyOfflineConflictManifestClaimTranscript,encodeOfflineConflictManifestClaimTranscript} from '../src/offline-conflict-manifest-claim-transcript.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const digest=x=>createHash('sha256').update('TJ-32Y-INSPECTION-TRANSCRIPT\0').update(x).digest('hex');
const error=code=>e=>e?.code===code;
const now=1792280000000;
const a=[1,2,3].map(i=>({reviewerId:`alpha32y_reviewer_${i}`,...generateKeyPairSync('ed25519')}));
const b=[1,2,3].map(i=>({reviewerId:`bravo32y_reviewer_${i}`,...generateKeyPairSync('ed25519')}));
const pub=g=>g.map(({reviewerId,publicKey})=>({reviewerId,publicKey}));
const policy=g=>offlineConflictExchangeRecoveryReviewerPolicyDigest(pub(g));
const signGroup=(body,g)=>g.slice(0,2).map(k=>({reviewerId:k.reviewerId,signature:sign(null,offlineConflictManifestClaimDecisionBytes(body),k.privateKey).toString('base64url')}));
const t=(name,fn)=>test('32Y '+name,fn);
async function scenario(fn,{stage='after-pending-sync',prior=false}={}){
 const root=await mkdtemp(join(tmpdir(),'trendy32y-')),dir=join(root,'journal');
 try{
  let head=offlineConflictManifestJournalGenesisHead();
  if(prior){const r=await createOfflineConflictManifestJournal({directory:dir}).claim({
   verificationArgs:fixturePack('session_32y_prior_001',2048,'a'),expectedHead:head});
   head={count:r.count,headDigest:r.headDigest};}
  const j=createOfflineConflictManifestJournal({directory:dir,injectFault:s=>{if(s===stage)throw Error('simulated crash');}});
  await assert.rejects(j.claim({verificationArgs:fixturePack('session_32y_pending_001',2048,prior?'b':'a'),expectedHead:head}),/simulated crash/);
  const pending=await readFile(join(dir,'.pending.json')),record=JSON.parse(pending);
  const body={schema:OFFLINE_CONFLICT_MANIFEST_CLAIM_ADJUDICATION_SCHEMA,action:'inspect-only',journalHead:head,
   pendingBytesDigest:sha(pending),pendingRecordDigest:record.recordDigest,pendingIndex:head.count+1,
   expectedPendingState:stage==='after-link-sync'?'linked-pending':'pending-only',
   reviewerGroupADigest:policy(a),reviewerGroupBDigest:policy(b),issuedAt:now-1000,
   expiresAt:now+10000,nonce:'transcript32y_nonce_0001'};
  const decision={body,groupASignatures:signGroup(body,a),groupBSignatures:signGroup(body,b)};
  const args={decision,reviewerGroupA:pub(a),reviewerGroupB:pub(b),
   expectedDecisionDigest:offlineConflictManifestClaimDecisionDigest(decision),
   expectedReviewerGroupADigest:policy(a),expectedReviewerGroupBDigest:policy(b),
   expectedHead:head,expectedPendingBytesDigest:sha(pending),nowMs:now};
  const inspector=createOfflineConflictManifestJournal({directory:dir});
  const exported=await inspector.exportInterruptedClaimTranscriptReadOnly(args);
  const pins={bytes:exported.bytes,expectedTranscriptDigest:exported.transcriptDigest,
   expectedSnapshotDigest:exported.snapshotDigest,...args};
  await fn({root,dir,inspector,args,pins,exported,pending,record,head});
 }finally{await rm(root,{recursive:true,force:true});}
}
const verify=x=>verifyOfflineConflictManifestClaimTranscript(x);
const mutate=(pins,change)=>{
 const b=JSON.parse(pins.bytes);change(b);
 const bytes=Buffer.from(JSON.stringify(b));
 return {...pins,bytes,expectedTranscriptDigest:digest(bytes)};
};
t('unlinked pending export verifies with independently retained pins',()=>scenario(async x=>{
 const r=verify(x.pins);assert.equal(r.verified,true);assert.equal(r.observedState,'pending-only');
 assert.deepEqual(r.priorHead,r.observedHead);assert.equal(r.authorizesRepair,false);
 assert.equal(r.independentlyWitnessed,false);assert.equal(r.requiresIndependentResolution,true);
 assert.equal(x.exported.bytes.length<=OFFLINE_CONFLICT_MANIFEST_CLAIM_TRANSCRIPT_MAX_BYTES,true);
}));
t('linked pending export proves only local linked state',()=>scenario(async x=>{
 const r=verify(x.pins);assert.equal(r.observedState,'linked-pending');
 assert.equal(r.observedHead.count,x.head.count+1);
 assert.equal(r.observedHead.headDigest,x.record.recordDigest);
 assert.equal((await stat(join(x.dir,'.pending.json'))).nlink,2);
},{stage:'after-link-sync'}));
t('nonempty prior history is pinned in unlinked transcript',()=>scenario(async x=>{
 const r=verify(x.pins);assert.equal(r.priorHead.count,1);assert.equal(r.observedHead.count,1);
},{prior:true}));
t('nonempty prior history is pinned in linked transcript',()=>scenario(async x=>{
 const r=verify(x.pins);assert.equal(r.priorHead.count,1);assert.equal(r.observedHead.count,2);
},{prior:true,stage:'after-link-sync'}));
t('export never alters on-disk pending and journal records',()=>scenario(async x=>{
 const before=await readdir(x.dir),pending=await readFile(join(x.dir,'.pending.json'));
 await x.inspector.exportInterruptedClaimTranscriptReadOnly(x.args);
 assert.deepEqual(await readdir(x.dir),before);assert.deepEqual(await readFile(join(x.dir,'.pending.json')),pending);
}));
t('deterministic repeat export has byte-identical canonical transcript',()=>scenario(async x=>{
 const again=await x.inspector.exportInterruptedClaimTranscriptReadOnly(x.args);
 assert.deepEqual(again.bytes,x.exported.bytes);assert.equal(again.snapshotDigest,x.exported.snapshotDigest);
}));
t('valid byte digest is domain-separated from plain SHA-256',()=>scenario(async x=>{
 assert.equal(offlineConflictManifestClaimTranscriptDigest(x.pins.bytes),x.exported.transcriptDigest);
 assert.notEqual(sha(x.pins.bytes),x.exported.transcriptDigest);
}));
t('missing transcript pin fails closed',()=>scenario(async x=>assert.throws(()=>verify({...x.pins,expectedTranscriptDigest:undefined}),error('EXCHANGE32Y_EXTERNAL_PINS_REQUIRED'))));
t('missing snapshot pin fails closed',()=>scenario(async x=>assert.throws(()=>verify({...x.pins,expectedSnapshotDigest:undefined}),error('EXCHANGE32Y_EXTERNAL_PINS_REQUIRED'))));
t('missing decision pin fails closed',()=>scenario(async x=>assert.throws(()=>verify({...x.pins,expectedDecisionDigest:undefined}),error('EXCHANGE32Y_EXTERNAL_PINS_REQUIRED'))));
t('missing prior head pin fails closed',()=>scenario(async x=>assert.throws(()=>verify({...x.pins,expectedHead:undefined}),error('EXCHANGE32Y_EXTERNAL_PINS_REQUIRED'))));
t('missing pending-byte pin fails closed',()=>scenario(async x=>assert.throws(()=>verify({...x.pins,expectedPendingBytesDigest:undefined}),error('EXCHANGE32Y_EXTERNAL_PINS_REQUIRED'))));
t('wrong transcript pin fails closed',()=>scenario(async x=>assert.throws(()=>verify({...x.pins,expectedTranscriptDigest:sha('wrong')}),error('EXCHANGE32Y_TRANSCRIPT_PIN_MISMATCH'))));
t('wrong snapshot pin fails closed',()=>scenario(async x=>assert.throws(()=>verify({...x.pins,expectedSnapshotDigest:sha('wrong')}),error('EXCHANGE32Y_SNAPSHOT_PIN_MISMATCH'))));
t('wrong reviewer policy pin fails closed',()=>scenario(async x=>assert.throws(()=>verify({...x.pins,expectedReviewerGroupADigest:sha('wrong')}),error('EXCHANGE32Y_SNAPSHOT_PIN_MISMATCH'))));
t('wrong head pin fails closed',()=>scenario(async x=>assert.throws(()=>verify({...x.pins,expectedHead:{count:0,headDigest:sha('wrong')}}),error('EXCHANGE32Y_SNAPSHOT_PIN_MISMATCH'))));
t('wrong pending bytes pin fails closed',()=>scenario(async x=>assert.throws(()=>verify({...x.pins,expectedPendingBytesDigest:sha('wrong')}),error('EXCHANGE32Y_SNAPSHOT_PIN_MISMATCH'))));
t('truncated bytes fail even with recomputed transport digest',()=>scenario(async x=>{
 const bytes=x.pins.bytes.subarray(0,x.pins.bytes.length-1);
 assert.throws(()=>verify({...x.pins,bytes,expectedTranscriptDigest:digest(bytes)}),error('EXCHANGE32Y_TRANSCRIPT_INVALID'));
}));
t('appended trailing bytes fail even with recomputed transport digest',()=>scenario(async x=>{
 const bytes=Buffer.concat([x.pins.bytes,Buffer.from('x')]);
 assert.throws(()=>verify({...x.pins,bytes,expectedTranscriptDigest:digest(bytes)}),error('EXCHANGE32Y_TRANSCRIPT_INVALID'));
}));
t('invalid UTF-8 fails even with recomputed transport digest',()=>scenario(async x=>{
 const bytes=Buffer.concat([x.pins.bytes.subarray(0,20),Buffer.from([0xff]),x.pins.bytes.subarray(20)]);
 assert.throws(()=>verify({...x.pins,bytes,expectedTranscriptDigest:digest(bytes)}),error('EXCHANGE32Y_TRANSCRIPT_INVALID'));
}));
t('duplicate JSON keys fail even with recomputed transport digest',()=>scenario(async x=>{
 const str=x.pins.bytes.toString('utf8');
 const bytes=Buffer.from(str.replace('{','{"schema":"'+OFFLINE_CONFLICT_MANIFEST_CLAIM_TRANSCRIPT_SCHEMA+'",'));
 assert.throws(()=>verify({...x.pins,bytes,expectedTranscriptDigest:digest(bytes)}),error('EXCHANGE32Y_NONCANONICAL_BYTES'));
}));
t('reordered keys fail even with recomputed transport digest',()=>scenario(async x=>{
 const b=JSON.parse(x.pins.bytes),keys=Object.keys(b).reverse();
 const bytes=Buffer.from(JSON.stringify(Object.fromEntries(keys.map(k=>[k,b[k]]))));
 assert.throws(()=>verify({...x.pins,bytes,expectedTranscriptDigest:digest(bytes)}),error('EXCHANGE32Y_NONCANONICAL_BYTES'));
}));
t('whitespace JSON fails even with recomputed transport digest',()=>scenario(async x=>{
 const bytes=Buffer.from(JSON.stringify(JSON.parse(x.pins.bytes),null,2));
 assert.throws(()=>verify({...x.pins,bytes,expectedTranscriptDigest:digest(bytes)}),error('EXCHANGE32Y_NONCANONICAL_BYTES'));
}));
t('UTF-8 BOM fails even with recomputed transport digest',()=>scenario(async x=>{
 const bytes=Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),x.pins.bytes]);
 assert.throws(()=>verify({...x.pins,bytes,expectedTranscriptDigest:digest(bytes)}),error('EXCHANGE32Y_TRANSCRIPT_INVALID'));
}));
t('oversized transcript is rejected before parse',()=>scenario(async x=>{
 const bytes=Buffer.alloc(OFFLINE_CONFLICT_MANIFEST_CLAIM_TRANSCRIPT_MAX_BYTES+1,0x20);
 assert.throws(()=>verify({...x.pins,bytes,expectedTranscriptDigest:digest(bytes)}),error('EXCHANGE32Y_TRANSCRIPT_BYTES_INVALID'));
}));
t('non-buffer transcript rejected',()=>scenario(async x=>assert.throws(()=>verify({...x.pins,bytes:x.pins.bytes.toString('utf8')}),error('EXCHANGE32Y_TRANSCRIPT_BYTES_INVALID'))));
t('extra unapproved field rejected',()=>scenario(async x=>{
 const pins=mutate(x.pins,b=>{b.productionApproved=true;});
 assert.throws(()=>verify(pins),error('EXCHANGE32Y_TRANSCRIPT_INVALID'));
}));
t('production authorization bit cannot be enabled',()=>scenario(async x=>{
 const pins=mutate(x.pins,b=>{b.authorizesProduction=true;});
 assert.throws(()=>verify(pins),error('EXCHANGE32Y_TRANSCRIPT_INVALID'));
}));
t('repair authorization bit cannot be enabled',()=>scenario(async x=>{
 const pins=mutate(x.pins,b=>{b.authorizesRepair=true;});
 assert.throws(()=>verify(pins),error('EXCHANGE32Y_TRANSCRIPT_INVALID'));
}));
t('independent witness bit cannot be forged',()=>scenario(async x=>{
 const pins=mutate(x.pins,b=>{b.independentlyWitnessed=true;});
 assert.throws(()=>verify(pins),error('EXCHANGE32Y_TRANSCRIPT_INVALID'));
}));
t('snapshot mismatch rejected after pending record substitution',()=>scenario(async x=>{
 const pins=mutate(x.pins,b=>{b.pendingRecordDigest=sha('replacement');});
 assert.throws(()=>verify(pins),error('EXCHANGE32Y_SNAPSHOT_INVALID'));
}));
t('snapshot mismatch rejected after state substitution',()=>scenario(async x=>{
 const pins=mutate(x.pins,b=>{b.observedState='linked-pending';});
 assert.throws(()=>verify(pins),error('EXCHANGE32Y_SNAPSHOT_INVALID'));
}));
t('snapshot mismatch rejected after prior head fork',()=>scenario(async x=>{
 const pins=mutate(x.pins,b=>{b.priorHead.headDigest=sha('fork');});
 assert.throws(()=>verify(pins),error('EXCHANGE32Y_SNAPSHOT_INVALID'));
}));
t('snapshot mismatch rejected after timestamp substitution',()=>scenario(async x=>{
 const pins=mutate(x.pins,b=>{b.observedAt++;});
 assert.throws(()=>verify(pins),error('EXCHANGE32Y_SNAPSHOT_INVALID'));
}));
t('recomputed snapshot and transport digests cannot evade external snapshot pin',()=>scenario(async x=>{
 const pins=mutate(x.pins,b=>{
  b.observedAt++;
  b.snapshotDigest=offlineConflictManifestClaimSnapshotDigest({priorHead:b.priorHead,observedHead:b.observedHead,
   pendingIndex:b.pendingIndex,pendingRecordDigest:b.pendingRecordDigest,pendingBytesDigest:b.pendingBytesDigest,
   observedState:b.observedState,decisionDigest:b.decisionDigest,observedAt:b.observedAt});
 });
 assert.throws(()=>verify(pins),error('EXCHANGE32Y_SNAPSHOT_PIN_MISMATCH'));
}));
t('recomputed transcript digest cannot forge Ed25519 reviewer signature',()=>scenario(async x=>{
 const decision=structuredClone(x.args.decision),old=decision.groupASignatures[0].signature;
 decision.groupASignatures[0].signature=(old[0]==='A'?'B':'A')+old.slice(1);
 const expectedDecisionDigest=offlineConflictManifestClaimDecisionDigest(decision);
 const pins=mutate(x.pins,b=>{b.decisionDigest=expectedDecisionDigest;
  b.snapshotDigest=offlineConflictManifestClaimSnapshotDigest({priorHead:b.priorHead,observedHead:b.observedHead,
   pendingIndex:b.pendingIndex,pendingRecordDigest:b.pendingRecordDigest,pendingBytesDigest:b.pendingBytesDigest,
   observedState:b.observedState,decisionDigest:b.decisionDigest,observedAt:b.observedAt});});
 assert.throws(()=>verify({...pins,decision,expectedDecisionDigest,expectedSnapshotDigest:JSON.parse(pins.bytes).snapshotDigest}),error('EXCHANGE32X_SIGNATURE_INVALID'));
}));
t('substituted signed decision rejected',()=>scenario(async x=>{
 const decision=structuredClone(x.args.decision);decision.body.nonce='transcript32y_nonce_9999';
 assert.throws(()=>verify({...x.pins,decision}),error('EXCHANGE32X_EXTERNAL_PIN_MISMATCH'));
}));
t('expired signing decision rejected on fresh journal export',()=>scenario(async x=>{
 await assert.rejects(x.inspector.exportInterruptedClaimTranscriptReadOnly({...x.args,nowMs:now+11000}),error('EXCHANGE32X_DECISION_EXPIRED'));
}));
t('missing pending file blocks a new export; old transcript remains historical',()=>scenario(async x=>{
 await unlink(join(x.dir,'.pending.json'));
 await assert.rejects(x.inspector.exportInterruptedClaimTranscriptReadOnly(x.args),error('EXCHANGE32X_PENDING_REQUIRED'));
 assert.equal(verify(x.pins).verified,true);
}));
t('tampered pending file blocks fresh export; historical transcript remains only an offline record',()=>scenario(async x=>{
 await writeFile(join(x.dir,'.pending.json'),Buffer.from('{}'));
 await assert.rejects(x.inspector.exportInterruptedClaimTranscriptReadOnly(x.args));
 assert.equal(verify(x.pins).verified,true);
}));
t('no repair occurs during export, and normal claim remains blocked',()=>scenario(async x=>{
 await x.inspector.exportInterruptedClaimTranscriptReadOnly(x.args);
 await assert.rejects(x.inspector.inspect({expectedHead:x.head}),error('EXCHANGE32W_UNCERTAIN_COMMIT'));
 assert.ok((await readdir(x.dir)).includes('.pending.json'));
}));
t('forged local inspection object cannot claim production authority',()=>scenario(async x=>{
 const inspection=await x.inspector.adjudicateInterruptedClaimReadOnly(x.args);
 assert.throws(()=>encodeOfflineConflictManifestClaimTranscript({inspection:{...inspection,authorizesProduction:true},
  decision:x.args.decision,observedAt:now}),error('EXCHANGE32Y_INSPECTION_REQUIRED'));
}));
t('inspection must match signed decision state',()=>scenario(async x=>{
 const inspection=await x.inspector.adjudicateInterruptedClaimReadOnly(x.args);
 assert.throws(()=>encodeOfflineConflictManifestClaimTranscript({inspection:{...inspection,observedState:'linked-pending'},
  decision:x.args.decision,observedAt:now}),error('EXCHANGE32Y_DECISION_SNAPSHOT_MISMATCH'));
}));
t('invalid standalone snapshot cannot claim linked head without record digest',()=>{
 assert.throws(()=>offlineConflictManifestClaimSnapshotDigest({priorHead:{count:0,headDigest:sha('a')},
  observedHead:{count:1,headDigest:sha('wrong')},pendingIndex:1,pendingRecordDigest:sha('correct'),
  pendingBytesDigest:sha('bytes'),observedState:'linked-pending',decisionDigest:sha('decision'),observedAt:now}),error('EXCHANGE32Y_SNAPSHOT_INVALID'));
});
