import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,readdir,unlink,link,symlink,chmod,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {fixturePack} from './support/objective32w-fixture.mjs';
import {createOfflineConflictManifestJournal,offlineConflictManifestJournalGenesisHead} from '../src/offline-conflict-resolution-manifest-journal.mjs';
import {offlineConflictExchangeRecoveryReviewerPolicyDigest} from '../src/offline-conflict-exchange-recovery.mjs';
import {offlineConflictManifestClaimDecisionBytes,offlineConflictManifestClaimDecisionDigest,
 OFFLINE_CONFLICT_MANIFEST_CLAIM_ADJUDICATION_SCHEMA} from '../src/offline-conflict-manifest-claim-adjudication.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const now=1792280000000;
const head0=offlineConflictManifestJournalGenesisHead();
const group=prefix=>[1,2,3].map(i=>({reviewerId:`${prefix}_reviewer_${i}`,...generateKeyPairSync('ed25519')}));
const a=group('alpha32x'),b=group('bravo32x');
const pub=g=>g.map(({reviewerId,publicKey})=>({reviewerId,publicKey}));
const policy=g=>offlineConflictExchangeRecoveryReviewerPolicyDigest(pub(g));
const signatures=(body,g)=>g.slice(0,2).map(k=>({reviewerId:k.reviewerId,
 signature:sign(null,offlineConflictManifestClaimDecisionBytes(body),k.privateKey).toString('base64url')}));
const error=code=>e=>e?.code===code;
const t=(name,fn)=>test('32X '+name,fn);
async function scenario(fn,stage='after-pending-sync',priorCount=0){
 const root=await mkdtemp(join(tmpdir(),'trendy32x-')),dir=join(root,'journal');
 try{
  let priorHead=head0;
  if(priorCount===1){
   const r=await createOfflineConflictManifestJournal({directory:dir}).claim({
    verificationArgs:fixturePack('session_32x_prior_001',2048,'a'),expectedHead:head0});
   priorHead={count:r.count,headDigest:r.headDigest};
  }
  const j=createOfflineConflictManifestJournal({directory:dir,injectFault:s=>{if(s===stage)throw Error('simulated 32X crash');}});
  await assert.rejects(j.claim({verificationArgs:fixturePack('session_32x_valid_001',2048,priorCount?'b':'a'),expectedHead:priorHead}),/simulated 32X crash/);
  const pendingPath=join(dir,'.pending.json'),pending=await readFile(pendingPath),record=JSON.parse(pending);
  const body={schema:OFFLINE_CONFLICT_MANIFEST_CLAIM_ADJUDICATION_SCHEMA,action:'inspect-only',
   journalHead:priorHead,pendingBytesDigest:sha(pending),pendingRecordDigest:record.recordDigest,
   pendingIndex:priorHead.count+1,expectedPendingState:stage==='after-link-sync'?'linked-pending':'pending-only',
   reviewerGroupADigest:policy(a),reviewerGroupBDigest:policy(b),
   issuedAt:now-1000,expiresAt:now+10000,nonce:'manifest32x_inspect_nonce_01'};
  const decision={body,groupASignatures:signatures(body,a),groupBSignatures:signatures(body,b)};
  const args={decision,reviewerGroupA:pub(a),reviewerGroupB:pub(b),
   expectedDecisionDigest:offlineConflictManifestClaimDecisionDigest(decision),
   expectedReviewerGroupADigest:policy(a),expectedReviewerGroupBDigest:policy(b),
   expectedHead:priorHead,expectedPendingBytesDigest:sha(pending),nowMs:now};
  const inspector=createOfflineConflictManifestJournal({directory:dir});
  await fn({root,dir,pendingPath,pending,record,inspector,args,priorHead});
 }finally{await rm(root,{recursive:true,force:true});}
}
function reSign(args,body){
 args=args.args??args;
 const decision={body,groupASignatures:signatures(body,a),groupBSignatures:signatures(body,b)};
 return {...args,decision,expectedDecisionDigest:offlineConflictManifestClaimDecisionDigest(decision)};
}
const inspect=(x,args=x.args)=>x.inspector.adjudicateInterruptedClaimReadOnly(args);
t('signed two-quorum inspection of unlinked pending remains non-mutating',()=>scenario(async x=>{
 const before=await readdir(x.dir),bytes=await readFile(x.pendingPath);
 const result=await inspect(x);
 assert.equal(result.verified,true);assert.equal(result.observedState,'pending-only');
 assert.equal(result.pendingRecordDigest,x.record.recordDigest);assert.equal(result.requiresIndependentResolution,true);
 assert.equal(result.authorizesRepair,false);assert.equal(result.authorizesProduction,false);
 assert.deepEqual(await readdir(x.dir),before);assert.deepEqual(await readFile(x.pendingPath),bytes);
 await assert.rejects(x.inspector.inspect({expectedHead:head0}),error('EXCHANGE32W_UNCERTAIN_COMMIT'));
}));
t('signed two-quorum inspection of linked pending remains non-mutating',()=>scenario(async x=>{
 const before=await readdir(x.dir),bytes=await readFile(x.pendingPath);
 const result=await inspect(x);assert.equal(result.observedState,'linked-pending');
 assert.deepEqual(await readdir(x.dir),before);assert.deepEqual(await readFile(x.pendingPath),bytes);
 assert.equal((await stat(x.pendingPath)).nlink,2);
},'after-link-sync'));
t('inspection never clears a blocked claim, even on repeated authorization',()=>scenario(async x=>{
 await inspect(x);await inspect(x);
 assert.ok((await readdir(x.dir)).includes('.pending.json'));
 await assert.rejects(x.inspector.claim({verificationArgs:fixturePack('session_32x_valid_002',2048,'b'),expectedHead:head0}),error('EXCHANGE32W_UNCERTAIN_COMMIT'));
}));
t('no pending claim is rejected',()=>scenario(async x=>{
 await unlink(x.pendingPath);
 await assert.rejects(inspect(x),error('EXCHANGE32X_PENDING_REQUIRED'));
}));
t('missing external decision pin rejected',()=>scenario(async x=>{
 await assert.rejects(inspect(x,{...x.args,expectedDecisionDigest:undefined}),error('EXCHANGE32X_EXTERNAL_PINS_REQUIRED'));
}));
t('missing external head rejected',()=>scenario(async x=>{
 await assert.rejects(inspect(x,{...x.args,expectedHead:undefined}),error('EXCHANGE32X_EXTERNAL_PINS_REQUIRED'));
}));
t('missing pending pin rejected',()=>scenario(async x=>{
 await assert.rejects(inspect(x,{...x.args,expectedPendingBytesDigest:undefined}),error('EXCHANGE32X_EXTERNAL_PINS_REQUIRED'));
}));
t('stale external head rejected even with re-signed decision',()=>scenario(async x=>{
 const forged={count:1,headDigest:sha('forged')};
 const args=reSign(x,{...x.args.decision.body,journalHead:forged,pendingIndex:2});
 await assert.rejects(inspect(x,{...args,expectedHead:forged}),error('EXCHANGE32X_HISTORY_PIN_MISMATCH'));
}));
t('wrong pending bytes pin rejected even with re-signed decision',()=>scenario(async x=>{
 const pin=sha('wrong');const args=reSign(x,{...x.args.decision.body,pendingBytesDigest:pin});
 await assert.rejects(inspect(x,{...args,expectedPendingBytesDigest:pin}),error('EXCHANGE32X_PENDING_PIN_MISMATCH'));
}));
t('wrong signed pending record digest rejected',()=>scenario(async x=>{
 const args=reSign(x,{...x.args.decision.body,pendingRecordDigest:sha('wrong')});
 await assert.rejects(inspect(x,args),error('EXCHANGE32X_DECISION_STATE_MISMATCH'));
}));
t('wrong signed expected pending state rejected',()=>scenario(async x=>{
 const args=reSign(x,{...x.args.decision.body,expectedPendingState:'linked-pending'});
 await assert.rejects(inspect(x,args),error('EXCHANGE32X_DECISION_STATE_MISMATCH'));
}));
t('wrong signed linked pending state rejected',()=>scenario(async x=>{
 const args=reSign(x,{...x.args.decision.body,expectedPendingState:'pending-only'});
 await assert.rejects(inspect(x,args),error('EXCHANGE32X_DECISION_STATE_MISMATCH'));
},'after-link-sync'));
t('forged signature rejected despite repinned decision digest',()=>scenario(async x=>{
 const decision=structuredClone(x.args.decision);
 const old=decision.groupASignatures[0].signature;
 decision.groupASignatures[0].signature=(old[0]==='A'?'B':'A')+old.slice(1);
 await assert.rejects(inspect(x,{...x.args,decision,expectedDecisionDigest:offlineConflictManifestClaimDecisionDigest(decision)}),error('EXCHANGE32X_SIGNATURE_INVALID'));
}));
t('outgoing reviewer quorum is mandatory',()=>scenario(async x=>{
 const decision=structuredClone(x.args.decision);decision.groupASignatures.pop();
 await assert.rejects(inspect(x,{...x.args,decision,expectedDecisionDigest:offlineConflictManifestClaimDecisionDigest(decision)}),error('EXCHANGE32X_QUORUM_REQUIRED'));
}));
t('incoming reviewer quorum is mandatory',()=>scenario(async x=>{
 const decision=structuredClone(x.args.decision);decision.groupBSignatures.pop();
 await assert.rejects(inspect(x,{...x.args,decision,expectedDecisionDigest:offlineConflictManifestClaimDecisionDigest(decision)}),error('EXCHANGE32X_QUORUM_REQUIRED'));
}));
t('expired inspection authorization rejected',()=>scenario(async x=>{
 await assert.rejects(inspect(x,{...x.args,nowMs:now+12000}),error('EXCHANGE32X_DECISION_EXPIRED'));
}));
t('not-yet-valid inspection authorization rejected',()=>scenario(async x=>{
 await assert.rejects(inspect(x,{...x.args,nowMs:now-2000}),error('EXCHANGE32X_DECISION_EXPIRED'));
}));
t('decision digest cannot be substituted',()=>scenario(async x=>{
 await assert.rejects(inspect(x,{...x.args,expectedDecisionDigest:sha('other')}),error('EXCHANGE32X_EXTERNAL_PIN_MISMATCH'));
}));
t('reviewer roster pin substitution rejected',()=>scenario(async x=>{
 await assert.rejects(inspect(x,{...x.args,expectedReviewerGroupADigest:sha('other')}),error('EXCHANGE32X_REVIEWER_PIN_MISMATCH'));
}));
t('overlapping reviewer identities rejected across independently pinned groups',()=>scenario(async x=>{
 const groupB=pub(b);groupB[0]={...pub(a)[0]};
 const args={...x.args,reviewerGroupB:groupB,expectedReviewerGroupBDigest:policy(groupB)};
 const signed=reSign(args,{...x.args.decision.body,reviewerGroupBDigest:args.expectedReviewerGroupBDigest});
 await assert.rejects(inspect(x,signed),error('EXCHANGE32X_REVIEWER_OVERLAP'));
}));
t('reordered signatures rejected',()=>scenario(async x=>{
 const decision=structuredClone(x.args.decision);decision.groupASignatures.reverse();
 await assert.rejects(inspect(x,{...x.args,decision,expectedDecisionDigest:offlineConflictManifestClaimDecisionDigest(decision)}),error('EXCHANGE32X_SIGNATURE_INVALID'));
}));
t('replayed signature from different decision rejected',()=>scenario(async x=>{
 const decision=structuredClone(x.args.decision);decision.body.nonce='nonce_changed_32x';
 await assert.rejects(inspect(x,{...x.args,decision,expectedDecisionDigest:offlineConflictManifestClaimDecisionDigest(decision)}),error('EXCHANGE32X_SIGNATURE_INVALID'));
}));
t('tampered pending bytes rejected',()=>scenario(async x=>{
 await writeFile(x.pendingPath,Buffer.from('tampered'));
 await assert.rejects(inspect(x),error('EXCHANGE32X_PENDING_PIN_MISMATCH'));
}));
t('symlinked pending refused',()=>scenario(async x=>{
 const target=join(x.root,'other');await writeFile(target,x.pending);
 await unlink(x.pendingPath);await symlink(target,x.pendingPath);
 await assert.rejects(inspect(x));
}));
t('world-readable pending refused',()=>scenario(async x=>{
 await chmod(x.pendingPath,0o644);await assert.rejects(inspect(x),error('EXCHANGE32W_RECORD_UNSAFE'));
}));
t('hardlinked pending to unknown target refused',()=>scenario(async x=>{
 await link(x.pendingPath,join(x.root,'unrelated'));
 await assert.rejects(inspect(x),error('EXCHANGE32X_LINK_MISMATCH'));
}));
t('linked pending missing target fails closed',()=>scenario(async x=>{
 await unlink(join(x.dir,'0001.json'));
 await assert.rejects(inspect(x));
},'after-link-sync'));
t('linked pending with substituted record fails closed',()=>scenario(async x=>{
 await unlink(join(x.dir,'0001.json'));
 await writeFile(join(x.dir,'0001.json'),x.pending);
 await assert.rejects(inspect(x));
},'after-link-sync'));
t('linked pending cannot conceal a forged prior head',()=>scenario(async x=>{
 const wrong={count:0,headDigest:sha('rolled-back')};
 const args=reSign(x,{...x.args.decision.body,journalHead:wrong});
 await assert.rejects(inspect(x,{...args,expectedHead:wrong}),error('EXCHANGE32X_HISTORY_PIN_MISMATCH'));
},'after-link-sync'));
t('invalid authorization action cannot become a repair permit',()=>scenario(async x=>{
 const decision=structuredClone(x.args.decision);decision.body.action='repair';
 assert.throws(()=>offlineConflictManifestClaimDecisionDigest(decision),error('EXCHANGE32X_DECISION_INVALID'));
}));
t('malformed nonce cannot authorize inspection',()=>scenario(async x=>{
 const decision=structuredClone(x.args.decision);decision.body.nonce='x';
 assert.throws(()=>offlineConflictManifestClaimDecisionDigest(decision),error('EXCHANGE32X_DECISION_INVALID'));
}));
t('invalid pending record with repinned bytes rejected',()=>scenario(async x=>{
 const bad=JSON.parse(x.pending);bad.sessionId='short';
 const bytes=Buffer.from(JSON.stringify(bad));await writeFile(x.pendingPath,bytes);
 const args=reSign(x,{...x.args.decision.body,pendingBytesDigest:sha(bytes)});
 await assert.rejects(inspect(x,{...args,expectedPendingBytesDigest:sha(bytes)}),error('EXCHANGE32X_PENDING_INVALID'));
}));
t('unexpected extra journal file blocks adjudication',()=>scenario(async x=>{
 await writeFile(join(x.dir,'fork.json'),'{}');
 await assert.rejects(inspect(x),error('EXCHANGE32W_HISTORY_INVALID'));
}));

t('nonempty history: signed pending-only inspection binds exact prior head',()=>scenario(async x=>{
 const result=await inspect(x);
 assert.equal(result.observedState,'pending-only');assert.equal(result.priorHead.count,1);
 assert.equal(result.priorHead.headDigest,x.priorHead.headDigest);
 assert.ok((await readdir(x.dir)).includes('0001.json'));
},'after-pending-sync',1));
t('nonempty history: signed linked-pending inspection binds both records',()=>scenario(async x=>{
 const result=await inspect(x);
 assert.equal(result.observedState,'linked-pending');assert.equal(result.pendingIndex,2);
 assert.equal(result.priorHead.headDigest,x.priorHead.headDigest);
 assert.equal((await stat(join(x.dir,'0002.json'))).nlink,2);
},'after-link-sync',1));
t('prior record omission blocks inspection despite valid pending signatures',()=>scenario(async x=>{
 await unlink(join(x.dir,'0001.json'));
 await assert.rejects(inspect(x),error('EXCHANGE32X_HISTORY_PIN_MISMATCH'));
},'after-pending-sync',1));
t('prior record fork with recomputed local digest fails independent head pin',()=>scenario(async x=>{
 const path=join(x.dir,'0001.json'),entry=JSON.parse(await readFile(path));
 entry.sessionId='session_32x_forked_prior';
 const {recordDigest,...body}=entry;
 entry.recordDigest=sha(Buffer.concat([Buffer.from('TJ-32W-RECORD\0'),Buffer.from(JSON.stringify(body))]));
 await writeFile(path,JSON.stringify(entry));
 await assert.rejects(inspect(x),error('EXCHANGE32X_HISTORY_PIN_MISMATCH'));
},'after-pending-sync',1));
t('prior record fork breaks linked pending continuity',()=>scenario(async x=>{
 const path=join(x.dir,'0001.json'),entry=JSON.parse(await readFile(path));
 entry.sessionId='session_32x_forked_prior';
 const {recordDigest,...body}=entry;
 entry.recordDigest=sha(Buffer.concat([Buffer.from('TJ-32W-RECORD\0'),Buffer.from(JSON.stringify(body))]));
 await writeFile(path,JSON.stringify(entry));
 await assert.rejects(inspect(x),error('EXCHANGE32W_HISTORY_INVALID'));
},'after-link-sync',1));
