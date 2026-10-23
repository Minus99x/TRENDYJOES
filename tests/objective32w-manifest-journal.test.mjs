import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,chmod,symlink,link,unlink,readdir,truncate} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fixturePack} from './support/objective32w-fixture.mjs';
import {createOfflineConflictManifestJournal,offlineConflictManifestJournalGenesisHead,
 OFFLINE_CONFLICT_MANIFEST_JOURNAL_SCHEMA} from '../src/offline-conflict-resolution-manifest-journal.mjs';
const t=(name,fn)=>test('32W '+name,fn);
const head0=offlineConflictManifestJournalGenesisHead();
const err=code=>e=>e?.code===code;
const temp=async fn=>{const root=await mkdtemp(join(tmpdir(),'trendy32w-'));
 try{return await fn(join(root,'ledger'),root);}finally{await rm(root,{recursive:true,force:true});}};
const journal=(dir,opts={})=>createOfflineConflictManifestJournal({directory:dir,...opts});
const pack=(s='session_32w_unique_A_001',seed='a')=>fixturePack(s,2048,seed);
const claim=(j,f=pack(),expectedHead=head0)=>j.claim({verificationArgs:f,expectedHead});
const copy=f=>({...f,chunks:f.chunks.map(c=>({...c,bytes:Buffer.from(c.bytes)})),
 manifestBytes:Buffer.from(f.manifestBytes)});
const sha=b=>createHash('sha256').update(b).digest('hex');
const worker=async(dir,file,mode)=>new Promise((done,reject)=>{
 const p=spawn(process.execPath,['tests/support/objective32w-worker.mjs',dir,file,mode],{cwd:resolve('.'),stdio:['ignore','pipe','pipe']});
 let out='',stderr='';p.stdout.on('data',x=>out+=x);p.stderr.on('data',x=>stderr+=x);
 p.once('error',reject);p.once('close',(code,signal)=>done({code,signal,out,stderr}));
});
const fixtureFile=async(root,f=pack(),head=head0)=>{
 const file=join(root,'fixture.json');await writeFile(file,JSON.stringify({
  ...f,manifestBytes:f.manifestBytes.toString('base64'),
  chunks:f.chunks.map(c=>({...c,bytes:c.bytes.toString('base64')})),expectedHead:head,
  previouslyAcceptedManifestDigests:undefined}));return file;
};

t('genesis is deterministic and requires external pin',()=>temp(async dir=>{
 assert.deepEqual(offlineConflictManifestJournalGenesisHead(),head0);
 assert.equal((await journal(dir).inspect({expectedHead:head0})).count,0);
 await assert.rejects(journal(dir).inspect(),err('EXCHANGE32W_EXTERNAL_HEAD_REQUIRED'));
}));
t('signed chunk evidence is verified and durably claimed',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j);assert.equal(a.count,1);
 assert.equal(a.acceptedManifestCount,1);assert.equal(a.durableSingleHostReplayProtection,true);
 assert.equal(a.independentlyAnchored,false);assert.equal(a.authorizesProduction,false);
 const b=await journal(dir).inspect({expectedHead:{count:1,headDigest:a.headDigest}});
 assert.equal(b.headDigest,a.headDigest);
}));
t('second distinct session claim extends chained journal',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j);
 const b=await claim(j,pack('session_32w_unique_B_002','b'),{count:1,headDigest:a.headDigest});
 assert.equal(b.count,2);assert.notEqual(b.headDigest,a.headDigest);
 assert.equal((await readdir(dir)).filter(n=>/^\d{4}\.json$/.test(n)).length,2);
}));
t('replayed manifest is rejected regardless of caller replay snapshot',()=>temp(async dir=>{
 const j=journal(dir),f=pack(),a=await claim(j,f);
 f.previouslyAcceptedManifestDigests=new Set();
 await assert.rejects(claim(j,f,{count:1,headDigest:a.headDigest}),err('EXCHANGE32W_REPLAY'));
}));
t('session reuse with distinct manifest is rejected',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j),f=pack();
 // Alter chunk size while preserving signed transport and session, producing a different manifest.
 const {encodeOfflineConflictResolutionChunks}=await import('../src/offline-conflict-resolution-chunks.mjs');
 const e=encodeOfflineConflictResolutionChunks({transportBytes:f.transportBytes,sessionId:f.expectedSessionId,chunkSize:4096});
 f.manifestBytes=e.manifestBytes;f.expectedManifestDigest=e.manifestDigest;f.chunks=e.chunks;
 await assert.rejects(claim(j,f,{count:1,headDigest:a.headDigest}),err('EXCHANGE32W_REPLAY'));
}));
t('same signed transport cannot be reaccepted under a new session',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j);
 const f=pack('session_32w_unique_B_002');
 await assert.rejects(claim(j,f,{count:1,headDigest:a.headDigest}),err('EXCHANGE32W_REPLAY'));
}));
t('stale independently pinned head fails closed',()=>temp(async dir=>{
 const j=journal(dir);await claim(j);
 await assert.rejects(j.inspect({expectedHead:head0}),err('EXCHANGE32W_STALE_OR_ROLLED_BACK_HEAD'));
 await assert.rejects(claim(j,pack('session_32w_unique_B_002')),err('EXCHANGE32W_STALE_OR_ROLLED_BACK_HEAD'));
}));
t('forged manifest digest cannot enter journal',()=>temp(async dir=>{
 const f=pack();f.expectedManifestDigest=sha('forged');
 await assert.rejects(claim(journal(dir),f),err('EXCHANGE32V_MANIFEST_PIN_MISMATCH'));
 assert.equal((await journal(dir).inspect({expectedHead:head0})).count,0);
}));
t('altered signed transport rejected before durable write',()=>temp(async dir=>{
 const f=copy(pack());f.chunks[0].bytes[0]^=1;
 await assert.rejects(claim(journal(dir),f),err('EXCHANGE32V_CHUNK_DIGEST_MISMATCH'));
 assert.equal((await journal(dir).inspect({expectedHead:head0})).count,0);
}));
t('reordered chunks rejected before durable write',()=>temp(async dir=>{
 const f=copy(pack());[f.chunks[0],f.chunks[1]]=[f.chunks[1],f.chunks[0]];
 await assert.rejects(claim(journal(dir),f),err('EXCHANGE32V_CHUNK_BINDING_MISMATCH'));
}));
t('missing external observer pins rejected before durable write',()=>temp(async dir=>{
 const f=pack();delete f.anchors;
 await assert.rejects(claim(journal(dir),f));
 assert.equal((await journal(dir).inspect({expectedHead:head0})).count,0);
}));
t('invalid request and missing head rejected',()=>temp(async dir=>{
 const j=journal(dir);await assert.rejects(j.claim({verificationArgs:pack()}),err('EXCHANGE32W_REQUEST_INVALID'));
 await assert.rejects(j.claim({verificationArgs:[],expectedHead:head0}),err('EXCHANGE32W_REQUEST_INVALID'));
}));
t('invalid journal configurations rejected',()=>{
 for(const config of [{directory:''},{directory:'/tmp/x',lockTimeoutMs:-1},{directory:'/tmp/x',lockTimeoutMs:10001},
  {directory:'/tmp/x',injectFault:true}])assert.throws(()=>createOfflineConflictManifestJournal(config),err('EXCHANGE32W_CONFIGURATION'));
});
t('pending fsynced crash remains uncertain, no retry or auto repair',()=>temp(async dir=>{
 const j=journal(dir,{injectFault:async stage=>{if(stage==='after-pending-sync')throw Error('injected crash');}});
 await assert.rejects(claim(j),/injected crash/);
 await assert.rejects(j.inspect({expectedHead:head0}),err('EXCHANGE32W_UNCERTAIN_COMMIT'));
 await assert.rejects(claim(journal(dir)),err('EXCHANGE32W_UNCERTAIN_COMMIT'));
}));
t('linked pending crash remains uncertain',()=>temp(async dir=>{
 const j=journal(dir,{injectFault:async stage=>{if(stage==='after-link-sync')throw Error('injected crash');}});
 await assert.rejects(claim(j),/injected crash/);
 await assert.rejects(j.inspect({expectedHead:head0}),err('EXCHANGE32W_UNCERTAIN_COMMIT'));
}));
t('crash after commit leaves committed entry but caller must re-pin',()=>temp(async dir=>{
 const j=journal(dir,{injectFault:async stage=>{if(stage==='after-commit-sync')throw Error('lost acknowledgement');}});
 await assert.rejects(claim(j),/lost acknowledgement/);
 await assert.rejects(j.inspect({expectedHead:head0}),err('EXCHANGE32W_STALE_OR_ROLLED_BACK_HEAD'));
 const files=await readdir(dir);assert.equal(files.includes('.pending.json'),false);
}));
t('tampered record fails closed even if caller updates head',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j),file=join(dir,'0001.json');
 const e=JSON.parse(await readFile(file));e.sessionId='session_32w_fake_fake_001';
 await writeFile(file,JSON.stringify(e));
 await assert.rejects(j.inspect({expectedHead:{count:1,headDigest:a.headDigest}}),err('EXCHANGE32W_HISTORY_INVALID'));
}));
t('truncated record fails closed',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j);await truncate(join(dir,'0001.json'),17);
 await assert.rejects(j.inspect({expectedHead:{count:1,headDigest:a.headDigest}}),err('EXCHANGE32W_HISTORY_INVALID'));
}));
t('record deletion is detected by independent head',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j);await unlink(join(dir,'0001.json'));
 await assert.rejects(j.inspect({expectedHead:{count:1,headDigest:a.headDigest}}),err('EXCHANGE32W_STALE_OR_ROLLED_BACK_HEAD'));
}));
t('unknown files fail closed',()=>temp(async dir=>{
 const j=journal(dir);await j.inspect({expectedHead:head0});await writeFile(join(dir,'extra.json'),'{}');
 await assert.rejects(j.inspect({expectedHead:head0}),err('EXCHANGE32W_HISTORY_INVALID'));
}));
t('nonconsecutive record fails closed',()=>temp(async dir=>{
 const j=journal(dir);await j.inspect({expectedHead:head0});await writeFile(join(dir,'0002.json'),'{}');
 await assert.rejects(j.inspect({expectedHead:head0}),err('EXCHANGE32W_HISTORY_INVALID'));
}));
t('symlinked record rejected',()=>temp(async(dir,root)=>{
 const j=journal(dir),a=await claim(j),file=join(dir,'0001.json'),replacement=join(root,'replacement.json');
 await writeFile(replacement,await readFile(file));await unlink(file);await symlink(replacement,file);
 await assert.rejects(j.inspect({expectedHead:{count:1,headDigest:a.headDigest}}));
}));
t('hardlinked record rejected',()=>temp(async(dir,root)=>{
 const j=journal(dir),a=await claim(j);await link(join(dir,'0001.json'),join(root,'duplicate'));
 await assert.rejects(j.inspect({expectedHead:{count:1,headDigest:a.headDigest}}),err('EXCHANGE32W_RECORD_UNSAFE'));
}));
t('world-readable directory rejected',()=>temp(async dir=>{
 const j=journal(dir);await j.inspect({expectedHead:head0});await chmod(dir,0o755);
 await assert.rejects(j.inspect({expectedHead:head0}),err('EXCHANGE32W_DIRECTORY_UNSAFE'));
}));
t('world-readable record rejected',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j);await chmod(join(dir,'0001.json'),0o644);
 await assert.rejects(j.inspect({expectedHead:{count:1,headDigest:a.headDigest}}),err('EXCHANGE32W_RECORD_UNSAFE'));
}));
t('symlinked lock refused',()=>temp(async(dir,root)=>{
 const j=journal(dir);await j.inspect({expectedHead:head0});
 await unlink(join(dir,'.manifest-lock'));await symlink(join(root,'outside'),join(dir,'.manifest-lock'));
 await assert.rejects(j.inspect({expectedHead:head0}));
}));
t('concurrent independent processes: only one claim succeeds',()=>temp(async(dir,root)=>{
 const file=await fixtureFile(root);const [a,b]=await Promise.all([worker(dir,file,'normal'),worker(dir,file,'normal')]);
 const results=[a,b].map(x=>JSON.parse(x.out.trim()));
 assert.equal(results.filter(x=>x.ok).length,1);
 assert.equal(results.filter(x=>!x.ok).length,1);
 assert.ok(['EXCHANGE32W_STALE_OR_ROLLED_BACK_HEAD','EXCHANGE32W_REPLAY'].includes(results.find(x=>!x.ok).code));
 const winner=results.find(x=>x.ok).result;
 assert.equal((await journal(dir).inspect({expectedHead:{count:1,headDigest:winner.headDigest}})).count,1);
}));
t('real child-process SIGKILL after pending fsync remains fail-closed',()=>temp(async(dir,root)=>{
 const file=await fixtureFile(root);const p=await worker(dir,file,'crash');
 assert.equal(p.signal,'SIGKILL');
 await assert.rejects(journal(dir).inspect({expectedHead:head0}),err('EXCHANGE32W_UNCERTAIN_COMMIT'));
}));
t('record schema and digest bind manifest and session',()=>temp(async dir=>{
 const j=journal(dir),f=pack(),a=await claim(j,f);
 const e=JSON.parse(await readFile(join(dir,'0001.json'),'utf8'));
 assert.equal(e.schema,OFFLINE_CONFLICT_MANIFEST_JOURNAL_SCHEMA);
 assert.equal(e.manifestDigest,f.expectedManifestDigest);
 assert.equal(e.transportDigest,f.expectedTransportDigest);
 assert.equal(e.sessionId,f.expectedSessionId);assert.equal(e.recordDigest,a.headDigest);
}));
t('recomputed forged record hash cannot bypass external head pin',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j),file=join(dir,'0001.json');
 const e=JSON.parse(await readFile(file));e.manifestDigest=sha('forged-manifest');
 const {recordDigest,...body}=e;
 e.recordDigest=sha(Buffer.concat([Buffer.from('TJ-32W-RECORD\0'),Buffer.from(JSON.stringify(body))]));
 await writeFile(file,JSON.stringify(e));
 await assert.rejects(j.inspect({expectedHead:{count:1,headDigest:a.headDigest}}),err('EXCHANGE32W_STALE_OR_ROLLED_BACK_HEAD'));
}));
t('forged second-record duplicate manifest rejected despite recomputed hash',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j),b=await claim(j,pack('session_32w_unique_B_002','b'),{count:1,headDigest:a.headDigest});
 const first=JSON.parse(await readFile(join(dir,'0001.json'))),file=join(dir,'0002.json');
 const e=JSON.parse(await readFile(file));e.manifestDigest=first.manifestDigest;
 const {recordDigest,...body}=e;
 e.recordDigest=sha(Buffer.concat([Buffer.from('TJ-32W-RECORD\0'),Buffer.from(JSON.stringify(body))]));
 await writeFile(file,JSON.stringify(e));
 await assert.rejects(j.inspect({expectedHead:{count:2,headDigest:b.headDigest}}),err('EXCHANGE32W_HISTORY_INVALID'));
}));
t('noncanonical record JSON rejected even if fields parse',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j),file=join(dir,'0001.json');
 await writeFile(file,Buffer.concat([await readFile(file),Buffer.from(' ')]));
 await assert.rejects(j.inspect({expectedHead:{count:1,headDigest:a.headDigest}}),err('EXCHANGE32W_HISTORY_INVALID'));
}));
