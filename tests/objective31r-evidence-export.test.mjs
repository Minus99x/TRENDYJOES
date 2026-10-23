import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtemp,mkdir,writeFile,readFile,chmod,symlink,link,rm,rename} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createOfflineAcquisitionEvidenceExport,verifyOfflineAcquisitionEvidenceExport,OFFLINE_ACQUISITION_EXPORT_SCHEMA} from '../src/offline-acquisition-evidence-export.mjs';
import {OFFLINE_ACQUISITION_SESSION_SCHEMA} from '../src/offline-acquisition-session-journal.mjs';
import {OFFLINE_ACQUISITION_MANIFEST_SCHEMA} from '../src/offline-forensic-acquisition-provenance.mjs';

const hash=b=>createHash('sha256').update(b).digest('hex');
const ROOT='0'.repeat(64),id='acquisition_31r_0001';
const paths=['manifest.json','session/0001.json','session/0002.json','session/0003.json','evidence/branch_01.json'];
const fail=(fn,code)=>assert.rejects(fn,e=>e?.code===code);
const failSync=(fn,code)=>assert.throws(fn,e=>e?.code===code);
const pack=(header,payload)=>{const h=Buffer.from(JSON.stringify(header)),len=Buffer.alloc(4);len.writeUInt32BE(h.length);return Buffer.concat([Buffer.from(`${OFFLINE_ACQUISITION_EXPORT_SCHEMA}\n`),len,h,payload]);};
function unpack(bytes){const off=Buffer.byteLength(`${OFFLINE_ACQUISITION_EXPORT_SCHEMA}\n`),len=bytes.readUInt32BE(off),header=JSON.parse(bytes.subarray(off+4,off+4+len).toString());return {header,payload:bytes.subarray(off+4+len)};}
async function fixture(t){
 const root=await mkdtemp(join(tmpdir(),'tj31r-'));
 t.after(()=>rm(root,{recursive:true,force:true}));
 await mkdir(join(root,'session'),{mode:0o700});await mkdir(join(root,'evidence'),{mode:0o700});
 const pre={phase:'PRE',acquisitionId:id},post={phase:'POST',acquisitionId:id};
 const manifest={schema:OFFLINE_ACQUISITION_MANIFEST_SCHEMA,acquisitionId:id,envelope:{transportDigest:'a'.repeat(64)},receiptHistory:[pre,post]};
 let previous=ROOT;const events=[];
 for(const [i,action,payload] of [[1,'BEGIN',{acquisitionId:id}],[2,'PRE',pre],[3,'POST',manifest]]){
  const body={schema:OFFLINE_ACQUISITION_SESSION_SCHEMA,index:i,previousDigest:previous,action,payload};
  const e={...body,digest:hash(Buffer.from(`${OFFLINE_ACQUISITION_SESSION_SCHEMA}\0${JSON.stringify(body)}`))};previous=e.digest;events.push(e);
 }
 const values={'manifest.json':manifest,'session/0001.json':events[0],'session/0002.json':events[1],'session/0003.json':events[2],'evidence/branch_01.json':{epoch:1,verified:false}};
 for(const [name,value] of Object.entries(values))await writeFile(join(root,name),JSON.stringify(value),{mode:0o600});
 const create=(extra={})=>createOfflineAcquisitionEvidenceExport({rootDirectory:root,acquisitionId:id,relativePaths:paths,...extra});
 const get=async()=>{const archive=await create();return {archive,result:verifyOfflineAcquisitionEvidenceExport({bytes:archive.bytes,expectedDigest:archive.digest,expectedAcquisitionId:id})};};
 return {root,create,get,values};
}

test('31R canonical deterministic export verifies independently pinned transport and read-only boundaries',async t=>{
 const f=await fixture(t),a=await f.get(),b=await f.get();
 assert.equal(a.archive.digest,b.archive.digest);assert.deepEqual(a.archive.bytes,b.archive.bytes);
 assert.equal(a.result.verified,true);assert.equal(a.result.fileCount,5);assert.equal(a.result.classification,'EXTERNALLY_PINNED_TRANSPORT_ONLY');
 assert.equal(a.result.underlyingSignaturesVerified,false);assert.equal(a.result.productionApproved,false);assert.equal(a.result.mayRetry,false);assert.equal(a.result.mayManufacture,false);
 assert.deepEqual(a.result.manifest,f.values['manifest.json']);assert.equal(a.result.sessionEvents.length,3);
});
test('31R caller path ordering cannot affect canonical output',async t=>{const f=await fixture(t),a=await f.create(),b=await f.create({relativePaths:[...paths].reverse()});assert.deepEqual(a.bytes,b.bytes);});
test('31R rejects missing independent pin',async t=>{const f=await fixture(t),a=await f.create();failSync(()=>verifyOfflineAcquisitionEvidenceExport({bytes:a.bytes,expectedAcquisitionId:id}),'ACQUISITION_EXPORT_EXTERNAL_PIN_REQUIRED');});
test('31R rejects wrong independent pin',async t=>{const f=await fixture(t),a=await f.create();failSync(()=>verifyOfflineAcquisitionEvidenceExport({bytes:a.bytes,expectedAcquisitionId:id,expectedDigest:'a'.repeat(64)}),'ACQUISITION_EXPORT_PIN_MISMATCH');});
test('31R rejects wrong acquisition identity even with correct digest',async t=>{const f=await fixture(t),a=await f.create();failSync(()=>verifyOfflineAcquisitionEvidenceExport({bytes:a.bytes,expectedAcquisitionId:'different_acquisition_31r',expectedDigest:a.digest}),'ACQUISITION_EXPORT_HEADER_INVALID');});
test('31R rejects replayed previous export against new independently pinned digest',async t=>{const f=await fixture(t),a=await f.create();await writeFile(join(f.root,'evidence/branch_01.json'),JSON.stringify({epoch:2}),{mode:0o600});const b=await f.create();assert.notEqual(a.digest,b.digest);failSync(()=>verifyOfflineAcquisitionEvidenceExport({bytes:a.bytes,expectedDigest:b.digest,expectedAcquisitionId:id}),'ACQUISITION_EXPORT_PIN_MISMATCH');});
test('31R rejects truncated container at every boundary',async t=>{const f=await fixture(t),a=await f.create();for(const n of [0,1,20,100,a.bytes.length-1])failSync(()=>verifyOfflineAcquisitionEvidenceExport({bytes:a.bytes.subarray(0,n),expectedDigest:a.digest,expectedAcquisitionId:id}),n<45?'ACQUISITION_EXPORT_FORMAT_INVALID':'ACQUISITION_EXPORT_PIN_MISMATCH');});
test('31R rejects appended data',async t=>{const f=await fixture(t),a=await f.create();failSync(()=>verifyOfflineAcquisitionEvidenceExport({bytes:Buffer.concat([a.bytes,Buffer.from('extra')]),expectedDigest:a.digest,expectedAcquisitionId:id}),'ACQUISITION_EXPORT_PIN_MISMATCH');});
test('31R rejects payload bitflip',async t=>{const f=await fixture(t),a=await f.create();const b=Buffer.from(a.bytes);b[b.length-1]^=1;failSync(()=>verifyOfflineAcquisitionEvidenceExport({bytes:b,expectedDigest:a.digest,expectedAcquisitionId:id}),'ACQUISITION_EXPORT_PIN_MISMATCH');});
test('31R rejects forged internal manifest offset even with attacker-computed outer digest',async t=>{const f=await fixture(t),a=await f.create(),{header,payload}=unpack(a.bytes);header.files[1].offset++;const bytes=pack(header,payload);failSync(()=>verifyOfflineAcquisitionEvidenceExport({bytes,expectedDigest:hash(bytes),expectedAcquisitionId:id}),'ACQUISITION_EXPORT_ENTRY_INVALID');});
test('31R rejects forged internal payload digest even with attacker-computed outer digest',async t=>{const f=await fixture(t),a=await f.create(),{header,payload}=unpack(a.bytes);header.payloadDigest='b'.repeat(64);const bytes=pack(header,payload);failSync(()=>verifyOfflineAcquisitionEvidenceExport({bytes,expectedDigest:hash(bytes),expectedAcquisitionId:id}),'ACQUISITION_EXPORT_TRUNCATED_OR_TAMPERED');});
test('31R rejects reordered manifest file table even with new outer pin',async t=>{const f=await fixture(t),a=await f.create(),{header,payload}=unpack(a.bytes);[header.files[0],header.files[1]]=[header.files[1],header.files[0]];const bytes=pack(header,payload);failSync(()=>verifyOfflineAcquisitionEvidenceExport({bytes,expectedDigest:hash(bytes),expectedAcquisitionId:id}),'ACQUISITION_EXPORT_ENUMERATION_INVALID');});
test('31R rejects duplicate manifest paths',async t=>{const f=await fixture(t),a=await f.create(),{header,payload}=unpack(a.bytes);header.files[1].path=header.files[0].path;const bytes=pack(header,payload);failSync(()=>verifyOfflineAcquisitionEvidenceExport({bytes,expectedDigest:hash(bytes),expectedAcquisitionId:id}),'ACQUISITION_EXPORT_ENUMERATION_INVALID');});
test('31R rejects extra unenumerated payload',async t=>{const f=await fixture(t),a=await f.create(),{header,payload}=unpack(a.bytes);const bytes=pack(header,Buffer.concat([payload,Buffer.from('x')]));failSync(()=>verifyOfflineAcquisitionEvidenceExport({bytes,expectedDigest:hash(bytes),expectedAcquisitionId:id}),'ACQUISITION_EXPORT_TRUNCATED_OR_TAMPERED');});
test('31R rejects missing required session file',async t=>{const f=await fixture(t);await fail(()=>f.create({relativePaths:paths.filter(p=>p!=='session/0002.json')}),'ACQUISITION_EXPORT_ENUMERATION_INVALID');});
test('31R rejects traversal and backslash paths',async t=>{const f=await fixture(t);for(const p of ['../manifest.json','session/../manifest.json','session\\0001.json','/etc/passwd','evidence/%2e%2e.json'])await fail(()=>f.create({relativePaths:[...paths,p]}),'ACQUISITION_EXPORT_PATH_INVALID');});
test('31R rejects duplicate and case-folding variants',async t=>{const f=await fixture(t);await fail(()=>f.create({relativePaths:[...paths,'manifest.json']}),'ACQUISITION_EXPORT_ENUMERATION_INVALID');await fail(()=>f.create({relativePaths:[...paths,'evidence/BRANCH_01.json']}),'ACQUISITION_EXPORT_PATH_INVALID');});
test('31R rejects arbitrary file extensions and unsupported nested trees',async t=>{const f=await fixture(t);for(const p of ['evidence/private.key','evidence/a/b.json','session/0004.json','evidence/.json'])await fail(()=>f.create({relativePaths:[...paths,p]}),'ACQUISITION_EXPORT_PATH_INVALID');});
test('31R rejects unsafe root permissions',async t=>{const f=await fixture(t);await chmod(f.root,0o755);await fail(()=>f.create(),'ACQUISITION_EXPORT_DIRECTORY_UNSAFE');});
test('31R rejects symlinked root',async t=>{const f=await fixture(t),alias=f.root+'-alias';await symlink(f.root,alias);t.after(()=>rm(alias,{force:true}));await fail(()=>f.create({rootDirectory:alias}),'ACQUISITION_EXPORT_DIRECTORY_UNSAFE');});
test('31R rejects symlinked evidence directory',async t=>{const f=await fixture(t);await rename(join(f.root,'evidence'),f.root+'-evidence');t.after(()=>rm(f.root+'-evidence',{recursive:true,force:true}));await symlink(f.root+'-evidence',join(f.root,'evidence'));await fail(()=>f.create(),'ACQUISITION_EXPORT_DIRECTORY_UNSAFE');});
test('31R rejects symlinked source file',async t=>{const f=await fixture(t);await rename(join(f.root,'manifest.json'),f.root+'-manifest.json');t.after(()=>rm(f.root+'-manifest.json',{force:true}));await symlink(f.root+'-manifest.json',join(f.root,'manifest.json'));await fail(()=>f.create(),'ACQUISITION_EXPORT_FILE_UNSAFE');});
test('31R rejects hardlinked source file',async t=>{const f=await fixture(t);await link(join(f.root,'manifest.json'),f.root+'-hardlink');t.after(()=>rm(f.root+'-hardlink',{force:true}));await fail(()=>f.create(),'ACQUISITION_EXPORT_FILE_UNSAFE');});
test('31R rejects group-readable evidence',async t=>{const f=await fixture(t);await chmod(join(f.root,'manifest.json'),0o640);await fail(()=>f.create(),'ACQUISITION_EXPORT_FILE_UNSAFE');});
test('31R rejects oversized individual evidence file',async t=>{const f=await fixture(t);await writeFile(join(f.root,'evidence/branch_01.json'),Buffer.alloc(12*1024*1024+1,65),{mode:0o600});await fail(()=>f.create(),'ACQUISITION_EXPORT_FILE_UNSAFE');});
test('31R rejects malformed JSON evidence',async t=>{const f=await fixture(t);await writeFile(join(f.root,'evidence/branch_01.json'),'{bad',{mode:0o600});await fail(()=>f.create(),'ACQUISITION_EXPORT_JSON_INVALID');});
test('31R rejects noncanonical whitespace in evidence',async t=>{const f=await fixture(t);await writeFile(join(f.root,'evidence/branch_01.json'),'{"epoch": 1}',{mode:0o600});await fail(()=>f.create(),'ACQUISITION_EXPORT_JSON_INVALID');});
test('31R rejects invalid UTF-8 evidence',async t=>{const f=await fixture(t);await writeFile(join(f.root,'evidence/branch_01.json'),Buffer.from([0x7b,0x22,0xff,0x22,0x3a,0x31,0x7d]),{mode:0o600});await fail(()=>f.create(),'ACQUISITION_EXPORT_JSON_INVALID');});
test('31R rejects forged acquisition manifest binding',async t=>{const f=await fixture(t);const m={...f.values['manifest.json'],acquisitionId:'forged_acquisition_31r'};await writeFile(join(f.root,'manifest.json'),JSON.stringify(m),{mode:0o600});await fail(()=>f.create(),'ACQUISITION_EXPORT_MANIFEST_INVALID');});
test('31R rejects modified session digest',async t=>{const f=await fixture(t),p=join(f.root,'session/0002.json'),e=JSON.parse(await readFile(p));e.digest='b'.repeat(64);await writeFile(p,JSON.stringify(e));await fail(()=>f.create(),'ACQUISITION_EXPORT_SESSION_INVALID');});
test('31R rejects modified session PRE binding',async t=>{const f=await fixture(t),p=join(f.root,'manifest.json'),m=JSON.parse(await readFile(p));m.receiptHistory[0].phase='POST';await writeFile(p,JSON.stringify(m));await fail(()=>f.create(),'ACQUISITION_EXPORT_BINDING_INVALID');});
test('31R rejects concurrent file mutation between collection passes',async t=>{const f=await fixture(t);await fail(()=>f.create({injectFault:async stage=>{assert.equal(stage,'after-first-pass');await writeFile(join(f.root,'evidence/branch_01.json'),JSON.stringify({epoch:2}));}}),'ACQUISITION_EXPORT_FILE_CHANGED');});
test('31R rejects concurrent root replacement between collection passes',async t=>{const f=await fixture(t);await fail(()=>f.create({injectFault:async()=>{await rename(f.root,f.root+'-old');await mkdir(f.root,{mode:0o700});t.after(()=>rm(f.root+'-old',{recursive:true,force:true}));}}),'ACQUISITION_EXPORT_DIRECTORY_CHANGED');});
test('31R rejects injected unknown header fields',async t=>{const f=await fixture(t),a=await f.create(),{header,payload}=unpack(a.bytes);header.productionApproved=true;const bytes=pack(header,payload);failSync(()=>verifyOfflineAcquisitionEvidenceExport({bytes,expectedDigest:hash(bytes),expectedAcquisitionId:id}),'ACQUISITION_EXPORT_HEADER_INVALID');});
test('31R rejects zero-length/invalid header length',async t=>{const f=await fixture(t),a=await f.create(),bytes=Buffer.from(a.bytes),off=Buffer.byteLength(`${OFFLINE_ACQUISITION_EXPORT_SCHEMA}\n`);bytes.writeUInt32BE(0,off);failSync(()=>verifyOfflineAcquisitionEvidenceExport({bytes,expectedDigest:hash(bytes),expectedAcquisitionId:id}),'ACQUISITION_EXPORT_FORMAT_INVALID');});
test('31R rejects noncanonical serialized header',async t=>{const f=await fixture(t),a=await f.create(),{header,payload}=unpack(a.bytes),h=Buffer.from(JSON.stringify(header,null,2)),len=Buffer.alloc(4);len.writeUInt32BE(h.length);const bytes=Buffer.concat([Buffer.from(`${OFFLINE_ACQUISITION_EXPORT_SCHEMA}\n`),len,h,payload]);failSync(()=>verifyOfflineAcquisitionEvidenceExport({bytes,expectedDigest:hash(bytes),expectedAcquisitionId:id}),'ACQUISITION_EXPORT_JSON_INVALID');});

test('31R rejects extra unenumerated evidence file',async t=>{const f=await fixture(t);await writeFile(join(f.root,'evidence/hidden.json'),'{}',{mode:0o600});await fail(()=>f.create(),'ACQUISITION_EXPORT_ENUMERATION_INVALID');});
test('31R rejects unenumerated journal file and pending commit',async t=>{const f=await fixture(t);await writeFile(join(f.root,'session/0004.json'),'{}',{mode:0o600});await fail(()=>f.create(),'ACQUISITION_EXPORT_ENUMERATION_INVALID');await rm(join(f.root,'session/0004.json'));await writeFile(join(f.root,'session/.pending.json'),'{}',{mode:0o600});await fail(()=>f.create(),'ACQUISITION_EXPORT_ENUMERATION_INVALID');});
test('31R rejects unenumerated root files',async t=>{const f=await fixture(t);await writeFile(join(f.root,'secret.txt'),'secret',{mode:0o600});await fail(()=>f.create(),'ACQUISITION_EXPORT_ENUMERATION_INVALID');});
test('31R rejects evidence inserted between collection passes',async t=>{const f=await fixture(t);await fail(()=>f.create({injectFault:async()=>writeFile(join(f.root,'evidence/injected.json'),'{}',{mode:0o600})}),'ACQUISITION_EXPORT_ENUMERATION_INVALID');});
test('31R permits only safe known journal lock as non-evidence',async t=>{const f=await fixture(t);await writeFile(join(f.root,'session/.session-lock'),'',{mode:0o600});assert.equal((await f.get()).result.verified,true);await chmod(join(f.root,'session/.session-lock'),0o644);await fail(()=>f.create(),'ACQUISITION_EXPORT_FILE_UNSAFE');});
