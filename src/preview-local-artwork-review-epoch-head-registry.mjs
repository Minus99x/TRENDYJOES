/** Objective 35AI: local append-only epoch-head registry with independently
 * supplied pins. This is a single-host durability contract, NOT external
 * custody, trusted time, global consensus, or production authorization. */
import {createHash,timingSafeEqual} from 'node:crypto';
import {open,readFile,readdir,lstat,realpath} from 'node:fs/promises';
import {join,isAbsolute,resolve} from 'node:path';
import {verifyOfflineWitnessRosterEpochTransition} from './preview-local-artwork-review-witness-epoch.mjs';
export const OFFLINE_EPOCH_HEAD_SCHEMA='TJ-LOCAL-EPOCH-HEAD-35AI-1';
const HEX=/^[0-9a-f]{64}$/;
const ZERO='0'.repeat(64);
const MARKER='.tj-epoch-namespace.json';
const FIELDS=['schema','namespacePin','rootPin','registryId','epoch','rosterSha256','transitionSha256','previousRecordSha256','authority'];
const sha=b=>createHash('sha256').update(b).digest('hex');
const hex=x=>typeof x==='string'&&HEX.test(x);
const eq=(a,b)=>hex(a)&&hex(b)&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
const fail=code=>{throw Object.assign(new Error(code),{code});};
const safeInt=x=>Number.isSafeInteger(x)&&x>=0&&x<1e15;
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&d.enumerable&&'value'in d;});
const name=e=>`epoch-${String(e).padStart(15,'0')}.json`;
function record(body){
 if(!exact(body,FIELDS)||body.schema!==OFFLINE_EPOCH_HEAD_SCHEMA||body.authority!=='NONE'||
  !safeInt(body.epoch)||![body.namespacePin,body.rootPin,body.registryId,
   body.rosterSha256,body.transitionSha256,body.previousRecordSha256].every(hex))
  fail('OFFLINE_EPOCH_HEAD_INVALID_RECORD');
 return Buffer.from(JSON.stringify(body));
}
function parse(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<2||bytes.length>2048)fail('OFFLINE_EPOCH_HEAD_INVALID_RECORD');
 let body;try{body=JSON.parse(bytes.toString('utf8'));}catch{fail('OFFLINE_EPOCH_HEAD_INVALID_RECORD');}
 if(!Buffer.from(JSON.stringify(body)).equals(bytes)||!exact(body,FIELDS)||
  !Object.keys(body).every((k,i)=>k===FIELDS[i]))fail('OFFLINE_EPOCH_HEAD_NONCANONICAL');
 record(body);return body;
}
function pin(head){
 if(!exact(head,['epoch','rosterSha256','recordSha256'])||!safeInt(head.epoch)||
  !hex(head.rosterSha256)||!hex(head.recordSha256))fail('OFFLINE_EPOCH_HEAD_MISSING_EXTERNAL_PIN');
 return Object.freeze({...head});
}
async function dirCheck(directory){
 if(typeof directory!=='string'||!isAbsolute(directory)||resolve(directory)!==directory)
  fail('OFFLINE_EPOCH_HEAD_UNSAFE_DIRECTORY');
 let st,real;try{st=await lstat(directory);real=await realpath(directory);}catch{fail('OFFLINE_EPOCH_HEAD_UNAVAILABLE');}
 if(!st.isDirectory()||st.isSymbolicLink()||real!==directory||(st.mode&0o077)!==0||
  (typeof process.getuid==='function'&&st.uid!==process.getuid()))
  fail('OFFLINE_EPOCH_HEAD_UNSAFE_DIRECTORY');
}
async function syncDir(directory){
 let h;try{h=await open(directory,'r');await h.sync();}
 catch{fail('OFFLINE_EPOCH_HEAD_DURABILITY_UNCERTAIN');}
 finally{await h?.close().catch(()=>{});}
}
async function readSecure(directory,filename){
 const p=join(directory,filename);let st,b;
 try{st=await lstat(p);b=await readFile(p);}catch{fail('OFFLINE_EPOCH_HEAD_MISSING_RECORD');}
 if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||(st.mode&0o077)!==0||
  (typeof process.getuid==='function'&&st.uid!==process.getuid())||b.length>2048)
  fail('OFFLINE_EPOCH_HEAD_UNSAFE_RECORD');
 return b;
}
async function writeOnce(directory,filename,bytes){
 let h;try{h=await open(join(directory,filename),'wx',0o600);}
 catch(e){if(e?.code==='EEXIST')fail('OFFLINE_EPOCH_HEAD_CONFLICT');fail('OFFLINE_EPOCH_HEAD_WRITE_UNCERTAIN');}
 try{await h.writeFile(bytes);await h.sync();}
 catch{fail('OFFLINE_EPOCH_HEAD_WRITE_UNCERTAIN');}
 finally{await h.close().catch(()=>{});}
 await syncDir(directory);
}
const markerBytes=namespacePin=>Buffer.from(JSON.stringify({schema:OFFLINE_EPOCH_HEAD_SCHEMA,namespacePin}));
/** Creates a genesis record from externally supplied values; digest returned
 * here MUST be pinned independently before any later open/advance. */
export function createOfflineEpochGenesis({namespacePin,rootPin,registryId,epoch,rosterSha256}={}){
 const bytes=record({schema:OFFLINE_EPOCH_HEAD_SCHEMA,namespacePin,rootPin,registryId,
  epoch,rosterSha256,transitionSha256:ZERO,previousRecordSha256:ZERO,authority:'NONE'});
 return Object.freeze({bytes,head:pin({epoch,rosterSha256,recordSha256:sha(bytes)}),authorizesProduction:false});
}
/** Dedicated empty directory only; interrupted initialization is NOT repaired. */
export async function initializeOfflineEpochHeadRegistry({directory,namespacePin,genesisBytes,
 expectedGenesisSha256}={}){
 await dirCheck(directory);
 if(!hex(namespacePin)||!hex(expectedGenesisSha256)||!Buffer.isBuffer(genesisBytes))
  fail('OFFLINE_EPOCH_HEAD_MISSING_EXTERNAL_PIN');
 const genesis=Buffer.from(genesisBytes),body=parse(genesis);
 if(!eq(body.namespacePin,namespacePin)||!eq(sha(genesis),expectedGenesisSha256)||
  body.transitionSha256!==ZERO||body.previousRecordSha256!==ZERO)
  fail('OFFLINE_EPOCH_HEAD_GENESIS_MISMATCH');
 if((await readdir(directory)).length!==0)fail('OFFLINE_EPOCH_HEAD_NOT_EMPTY');
 await writeOnce(directory,MARKER,markerBytes(namespacePin));
 await writeOnce(directory,name(body.epoch),genesis);
 return Object.freeze({initialized:true,independentCustodyVerified:false,authorizesProduction:false});
}
async function inspect(directory,namespacePin,expectedHead,expectedGenesisSha256){
 await dirCheck(directory);
 if(!hex(namespacePin)||!hex(expectedGenesisSha256))fail('OFFLINE_EPOCH_HEAD_MISSING_EXTERNAL_PIN');
 const expected=pin(expectedHead);
 if(!(await readSecure(directory,MARKER)).equals(markerBytes(namespacePin)))
  fail('OFFLINE_EPOCH_HEAD_NAMESPACE_MISMATCH');
 const entries=await readdir(directory);
 if(entries.some(x=>x!==MARKER&&!/^epoch-[0-9]{15}\.json$/.test(x)))
  fail('OFFLINE_EPOCH_HEAD_UNEXPECTED_ENTRY');
 const epochs=entries.filter(x=>x!==MARKER).map(x=>Number(x.slice(6,21))).sort((a,b)=>a-b);
 if(!epochs.length||epochs[0]<0)fail('OFFLINE_EPOCH_HEAD_MISSING_RECORD');
 let prior,latest;
 for(let i=0;i<epochs.length;i++){
  const e=epochs[i];if(i&&e!==epochs[i-1]+1)fail('OFFLINE_EPOCH_HEAD_GAP');
  const bytes=await readSecure(directory,name(e)),body=parse(bytes);
  if(body.epoch!==e||!eq(body.namespacePin,namespacePin))fail('OFFLINE_EPOCH_HEAD_INVALID_RECORD');
  if(i){if(!eq(body.previousRecordSha256,sha(prior.bytes))||
    !eq(body.rootPin,prior.body.rootPin)||!eq(body.registryId,prior.body.registryId)||
    eq(body.rosterSha256,prior.body.rosterSha256)||body.transitionSha256===ZERO)
    fail('OFFLINE_EPOCH_HEAD_CHAIN_MISMATCH');}
  else if(body.previousRecordSha256!==ZERO||body.transitionSha256!==ZERO||
    !eq(sha(bytes),expectedGenesisSha256))fail('OFFLINE_EPOCH_HEAD_GENESIS_MISMATCH');
  prior={body,bytes};latest=prior;
 }
 if(latest.body.epoch!==expected.epoch||!eq(latest.body.rosterSha256,expected.rosterSha256)||
  !eq(sha(latest.bytes),expected.recordSha256))fail('OFFLINE_EPOCH_HEAD_PIN_MISMATCH');
 return Object.freeze({epoch:latest.body.epoch,rosterSha256:latest.body.rosterSha256,
  recordSha256:sha(latest.bytes),rootPin:latest.body.rootPin,registryId:latest.body.registryId,
  independentCustodyVerified:false,authorizesProduction:false});
}
export async function readOfflinePinnedEpochHead({directory,namespacePin,expectedHead,expectedGenesisSha256}={}){
 return inspect(directory,namespacePin,expectedHead,expectedGenesisSha256);
}
/** Caller pins the *current* head outside the directory and separately pins
 * the transition signature/issuer. No implicit trust in local latest state. */
export async function advanceOfflinePinnedEpochHead({directory,namespacePin,expectedHead,expectedGenesisSha256,
 transitionVerification}={}){
 const previous=await inspect(directory,namespacePin,expectedHead,expectedGenesisSha256);
 if(!transitionVerification||typeof transitionVerification!=='object'||Array.isArray(transitionVerification))
  fail('OFFLINE_EPOCH_HEAD_MISSING_TRANSITION');
 const verified=verifyOfflineWitnessRosterEpochTransition({...transitionVerification,
  expectedPreviousEpoch:previous.epoch,expectedNextEpoch:previous.epoch+1,
  expectedPreviousRosterSha256:previous.rosterSha256,expectedRootPin:previous.rootPin,
  expectedRegistryId:previous.registryId});
 const bytes=record({schema:OFFLINE_EPOCH_HEAD_SCHEMA,namespacePin,rootPin:previous.rootPin,
  registryId:previous.registryId,epoch:verified.epoch,rosterSha256:verified.rosterSha256,
  transitionSha256:verified.transitionSha256,previousRecordSha256:previous.recordSha256,
  authority:'NONE'});
 await writeOnce(directory,name(verified.epoch),bytes);
 const next=pin({epoch:verified.epoch,rosterSha256:verified.rosterSha256,recordSha256:sha(bytes)});
 await inspect(directory,namespacePin,next,expectedGenesisSha256);
 return Object.freeze({...next,independentCustodyVerified:false,authorizesProduction:false});
}
/** Same-epoch differing independent pins prove split-view; different epochs
 * cannot prove continuity without independently retained chain evidence. */
export function compareOfflineEpochHeadPins(left,right){
 const a=pin(left),b=pin(right);
 if(a.epoch===b.epoch&&(!eq(a.recordSha256,b.recordSha256)||!eq(a.rosterSha256,b.rosterSha256)))
  fail('OFFLINE_EPOCH_HEAD_SPLIT_VIEW');
 return Object.freeze({sameHead:a.epoch===b.epoch,continuityVerified:false,
  independentCustodyVerified:false,authorizesProduction:false});
}
