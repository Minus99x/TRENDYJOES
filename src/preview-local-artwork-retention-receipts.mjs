/** Objective 35AM: offline-only, portable Ed25519 retention receipts.
 * All verifier pins are supplied by a separately trusted caller. A transport
 * is never permitted to choose its own head, anchor, signer, or clock.
 * No Shopify operations, custody, trusted clock, or production authorization.
 */
import {createHash,sign,verify,timingSafeEqual} from 'node:crypto';

export const OFFLINE_RETENTION_RECEIPT_SCHEMA='TJ-LOCAL-RETENTION-RECEIPT-35AM-1';
export const OFFLINE_RETENTION_PRUNE_SCHEMA='TJ-LOCAL-RETENTION-PRUNE-35AM-1';
export const OFFLINE_RETENTION_ENVELOPE_SCHEMA='TJ-LOCAL-RETENTION-ENVELOPE-35AM-1';
export const OFFLINE_RETENTION_ZERO_SHA256='0'.repeat(64);
const HEX=/^[0-9a-f]{64}$/;
const BASE64=/^[A-Za-z0-9_-]+$/;
const DAY=86_400_000;
const MAX_RECEIPTS=128;
const MAX_ENVELOPE=4096;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hex=x=>typeof x==='string'&&HEX.test(x);
const integer=x=>Number.isSafeInteger(x)&&x>=0;
const clock=x=>integer(x)&&x<1e15;
const hash=x=>createHash('sha256').update(x).digest('hex');
const equal=(a,b)=>hex(a)&&hex(b)&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
const plain=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 (Object.getPrototypeOf(o)===Object.prototype||Object.getPrototypeOf(o)===null)&&
 Reflect.ownKeys(o).length===keys.length&&keys.every(k=>{
  const d=Object.getOwnPropertyDescriptor(o,k);return d?.enumerable&&'value'in d;
 });
const dense=(a,min=1,max=MAX_RECEIPTS)=>Array.isArray(a)&&a.length>=min&&a.length<=max&&
 Reflect.ownKeys(a).length===a.length+1;
const CHECKPOINT=['epoch','provenanceSha256','evidenceSha256','headSha256'];
const RECEIPT=['schema','streamId','sequence','observedAtMs','retainUntilMs','checkpoint','previousReceiptSha256','authority'];
const PRUNE=['schema','streamId','anchorSequence','anchorReceiptSha256','anchorRetainUntilMs','pruneAtMs','firstRetainedSequence','authority'];
const ENVELOPE=['schema','body','signerFingerprint','signature'];
const HEAD=['sequence','receiptSha256'];
const ANCHOR=['sequence','receiptSha256','observedAtMs','retainUntilMs'];
const PIN=['checkpoint','observedAtMs','retainUntilMs'];
const EXTERNAL=['mode','streamId','signerFingerprint','trustedNowMs','expectedHead','expectedAnchor','expectedCheckpoints'];
const VALID_MODES=['genesis','append','pruned'];
function checkpointOk(c){return plain(c,CHECKPOINT)&&integer(c.epoch)&&
 [c.provenanceSha256,c.evidenceSha256,c.headSha256].every(hex);}
function receiptOk(p){return plain(p,RECEIPT)&&p.schema===OFFLINE_RETENTION_RECEIPT_SCHEMA&&
 hex(p.streamId)&&integer(p.sequence)&&clock(p.observedAtMs)&&clock(p.retainUntilMs)&&
 p.retainUntilMs>p.observedAtMs&&p.retainUntilMs-p.observedAtMs<=365*DAY&&
 checkpointOk(p.checkpoint)&&hex(p.previousReceiptSha256)&&p.authority==='NONE';}
function pruneOk(p){return plain(p,PRUNE)&&p.schema===OFFLINE_RETENTION_PRUNE_SCHEMA&&
 hex(p.streamId)&&integer(p.anchorSequence)&&hex(p.anchorReceiptSha256)&&
 clock(p.anchorRetainUntilMs)&&clock(p.pruneAtMs)&&p.pruneAtMs>p.anchorRetainUntilMs&&
 p.firstRetainedSequence===p.anchorSequence+1&&p.authority==='NONE';}
function keyFingerprint(publicKey){
 if(publicKey?.type!=='public'||publicKey.asymmetricKeyType!=='ed25519')
  fail('OFFLINE_RETENTION_INVALID_KEY');
 return hash(publicKey.export({type:'spki',format:'der'}));
}
function signingKeyOk(key){return key?.type==='private'&&key.asymmetricKeyType==='ed25519';}
function canonicalEnvelope(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<80||bytes.length>MAX_ENVELOPE)
  fail('OFFLINE_RETENTION_INVALID_ENVELOPE');
 let obj;try{obj=JSON.parse(bytes.toString('utf8'));}catch{fail('OFFLINE_RETENTION_INVALID_ENVELOPE');}
 if(!plain(obj,ENVELOPE)||obj.schema!==OFFLINE_RETENTION_ENVELOPE_SCHEMA||
  !hex(obj.signerFingerprint)||typeof obj.body!=='string'||!BASE64.test(obj.body)||
  typeof obj.signature!=='string'||!BASE64.test(obj.signature)||
  !Buffer.from(JSON.stringify({schema:obj.schema,body:obj.body,
   signerFingerprint:obj.signerFingerprint,signature:obj.signature})).equals(bytes))
  fail('OFFLINE_RETENTION_INVALID_ENVELOPE');
 const body=Buffer.from(obj.body,'base64url');
 const signature=Buffer.from(obj.signature,'base64url');
 if(body.toString('base64url')!==obj.body||signature.toString('base64url')!==obj.signature||
  signature.length!==64||body.length<80||body.length>2500)
  fail('OFFLINE_RETENTION_INVALID_ENVELOPE');
 let payload;try{payload=JSON.parse(body.toString('utf8'));}catch{fail('OFFLINE_RETENTION_INVALID_BODY');}
 if(!Buffer.from(JSON.stringify(payload)).equals(body))fail('OFFLINE_RETENTION_INVALID_BODY');
 return {obj,body,signature,payload};
}
function canonicalPayload(payload,schema){
 if(schema===OFFLINE_RETENTION_RECEIPT_SCHEMA){
  const c=payload.checkpoint;
  return {schema:payload.schema,streamId:payload.streamId,sequence:payload.sequence,
   observedAtMs:payload.observedAtMs,retainUntilMs:payload.retainUntilMs,
   checkpoint:{epoch:c.epoch,provenanceSha256:c.provenanceSha256,
    evidenceSha256:c.evidenceSha256,headSha256:c.headSha256},
   previousReceiptSha256:payload.previousReceiptSha256,authority:payload.authority};
 }
 return {schema:payload.schema,streamId:payload.streamId,anchorSequence:payload.anchorSequence,
  anchorReceiptSha256:payload.anchorReceiptSha256,anchorRetainUntilMs:payload.anchorRetainUntilMs,
  pruneAtMs:payload.pruneAtMs,firstRetainedSequence:payload.firstRetainedSequence,
  authority:payload.authority};
}
function domain(schema){return Buffer.from(schema===OFFLINE_RETENTION_RECEIPT_SCHEMA?
 'TJ35AM_RECEIPT\0':'TJ35AM_PRUNE\0','utf8');}
function issue(payload,signingKey,publicKey,schema){
 if(!signingKeyOk(signingKey))fail('OFFLINE_RETENTION_INVALID_KEY');
 const fingerprint=keyFingerprint(publicKey);
 if(!verify(null,Buffer.from('35AM-key-check'),publicKey,
  sign(null,Buffer.from('35AM-key-check'),signingKey)))fail('OFFLINE_RETENTION_KEY_MISMATCH');
 const body=Buffer.from(JSON.stringify(canonicalPayload(payload,schema)));
 const signature=sign(null,Buffer.concat([domain(schema),body]),signingKey).toString('base64url');
 const bytes=Buffer.from(JSON.stringify({schema:OFFLINE_RETENTION_ENVELOPE_SCHEMA,
  body:body.toString('base64url'),signerFingerprint:fingerprint,signature}));
 if(bytes.length>MAX_ENVELOPE)fail('OFFLINE_RETENTION_INVALID_ENVELOPE');
 return Object.freeze({bytes,sha256:hash(bytes),signerFingerprint:fingerprint});
}
function readSigned(bytes,publicKey,expectedFingerprint,expectedSchema){
 const {obj,body,signature,payload}=canonicalEnvelope(bytes);
 if(!equal(keyFingerprint(publicKey),expectedFingerprint)||
  !equal(obj.signerFingerprint,expectedFingerprint))fail('OFFLINE_RETENTION_SIGNER_SUBSTITUTION');
 if(payload?.schema!==expectedSchema||
  !(expectedSchema===OFFLINE_RETENTION_RECEIPT_SCHEMA?receiptOk(payload):pruneOk(payload)))
  fail('OFFLINE_RETENTION_INVALID_BODY');
 if(!Buffer.from(JSON.stringify(canonicalPayload(payload,expectedSchema))).equals(body))
  fail('OFFLINE_RETENTION_INVALID_BODY');
 if(!verify(null,Buffer.concat([domain(expectedSchema),body]),publicKey,signature))
  fail('OFFLINE_RETENTION_INVALID_SIGNATURE');
 return {payload,sha256:hash(bytes)};
}
/** Fixture/service-side signing primitive. Do not place private keys in a browser. */
export function createOfflineRetentionReceipt({streamId,sequence,observedAtMs,retainUntilMs,
 checkpoint,previousReceiptSha256,signingKey,publicKey}={}){
 const payload={schema:OFFLINE_RETENTION_RECEIPT_SCHEMA,streamId,sequence,observedAtMs,
  retainUntilMs,checkpoint,previousReceiptSha256,authority:'NONE'};
 if(!receiptOk(payload))fail('OFFLINE_RETENTION_INVALID_BODY');
 return issue(payload,signingKey,publicKey,OFFLINE_RETENTION_RECEIPT_SCHEMA);
}
/** Signed pruning evidence. A certificate alone never proves external custody. */
export function createOfflineRetentionPruneCertificate({streamId,anchorSequence,
 anchorReceiptSha256,anchorRetainUntilMs,pruneAtMs,firstRetainedSequence,
 signingKey,publicKey}={}){
 const payload={schema:OFFLINE_RETENTION_PRUNE_SCHEMA,streamId,anchorSequence,
  anchorReceiptSha256,anchorRetainUntilMs,pruneAtMs,firstRetainedSequence,authority:'NONE'};
 if(!pruneOk(payload))fail('OFFLINE_RETENTION_INVALID_BODY');
 return issue(payload,signingKey,publicKey,OFFLINE_RETENTION_PRUNE_SCHEMA);
}
/** Verify a complete genesis window, an append-only extension, or an explicitly
 * pruned window. Every external pin MUST be independently retained. The caller
 * is responsible for protecting those pins and providing a trusted clock.
 */
export function verifyOfflineRetentionReceiptWindow({receiptBytes,externalPins,
 signerPublicKey,pruneCertificateBytes=null}={}){
 if(!dense(receiptBytes)||!plain(externalPins,EXTERNAL)||
  !VALID_MODES.includes(externalPins.mode)||!hex(externalPins.streamId)||
  !hex(externalPins.signerFingerprint)||!clock(externalPins.trustedNowMs)||
  !plain(externalPins.expectedHead,HEAD)||!integer(externalPins.expectedHead.sequence)||
  !hex(externalPins.expectedHead.receiptSha256)||
  !dense(externalPins.expectedCheckpoints)||
  externalPins.expectedCheckpoints.length!==receiptBytes.length)
  fail('OFFLINE_RETENTION_MISSING_EXTERNAL_PINS');
 const {mode,expectedAnchor,expectedHead,expectedCheckpoints,trustedNowMs}=externalPins;
 if(mode==='genesis'){
  if(expectedAnchor!==null||pruneCertificateBytes!==null||
   expectedHead.sequence!==receiptBytes.length-1)
   fail('OFFLINE_RETENTION_MISSING_EXTERNAL_PINS');
 }else if(!plain(expectedAnchor,ANCHOR)||!integer(expectedAnchor.sequence)||
  !hex(expectedAnchor.receiptSha256)||equal(expectedAnchor.receiptSha256,OFFLINE_RETENTION_ZERO_SHA256)||
  !clock(expectedAnchor.observedAtMs)||!clock(expectedAnchor.retainUntilMs)||
  expectedAnchor.retainUntilMs<=expectedAnchor.observedAtMs||
  expectedHead.sequence!==expectedAnchor.sequence+receiptBytes.length||
  (mode==='append'&&pruneCertificateBytes!==null)||
  (mode==='pruned'&&!Buffer.isBuffer(pruneCertificateBytes)))
  fail('OFFLINE_RETENTION_MISSING_EXTERNAL_PINS');
 let prior=mode==='genesis'?OFFLINE_RETENTION_ZERO_SHA256:expectedAnchor.receiptSha256;
 let lastObservedAt=-1;
 const firstSequence=mode==='genesis'?0:expectedAnchor.sequence+1;
 const checked=[];
 for(let i=0;i<receiptBytes.length;i++){
  const pin=expectedCheckpoints[i];
  if(!plain(pin,PIN)||!checkpointOk(pin.checkpoint)||!clock(pin.observedAtMs)||
   !clock(pin.retainUntilMs))fail('OFFLINE_RETENTION_MISSING_EXTERNAL_PINS');
  const {payload,sha256}=readSigned(receiptBytes[i],signerPublicKey,
   externalPins.signerFingerprint,OFFLINE_RETENTION_RECEIPT_SCHEMA);
  if(!equal(payload.streamId,externalPins.streamId)||
   payload.sequence!==firstSequence+i||!equal(payload.previousReceiptSha256,prior))
   fail('OFFLINE_RETENTION_CHAIN_BROKEN');
  if(!equal(payload.checkpoint.provenanceSha256,pin.checkpoint.provenanceSha256)||
   !equal(payload.checkpoint.evidenceSha256,pin.checkpoint.evidenceSha256)||
   !equal(payload.checkpoint.headSha256,pin.checkpoint.headSha256)||
   payload.checkpoint.epoch!==pin.checkpoint.epoch||
   payload.observedAtMs!==pin.observedAtMs||payload.retainUntilMs!==pin.retainUntilMs)
   fail('OFFLINE_RETENTION_CHECKPOINT_PIN_MISMATCH');
  if(payload.observedAtMs>trustedNowMs||payload.observedAtMs<=lastObservedAt||
   (i===0&&mode!=='genesis'&&payload.observedAtMs<=expectedAnchor.observedAtMs))
   fail('OFFLINE_RETENTION_TIME_REPLAY');
  if(payload.retainUntilMs<=trustedNowMs)fail('OFFLINE_RETENTION_WINDOW_EXPIRED');
  lastObservedAt=payload.observedAtMs;
  checked.push(Object.freeze({sequence:payload.sequence,receiptSha256:sha256,
   checkpointHeadSha256:payload.checkpoint.headSha256}));
  prior=sha256;
 }
 if(!equal(prior,expectedHead.receiptSha256))fail('OFFLINE_RETENTION_HEAD_MISMATCH');
 if(mode==='pruned'){
  const {payload}=readSigned(pruneCertificateBytes,signerPublicKey,
   externalPins.signerFingerprint,OFFLINE_RETENTION_PRUNE_SCHEMA);
  if(!equal(payload.streamId,externalPins.streamId)||
   payload.anchorSequence!==expectedAnchor.sequence||
   !equal(payload.anchorReceiptSha256,expectedAnchor.receiptSha256)||
   payload.anchorRetainUntilMs!==expectedAnchor.retainUntilMs||
   payload.firstRetainedSequence!==firstSequence)
   fail('OFFLINE_RETENTION_PRUNE_MISMATCH');
  if(payload.pruneAtMs>trustedNowMs||trustedNowMs<=expectedAnchor.retainUntilMs||
   false)
   fail('OFFLINE_RETENTION_PRUNE_TOO_EARLY');
 }else if(mode==='append'&&lastObservedAt<=0){
  fail('OFFLINE_RETENTION_TIME_REPLAY');
 }
 return Object.freeze({schema:OFFLINE_RETENTION_RECEIPT_SCHEMA,mode,
  verifiedCount:checked.length,firstSequence,lastSequence:expectedHead.sequence,
  headSha256:prior,verifiedReceipts:Object.freeze(checked),
  signaturesVerified:true,externallyPinnedHeadMatched:true,
  completeHistoryVerified:mode==='genesis',
  pruneCertificateVerified:mode==='pruned',prunedPrefixVerified:false,independentCustodyVerified:false,
  trustedClockIndependentlyVerified:false,authorizesProduction:false});
}
