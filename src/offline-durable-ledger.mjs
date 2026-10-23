/** Offline-only crash-conscious filesystem fixture for atomic revision CAS and replay.
 * NOT a hosted datastore: no multi-host guarantees, lease recovery, encryption, or checkout.
 * All writes occur inside a caller-selected LOCAL scratch directory. Never Shopify.
 */
import {mkdir,open,rename,rm,rmdir,lstat} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {constants as fsConstants} from 'node:fs';
import {join,resolve} from 'node:path';
import {randomBytes,createHmac,createHash,timingSafeEqual,verify as verifySignature} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';

const fail=code=>{throw Object.assign(new Error(code),{code});};
const shopRe=/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/;
const gidRe=kind=>new RegExp(`^gid://shopify/${kind}/[1-9][0-9]*$`);
const hex=/^[a-f0-9]{64}$/;
const refRe=/^TJ-[A-F0-9]{24}$/;
const uuidRe=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const obj=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const fields=['shop','ownerSubject','reference','revision','productGid','variantGid','compositionSha256','status'];
const matchFields=['reference','revision','productGid','variantGid','compositionSha256'];
const same=(a,b,keys)=>keys.every(k=>a[k]===b[k]);
const key=(shop,reference)=>`${shop}|${reference}`;
const orderKey=(shop,orderGid)=>`${shop}|${orderGid}`;
const maxStateBytes=2*1024*1024;
const auditHex=/^[a-f0-9]{64}$/;
const auditId=/^[A-Za-z0-9_-]{1,64}$/;
const auditZero='0'.repeat(64);
const auditKeys=['schema','sequence','previousMac','keyId','mac'];
const recoverySchema='TJ-OFFLINE-LEDGER-RECOVERY-1';
const recoveryPayloadKeys=['schema','ledgerId','authorizationId','issuedAt','expiresAt',
 'expectedAnchor','targetAnchor','reason'];
const recoveryId=/^[A-Za-z0-9_-]{12,80}$/;
function recoveryConfiguration(input){
 if(input===undefined)return null;
 if(!obj(input)||!recoveryId.test(input.ledgerId||'')||
  input.publicKey?.type!=='public'||input.publicKey?.asymmetricKeyType!=='ed25519')
  fail('LEDGER_AUDIT_RECOVERY_CONFIGURATION');
 return {ledgerId:input.ledgerId,publicKey:input.publicKey};
}
function validateRecoveryAuthorization(input,cfg,now){
 if(!obj(input)||Object.keys(input).length!==recoveryPayloadKeys.length+1||
  !recoveryPayloadKeys.every(k=>Object.hasOwn(input,k))||
  input.schema!==recoverySchema||input.ledgerId!==cfg.ledgerId||
  !uuidRe.test(input.authorizationId||'')||
  input.authorizationId!==input.authorizationId.toLowerCase()||
  !Number.isSafeInteger(input.issuedAt)||!Number.isSafeInteger(input.expiresAt)||
  input.issuedAt>now||input.expiresAt<=now||input.expiresAt<=input.issuedAt||
  input.expiresAt-input.issuedAt>15*60_000||
  typeof input.reason!=='string'||input.reason.length<8||input.reason.length>200||
  input.reason!==input.reason.trim()||/[\x00-\x1f\x7f]/.test(input.reason)||
  !Object.hasOwn(input,'signature')||typeof input.signature!=='string'||
  !/^[A-Za-z0-9_-]{86}$/.test(input.signature))fail('LEDGER_AUDIT_RECOVERY_AUTH_INVALID');
 if(input.expectedAnchor!==null)checkAnchor(input.expectedAnchor);
 checkAnchor(input.targetAnchor);
 const payload=Object.fromEntries(recoveryPayloadKeys.map(k=>[k,input[k]]));
 const bytes=Buffer.from(input.signature,'base64url');
 if(bytes.length!==64||bytes.toString('base64url')!==input.signature||
  !verifySignature(null,Buffer.from(`${recoverySchema}\0${JSON.stringify(payload)}`),cfg.publicKey,bytes))
  fail('LEDGER_AUDIT_RECOVERY_SIGNATURE');
 return payload;
}
function auditConfiguration(input){
 if(input===undefined)return null;
 if(!obj(input)||!Array.isArray(input.keys)||input.keys.length<1||input.keys.length>8||
  !auditId.test(input.activeKeyId||'')||typeof input.readAnchor!=='function'||
  typeof input.compareAndSetAnchor!=='function')fail('LEDGER_AUDIT_CONFIGURATION');
 const keys=new Map();
 for(const item of input.keys){
  if(!obj(item)||!auditId.test(item.id||'')||!Buffer.isBuffer(item.secret)||
   item.secret.length<32||keys.has(item.id))fail('LEDGER_AUDIT_CONFIGURATION');
  keys.set(item.id,Buffer.from(item.secret));
 }
 if(!keys.has(input.activeKeyId))fail('LEDGER_AUDIT_CONFIGURATION');
 return {keys,activeKeyId:input.activeKeyId,readAnchor:input.readAnchor,
  compareAndSetAnchor:input.compareAndSetAnchor,recovery:recoveryConfiguration(input.recovery)};
}
function checkAnchor(a){
 if(a===null)return null;
 if(!obj(a)||Object.keys(a).length!==2||!Number.isSafeInteger(a.sequence)||
  a.sequence<1||!auditHex.test(a.mac||''))fail('LEDGER_AUDIT_ANCHOR_INVALID');
 return a;
}
function auditMac(key,keyId,sequence,previousMac,state){
 const content={...state};delete content.audit;
 const digest=createHash('sha256').update(JSON.stringify(content)).digest('hex');
 return createHmac('sha256',key).update(`TJ-OFFLINE-LEDGER-AUDIT-1\0${keyId}\0${sequence}\0${previousMac}\0${digest}`).digest('hex');
}

const nonceMaxAgeMs=15*60_000;
const lineageActions=['ORDER_OBSERVED','CANCELLATION_OBSERVED'];
const checkoutRe=/^offline-checkout:[A-Za-z0-9_-]{16,80}$/;
const positive=v=>Number.isSafeInteger(v)&&v>0;
const lineageFields=['shop','orderGid','checkoutId','ownerSubject','sessionHash','lineId',...matchFields,'state'];
const lineageMatch=['shop','orderGid','checkoutId','ownerSubject','sessionHash','lineId',...matchFields];
const multiFields=['shop','orderGid','checkoutId','ownerSubject','sessionHash','state','lines'];
const multiLineFields=['lineId',...matchFields];
// Bounded per-order history prevents untrusted repeated cancellation IDs from
// consuming the entire shared 5,000-event ledger. Includes the observed event.
const maxMultiEventsPerOrder=32;
function validateMultiLines(lines){
 if(!Array.isArray(lines)||lines.length<2||lines.length>25)fail('LEDGER_MULTI_LINES_INVALID');
 const ids=new Set(),refs=new Set();
 for(const l of lines){
  if(!obj(l)||Object.keys(l).length!==multiLineFields.length||!positive(l.lineId))fail('LEDGER_MULTI_LINES_INVALID');
  validateMatch(l);
  if(ids.has(l.lineId)||refs.has(l.reference))fail('LEDGER_MULTI_LINES_DUPLICATE');
  ids.add(l.lineId);refs.add(l.reference);
 }
}
function validateMultiOrder(o){
 if(!obj(o)||Object.keys(o).length!==multiFields.length||multiFields.some(k=>!Object.hasOwn(o,k))||
 !shopRe.test(o.shop)||!gidRe('Order').test(o.orderGid)||!checkoutRe.test(o.checkoutId)||
 !gidRe('Customer').test(o.ownerSubject)||!hex.test(o.sessionHash)||
 !['OBSERVED','CANCELLED'].includes(o.state))fail('LEDGER_MULTI_ORDER_INVALID');
 validateMultiLines(o.lines);
}
function multiSame(a,b){return same(a,b,['shop','orderGid','checkoutId','ownerSubject','sessionHash'])&&
 a.lines.length===b.lines.length&&a.lines.every((l,i)=>same(l,b.lines[i],multiLineFields));}

function validateLineage(l){
 if(!obj(l)||Object.keys(l).length!==lineageFields.length||lineageFields.some(k=>!Object.hasOwn(l,k))||
 !shopRe.test(l.shop)||!gidRe('Order').test(l.orderGid)||!checkoutRe.test(l.checkoutId)||
 !gidRe('Customer').test(l.ownerSubject)||!hex.test(l.sessionHash)||!positive(l.lineId)||
 !['OBSERVED','CANCELLED'].includes(l.state))fail('LEDGER_LINEAGE_STATE_INVALID');
 validateMatch(l);
}
// Compact storage keeps every event ID and authenticated body digest. The first
// entry is the observed event; all later entries are cancellations. No event
// is discarded, and no order/design/nonce claim is ever pruned by compaction.
function archivedMultiEvents(s){
 return (s.multiArchives||[]).flatMap(a=>a.entries.map(([eventId,bodySha256],i)=>({
  shop:a.shop,orderGid:a.orderGid,eventId,bodySha256,
  action:i===0?'ORDER_OBSERVED':'CANCELLATION_OBSERVED'})));
}
function multiOrderEvents(s,shop,orderGid){
 const a=(s.multiArchives||[]).find(x=>x.shop===shop&&x.orderGid===orderGid);
 return a?a.entries.map(([eventId,bodySha256],i)=>({shop,orderGid,eventId,bodySha256,
  action:i===0?'ORDER_OBSERVED':'CANCELLATION_OBSERVED'})):
  (s.multiEvents||[]).filter(e=>e.shop===shop&&e.orderGid===orderGid);
}
function multiEventById(s,shop,id){
 return [...(s.multiEvents||[]),...archivedMultiEvents(s)].find(e=>e.shop===shop&&e.eventId===id);
}
function validateMultiArchives(s){
 const archives=s.multiArchives||[];
 if(!Array.isArray(archives)||archives.length>5000)fail('LEDGER_MULTI_ARCHIVE_INVALID');
 const ids=new Set();let total=(s.multiEvents||[]).length;
 for(const a of archives){
  if(!obj(a)||Object.keys(a).length!==3||!shopRe.test(a.shop)||
   !gidRe('Order').test(a.orderGid)||!Array.isArray(a.entries)||
   a.entries.length<2||a.entries.length>maxMultiEventsPerOrder)
   fail('LEDGER_MULTI_ARCHIVE_INVALID');
  const k=orderKey(a.shop,a.orderGid);
  if(ids.has(k))fail('LEDGER_MULTI_ARCHIVE_DUPLICATE');ids.add(k);
  const order=(s.multiOrders||[]).find(o=>orderKey(o.shop,o.orderGid)===k);
  if(!order||order.state!=='CANCELLED'||
   (s.multiEvents||[]).some(e=>orderKey(e.shop,e.orderGid)===k))
   fail('LEDGER_MULTI_ARCHIVE_STATE');
  for(const entry of a.entries){
   if(!Array.isArray(entry)||entry.length!==2||typeof entry[0]!=='string'||
    !uuidRe.test(entry[0])||entry[0]!==entry[0].toLowerCase()||
    typeof entry[1]!=='string'||!hex.test(entry[1]))
    fail('LEDGER_MULTI_ARCHIVE_INVALID');
  }
  total+=a.entries.length;
 }
 if(total>5000)fail('LEDGER_MULTI_ARCHIVE_CAPACITY');
}
function validateLineageEvent(e){
 if(!obj(e)||Object.keys(e).length!==5||!shopRe.test(e.shop)||!uuidRe.test(e.eventId)||
 !hex.test(e.bodySha256)||!gidRe('Order').test(e.orderGid)||
 !lineageActions.includes(e.action))fail('LEDGER_LINEAGE_EVENT_INVALID');
}
function validateDesign(d){
 if(!obj(d)||Object.keys(d).length!==fields.length||fields.some(k=>!Object.hasOwn(d,k))||
 !shopRe.test(d.shop)||!gidRe('Customer').test(d.ownerSubject)||!refRe.test(d.reference)||
 !Number.isSafeInteger(d.revision)||d.revision<1||!gidRe('Product').test(d.productGid)||
 !gidRe('ProductVariant').test(d.variantGid)||!hex.test(d.compositionSha256)||d.status!=='CURRENT')fail('LEDGER_DESIGN_INVALID');
}
function validateMatch(m){
 if(!obj(m)||!matchFields.every(k=>Object.hasOwn(m,k))||!refRe.test(m.reference)||
 !Number.isSafeInteger(m.revision)||m.revision<1||!gidRe('Product').test(m.productGid)||
 !gidRe('ProductVariant').test(m.variantGid)||!hex.test(m.compositionSha256))fail('LEDGER_MATCH_INVALID');
}
function validateState(s){
 if(!obj(s)||s.schema!=='TJ-OFFLINE-DURABLE-LEDGER-1'||!Array.isArray(s.designs)||
 !Array.isArray(s.events)||!Array.isArray(s.orders)||!Array.isArray(s.claims)||
 [s.designs,s.events,s.orders,s.claims].some(a=>a.length>5000)||
 (s.nonces!==undefined&&(!Array.isArray(s.nonces)||s.nonces.length>5000))||
 (s.lineage!==undefined&&(!Array.isArray(s.lineage)||s.lineage.length>5000))||
 (s.lineageEvents!==undefined&&(!Array.isArray(s.lineageEvents)||s.lineageEvents.length>5000))||
 (s.multiOrders!==undefined&&(!Array.isArray(s.multiOrders)||s.multiOrders.length>5000))||
 (s.multiEvents!==undefined&&(!Array.isArray(s.multiEvents)||s.multiEvents.length>5000)))fail('LEDGER_STATE_INVALID');
 validateMultiArchives(s);
 const unique=(arr,k)=>{const seen=new Set();for(const x of arr){const v=k(x);if(seen.has(v))fail('LEDGER_STATE_DUPLICATE');seen.add(v);}};
 for(const d of s.designs)validateDesign(d);
 unique(s.designs,d=>key(d.shop,d.reference));
 for(const e of s.events){if(!obj(e)||!shopRe.test(e.shop)||!uuidRe.test(e.eventId)||!hex.test(e.bodySha256)||!gidRe('Order').test(e.orderGid))fail('LEDGER_STATE_INVALID');}
 unique(s.events,e=>`${e.shop}|${e.eventId}`);
 for(const o of s.orders){if(!obj(o)||!shopRe.test(o.shop)||!gidRe('Order').test(o.orderGid)||!hex.test(o.bodySha256)||!Array.isArray(o.matchedLines)||!o.matchedLines.length||o.matchedLines.length>250)fail('LEDGER_STATE_INVALID');for(const m of o.matchedLines)validateMatch(m);}
 unique(s.orders,o=>orderKey(o.shop,o.orderGid));
 for(const c of s.claims){if(!obj(c)||!shopRe.test(c.shop)||!refRe.test(c.reference)||!Number.isSafeInteger(c.revision)||c.revision<1||!gidRe('Order').test(c.orderGid))fail('LEDGER_STATE_INVALID');}
 unique(s.claims,c=>`${key(c.shop,c.reference)}|${c.revision}`);
 for(const n of s.nonces||[]){if(!obj(n)||!hex.test(n.nonceKey)||!hex.test(n.receiptSha256)||!Number.isSafeInteger(n.expiresAt)||n.expiresAt<1)fail('LEDGER_NONCE_STATE_INVALID');}
 unique(s.nonces||[],n=>n.nonceKey);
 for(const l of s.lineage||[])validateLineage(l);
 unique(s.lineage||[],l=>orderKey(l.shop,l.orderGid));
 unique(s.lineage||[],l=>`${l.shop}|${l.checkoutId}`);
 unique(s.lineage||[],l=>`${l.shop}|${l.reference}|${l.revision}`);
 for(const e of s.lineageEvents||[])validateLineageEvent(e);
 unique(s.lineageEvents||[],e=>`${e.shop}|${e.eventId.toLowerCase()}`);
 for(const o of s.multiOrders||[])validateMultiOrder(o);
 unique(s.multiOrders||[],o=>orderKey(o.shop,o.orderGid));
 unique(s.multiOrders||[],o=>`${o.shop}|${o.checkoutId}`);
 unique((s.multiOrders||[]).flatMap(o=>o.lines.map(l=>({shop:o.shop,...l}))),
  l=>`${l.shop}|${l.reference}|${l.revision}`);
 for(const e of [...(s.multiEvents||[]),...archivedMultiEvents(s)])validateLineageEvent(e);
 unique([...(s.multiEvents||[]),...archivedMultiEvents(s)],e=>`${e.shop}|${e.eventId.toLowerCase()}`);
 // Cross-protocol state must never claim the same order, checkout, event, or design.
 const orders=new Set(s.orders.map(o=>orderKey(o.shop,o.orderGid)));
 const checkouts=new Set();const claimed=new Set(s.claims.map(c=>`${c.shop}|${c.reference}|${c.revision}`));
 for(const l of s.lineage||[]){
  if(orders.has(orderKey(l.shop,l.orderGid)))fail('LEDGER_CROSS_PROTOCOL_CONFLICT');
  orders.add(orderKey(l.shop,l.orderGid));checkouts.add(`${l.shop}|${l.checkoutId}`);
  const k=`${l.shop}|${l.reference}|${l.revision}`;
  if(claimed.has(k))fail('LEDGER_CROSS_PROTOCOL_CONFLICT');claimed.add(k);
 }
 for(const o of s.multiOrders||[]){
  if(orders.has(orderKey(o.shop,o.orderGid))||checkouts.has(`${o.shop}|${o.checkoutId}`))
   fail('LEDGER_CROSS_PROTOCOL_CONFLICT');
  orders.add(orderKey(o.shop,o.orderGid));checkouts.add(`${o.shop}|${o.checkoutId}`);
  for(const l of o.lines){const k=`${o.shop}|${l.reference}|${l.revision}`;
   if(claimed.has(k))fail('LEDGER_CROSS_PROTOCOL_CONFLICT');claimed.add(k);}
 }
 const events=new Set(s.events.map(e=>`${e.shop}|${e.eventId.toLowerCase()}`));
 for(const e of [...(s.lineageEvents||[]),...(s.multiEvents||[]),...archivedMultiEvents(s)]){
  const k=`${e.shop}|${e.eventId.toLowerCase()}`;
  if(events.has(k))fail('LEDGER_CROSS_PROTOCOL_CONFLICT');events.add(k);
 }
 // Objective 16: replay history must be a complete, chronologically consistent
 // explanation of each multi-order's state, never an orphan/partial mutation.
 // Array position is append order within the single atomic ledger transaction.
 const histories=new Map((s.multiOrders||[]).map(o=>[orderKey(o.shop,o.orderGid),{
  order:o,observed:0,cancellations:0,count:0
 }]));
 for(const e of [...(s.multiEvents||[]),...archivedMultiEvents(s)]){
  const history=histories.get(orderKey(e.shop,e.orderGid));
  if(!history)fail('LEDGER_MULTI_HISTORY_ORPHAN');
  if(++history.count>maxMultiEventsPerOrder)fail('LEDGER_MULTI_HISTORY_CAPACITY');
  if(e.action==='ORDER_OBSERVED'){
   if(history.observed!==0||history.cancellations!==0)fail('LEDGER_MULTI_HISTORY_ORDER');
   history.observed++;
  }else{
   if(history.observed!==1)fail('LEDGER_MULTI_HISTORY_ORDER');
   history.cancellations++;
  }
 }
 for(const history of histories.values()){
  if(history.observed!==1||
   (history.order.state==='CANCELLED')!==(history.cancellations>0))
   fail('LEDGER_MULTI_HISTORY_STATE');
 }
}
const fresh=()=>({schema:'TJ-OFFLINE-DURABLE-LEDGER-1',designs:[],events:[],orders:[],claims:[],nonces:[],lineage:[],lineageEvents:[],multiOrders:[],multiEvents:[],multiArchives:[]});
function sameLines(a,b){return a.length===b.length&&a.every((line,i)=>same(line,b[i],matchFields));}
export function createOfflineDurableLedger({directory,lockTimeoutMs=1200,injectFault,lockMode='mkdir',audit}={}){
 if(typeof directory!=='string'||!directory.trim()||!Number.isInteger(lockTimeoutMs)||lockTimeoutMs<0||lockTimeoutMs>10000||
 (injectFault!==undefined&&typeof injectFault!=='function')||!['mkdir','kernel'].includes(lockMode))fail('LEDGER_CONFIGURATION');
 const auditCfg=auditConfiguration(audit);
 const dir=resolve(directory),lock=join(dir,'.atomic-lock'),stateFile=join(dir,'ledger.json');
 async function anchorRead(){
  try{return checkAnchor(await auditCfg.readAnchor());}
  catch(e){if(e.code==='LEDGER_AUDIT_ANCHOR_INVALID')throw e;fail('LEDGER_AUDIT_ANCHOR_UNAVAILABLE');}
 }
 async function verifyAudit(state,{skipAnchorMatch=false}={}){
  if(!auditCfg){if(state.audit!==undefined)fail('LEDGER_AUDIT_REQUIRED');return;}
  const a=state.audit;
  if(!obj(a)||Object.keys(a).length!==auditKeys.length||
   !auditKeys.every(k=>Object.hasOwn(a,k))||a.schema!=='TJ-OFFLINE-LEDGER-AUDIT-1'||
   !Number.isSafeInteger(a.sequence)||a.sequence<1||!auditHex.test(a.previousMac)||
   !auditId.test(a.keyId)||!auditHex.test(a.mac))fail('LEDGER_AUDIT_INVALID');
  const k=auditCfg.keys.get(a.keyId);
  if(!k)fail('LEDGER_AUDIT_KEY_UNAVAILABLE');
  const expected=auditMac(k,a.keyId,a.sequence,a.previousMac,state);
  if(!timingSafeEqual(Buffer.from(expected,'hex'),Buffer.from(a.mac,'hex')))
   fail('LEDGER_AUDIT_TAMPERED');
  if(!skipAnchorMatch){
   const anchor=await anchorRead();
   if(!anchor||anchor.sequence!==a.sequence||anchor.mac!==a.mac)
    fail('LEDGER_AUDIT_ROLLBACK');
  }
 }

 async function assertDirectory(){
  await mkdir(dir,{recursive:true,mode:0o700});
  const st=await lstat(dir);if(!st.isDirectory()||st.isSymbolicLink())fail('LEDGER_DIRECTORY_UNSAFE');
 }
 async function load({recoveryRead=false}={}){
  let bytes;try{
   if(!fsConstants.O_NOFOLLOW)fail('LEDGER_NOFOLLOW_UNAVAILABLE');
   const h=await open(stateFile,fsConstants.O_RDONLY|fsConstants.O_NOFOLLOW);
   try{const st=await h.stat();if(!st.isFile()||st.size>maxStateBytes)fail('LEDGER_FILE_UNSAFE');bytes=await h.readFile();}
   finally{await h.close();}
  }catch(e){if(e.code==='ENOENT'){
   if(recoveryRead)fail('LEDGER_AUDIT_RECOVERY_STATE_MISSING');
   if(auditCfg&&(await anchorRead())!==null)fail('LEDGER_AUDIT_ROLLBACK');
   return fresh();
  }if(e.code==='ELOOP')fail('LEDGER_FILE_UNSAFE');throw e;}
  if(bytes.length>maxStateBytes)fail('LEDGER_FILE_UNSAFE');
  let data;try{data=JSON.parse(bytes.toString('utf8'));}catch{fail('LEDGER_STATE_CORRUPT');}
  validateState(data);await verifyAudit(data,{skipAnchorMatch:recoveryRead});return data;
 }
 async function persist(data){
  validateState(data);
  let previousAnchor=null,nextAnchor=null;
  if(auditCfg){
   const old=data.audit;
   if(old!==undefined){
    if(!obj(old)||!Number.isSafeInteger(old.sequence)||old.sequence<1||
     old.sequence>=Number.MAX_SAFE_INTEGER||!auditHex.test(old.mac||''))fail('LEDGER_AUDIT_INVALID');
    previousAnchor={sequence:old.sequence,mac:old.mac};
   }
   const sequence=previousAnchor?previousAnchor.sequence+1:1;
   const previousMac=previousAnchor?previousAnchor.mac:auditZero;
   const keyId=auditCfg.activeKeyId;
   data.audit={schema:'TJ-OFFLINE-LEDGER-AUDIT-1',sequence,previousMac,keyId,
    mac:auditMac(auditCfg.keys.get(keyId),keyId,sequence,previousMac,data)};
   nextAnchor={sequence,mac:data.audit.mac};
  }else if(data.audit!==undefined)fail('LEDGER_AUDIT_REQUIRED');
  const bytes=Buffer.from(JSON.stringify(data));if(bytes.length>maxStateBytes)fail('LEDGER_STATE_TOO_LARGE');
  const temp=join(dir,`.pending-${process.pid}-${randomBytes(12).toString('hex')}`);
  let h;
  try{
   h=await open(temp,'wx',0o600);await h.writeFile(bytes);await h.sync();await h.close();h=undefined;
   if(injectFault)await injectFault('before-rename');
   await rename(temp,stateFile);
   const d=await open(dir,'r');try{await d.sync();}finally{await d.close();}
   if(injectFault)await injectFault('after-rename');
   if(auditCfg){
    let ok;try{ok=await auditCfg.compareAndSetAnchor(previousAnchor,nextAnchor);}
    catch{fail('LEDGER_AUDIT_ANCHOR_UNAVAILABLE');}
    if(ok!==true)fail('LEDGER_AUDIT_ANCHOR_CONFLICT');
    const verified=await anchorRead();
    if(!verified||verified.sequence!==nextAnchor.sequence||verified.mac!==nextAnchor.mac)
     fail('LEDGER_AUDIT_ANCHOR_CONFLICT');
   }
  }finally{if(h)await h.close();await rm(temp,{force:true}).catch(()=>{});}
 }
 /** Optional Linux-only kernel lock. A separate `flock` helper locks fd 3, which
  * refers to the SAME open-file-description retained by this Node process.
  * Once the helper exits, the parent still holds the kernel lock until close().
  * SIGKILL closes the parent's descriptor and releases it automatically.
  * Never unlink this lock file: doing so would permit two independent inodes.
  * The shared `.atomic-lock` pathname excludes older mkdir-lock processes.
  */
 async function kernelLock(){
  if(process.platform!=='linux'||!fsConstants.O_NOFOLLOW)fail('LEDGER_KERNEL_LOCK_UNAVAILABLE');
  // A writable-by-others directory permits pathname replacement despite flock.
  const dst=await lstat(dir);
  if(!dst.isDirectory()||dst.isSymbolicLink()||dst.uid!==process.getuid()||
   (dst.mode&0o022)!==0)fail('LEDGER_KERNEL_LOCK_UNSAFE');
  let h;
  try{
   h=await open(lock,fsConstants.O_RDWR|fsConstants.O_CREAT|fsConstants.O_NOFOLLOW,0o600);
   const st=await h.stat(),pathSt=await lstat(lock);
   if(!st.isFile()||!pathSt.isFile()||st.nlink!==1||st.dev!==pathSt.dev||
    st.ino!==pathSt.ino||(st.mode&0o077)!==0)fail('LEDGER_KERNEL_LOCK_UNSAFE');
   await new Promise((resolve,reject)=>{
    let settled=false,stderr='';
    const child=spawn('/usr/bin/flock',['-x','-w',(lockTimeoutMs/1000).toFixed(3),'3'],
     {stdio:['ignore','ignore','pipe',h.fd]});
    const done=(err)=>{if(settled)return;settled=true;err?reject(err):resolve();};
    child.stderr.on('data',chunk=>{stderr=(stderr+chunk.toString()).slice(-512);});
    child.on('error',()=>done(Object.assign(new Error('LEDGER_KERNEL_LOCK_UNAVAILABLE'),{code:'LEDGER_KERNEL_LOCK_UNAVAILABLE'})));
    child.on('close',code=>done(code===0?null:Object.assign(
     new Error('LEDGER_LOCK_UNAVAILABLE'),{code:'LEDGER_LOCK_UNAVAILABLE'})));
   });
   // Reject lock pathname substitution even if the original inode is still locked.
   const after=await lstat(lock);
   if(!after.isFile()||after.dev!==st.dev||after.ino!==st.ino||after.nlink!==1)
    fail('LEDGER_KERNEL_LOCK_UNSAFE');
   return h;
  }catch(e){if(h)await h.close();
   if(['ELOOP','EISDIR','ENOTDIR'].includes(e.code))fail('LEDGER_KERNEL_LOCK_UNSAFE');
   throw e;
  }
 }
 async function transaction(fn,{recovery=false}={}){
  await assertDirectory();
  if(lockMode==='kernel'){
   const h=await kernelLock();
   try{const state=await load({recoveryRead:recovery});return await fn(state);}
   finally{await h.close();}
  }
  const start=Date.now();let locked=false;
  while(!locked){
   try{await mkdir(lock,{mode:0o700});locked=true;}
   catch(e){if(e.code!=='EEXIST')throw e;if(Date.now()-start>=lockTimeoutMs)fail('LEDGER_LOCK_UNAVAILABLE');await delay(10);}
  }
  try{const state=await load({recoveryRead:recovery});return await fn(state);}
  finally{await rmdir(lock).catch(()=>{fail('LEDGER_LOCK_RELEASE_FAILED');});}
 }
 /** Operator-signed, externally witnessed ONE-STEP anchor catch-up only.
  * No state rewrite, no automatic recovery, no rollback, no trust in ledger alone.
  * Private signing key MUST be held independently of this local process.
  */
 async function recoverInterruptedAudit({authorization}={}){
  if(!auditCfg?.recovery)fail('LEDGER_AUDIT_RECOVERY_UNAVAILABLE');
  const permit=validateRecoveryAuthorization(authorization,auditCfg.recovery,Date.now());
  return transaction(async state=>{
   // load() verified the local HMAC but intentionally did not accept an anchor
   // mismatch. This method is the ONLY call path with recoveryRead enabled.
   const target={sequence:state.audit.sequence,mac:state.audit.mac};
   if(permit.targetAnchor.sequence!==target.sequence||permit.targetAnchor.mac!==target.mac)
    fail('LEDGER_AUDIT_RECOVERY_TARGET');
   const anchor=await anchorRead();
   if(anchor&&anchor.sequence===target.sequence&&anchor.mac===target.mac)
    return 'already-recovered';
   const prior=permit.expectedAnchor;
   if((anchor===null)!==(prior===null)||
    (anchor!==null&&(anchor.sequence!==prior.sequence||anchor.mac!==prior.mac))||
    target.sequence!==(prior?prior.sequence+1:1)||
    state.audit.previousMac!==(prior?prior.mac:auditZero))
    fail('LEDGER_AUDIT_RECOVERY_CHAIN');
   let ok;try{ok=await auditCfg.compareAndSetAnchor(prior,target);}
   catch{fail('LEDGER_AUDIT_ANCHOR_UNAVAILABLE');}
   if(ok!==true)fail('LEDGER_AUDIT_ANCHOR_CONFLICT');
   const after=await anchorRead();
   if(!after||after.sequence!==target.sequence||after.mac!==target.mac)
    fail('LEDGER_AUDIT_ANCHOR_CONFLICT');
   return 'recovered';
  },{recovery:true});
 }
 async function putDesignCAS({design,expectedRevision=null}={}){
  validateDesign(design);
  if(expectedRevision!==null&&(!Number.isSafeInteger(expectedRevision)||expectedRevision<1))fail('LEDGER_CAS_EXPECTED_INVALID');
  return transaction(async s=>{
   const existing=s.designs.find(d=>key(d.shop,d.reference)===key(design.shop,design.reference));
   if(!existing){if(expectedRevision!==null||design.revision!==1)fail('LEDGER_REVISION_CAS');s.designs.push({...design});}
   else{
    if(existing.revision!==expectedRevision||design.revision!==expectedRevision+1)fail('LEDGER_REVISION_CAS');
    if(existing.ownerSubject!==design.ownerSubject)fail('LEDGER_OWNER_IMMUTABLE');
    s.designs[s.designs.indexOf(existing)]={...design};
   }
   await persist(s);return Object.freeze({...design});
  });
 }
 async function lookupDesign({shop,reference}={}){
  if(!shopRe.test(shop||'')||!refRe.test(reference||''))fail('LEDGER_LOOKUP_INVALID');
  await assertDirectory();const s=await load();const d=s.designs.find(x=>x.shop===shop&&x.reference===reference);
  return d?Object.freeze({...d}):null;
 }
 /** Atomic one-use metadata receipt nonce store, shared with order/design CAS lock.
  * Old v0.10 snapshots lacking `nonces` are migrated on first write.
  * Pruning occurs only AFTER token expiry; verifier must check expiry first.
  */
 async function consumeNonce({nonceKey,receiptSha256,expiresAt,expectedDesign}={}){
  const t=Date.now();
  if(!hex.test(nonceKey||'')||!hex.test(receiptSha256||'')||!Number.isSafeInteger(expiresAt)||
   expiresAt<=t||expiresAt-t>nonceMaxAgeMs)fail('LEDGER_NONCE_INVALID');
  validateDesign(expectedDesign);
  return transaction(async s=>{
   s.nonces??=[];
   const actual=s.designs.find(d=>d.shop===expectedDesign.shop&&d.reference===expectedDesign.reference);
   if(!actual||!same(actual,expectedDesign,fields))fail('LEDGER_REVISION_CAS');
   const existing=s.nonces.find(n=>n.nonceKey===nonceKey);
   if(existing)return existing.receiptSha256===receiptSha256?'duplicate':'conflict';
   s.nonces=s.nonces.filter(n=>n.expiresAt>t);
   if(s.nonces.length>=5000)fail('LEDGER_NONCE_CAPACITY');
   s.nonces.push({nonceKey,receiptSha256,expiresAt});
   await persist(s);return 'acquired';
  });
 }
 async function claimOnce({eventKey,bodySha256,orderGid,matchedLines}={}){
  if(typeof eventKey!=='string'||!hex.test(bodySha256||'')||!gidRe('Order').test(orderGid||'')||
   !Array.isArray(matchedLines)||!matchedLines.length||matchedLines.length>250)fail('LEDGER_CLAIM_INVALID');
  const event=eventKey.match(/^([a-z0-9][a-z0-9-]*\.myshopify\.com):orders\/create:([0-9a-f-]+)$/);
  if(!event||!uuidRe.test(event[2]))fail('LEDGER_EVENT_INVALID');
  const shop=event[1],eventId=event[2].toLowerCase();
  for(const m of matchedLines)validateMatch(m);
  if(new Set(matchedLines.map(m=>m.reference)).size!==matchedLines.length)fail('LEDGER_DUPLICATE_DESIGN');
  return transaction(async s=>{
   const oldEvent=s.events.find(e=>e.shop===shop&&e.eventId===eventId);
   if(oldEvent)return oldEvent.bodySha256===bodySha256&&oldEvent.orderGid===orderGid?'duplicate':'conflict';
   if((s.lineage||[]).some(l=>l.shop===shop&&l.orderGid===orderGid)||
    (s.multiOrders||[]).some(o=>o.shop===shop&&o.orderGid===orderGid)||
    (s.lineageEvents||[]).some(e=>e.shop===shop&&e.eventId===eventId)||
    [...(s.multiEvents||[]),...archivedMultiEvents(s)].some(e=>e.shop===shop&&e.eventId===eventId))fail('LEDGER_CROSS_PROTOCOL_CONFLICT');
   const oldOrder=s.orders.find(o=>o.shop===shop&&o.orderGid===orderGid);
   if(oldOrder){
    if(oldOrder.bodySha256!==bodySha256||!sameLines(oldOrder.matchedLines,matchedLines))return 'conflict';
    s.events.push({shop,eventId,bodySha256,orderGid});await persist(s);return 'duplicate';
   }
   for(const m of matchedLines){
    const d=s.designs.find(x=>x.shop===shop&&x.reference===m.reference);
    if(!d||!same(d,m,matchFields)||d.status!=='CURRENT')fail('LEDGER_REVISION_CAS');
    if(s.claims.some(c=>c.shop===shop&&c.reference===m.reference&&c.revision===m.revision)||
     (s.lineage||[]).some(l=>l.shop===shop&&l.reference===m.reference&&l.revision===m.revision)||
     (s.multiOrders||[]).some(o=>o.shop===shop&&o.lines.some(l=>l.reference===m.reference&&l.revision===m.revision)))fail('LEDGER_DESIGN_ALREADY_CLAIMED');
   }
   s.events.push({shop,eventId,bodySha256,orderGid});
   s.orders.push({shop,orderGid,bodySha256,matchedLines:matchedLines.map(m=>Object.fromEntries(matchFields.map(k=>[k,m[k]])))});
   for(const m of matchedLines)s.claims.push({shop,reference:m.reference,revision:m.revision,orderGid});
   await persist(s);return 'acquired';
  });
 }
 /** Atomic offline v2 order lineage transitions, sharing the design CAS lock.
  * These states are observations ONLY: never payment, checkout or fulfillment proof.
  * The event must be authenticated by a trusted external adapter before this call.
  */
 async function commitLineageTransition({shop,eventId,bodySha256,action,orderGid,checkoutId,
  ownerSubject,sessionHash,lineId,binding}={}){
  if(!shopRe.test(shop||'')||!uuidRe.test(eventId||'')||!hex.test(bodySha256||'')||
   !lineageActions.includes(action)||!gidRe('Order').test(orderGid||'')||
   !checkoutRe.test(checkoutId||'')||!gidRe('Customer').test(ownerSubject||'')||
   !hex.test(sessionHash||'')||!positive(lineId))fail('LEDGER_LINEAGE_INPUT_INVALID');
  validateMatch(binding);
  if(Object.keys(binding).length!==matchFields.length)fail('LEDGER_LINEAGE_INPUT_INVALID');
  const candidate={shop,orderGid,checkoutId,ownerSubject,sessionHash,lineId,...binding};
  return transaction(async s=>{
   s.lineage??=[];s.lineageEvents??=[];
   if([...(s.multiEvents||[]),...archivedMultiEvents(s)].some(e=>e.shop===shop&&e.eventId.toLowerCase()===eventId.toLowerCase())||
    s.events.some(e=>e.shop===shop&&e.eventId.toLowerCase()===eventId.toLowerCase())||
    s.orders.some(o=>o.shop===shop&&o.orderGid===orderGid)||
    (s.multiOrders||[]).some(o=>o.shop===shop&&(o.orderGid===orderGid||o.checkoutId===checkoutId||
     o.lines.some(l=>l.reference===binding.reference&&l.revision===binding.revision))))
    fail('LEDGER_CROSS_PROTOCOL_CONFLICT');
   const oldEvent=s.lineageEvents.find(e=>e.shop===shop&&e.eventId.toLowerCase()===eventId.toLowerCase());
   if(oldEvent)return oldEvent.bodySha256===bodySha256&&oldEvent.orderGid===orderGid&&oldEvent.action===action?'duplicate':'conflict';
   const existing=s.lineage.find(l=>l.shop===shop&&l.orderGid===orderGid);
   if(action==='ORDER_OBSERVED'){
    if(existing){
     if(existing.state!=='OBSERVED'||!same(existing,candidate,lineageMatch))return 'conflict';
     s.lineageEvents.push({shop,eventId:eventId.toLowerCase(),bodySha256,orderGid,action});
     await persist(s);return 'duplicate';
    }
    if(s.lineage.some(l=>l.shop===shop&&(l.checkoutId===checkoutId||
     (l.reference===binding.reference&&l.revision===binding.revision))))fail('LEDGER_LINEAGE_ALREADY_CLAIMED');
    if(s.claims.some(c=>c.shop===shop&&c.reference===binding.reference&&c.revision===binding.revision))fail('LEDGER_LINEAGE_LEGACY_CLAIM');
    const d=s.designs.find(x=>x.shop===shop&&x.reference===binding.reference);
    if(!d||d.ownerSubject!==ownerSubject||d.status!=='CURRENT'||!same(d,binding,matchFields))fail('LEDGER_LINEAGE_DESIGN_CAS');
    s.lineage.push({...candidate,state:'OBSERVED'});
   }else{
    if(!existing||!same(existing,candidate,lineageMatch))fail('LEDGER_LINEAGE_UNKNOWN_ORDER');
    if(existing.state==='CANCELLED'){
     s.lineageEvents.push({shop,eventId:eventId.toLowerCase(),bodySha256,orderGid,action});
     await persist(s);return 'duplicate';
    }
    if(existing.state!=='OBSERVED')fail('LEDGER_LINEAGE_TRANSITION_INVALID');
    existing.state='CANCELLED';
   }
   s.lineageEvents.push({shop,eventId:eventId.toLowerCase(),bodySha256,orderGid,action});
   await persist(s);return 'acquired';
  });
 }
 /** One durable transaction for nonce consumption AND observed lineage.
  * A server-owned validator must authenticate the in-memory prepared receipt.
  * This is an offline single-host fixture, not a public endpoint or Shopify proof.
  */
 async function commitLineageWithReceipt({shop,eventId,bodySha256,action,orderGid,checkoutId,
  ownerSubject,sessionHash,lineId,binding,preparedReceipt,assertPreparedReceipt}={}){
  if(action!=='ORDER_OBSERVED'||typeof assertPreparedReceipt!=='function'||
   !shopRe.test(shop||'')||!uuidRe.test(eventId||'')||!hex.test(bodySha256||'')||
   !gidRe('Order').test(orderGid||'')||!checkoutRe.test(checkoutId||'')||
   !gidRe('Customer').test(ownerSubject||'')||!hex.test(sessionHash||'')||!positive(lineId))
   fail('LEDGER_ATOMIC_INPUT_INVALID');
  validateMatch(binding);
  if(Object.keys(binding).length!==matchFields.length)fail('LEDGER_ATOMIC_INPUT_INVALID');
  const candidate={shop,orderGid,checkoutId,ownerSubject,sessionHash,lineId,...binding};
  return transaction(async s=>{
   s.lineage??=[];s.lineageEvents??=[];s.nonces??=[];
   if([...(s.multiEvents||[]),...archivedMultiEvents(s)].some(e=>e.shop===shop&&e.eventId.toLowerCase()===eventId.toLowerCase())||
    s.events.some(e=>e.shop===shop&&e.eventId.toLowerCase()===eventId.toLowerCase())||
    s.orders.some(o=>o.shop===shop&&o.orderGid===orderGid)||
    (s.multiOrders||[]).some(o=>o.shop===shop&&(o.orderGid===orderGid||o.checkoutId===checkoutId||
     o.lines.some(l=>l.reference===binding.reference&&l.revision===binding.revision))))
    fail('LEDGER_CROSS_PROTOCOL_CONFLICT');
   const oldEvent=s.lineageEvents.find(e=>e.shop===shop&&e.eventId===eventId.toLowerCase());
   if(oldEvent)return oldEvent.bodySha256===bodySha256&&oldEvent.orderGid===orderGid&&
    oldEvent.action===action?'duplicate':'conflict';
   // Validate proof *under the lock* after waiting for any other writer.
   const proof=assertPreparedReceipt(preparedReceipt);
   const t=Date.now();
   if(!obj(proof)||proof.schema!=='TJ-OFFLINE-PREPARED-CART-2'||
    proof.shop!==shop||proof.ownerSubject!==ownerSubject||proof.sessionHash!==sessionHash||
    !same(proof,binding,matchFields)||!hex.test(proof.nonceKey)||!hex.test(proof.receiptSha256)||
    !Number.isSafeInteger(proof.expiresAt)||proof.expiresAt<=t||
    proof.expiresAt-t>nonceMaxAgeMs||proof.checkoutEnabled!==false||
    proof.paymentVerified!==false||proof.productionApproved!==false||
    proof.fulfillmentAuthorized!==false||!obj(proof.expectedDesign)||
    !same(proof.expectedDesign,{shop,ownerSubject,...binding,status:'CURRENT'},fields))
    fail('LEDGER_ATOMIC_RECEIPT_INVALID');
   if(s.nonces.some(n=>n.nonceKey===proof.nonceKey))fail('LEDGER_ATOMIC_NONCE_REPLAY');
   if(s.lineage.some(l=>l.shop===shop&&(l.orderGid===orderGid||l.checkoutId===checkoutId||
    (l.reference===binding.reference&&l.revision===binding.revision))))fail('LEDGER_LINEAGE_ALREADY_CLAIMED');
   if(s.claims.some(c=>c.shop===shop&&c.reference===binding.reference&&c.revision===binding.revision))
    fail('LEDGER_LINEAGE_LEGACY_CLAIM');
   const d=s.designs.find(x=>x.shop===shop&&x.reference===binding.reference);
   if(!d||!same(d,proof.expectedDesign,fields))fail('LEDGER_LINEAGE_DESIGN_CAS');
   s.nonces=s.nonces.filter(n=>n.expiresAt>t);
   if(s.nonces.length>=5000||s.lineage.length>=5000||s.lineageEvents.length>=5000)
    fail('LEDGER_ATOMIC_CAPACITY');
   s.nonces.push({nonceKey:proof.nonceKey,receiptSha256:proof.receiptSha256,expiresAt:proof.expiresAt});
   s.lineage.push({...candidate,state:'OBSERVED'});
   s.lineageEvents.push({shop,eventId:eventId.toLowerCase(),bodySha256,orderGid,action});
   await persist(s);return 'acquired';
  });
 }

 /** Objective 15: all-or-nothing synthetic multi-line order observation.
  * All prepared proofs are authenticated by the server-owned v2 authority while
  * the SAME filesystem lock protects nonce, design, and order state.
  */
 async function commitMultiLineageWithReceipts({shop,eventId,bodySha256,action,orderGid,checkoutId,
  ownerSubject,sessionHash,lines,preparedReceipts,assertPreparedReceipt}={}){
  if(action!=='ORDER_OBSERVED'||typeof assertPreparedReceipt!=='function'||
   !shopRe.test(shop||'')||!uuidRe.test(eventId||'')||!hex.test(bodySha256||'')||
   !gidRe('Order').test(orderGid||'')||!checkoutRe.test(checkoutId||'')||
   !gidRe('Customer').test(ownerSubject||'')||!hex.test(sessionHash||''))fail('LEDGER_MULTI_INPUT_INVALID');
  validateMultiLines(lines);
  if(!Array.isArray(preparedReceipts)||preparedReceipts.length!==lines.length)fail('LEDGER_MULTI_RECEIPTS_INVALID');
  const candidate={shop,orderGid,checkoutId,ownerSubject,sessionHash,
   lines:lines.map(l=>({...l}))};
  return transaction(async s=>{
   s.multiOrders??=[];s.multiEvents??=[];s.nonces??=[];
   const id=eventId.toLowerCase();
   if(s.events.some(e=>e.shop===shop&&e.eventId.toLowerCase()===id)||
    (s.lineageEvents||[]).some(e=>e.shop===shop&&e.eventId.toLowerCase()===id))
    fail('LEDGER_MULTI_CROSS_PROTOCOL');
   const oldEvent=multiEventById(s,shop,id);
   if(oldEvent)return oldEvent.bodySha256===bodySha256&&oldEvent.orderGid===orderGid&&
    oldEvent.action===action?'duplicate':'conflict';
   if(s.orders.some(o=>o.shop===shop&&o.orderGid===orderGid)||
    (s.lineage||[]).some(l=>l.shop===shop&&(l.orderGid===orderGid||l.checkoutId===checkoutId))||
    s.multiOrders.some(o=>o.shop===shop&&(o.orderGid===orderGid||o.checkoutId===checkoutId)))
    fail('LEDGER_MULTI_ORDER_CLAIMED');
   const t=Date.now(),nonceKeys=new Set();
   const nonceRecords=[];
   for(let i=0;i<lines.length;i++){
    const line=lines[i],proof=assertPreparedReceipt(preparedReceipts[i]);
    if(!obj(proof)||proof.schema!=='TJ-OFFLINE-PREPARED-CART-2'||proof.shop!==shop||
     proof.ownerSubject!==ownerSubject||proof.sessionHash!==sessionHash||
     !same(proof,line,matchFields)||!hex.test(proof.nonceKey)||!hex.test(proof.receiptSha256)||
     !Number.isSafeInteger(proof.expiresAt)||proof.expiresAt<=t||proof.expiresAt-t>nonceMaxAgeMs||
     proof.checkoutEnabled!==false||proof.paymentVerified!==false||proof.productionApproved!==false||
     proof.fulfillmentAuthorized!==false||!obj(proof.expectedDesign)||
     !same(proof.expectedDesign,{shop,ownerSubject,...line,status:'CURRENT'},fields))
     fail('LEDGER_MULTI_RECEIPT_INVALID');
    if(nonceKeys.has(proof.nonceKey)||s.nonces.some(n=>n.nonceKey===proof.nonceKey))
     fail('LEDGER_MULTI_NONCE_REPLAY');
    nonceKeys.add(proof.nonceKey);
    if(s.claims.some(c=>c.shop===shop&&c.reference===line.reference&&c.revision===line.revision)||
     (s.lineage||[]).some(l=>l.shop===shop&&l.reference===line.reference&&l.revision===line.revision)||
     s.multiOrders.some(o=>o.shop===shop&&o.lines.some(l=>l.reference===line.reference&&l.revision===line.revision)))
     fail('LEDGER_MULTI_DESIGN_CLAIMED');
    const d=s.designs.find(x=>x.shop===shop&&x.reference===line.reference);
    if(!d||!same(d,proof.expectedDesign,fields))fail('LEDGER_MULTI_DESIGN_CAS');
    nonceRecords.push({nonceKey:proof.nonceKey,receiptSha256:proof.receiptSha256,expiresAt:proof.expiresAt});
   }
   const kept=s.nonces.filter(n=>n.expiresAt>t);
   if(kept.length+nonceRecords.length>5000||s.multiOrders.length>=5000||
    s.multiEvents.length+archivedMultiEvents(s).length>=5000)
    fail('LEDGER_MULTI_CAPACITY');
   s.nonces=[...kept,...nonceRecords];
   s.multiOrders.push({...candidate,state:'OBSERVED'});
   s.multiEvents.push({shop,eventId:id,bodySha256,orderGid,action});
   await persist(s);return 'acquired';
  });
 }
 async function commitMultiLineageCancellation({shop,eventId,bodySha256,action,orderGid,checkoutId,
  ownerSubject,sessionHash,lines}={}){
  if(action!=='CANCELLATION_OBSERVED'||!shopRe.test(shop||'')||!uuidRe.test(eventId||'')||
   !hex.test(bodySha256||'')||!gidRe('Order').test(orderGid||'')||!checkoutRe.test(checkoutId||'')||
   !gidRe('Customer').test(ownerSubject||'')||!hex.test(sessionHash||''))fail('LEDGER_MULTI_INPUT_INVALID');
  validateMultiLines(lines);
  const candidate={shop,orderGid,checkoutId,ownerSubject,sessionHash,lines};
  return transaction(async s=>{
   s.multiOrders??=[];s.multiEvents??=[];
   const id=eventId.toLowerCase();
   if(s.events.some(e=>e.shop===shop&&e.eventId.toLowerCase()===id)||
    (s.lineageEvents||[]).some(e=>e.shop===shop&&e.eventId.toLowerCase()===id))
    fail('LEDGER_MULTI_CROSS_PROTOCOL');
   const old=multiEventById(s,shop,id);
   if(old)return old.bodySha256===bodySha256&&old.orderGid===orderGid&&old.action===action?'duplicate':'conflict';
   const order=s.multiOrders.find(o=>o.shop===shop&&o.orderGid===orderGid);
   if(!order||!multiSame(order,candidate))fail('LEDGER_MULTI_UNKNOWN_ORDER');
   const outcome=order.state==='CANCELLED'?'duplicate':'acquired';
   if(!['OBSERVED','CANCELLED'].includes(order.state))fail('LEDGER_MULTI_TRANSITION_INVALID');
   order.state='CANCELLED';
   if(s.multiEvents.length+archivedMultiEvents(s).length>=5000||
    multiOrderEvents(s,shop,orderGid).length>=maxMultiEventsPerOrder)
    fail('LEDGER_MULTI_CAPACITY');
   const archive=(s.multiArchives||[]).find(a=>a.shop===shop&&a.orderGid===orderGid);
   if(archive)archive.entries.push([id,bodySha256]);
   else s.multiEvents.push({shop,eventId:id,bodySha256,orderGid,action});
   await persist(s);return outcome;
  });
 }
 /** Atomic, optional offline compaction of a CANCELLED order's full event
  * headers. Keeps all UUID+digest replay tombstones and all design/nonce claims.
  * Safe after a lost acknowledgment: retry reports duplicate. Not a GC API.
  */
 async function compactMultiLineageHistory({shop,orderGid}={}){
  if(!shopRe.test(shop||'')||!gidRe('Order').test(orderGid||''))
   fail('LEDGER_MULTI_COMPACTION_INPUT');
  return transaction(async s=>{
   s.multiArchives??=[];
   if(s.multiArchives.some(a=>a.shop===shop&&a.orderGid===orderGid))return 'duplicate';
   const order=(s.multiOrders||[]).find(o=>o.shop===shop&&o.orderGid===orderGid);
   if(!order)fail('LEDGER_MULTI_UNKNOWN_ORDER');
   if(order.state!=='CANCELLED')fail('LEDGER_MULTI_COMPACTION_STATE');
   const events=multiOrderEvents(s,shop,orderGid);
   if(events.length<2)fail('LEDGER_MULTI_COMPACTION_STATE');
   s.multiArchives.push({shop,orderGid,entries:events.map(e=>[e.eventId,e.bodySha256])});
   s.multiEvents=s.multiEvents.filter(e=>!(e.shop===shop&&e.orderGid===orderGid));
   await persist(s);return 'acquired';
  });
 }
 /** Objective 35J: single-snapshot, READ-ONLY durable observation recovery.
  * A lost post-rename acknowledgment may be recovered from an independently
  * authenticated synthetic event. Never issue new receipts or mutate claims.
  * The exact event, order, checkout, owner, session and ordered line bindings
  * must ALL survive in the same validated ledger snapshot.
  */
 async function inspectCommittedMultiLineage({shop,eventId,bodySha256,action,orderGid,
  checkoutId,ownerSubject,sessionHash,lines}={}){
  if(action!=='ORDER_OBSERVED'||!shopRe.test(shop||'')||!uuidRe.test(eventId||'')||
   !hex.test(bodySha256||'')||!gidRe('Order').test(orderGid||'')||
   !checkoutRe.test(checkoutId||'')||!gidRe('Customer').test(ownerSubject||'')||
   !hex.test(sessionHash||''))fail('LEDGER_MULTI_RECOVERY_INPUT');
  validateMultiLines(lines);
  await assertDirectory();const s=await load();
  const id=eventId.toLowerCase(),old=multiEventById(s,shop,id);
  // A cross-protocol ID or a claimed order without this event is not an
  // uncommitted observation that can safely be retried automatically.
  if(!old){
   if(s.events.some(e=>e.shop===shop&&e.eventId.toLowerCase()===id)||
    (s.lineageEvents||[]).some(e=>e.shop===shop&&e.eventId.toLowerCase()===id)||
    s.multiOrders.some(o=>o.shop===shop&&(o.orderGid===orderGid||o.checkoutId===checkoutId)))
    return 'conflict';
   return 'absent';
  }
  const order=s.multiOrders.find(o=>o.shop===shop&&o.orderGid===orderGid);
  const expected={shop,orderGid,checkoutId,ownerSubject,sessionHash,lines};
  if(old.bodySha256!==bodySha256||old.orderGid!==orderGid||old.action!==action||
   !order||!multiSame(order,expected))return 'conflict';
  return 'committed';
 }
 async function lookupMultiLineageEvent({shop,eventId}={}){
  if(!shopRe.test(shop||'')||!uuidRe.test(eventId||''))fail('LEDGER_MULTI_LOOKUP_INVALID');
  await assertDirectory();const s=await load();
  const e=multiEventById(s,shop,eventId.toLowerCase());
  return e?Object.freeze({...e}):null;
 }
 async function getMultiLineage({shop,orderGid}={}){
  if(!shopRe.test(shop||'')||!gidRe('Order').test(orderGid||''))fail('LEDGER_MULTI_LOOKUP_INVALID');
  await assertDirectory();const s=await load();
  const o=(s.multiOrders||[]).find(x=>x.shop===shop&&x.orderGid===orderGid);
  return o?Object.freeze({...o,lines:Object.freeze(o.lines.map(l=>Object.freeze({...l})))}):null;
 }
 /** Immutable, read-only reconciliation view. All underlying event/order history
  * is checked by load() before any result is returned. Never an authorization.
  */
 async function getMultiLineageHistory({shop,orderGid}={}){
  if(!shopRe.test(shop||'')||!gidRe('Order').test(orderGid||''))fail('LEDGER_MULTI_LOOKUP_INVALID');
  await assertDirectory();const s=await load();
  const order=(s.multiOrders||[]).find(o=>o.shop===shop&&o.orderGid===orderGid);
  if(!order)return null;
  const events=multiOrderEvents(s,shop,orderGid).map(e=>Object.freeze({...e}));
  return Object.freeze({schema:'TJ-OFFLINE-MULTILINE-HISTORY-1',shop,orderGid,
   state:order.state,checkoutId:order.checkoutId,ownerSubject:order.ownerSubject,
   sessionHash:order.sessionHash,lineCount:order.lines.length,
   lines:Object.freeze(order.lines.map(l=>Object.freeze({...l}))),
   observedEventId:events[0].eventId,cancellationCount:events.length-1,
   events:Object.freeze(events),syntheticOnly:true,checkoutEnabled:false,
   paymentVerified:false,productionApproved:false,fulfillmentAuthorized:false});
 }
 async function lookupLineageEvent({shop,eventId}={}){
  if(!shopRe.test(shop||'')||!uuidRe.test(eventId||''))fail('LEDGER_LINEAGE_EVENT_LOOKUP_INVALID');
  await assertDirectory();const s=await load();const event=(s.lineageEvents||[]).find(e=>e.shop===shop&&e.eventId===eventId.toLowerCase());
  return event?Object.freeze({...event}):null;
 }
 async function getLineage({shop,orderGid}={}){
  if(!shopRe.test(shop||'')||!gidRe('Order').test(orderGid||''))fail('LEDGER_LINEAGE_LOOKUP_INVALID');
  await assertDirectory();const s=await load();const item=(s.lineage||[]).find(l=>l.shop===shop&&l.orderGid===orderGid);
  return item?Object.freeze({...item}):null;
 }
 return Object.freeze({recoverInterruptedAudit,putDesignCAS,lookupDesign,claimOnce,consumeNonce,commitLineageTransition,commitLineageWithReceipt,commitMultiLineageWithReceipts,commitMultiLineageCancellation,compactMultiLineageHistory,inspectCommittedMultiLineage,lookupMultiLineageEvent,getMultiLineage,getMultiLineageHistory,getLineage,lookupLineageEvent,localOnly:true,checkoutEnabled:false,productionApproved:false});
}
