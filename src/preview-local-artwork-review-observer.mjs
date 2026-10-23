/** Objective 35AA: portable, independently RETAINED, observer-signed journal-head
 * receipts and read-only split-view detection. The trusted caller supplies the
 * already-authenticated 35Z journal, observer keys and externally saved pins.
 * No network, durable external witness, custody proof or mutation authority.
 */
import {createHash,sign as edSign,verify as edVerify} from 'node:crypto';
import {LOCAL_REVIEW_JOURNAL_SCHEMA,LOCAL_REVIEW_JOURNAL_MAX_RECORDS,localArtworkReviewJournalGenesisHead} from './preview-local-artwork-review-journal.mjs';

export const LOCAL_REVIEW_OBSERVER_SCHEMA='TJ-LOCAL-REVIEW-OBSERVER-35AA-1';
const HEX=/^[a-f0-9]{64}$/;
const IDENT=/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SIG=/^[A-Za-z0-9_-]{86}$/;
const BODY=['schema','journalSchema','rootPin','observerId','keyId','observedAt',
 'sequence','previousReceiptDigest','head','recordDigests','authority'];
const ALL=[...BODY,'signature','receiptDigest'];
const DOMAIN='TRENDYJOES_LOCAL_REVIEW_OBSERVER_35AA_V1\n';
const hash=b=>createHash('sha256').update(b).digest('hex');
const fail=code=>{throw Object.assign(new Error(code),{code});};
const plain=o=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o));
const exact=(o,keys)=>plain(o)&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value'in d&&d.enumerable;});
const headValid=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&
 h.count>=0&&h.count<=LOCAL_REVIEW_JOURNAL_MAX_RECORDS&&typeof h.headDigest==='string'&&HEX.test(h.headDigest);
const keyValid=(k,type)=>k?.type===type&&k?.asymmetricKeyType==='ed25519';
const signedBytes=body=>Buffer.from(DOMAIN+JSON.stringify(body),'utf8');
const receiptDigest=(body,signature)=>hash('TJ-35AA-RECEIPT\n'+JSON.stringify({...body,signature}));
const genesisReceiptDigest=hash('TJ-35AA-RECEIPT-GENESIS\n'+LOCAL_REVIEW_OBSERVER_SCHEMA);
const validTime=n=>Number.isSafeInteger(n)&&n>0&&n<=8640000000000000;
const historyValid=(history,head)=>Array.isArray(history)&&
 Reflect.ownKeys(history).length===history.length+1&&
 history.length===head.count&&history.length<=LOCAL_REVIEW_JOURNAL_MAX_RECORDS&&
 history.every((d,i)=>Object.hasOwn(history,i)&&typeof d==='string'&&HEX.test(d))&&
 (head.count?history.at(-1)===head.headDigest:head.headDigest===localArtworkReviewJournalGenesisHead().headDigest);
const frozenResult=(receipt,fp)=>Object.freeze({receipt:Object.freeze({...receipt,
  head:Object.freeze({...receipt.head}),recordDigests:Object.freeze([...receipt.recordDigests])}),
  observerKeyFingerprint:fp,signatureVerified:true,externallyWitnessed:false,
  trustedTime:false,observerKeyCustodyVerified:false,authorizesDeletion:false,
  authorizesQuarantine:false,authorizesProduction:false,shopifyWritesAllowed:false});

/** The public key resolver MUST be caller-trusted; the receipt contains no key. */
export async function verifyLocalReviewObserverReceipt(receipt,{resolveObserverPublicKey,expectedRootPin}={}){
 if(typeof resolveObserverPublicKey!=='function'||typeof expectedRootPin!=='string'||!HEX.test(expectedRootPin))
  fail('LOCAL_REVIEW_OBSERVER_INVALID_OPTIONS');
 if(!exact(receipt,ALL))fail('LOCAL_REVIEW_OBSERVER_MALFORMED');
 const body=Object.fromEntries(BODY.map(k=>[k,receipt[k]]));
 if(body.schema!==LOCAL_REVIEW_OBSERVER_SCHEMA||body.journalSchema!==LOCAL_REVIEW_JOURNAL_SCHEMA||
  body.rootPin!==expectedRootPin||typeof body.observerId!=='string'||!IDENT.test(body.observerId)||
  typeof body.keyId!=='string'||!IDENT.test(body.keyId)||
  !validTime(body.observedAt)||!Number.isSafeInteger(body.sequence)||body.sequence<1||
  body.sequence>1000000||typeof body.previousReceiptDigest!=='string'||!HEX.test(body.previousReceiptDigest)||
  (body.sequence===1&&body.previousReceiptDigest!==genesisReceiptDigest)||
  !headValid(body.head)||!historyValid(body.recordDigests,body.head)||body.authority!=='NONE'||
  typeof receipt.signature!=='string'||!SIG.test(receipt.signature)||
  typeof receipt.receiptDigest!=='string'||!HEX.test(receipt.receiptDigest))
  fail('LOCAL_REVIEW_OBSERVER_MALFORMED');
 const signature=Buffer.from(receipt.signature,'base64url');
 if(signature.length!==64||signature.toString('base64url')!==receipt.signature||
  receiptDigest(body,receipt.signature)!==receipt.receiptDigest)fail('LOCAL_REVIEW_OBSERVER_TAMPERED');
 let publicKey;
 try{publicKey=await resolveObserverPublicKey(body.observerId,body.keyId);}catch{fail('LOCAL_REVIEW_OBSERVER_UNTRUSTED_KEY');}
 if(!keyValid(publicKey,'public'))fail('LOCAL_REVIEW_OBSERVER_UNTRUSTED_KEY');
 if(!edVerify(null,signedBytes(body),publicKey,signature))fail('LOCAL_REVIEW_OBSERVER_BAD_SIGNATURE');
 return frozenResult(receipt,hash(publicKey.export({type:'spki',format:'der'})));
}

/** Calls 35Z.inspect with an OUT-OF-BAND pinned head before signing. The journal
 * object must originate from the trusted local implementation, not untrusted UI.
 * A previous receipt must be supplied for sequence > 1; it is not stored here.
 */
export async function issueLocalReviewObserverReceipt({journal,expectedHead,resolveReviewPublicKey,
 rootPin,observerId,keyId,signingKey,observedAt=Date.now(),previousReceipt,
 resolveObserverPublicKey}={}){
 if(!journal||typeof journal.inspect!=='function'||!headValid(expectedHead)||
  typeof resolveReviewPublicKey!=='function'||typeof rootPin!=='string'||!HEX.test(rootPin)||
  typeof observerId!=='string'||!IDENT.test(observerId)||typeof keyId!=='string'||!IDENT.test(keyId)||
  !keyValid(signingKey,'private')||!validTime(observedAt)||
  typeof resolveObserverPublicKey!=='function')
  fail('LOCAL_REVIEW_OBSERVER_INVALID_OPTIONS');
 let prior;
 if(previousReceipt!==undefined){
  prior=await verifyLocalReviewObserverReceipt(previousReceipt,{resolveObserverPublicKey,expectedRootPin:rootPin});
  if(prior.receipt.observerId!==observerId||prior.receipt.keyId!==keyId)
   fail('LOCAL_REVIEW_OBSERVER_WRONG_PREDECESSOR');
 }
 const report=await journal.inspect({expectedHead,resolvePublicKey:resolveReviewPublicKey});
 if(!report||report.historySignaturesVerified!==true||report.independentlyWitnessed!==false||
  report.shopifyWritesAllowed!==false||report.authorizesProduction!==false||
  !headValid(report.head)||report.head.count!==expectedHead.count||
  report.head.headDigest!==expectedHead.headDigest||!Array.isArray(report.entries))
  fail('LOCAL_REVIEW_OBSERVER_UNVERIFIED_JOURNAL');
 const history=[];
 if(report.entries.length!==report.head.count)fail('LOCAL_REVIEW_OBSERVER_UNVERIFIED_JOURNAL');
 for(let i=0;i<report.entries.length;i++){
  const entry=report.entries[i];
  if(!plain(entry)||entry.index!==i+1||entry.rootPin!==rootPin||
   typeof entry.recordDigest!=='string'||!HEX.test(entry.recordDigest)||
   entry.authority!=='NONE')fail('LOCAL_REVIEW_OBSERVER_UNVERIFIED_JOURNAL');
  history.push(entry.recordDigest);
 }
 if(!historyValid(history,report.head))fail('LOCAL_REVIEW_OBSERVER_UNVERIFIED_JOURNAL');
 if(prior){
  if(history.length<=prior.receipt.recordDigests.length||
   prior.receipt.recordDigests.some((d,i)=>history[i]!==d))
   fail('LOCAL_REVIEW_OBSERVER_NON_EXTENSION');
 }
 const body={schema:LOCAL_REVIEW_OBSERVER_SCHEMA,journalSchema:LOCAL_REVIEW_JOURNAL_SCHEMA,
  rootPin,observerId,keyId,observedAt,sequence:prior?prior.receipt.sequence+1:1,
  previousReceiptDigest:prior?prior.receipt.receiptDigest:genesisReceiptDigest,
  head:{...report.head},recordDigests:history,authority:'NONE'};
 if(body.sequence>1000000)fail('LOCAL_REVIEW_OBSERVER_INVALID_OPTIONS');
 const signature=edSign(null,signedBytes(body),signingKey).toString('base64url');
 const receipt={...body,signature,receiptDigest:receiptDigest(body,signature)};
 // Reject a signing key that does not match the caller-trusted observer registry.
 await verifyLocalReviewObserverReceipt(receipt,{resolveObserverPublicKey,expectedRootPin:rootPin});
 return Object.freeze({...receipt,head:Object.freeze(receipt.head),recordDigests:Object.freeze(history)});
}

/** Receipts and pins are caller-supplied; the pins MUST have been retained
 * outside the journal. Signatures establish authenticity, not independent
 * custody, trusted time or that the observer actually inspected the journal.
 */
export async function reconcileLocalReviewObserverReceipts({receipts,pins,
 resolveObserverPublicKey,expectedRootPin}={}){
 if(!Array.isArray(receipts)||!Array.isArray(pins)||!receipts.length||!pins.length||
  receipts.length>32||pins.length>32||typeof resolveObserverPublicKey!=='function')
  fail('LOCAL_REVIEW_OBSERVER_EXTERNAL_PINS_REQUIRED');
 const checked=[];
 for(const r of [...pins,...receipts])checked.push(await verifyLocalReviewObserverReceipt(r,
  {resolveObserverPublicKey,expectedRootPin}));
 const pinsChecked=checked.slice(0,pins.length),current=checked.slice(pins.length);
 const pinDigests=new Set(pinsChecked.map(v=>v.receipt.receiptDigest));
 if(pinDigests.size!==pinsChecked.length||
  current.some(v=>pinDigests.has(v.receipt.receiptDigest))||
  new Set(current.map(v=>v.receipt.receiptDigest)).size!==current.length)
  fail('LOCAL_REVIEW_OBSERVER_REPLAYED_RECEIPT');
 const byObserver=new Map(),fingerprints=new Map();
 for(const v of checked){
  const r=v.receipt,identity=r.observerId+':'+r.keyId;
  if(fingerprints.has(r.observerId)&&fingerprints.get(r.observerId)!==v.observerKeyFingerprint)
   fail('LOCAL_REVIEW_OBSERVER_KEY_CHANGED');
  fingerprints.set(r.observerId,v.observerKeyFingerprint);
  const prior=byObserver.get(identity)||[];prior.push(r);byObserver.set(identity,prior);
 }
 if(new Set(fingerprints.values()).size!==fingerprints.size)
  fail('LOCAL_REVIEW_OBSERVER_SHARED_KEY');
 for(const group of byObserver.values()){
  if(group.length===1&&group[0].sequence>1)fail('LOCAL_REVIEW_OBSERVER_CHAIN_GAP');
  group.sort((a,b)=>a.sequence-b.sequence);
  if(group[0].sequence>1)fail('LOCAL_REVIEW_OBSERVER_CHAIN_GAP');
  for(let i=1;i<group.length;i++){
   const a=group[i-1],b=group[i];
   if(a.sequence===b.sequence){
    if(a.receiptDigest!==b.receiptDigest)fail('LOCAL_REVIEW_OBSERVER_EQUIVOCATION');
   }else if(b.sequence===a.sequence+1){
    if(b.previousReceiptDigest!==a.receiptDigest)fail('LOCAL_REVIEW_OBSERVER_CHAIN_BROKEN');
   }else fail('LOCAL_REVIEW_OBSERVER_CHAIN_GAP');
  }
 }
 for(let i=0;i<checked.length;i++)for(let j=i+1;j<checked.length;j++){
  const a=checked[i].receipt,b=checked[j].receipt;
  const common=Math.min(a.recordDigests.length,b.recordDigests.length);
  for(let k=0;k<common;k++)if(a.recordDigests[k]!==b.recordDigests[k])
   fail('LOCAL_REVIEW_OBSERVER_SPLIT_VIEW');
  if(a.head.count===b.head.count&&a.head.headDigest!==b.head.headDigest)
   fail('LOCAL_REVIEW_OBSERVER_SPLIT_VIEW');
 }
 for(const r of current)for(const p of pinsChecked)
  if(r.receipt.head.count<p.receipt.head.count)fail('LOCAL_REVIEW_OBSERVER_ROLLBACK');
 const max=current.reduce((a,b)=>a.receipt.head.count>=b.receipt.head.count?a:b).receipt;
 return Object.freeze({schema:LOCAL_REVIEW_OBSERVER_SCHEMA,status:'CONSISTENT_WITH_SUPPLIED_EXTERNAL_PINS',
  head:Object.freeze({...max.head}),verifiedReceipts:checked.length,
  distinctObserverKeys:fingerprints.size,cryptographicallyDistinctObserverKeys:fingerprints.size>=2,
  independentlyRetainedPinsVerified:false,observerKeyCustodyVerified:false,trustedTime:false,
  independentlyWitnessed:false,authorizesDeletion:false,authorizesQuarantine:false,
  authorizesProduction:false,shopifyWritesAllowed:false});
}
