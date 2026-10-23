/** Objective 35K: ephemeral, opt-in, customer-facing MULTI-design preview review.
 * Only the loopback prototype receives local owner capabilities. This module
 * never creates cart lines, Shopify sessions, receipts or order observations.
 * The client cannot confer purchase/manufacturing authorization.
 */
const fail=code=>{throw Object.assign(new Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const exact=(x,keys)=>obj(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
const keys=['reference','revision','ownerToken','productManifestId','productLabel','productGid','variantGid'];
const responseKeys=['schema','scope','reference','revision','productGid','variantGid','compositionSha256',
 'previewValid','localOwnerChecked','shopifyCustomerAuthenticated','catalogCurrent','priceApproved',
 'productionReady','checkoutEnabled','cartLine','cartMutation','checkoutUrl','shopifyOrderId','blockers','checks'];
const ref=/^TJ-[A-F0-9]{24}$/;
const token=/^[a-f0-9]{64}$/;
const digest=/^[a-f0-9]{64}$/;
const id=/^[a-z][a-z0-9-]{0,63}$/;
const gid=kind=>new RegExp(`^gid:\/\/shopify\/${kind}\/[1-9][0-9]*$`);
const required=['CURRENT_CATALOG','ACTIVE_PURCHASABLE_VARIANT','AUTHORITATIVE_PRICE',
 'CUSTOMER_AUTHENTICATION','PRIVATE_ARTWORK_STORAGE','MANUFACTURING_APPROVAL','CHECKOUT_ORDER_RECONCILIATION'];
const allChecks=['LOCAL_DESIGN_OWNER','LOCAL_PRODUCT_VARIANT',...required];
const publicEntry=e=>Object.freeze({reference:e.reference,revision:e.revision,
 productManifestId:e.productManifestId,productLabel:e.productLabel,
 selected:e.selected,scope:'OFFLINE_PREVIEW_ONLY'});
export function validateEntry(e){
 if(!exact(e,keys)||!ref.test(e.reference)||!Number.isSafeInteger(e.revision)||e.revision<1||
  !token.test(e.ownerToken)||!id.test(e.productManifestId)||typeof e.productLabel!=='string'||
  !e.productLabel.trim()||e.productLabel.length>120||!gid('Product').test(e.productGid)||
  !gid('ProductVariant').test(e.variantGid))fail('MULTI_PREVIEW_ENTRY_INVALID');
}
export function validateReadiness(r,e){
 if(!exact(r,responseKeys)||r.schema!=='TJ-CUSTOMER-CART-READINESS-1'||
  r.scope!=='OFFLINE_PREVIEW_ONLY'||r.reference!==e.reference||r.revision!==e.revision||
  r.productGid!==e.productGid||r.variantGid!==e.variantGid||!digest.test(r.compositionSha256)||
  r.previewValid!==true||r.localOwnerChecked!==true||r.shopifyCustomerAuthenticated!==false||
  r.catalogCurrent!==false||r.priceApproved!==false||r.productionReady!==false||
  r.checkoutEnabled!==false||r.cartLine!==null||r.cartMutation!==null||
  r.checkoutUrl!==null||r.shopifyOrderId!==null||!Array.isArray(r.blockers)||
  r.blockers.length!==required.length||required.some(x=>!r.blockers.includes(x))||
  !Array.isArray(r.checks)||r.checks.length!==allChecks.length||
  r.checks.some((c,i)=>!exact(c,['id','status','reason'])||c.id!==allChecks[i]||
   c.status!==(i===0?'LOCAL_ONLY':i===1?'SNAPSHOT_ONLY':'BLOCKED')||
   typeof c.reason!=='string'||!c.reason.trim()))fail('MULTI_PREVIEW_READINESS_UNTRUSTED');
 return r.compositionSha256;
}
export function createLocalMultiDesignReview({readReadiness}={}){
 if(typeof readReadiness!=='function')fail('MULTI_PREVIEW_CONFIGURATION');
 const entries=new Map();let epoch=0;
 function add(entry){
  validateEntry(entry);
  if(!entries.has(entry.reference)&&entries.size>=25)fail('MULTI_PREVIEW_LIMIT');
  const prev=entries.get(entry.reference);
  // Never keep an older saved revision after an updated one was added.
  if(prev&&entry.revision<prev.revision)fail('MULTI_PREVIEW_STALE_CAPTURE');
  entries.set(entry.reference,{...Object.fromEntries(keys.map(k=>[k,entry[k]])),selected:prev?.selected??true});
  epoch++;return list();
 }
 /** Atomic recovered insertion: validate selection, binding and capacity before
  * one Map commit. Never implement recovery as add() followed by select().
  * Duplicate references are refused, including a different owner or variant.
  */
 function restore(entry,selected){
  if(typeof selected!=='boolean')fail('MULTI_PREVIEW_RESTORE_SELECTION_INVALID');
  // Read each field exactly once through an own data descriptor. Refuse
  // getters/proxies that could swap a reference between validation and commit.
  let descriptors;
  try{descriptors=Object.getOwnPropertyDescriptors(entry);}catch{fail('MULTI_PREVIEW_ENTRY_INVALID');}
  if(Object.keys(descriptors).length!==keys.length||
   keys.some(k=>!Object.hasOwn(descriptors,k)||!Object.hasOwn(descriptors[k],'value')))
   fail('MULTI_PREVIEW_ENTRY_INVALID');
  const saved=Object.fromEntries(keys.map(k=>[k,descriptors[k].value]));
  validateEntry(saved);
  if(entries.has(saved.reference))fail('MULTI_PREVIEW_RESTORE_DUPLICATE');
  if(entries.size>=25)fail('MULTI_PREVIEW_LIMIT');
  entries.set(saved.reference,{...saved,selected});epoch++;
  return list();
 }
 function remove(reference){if(entries.delete(reference))epoch++;return list();}
 function select(reference,selected){
  if(typeof selected!=='boolean'||!entries.has(reference))fail('MULTI_PREVIEW_SELECTION_INVALID');
  if(entries.get(reference).selected!==selected){entries.get(reference).selected=selected;epoch++;}
  return list();
 }
 function clear(){if(entries.size){entries.clear();epoch++;}return list();}
 function list(){return Object.freeze([...entries.values()].map(publicEntry));}
 function checklistEntries(){return Object.freeze([...entries.values()].map(e=>Object.freeze({
  reference:e.reference,revision:e.revision,
  productManifestId:e.productManifestId,productLabel:e.productLabel,
  productGid:e.productGid,variantGid:e.variantGid,selected:e.selected})));}
 async function review(){
  const chosen=[...entries.values()].filter(e=>e.selected).map(e=>({...e}));
  if(chosen.length<2||chosen.length>25)fail('MULTI_PREVIEW_NEEDS_TWO');
  const start=epoch, hashes=[];
  const ensure=()=>{if(epoch!==start)fail('MULTI_PREVIEW_SELECTION_CHANGED');};
  // Two passes reject drafts changed during another line's asynchronous read.
  // This is a non-authorizing UI check, NOT an atomic production order commit.
  for(let pass=0;pass<2;pass++)for(let i=0;i<chosen.length;i++){
   ensure();const e=chosen[i];let result;
   try{result=await readReadiness(Object.freeze({reference:e.reference,expectedRevision:e.revision,
    productGid:e.productGid,variantGid:e.variantGid,ownerToken:e.ownerToken}));}
   catch{fail('MULTI_PREVIEW_READINESS_REFUSED');}
   ensure();const hash=validateReadiness(result,e);
   if(pass===0)hashes.push(hash);
   else if(hash!==hashes[i])fail('MULTI_PREVIEW_DESIGN_CHANGED');
  }
  ensure();
  return Object.freeze({schema:'TJ-MULTI-PREVIEW-REVIEW-1',scope:'OFFLINE_PREVIEW_ONLY',
   outcome:'BLOCKED_FOR_COMMERCE',lineCount:chosen.length,
   lines:Object.freeze(chosen.map((e,i)=>Object.freeze({...publicEntry(e),compositionSha256:hashes[i]}))),
   checkoutEnabled:false,shopifyCustomerAuthenticated:false,productionApproved:false,
   paymentVerified:false,cartLines:null,orderId:null});
 }
 return Object.freeze({add,restore,remove,select,clear,list,checklistEntries,review,localOnly:true,checkoutEnabled:false});
}
