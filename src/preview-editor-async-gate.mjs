/** Objective 35R: fail-closed local editor async result gate. No hosted authority. */
const fail=code=>{throw Object.assign(new Error(code),{code});};
const keys=['productManifestId','surfaceId','variantGid','reference','revision'];
const copyBinding=value=>{
 if(!value||typeof value!=='object'||Array.isArray(value))fail('EDITOR_ASYNC_BINDING_INVALID');
 let d;try{d=Object.getOwnPropertyDescriptors(value);}catch{fail('EDITOR_ASYNC_BINDING_INVALID');}
 if(Object.keys(d).length!==keys.length||keys.some(k=>!Object.hasOwn(d,k)||!Object.hasOwn(d[k],'value')))
  fail('EDITOR_ASYNC_BINDING_INVALID');
 const b=Object.fromEntries(keys.map(k=>[k,d[k].value]));
 if(typeof b.productManifestId!=='string'||!b.productManifestId||b.productManifestId.length>100||
  typeof b.surfaceId!=='string'||!b.surfaceId||b.surfaceId.length>100||
  typeof b.variantGid!=='string'||b.variantGid.length>200||
  !(b.reference===null||(typeof b.reference==='string'&&/^TJ-[A-F0-9]{24}$/.test(b.reference)))||
  !(b.revision===null||(Number.isSafeInteger(b.revision)&&b.revision>0))||
  (b.reference===null)!==(b.revision===null))fail('EDITOR_ASYNC_BINDING_INVALID');
 return Object.freeze(b);
};
export function createPreviewEditorAsyncGate({readBinding}={}){
 if(typeof readBinding!=='function')fail('EDITOR_ASYNC_CONFIGURATION');
 let generation=0,active=null;
 function invalidate(){generation++;active=null;}
 function begin(kind){
  if(!['artwork','model','save'].includes(kind))fail('EDITOR_ASYNC_KIND_INVALID');
  invalidate();const binding=copyBinding(readBinding());
  active=Object.freeze({kind,generation,binding});return active;
 }
 function current(ticket){
  if(!active||ticket!==active||ticket.generation!==generation)return false;
  try{const now=copyBinding(readBinding());return keys.every(k=>now[k]===ticket.binding[k]);}catch{return false;}
 }
 function commit(ticket,fn){
  if(typeof fn!=='function')fail('EDITOR_ASYNC_COMMIT_INVALID');
  if(!current(ticket))return Object.freeze({applied:false});
  invalidate(); // consume before invoking side effects; reentrant/replayed commit refused
  return Object.freeze({applied:true,value:fn()});
 }
 return Object.freeze({begin,current,commit,invalidate,localOnly:true,checkoutEnabled:false});
}
/** Validate the exact local test server artwork response before retaining a grant. */
export function validateLocalArtworkReceipt(value,{mediaType,bytes}={}){
 if(!value||typeof value!=='object'||Array.isArray(value))fail('EDITOR_ARTWORK_RECEIPT_INVALID');
 let d;try{d=Object.getOwnPropertyDescriptors(value);}catch{fail('EDITOR_ARTWORK_RECEIPT_INVALID');}
 const fields=['id','grant','width','height','mediaType','bytes'];
 if(Object.keys(d).length!==fields.length||fields.some(k=>!Object.hasOwn(d,k)||!Object.hasOwn(d[k],'value')))
  fail('EDITOR_ARTWORK_RECEIPT_INVALID');
 const x=Object.fromEntries(fields.map(k=>[k,d[k].value]));
 if(!/^art_[a-f0-9]{32}$/.test(x.id)||!/^[a-f0-9]{64}$/.test(x.grant)||
  !Number.isSafeInteger(x.width)||x.width<1||x.width>50000||
  !Number.isSafeInteger(x.height)||x.height<1||x.height>50000||
  !['image/jpeg','image/png','image/webp'].includes(x.mediaType)||x.mediaType!==mediaType||
  !Number.isSafeInteger(x.bytes)||x.bytes<1||x.bytes>5*1024*1024||x.bytes!==bytes)
  fail('EDITOR_ARTWORK_RECEIPT_INVALID');
 return Object.freeze(x);
}
