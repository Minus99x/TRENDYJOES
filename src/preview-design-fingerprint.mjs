/** Unforgeable within one local session only; SHA is content integrity, NOT authority. */
const fail=code=>{throw Object.assign(new Error(code),{code});};
export async function fingerprintConceptEvidence(packet,{digest}={}){
 if(!packet||packet.schema!=='TJ-LOCAL-CONCEPT-DESIGN-EVIDENCE-1'||
  packet.checkoutEnabled!==false||packet.manufacturingApproved!==false||packet.privateContentIncluded!==false||
  packet.customerAuthenticated===true||packet.pricingVerified===true||packet.cartLine!=null||packet.orderId!=null)fail('CONCEPT_EVIDENCE_SCHEMA');
 const canonical=JSON.stringify(packet);
 if(typeof canonical!=='string'||canonical.length>150000)fail('CONCEPT_EVIDENCE_SIZE');
 const bytes=new TextEncoder().encode(canonical);
 const digestFn=digest??(async input=>{
  const subtle=globalThis.crypto?.subtle;
  if(!subtle||typeof subtle.digest!=='function')fail('CONCEPT_EVIDENCE_SECURE_CONTEXT_REQUIRED');
  return subtle.digest('SHA-256',input);
 });
 const binary=await digestFn(bytes);
 if(!(binary instanceof ArrayBuffer)||binary.byteLength!==32)fail('CONCEPT_EVIDENCE_DIGEST');
 return Object.freeze({schema:'TJ-LOCAL-CONCEPT-FINGERPRINT-1',digestSha256:[...new Uint8Array(binary)].map(x=>x.toString(16).padStart(2,'0')).join(''),
  bytes:bytes.byteLength,localOnly:true,manufacturingApproved:false,checkoutEnabled:false});
}
