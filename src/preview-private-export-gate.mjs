/** Race-safe explicitly invoked local download. No storage, network or order mutation. */
import {fingerprintConceptEvidence} from './preview-design-fingerprint.mjs';
const fail=code=>{throw Object.assign(new Error(code),{code});};
export async function preparePrivateConceptExport({readSnapshot,fingerprint=fingerprintConceptEvidence,readRevision}={}){
 if(typeof readSnapshot!=='function')fail('EXPORT_READER_REQUIRED');
 if(readRevision!==undefined&&typeof readRevision!=='function')fail('EXPORT_REVISION_READER');
 const revision=readRevision?.();
 if(readRevision&&(!Number.isSafeInteger(revision)||revision<0))fail('EXPORT_REVISION_INVALID');
 const first=readSnapshot(),serialized=JSON.stringify(first);
 if(typeof serialized!=='string'||serialized.length>150000)fail('EXPORT_INVALID');
 const signature=await fingerprint(first);
 if(!signature||signature.schema!=='TJ-LOCAL-CONCEPT-FINGERPRINT-1'||
  typeof signature.digestSha256!=='string'||!(/^[0-9a-f]{64}$/.test(signature.digestSha256))||
  !Number.isSafeInteger(signature.bytes)||signature.bytes<0||signature.localOnly!==true||
  signature.checkoutEnabled!==false||signature.manufacturingApproved!==false)fail('EXPORT_INTEGRITY_INVALID');
 const again=JSON.stringify(readSnapshot());
 // An ABA edit (change, then restore identical content during hashing) must
 // also invalidate the export. Revision is monotonic per local editor session.
 if(again!==serialized||(readRevision&&readRevision()!==revision))fail('EXPORT_STALE_EDITOR');
 const freezeDeep=(value)=>{if(value&&typeof value==='object'){for(const v of Object.values(value))freezeDeep(v);Object.freeze(value);}return value;};
 const detached=freezeDeep(JSON.parse(serialized));
 return Object.freeze({schema:'TJ-PRIVATE-CONCEPT-EXPORT-1',scope:'LOCAL_REDACTED_ONLY',
  evidence:detached,integrity:Object.freeze({...signature}),manufacturingApproved:false,checkoutEnabled:false,orderId:null});
}
