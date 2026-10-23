/** Shared pure draft-change guard used by the local editor and regression tests.
 * This guards against binding an old saved design when the onscreen draft changed.
 * Not a cryptographic commitment, server validation, or shopping authorization.
 */
export function editorSnapshot(productManifestId,layers,previewSelection=undefined){
 if(typeof productManifestId!=='string'||!productManifestId||!Array.isArray(layers))throw new TypeError('INVALID_EDITOR_STATE');
 return JSON.stringify({productManifestId,layers,...(previewSelection===undefined?{}:{previewSelection})});
}
export function savedDraftMatchesEditor({productManifestId,layers,previewSelection=undefined,saved,savedSnapshot}){
 if(!saved||typeof saved.reference!=='string'||!Number.isSafeInteger(saved.revision)||saved.revision<1||typeof savedSnapshot!=='string')return false;
 try{return editorSnapshot(productManifestId,layers,previewSelection)===savedSnapshot;}catch{return false;}
}

/** Discard an asynchronous readiness response when the shopper has changed any
 * product, variant, on-screen composition, reference, or saved revision.
 */
export function reviewSelectionMatches({productManifestId,layers,previewSelection=undefined,saved,savedSnapshot,productGid,variantGid,requested}){
 return savedDraftMatchesEditor({productManifestId,layers,previewSelection,saved,savedSnapshot})&&
  !!requested&&requested.reference===saved.reference&&requested.expectedRevision===saved.revision&&
  requested.productGid===productGid&&requested.variantGid===variantGid;
}
