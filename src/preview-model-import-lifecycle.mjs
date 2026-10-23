/** One local preview import at a time; changes invalidate pending async reads. */
const reject=code=>{throw Object.assign(new Error(code),{code});};
function snapshot(input){
 if(!input||typeof input!=='object'||Array.isArray(input))reject('MODEL_CONTEXT_INVALID');
 const fields=['productId','surfaceId','variantId'];
 const d=Object.getOwnPropertyDescriptors(input);
 if(Object.keys(d).length!==fields.length||fields.some(k=>!Object.hasOwn(d[k]||{},'value')))reject('MODEL_CONTEXT_INVALID');
 const result=Object.fromEntries(fields.map(k=>[k,d[k].value]));
 if(fields.some(k=>typeof result[k]!=='string'||result[k].length>200)||!result.productId||!result.surfaceId)reject('MODEL_CONTEXT_INVALID');
 return Object.freeze(result);
}
export function createModelImportLifecycle({readContext}={}){
 if(typeof readContext!=='function')reject('MODEL_CONTEXT_READER_REQUIRED');
 let epoch=0,active=null;
 function invalidate(){epoch++;active=null;}
 function begin(){invalidate();active=Object.freeze({epoch,context:snapshot(readContext())});return active;}
 function current(token){if(!token||token!==active||token.epoch!==epoch)return false;
  try{const now=snapshot(readContext());return Object.keys(token.context).every(k=>token.context[k]===now[k]);}catch{return false;}}
 function commit(token,fn){if(typeof fn!=='function')reject('MODEL_COMMIT_INVALID');if(!current(token))return false;
  invalidate();fn();return true;}
 return Object.freeze({begin,invalidate,current,commit,localOnly:true,authorizesManufacturing:false});
}
