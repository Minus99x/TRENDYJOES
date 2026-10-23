/** Future authenticated customer/guest app seam; no JWT verifier or hosted identity
 * is bundled here. A trusted backend MUST inject its real cryptographic verifier.
 * The request body, cookies and caller-provided `verified` booleans are NOT identities.
 */
const deny=code=>{throw Object.assign(new Error(code),{code,status:403});};
const shopPattern=/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/;
const customer=/^gid:\/\/shopify\/Customer\/[1-9][0-9]*$/;
const guest=/^guest:[A-Za-z0-9_-]{22,64}$/;
const safeString=(s,min,max)=>typeof s==='string'&&s.length>=min&&s.length<=max;
const validTime=t=>Number.isSafeInteger(t)&&t>=0;
// Objective 35D: the verifier is trusted to check signatures, but its claim
// projection still crosses an identity boundary. Never read inherited fields or
// invoke claim accessors: a polluted prototype could substitute an owner, and a
// throwing getter could expose private verifier internals in a raw exception.
// Accept only plain, own-data JSON claims (including null-prototype records).
const requiredClaims=['iss','aud','shop','sub','kind','sid','jti','iat','nbf','exp'];
function verifiedClaimData(claims){
 if(!claims||typeof claims!=='object'||Array.isArray(claims))deny('UNTRUSTED_PRINCIPAL');
 try{
  const prototype=Object.getPrototypeOf(claims);
  if(prototype!==Object.prototype&&prototype!==null)deny('UNTRUSTED_PRINCIPAL');
  const data=Object.create(null);
  for(const key of requiredClaims){
   const descriptor=Object.getOwnPropertyDescriptor(claims,key);
   if(!descriptor||!Object.prototype.hasOwnProperty.call(descriptor,'value'))deny('UNTRUSTED_PRINCIPAL');
   data[key]=descriptor.value;
  }
  return data;
 }catch{deny('UNTRUSTED_PRINCIPAL');}
}
/** `verifyBearer` is a trusted, server-only verifier which MUST check signature,
 * key provenance/rotation, token type, revocation and issuer/audience itself.
 * This function validates the returned claims, NOT token authenticity.
 */
export async function resolveTrustedPrincipal({authorizationHeader,verifyBearer,expectedShop,expectedIssuer,expectedAudience,now=Date.now()}={}){
 if(typeof verifyBearer!=='function')deny('VERIFIER_NOT_CONFIGURED');
 if(!shopPattern.test(expectedShop||'')||!safeString(expectedIssuer,8,300)||!safeString(expectedAudience,3,160)||!validTime(now))deny('TRUST_CONFIGURATION');
 if(typeof authorizationHeader!=='string'||authorizationHeader.length>8192||!/^Bearer [A-Za-z0-9._~-]{16,8000}$/.test(authorizationHeader))deny('BEARER_REQUIRED');
 let rawClaims;try{rawClaims=await verifyBearer(authorizationHeader.slice(7));}catch{deny('TOKEN_VERIFICATION_FAILED');}
 const claims=verifiedClaimData(rawClaims);
 if(claims.iss!==expectedIssuer||claims.aud!==expectedAudience||claims.shop!==expectedShop||
  !validTime(claims.iat)||!validTime(claims.nbf)||!validTime(claims.exp)||claims.iat>now+60_000||claims.nbf>now||claims.exp<=now||
  claims.exp-claims.iat>24*60*60_000||claims.exp<=claims.iat||
  !safeString(claims.sid,16,160)||!safeString(claims.jti,16,160)||
  !(typeof claims.sub==='string'&&((claims.kind==='customer'&&customer.test(claims.sub))||(claims.kind==='guest'&&guest.test(claims.sub)))))deny('UNTRUSTED_PRINCIPAL');
 // Never return bearer, signature, ownerToken, secret, or raw verifier claims.
 return Object.freeze({schema:'TJ-TRUSTED-PRINCIPAL-1',shop:claims.shop,subject:claims.sub,kind:claims.kind,
  sessionId:claims.sid,expiresAt:claims.exp,checkoutEnabled:false,productionReady:false});
}
