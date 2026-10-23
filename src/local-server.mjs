/** Local proof API: binds loopback ONLY; not a public service or Shopify production backend. */
import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {resolve,join,extname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {LocalDesignStore} from './local-store.mjs';
import {MANIFEST_BY_ID} from './catalog.mjs';
import {createStagingRegistry} from './shopify-bridge.mjs';
import {createCatalogRefreshRegistry} from './catalog-refresh.mjs';
import {prepareStagingBinding} from './shopify-intents.mjs';
import {reviewCustomerCartReadiness} from './customer-cart-readiness.mjs';
import {LocalPreviewCapabilityAuthority} from './preview-capabilities.mjs';
const projectRoot=resolve(fileURLToPath(new URL('..',import.meta.url)));
const mime={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.mjs':'text/javascript; charset=utf-8','.js':'text/javascript; charset=utf-8','.svg':'image/svg+xml'};
const hdr={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Cross-Origin-Resource-Policy':'same-origin','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'self'; connect-src 'self'; img-src 'self' blob: data:; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"};
function respond(res,status,obj){res.writeHead(status,{...hdr,'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(obj));}
function token(req){const s=req.headers.authorization||'';return s.startsWith('Bearer ')?s.slice(7):'';}
async function readBody(req,max){
 const parts=[];let size=0;
 for await(const chunk of req){size+=chunk.length;if(size>max)throw Object.assign(new Error('Payload too large'),{status:413});parts.push(chunk);}
 return Buffer.concat(parts);
}
function validateOrigin(req){const origin=req.headers.origin;if(!origin)return;
 const parsed=new URL(origin);if(!['127.0.0.1','localhost','[::1]'].includes(parsed.hostname))throw Object.assign(new Error('Cross-origin writes disabled'),{status:403});
}
function stagingIdentity(input){
 return {reference:input?.reference,expectedRevision:input?.expectedRevision,productGid:input?.productGid,variantGid:input?.variantGid};
}
async function jsonInput(req){
 if(!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type']||''))throw Object.assign(new Error('JSON content-type required'),{status:415});
 const bytes=await readBody(req,256*1024);let data;try{data=JSON.parse(bytes.toString('utf8'));}catch{throw Object.assign(new Error('Invalid JSON'),{status:400});}return data;
}
export async function createLocalServer({dataDir=join(projectRoot,'.tj-local-data'),host='127.0.0.1',shopifySnapshot=[],catalogCaptureOptions=null}={}){
 if(!['127.0.0.1','::1'].includes(host))throw new Error('Local studio may only bind loopback');
 const verifiedCapture=catalogCaptureOptions===null?null:createCatalogRefreshRegistry(catalogCaptureOptions);
 const registry=verifiedCapture?.registry??createStagingRegistry(shopifySnapshot);
 const extensions=Object.fromEntries(registry.entries.filter(e=>e.manifest&&!e.issues.length).map(e=>[e.manifest.id,e.manifest]));
 const store=new LocalDesignStore(dataDir,{manifests:{...MANIFEST_BY_ID,...extensions}});await store.init();
 const previewAuthority=new LocalPreviewCapabilityAuthority();
 const server=http.createServer(async(req,res)=>{
  try{
   const path=new URL(req.url,'http://localhost').pathname;
   if(path==='/api/health'&&req.method==='GET')return respond(res,200,{ok:true,scope:'LOCAL_DEVELOPMENT_ONLY',checkoutEnabled:false});
   if(path.startsWith('/api/')){
    if(['POST','PUT','PATCH','DELETE'].includes(req.method))validateOrigin(req);
    if(path==='/api/shopify/staging-products'&&req.method==='GET')return respond(res,200,{
     source:verifiedCapture?'VALIDATED_OFFLINE_CATALOG_CAPTURE':'READ_ONLY_SNAPSHOT',checkoutEnabled:false,
     captureDigest:verifiedCapture?.capture.digest??null,entries:registry.entries.map(e=>({
      productGid:e.product.id,title:e.product.title,status:e.product.status,manifestId:e.manifest?.id??null,
      variantGids:e.product.variants.map(v=>v.id),manifest:e.manifest,customizable:e.customizable,issues:e.issues.map(i=>i.code),productionReady:false
     }))});
    if(path==='/api/shopify/catalog-evidence'&&req.method==='GET')return respond(res,200,{
     schema:'TJ-LOCAL-CATALOG-EVIDENCE-1',sourceAuthenticated:false,checkoutEnabled:false,productionReady:false,
     shop:verifiedCapture?.capture.shop??null,scope:verifiedCapture?.capture.scope??'UNVERIFIED_FIXTURE',
     digest:verifiedCapture?.capture.digest??null,capturedAt:verifiedCapture?.capture.capturedAt??null});
    if(path==='/api/shopify/preview-binding'&&req.method==='POST'){
     const input=await jsonInput(req);
     const binding=await prepareStagingBinding({store,registry,...stagingIdentity(input),ownerToken:token(req)});
     return respond(res,200,binding);
    }
    if(path==='/api/shopify/cart-readiness'&&req.method==='POST'){
     const input=await jsonInput(req);
     // Never accept untrusted client 'approved', 'checkoutEnabled', or 'cartLine' fields.
     return respond(res,200,await reviewCustomerCartReadiness({store,registry,...stagingIdentity(input),ownerToken:token(req)}));
    }
    // Local security integration exercise only: owner-authenticated, one-use,
    // five-minute preview capability; no Shopify cart/order entry point.
    if(path==='/api/shopify/preview-capability'&&req.method==='POST'){
     const input=await jsonInput(req);
     return respond(res,200,await previewAuthority.issue({store,registry,...stagingIdentity(input),ownerToken:token(req)}));
    }
    if(path==='/api/shopify/consume-preview-capability'&&req.method==='POST'){
     const input=await jsonInput(req);
     return respond(res,200,await previewAuthority.consume({store,registry,...stagingIdentity(input),token:input?.token,ownerToken:token(req)}));
    }
    if(path==='/api/artworks'&&req.method==='POST'){
     const bytes=await readBody(req,5*1024*1024+1);
     const media=await store.putArtwork(bytes,req.headers['content-type']);return respond(res,201,media);
    }
    const asset=/^\/api\/artworks\/(art_[a-f0-9]{32})$/.exec(path);
    if(asset&&req.method==='GET'){
     const {bytes,meta}=await store.readArtwork(asset[1],token(req));
     res.writeHead(200,{...hdr,'Content-Type':meta.mediaType,'Content-Length':bytes.length,'Content-Disposition':'attachment; filename="preview-artwork.'+meta.extension+'"'});return res.end(bytes);
    }
    if(path==='/api/designs'&&req.method==='POST')return respond(res,201,await store.putDesign(await jsonInput(req)));
    const read=/^\/api\/designs\/(TJ-[A-F0-9]{24})$/.exec(path);
    if(read&&req.method==='GET')return respond(res,200,await store.getDesign(read[1],token(req)));
    const rev=/^\/api\/designs\/(TJ-[A-F0-9]{24})\/revisions$/.exec(path);
    if(rev&&req.method==='POST')return respond(res,201,await store.reviseDesign(rev[1],token(req),await jsonInput(req)));
    const old=/^\/api\/designs\/(TJ-[A-F0-9]{24})\/revisions\/([1-9][0-9]*)$/.exec(path);
    if(old&&req.method==='GET')return respond(res,200,await store.getDesign(old[1],token(req),Number(old[2])));
    return respond(res,404,{error:'Unknown local development API route'});
   }
   if(req.method!=='GET'&&req.method!=='HEAD')return respond(res,405,{error:'Method not allowed'});
   let file;
   if(path==='/'||path==='/demo'||path==='/demo/')file=join(projectRoot,'demo','index.html');
   else if(/^\/(?:demo|src)\/[a-zA-Z0-9._/-]+$/.test(path)&&!path.includes('..')&&!path.includes('//'))file=resolve(projectRoot,'.'+path);
   else return respond(res,404,{error:'Not found'});
   if(!file.startsWith(projectRoot+'/'))return respond(res,404,{error:'Not found'});
   const ext=extname(file);if(!mime[ext])return respond(res,404,{error:'Not found'});
   let bytes;try{bytes=await readFile(file);}catch{return respond(res,404,{error:'Not found'});}
   res.writeHead(200,{...hdr,'Content-Type':mime[ext]});return res.end(req.method==='HEAD'?undefined:bytes);
  }catch(e){return respond(res,e.status||500,{error:e.status?e.message:'Local server error'});}
 });
 return {server,store,registry,listen:(port=8000)=>new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,host,()=>{server.removeListener('error',reject);resolve(server.address());});})};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const snapshot=process.env.TJ_STAGING_FIXTURE?JSON.parse(await readFile(resolve(process.env.TJ_STAGING_FIXTURE),'utf8')).products:[];
 const {listen}=await createLocalServer({dataDir:process.env.TJ_STUDIO_DATA_DIR||join(projectRoot,'.tj-local-data'),shopifySnapshot:snapshot});
 const addr=await listen(Number(process.env.PORT||8000));
 console.log(`TrendyJoes local-only studio: http://127.0.0.1:${addr.port}/demo/`);
 console.log('PREVIEW ONLY — not exposed to the internet, not connected to Shopify checkout.');
}
