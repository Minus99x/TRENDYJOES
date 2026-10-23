/**
 * Objective 34G: offline browser-asset inventory for Main Engineering.
 * This is an integrity and dependency inventory, NOT a Shopify asset deployer.
 * The editor still requires loopback-only APIs for private draft operations.
 */
import {createHash} from 'node:crypto';
import {readFile,lstat,realpath} from 'node:fs/promises';
import {resolve,relative,dirname,extname,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
const DEFAULT_ROOT=resolve(fileURLToPath(new URL('..',import.meta.url)));
const ENTRY_FILES=['demo/start.html','demo/index.html','demo/entry.css','demo/studio.css','demo/studio.mjs'];
const types={'.html':'text/html','.css':'text/css','.mjs':'text/javascript'};
const fail=code=>{throw new Error(code);};
const isInside=(root,path)=>path===root||path.startsWith(root+sep);
const toRelative=(root,path)=>relative(root,path).split(sep).join('/');
const imports=code=>{
 const specs=[];
 for(const m of code.matchAll(/(?:^|\n)\s*(?:import|export)\s+(?:[^'"\n]*?\sfrom\s*)?['"]([^'"\n]+)['"]/g))specs.push(m[1]);
 const dynamic=[...code.matchAll(/\bimport\s*\(\s*['"]([^'"\n]+)['"]\s*\)/g)];
 if((code.match(/\bimport\s*\(/g)||[]).length!==dynamic.length)fail('UNRESOLVED_DYNAMIC_IMPORT');
 for(const m of dynamic)specs.push(m[1]);
 return specs;
};
export async function collectPreviewAssetManifest({root=DEFAULT_ROOT,entryFiles=ENTRY_FILES}={}){
 const project=resolve(root),realRoot=await realpath(project);
 if(!Array.isArray(entryFiles)||entryFiles.length<1||entryFiles.length>30)fail('INVALID_ENTRIES');
 const assets=new Map(),queue=[...entryFiles];
 while(queue.length){
  const name=queue.shift();
  if(typeof name!=='string'||!name||name.startsWith('/')||name.includes('\\')||name.split('/').some(x=>x==='..'||x==='.'||x===''))fail('UNSAFE_ASSET_PATH');
  const abs=resolve(project,name);
  if(!isInside(project,abs))fail('ASSET_ESCAPE');
  if(assets.has(name))continue;
  const info=await lstat(abs);
  if(!info.isFile()||info.isSymbolicLink()||info.size>2*1024*1024)fail('UNSAFE_ASSET');
  const actual=await realpath(abs);
  if(!isInside(realRoot,actual))fail('ASSET_ESCAPE');
  const extension=extname(abs);
  if(!types[extension])fail('UNSUPPORTED_ASSET');
  const bytes=await readFile(abs);
  const asset={path:name,url:'/'+name,contentType:types[extension],bytes:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')};
  assets.set(name,asset);
  if(extension==='.mjs'){
   const source=bytes.toString('utf8');
   for(const spec of imports(source)){
    if(!spec.startsWith('./')&&!spec.startsWith('../'))fail('NONLOCAL_BROWSER_IMPORT');
    const next=resolve(dirname(abs),spec);
    if(!isInside(project,next))fail('IMPORT_ESCAPE');
    queue.push(toRelative(project,next));
   }
  }
 }
 return {
  schema:'TJ-OFFLINE-BROWSER-ASSET-INVENTORY-1',scope:'LOCAL_PREVIEW_ONLY',hostedPreviewReady:false,
  shopifyThemeInstalled:false,shopifyAccepted:false,checkoutEnabled:false,
  backendRequirement:'LOOPBACK_API_NOT_HOSTABLE_AS_THEME_ASSET',
  blockedHostedFeatures:['PRIVATE_DRAFT_SAVE','PRIVATE_ARTWORK_UPLOAD','AUTHENTICATED_REVISIONS','CATALOG_SNAPSHOT','CART_AND_CHECKOUT'],
  assets:[...assets.values()].sort((a,b)=>a.path.localeCompare(b.path,'en'))
 };
}
export function verifyPreviewAssetManifest(actual,expected){
 if(!actual||typeof actual!=='object'||Array.isArray(actual))fail('INVALID_ASSET_MANIFEST');
 if(JSON.stringify(actual)!==JSON.stringify(expected))fail('ASSET_MANIFEST_MISMATCH');
 return true;
}
