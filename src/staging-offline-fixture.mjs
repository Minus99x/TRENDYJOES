/** Offline-only host/asset fixture for generated Shopify theme candidates.
 * This is NOT a Liquid compiler, Shopify CDN emulator, hosted acceptance, or checkout.
 */
import {createHash} from 'node:crypto';
import {createServer} from 'node:http';

const SECTION='sections/tj-static-preview-34i.liquid';
const fail=code=>{throw new Error(code);};
const sha=value=>createHash('sha256').update(value).digest('hex');
const ASSET=/^assets\/tj34i-[a-z0-9-]+\.(?:js|css)$/;

export function validateOfflineStagingCandidate(files,manifest){
 if(!(files instanceof Map)||!manifest||manifest.schema!=='TJ-STAGING-STATIC-PREVIEW-PACKAGE-1'||manifest.shopifyThemeInstalled!==false||manifest.checkoutEnabled!==false||manifest.hostedPreviewReady!==false)fail('INVALID_OFFLINE_CANDIDATE');
 if(!Array.isArray(manifest.entries)||manifest.entries.length!==13||files.size!==13)fail('INCOMPLETE_OFFLINE_CANDIDATE');
 const names=new Set();let assets=0,sections=0;
 for(const entry of manifest.entries){
  if(!entry||typeof entry.path!=='string'||names.has(entry.path)||!(ASSET.test(entry.path)||entry.path===SECTION))fail('INVALID_CANDIDATE_PATH');
  names.add(entry.path);
  if(entry.path===SECTION)sections++;else assets++;
  const data=files.get(entry.path);
  if(typeof data!=='string'||Buffer.byteLength(data)!==entry.bytes||sha(data)!==entry.sha256)fail('CANDIDATE_INTEGRITY_MISMATCH');
 }
 if(assets!==12||sections!==1||files.size!==names.size||[...files.keys()].some(p=>!names.has(p)))fail('INVALID_CANDIDATE_INVENTORY');
 return true;
}

/** Narrow offline Liquid *substitution* for this one pinned candidate, never a Liquid interpreter. */
export function renderOfflineStagingFixture(files,manifest){
 validateOfflineStagingCandidate(files,manifest);
 let section=files.get(SECTION);
 section=section.replace(/\{% comment %\}[\s\S]*?\{% endcomment %\}/g,'');
 section=section.replace(/\{% schema %\}[\s\S]*?\{% endschema %\}/g,'');
 let cssCount=0,jsCount=0;
 section=section.replace(/\{\{ '([^']+)' \| asset_url(?: \| stylesheet_tag)? \}\}/g,(whole,name)=>{
  const path='assets/'+name;
  if(!ASSET.test(path)||!files.has(path))fail('MISSING_FIXTURE_ASSET');
  if(whole.includes('stylesheet_tag')){
   if(!name.endsWith('.css'))fail('INVALID_FIXTURE_CSS');cssCount++;
   return `<link rel="stylesheet" href="/assets/${name}">`;
  }
  if(!name.endsWith('.js'))fail('INVALID_FIXTURE_SCRIPT');jsCount++;
  return `/assets/${name}`;
 });
 if(cssCount!==2||jsCount!==1||/\{%|\{\{|\}%|\}\}/.test(section))fail('UNSUPPORTED_FIXTURE_LIQUID');
 if((section.match(/<main\b/gi)||[]).length!==0||(section.match(/<section\b/gi)||[]).length<1)fail('INVALID_FIXTURE_LANDMARKS');
 if(/<form\b|\bhref\s*=\s*["']\/(?:cart|checkout)|<input[^>]*type\s*=\s*["']file/i.test(section))fail('FORBIDDEN_FIXTURE_COMMERCE');
 return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Offline staging acceptance fixture — NOT SHOPIFY</title></head><body><header>Simulated host header</header><main id="offline-host-main"><h1>Offline staging fixture</h1>${section}</main><footer>Simulated host footer</footer></body></html>`;
}

export function createOfflineStagingFixtureServer(files,manifest){
 const html=renderOfflineStagingFixture(files,manifest);
 const server=createServer((req,res)=>{
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Cache-Control','no-store');
  res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; form-action 'none'; object-src 'none'; base-uri 'none'");
  if(req.method!=='GET'){res.writeHead(405,{'Allow':'GET'});res.end();return;}
  // Raw request target check prevents percent-encoded traversal and query aliasing.
  const target=req.url;
  if(target==='/preview'){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});res.end(html);return;}
  if(typeof target==='string'&&/^\/assets\/tj34i-[a-z0-9-]+\.(?:js|css)$/.test(target)){
   const path=target.slice(1);const data=files.get(path);
   if(typeof data==='string'){
    res.writeHead(200,{'Content-Type':path.endsWith('.js')?'text/javascript; charset=utf-8':'text/css; charset=utf-8'});
    res.end(data);return;
   }
  }
  res.writeHead(404,{'Content-Type':'text/plain; charset=utf-8'});res.end('Not found');
 });
 return server;
}
