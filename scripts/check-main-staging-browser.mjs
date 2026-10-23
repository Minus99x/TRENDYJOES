/** Optional native Chromium smoke of OFFLINE reconciled assets. No Shopify/network traffic. */
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {resolve,extname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {validateOfflineMainDom,verifyOfflineMainAssetBytes} from '../src/offline-main-dom-acceptance.mjs';
import {validateOfflineMobileInteraction} from '../src/offline-mobile-interaction.mjs';
import {buildMainStagingReconciliation} from '../src/main-staging-reconciliation.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const base=resolve(root,'integrations/shopify/main-staging-reconciliation-candidate');
const {files}=await buildMainStagingReconciliation({root});
const accepted=validateOfflineMainDom({files});
const mobile=validateOfflineMobileInteraction(files);
await verifyOfflineMainAssetBytes(files,path=>readFile(resolve(base,path),'utf8'));
const section=await readFile(resolve(base,'sections/tj-static-preview-34i.liquid'),'utf8');
const body=section.replace(/\{% comment %\}[\s\S]*?\{% endcomment %\}/g,'')
 .replace(/\{\{ '[^']+' \| asset_url \| stylesheet_tag \}\}/g,'')
 .replace(/\{% schema %\}[\s\S]*?\{% endschema %\}/g,'')
 .replace(/<script type="module" src="\{\{ '([^']+)' \| asset_url \}\}"><\/script>/g,(_,asset)=>`<script type="module" src="/assets/${asset}"></script>`);
if(body!==accepted.markup)throw new Error('DOM_RECONCILIATION_DRIFT');
if(process.argv.includes('--static-check')){
 console.log(`OFFLINE_DOM_ACCEPTANCE ${accepted.idCount} unique IDs, ${accepted.linkedReferences} references, ${accepted.assetCount} pinned assets, mobile scroll ${mobile.scrollPolicy} / focus recovery ${mobile.focusRecovery}; Shopify writes NONE; NATIVE_BROWSER_NOT_RUN`);
 process.exit(0);
}
const harness=`<script>
window.__checks=[];
const record=(name,ok)=>window.__checks.push({name,pass:!!ok});
window.addEventListener('error',e=>window.__checks.push({name:'UNCAUGHT_ERROR',pass:false,message:String(e.message)}));
window.addEventListener('unhandledrejection',e=>window.__checks.push({name:'UNHANDLED_REJECTION',pass:false,message:String(e.reason)}));
window.addEventListener('load',()=>setTimeout(()=>{
 try{
  const $=s=>document.getElementById('tj34i-'+s);
  record('MAIN_H2',!!document.querySelector('#tj34i-root .masthead h2')&&!document.querySelector('#tj34i-root .masthead h1'));
  record('MAIN_ARTWORK_LINK',document.querySelectorAll('#tj34i-root a[href="#tj-try-studio"]').length===1);
  record('UNIVERSAL_PRODUCTS',$('product').options.length>=7);
  record('REVIEW_INITIAL_DISABLED',$('review-preview').disabled);
  record('CHECKOUT_DISABLED',document.querySelector('#tj34i-root .disabled-checkout')?.disabled);
  $('text-entry').value='A personal design';$('text-entry').dispatchEvent(new Event('input',{bubbles:true}));
  record('DRAFT_BLOCKS_REVIEW',$('review-preview').disabled);
  $('add-text').click();
  record('ADD_ENABLES_REVIEW',!$('review-preview').disabled&&$('layers').options.length===2);
  $('review-preview').click();record('REVIEW_OPENS',!$('preview-summary-panel').hidden&&$('review-layers').textContent.includes('1 lettering'));
  $('stage-3d').focus();$('mode-2d').click();record('HIDDEN_CANVAS_FOCUS_RECOVERED',document.activeElement===$('mode-2d'));
  record('TWO_D_MODE',$('mode-2d').getAttribute('aria-pressed')==='true'&&!$('stage').hidden);
  $('mode-3d').click();record('THREE_D_MODE',$('mode-3d').getAttribute('aria-pressed')==='true'&&!$('stage-3d').hidden);
  $('text-entry').value='\\u202Ebad';$('text-entry').dispatchEvent(new Event('input',{bubbles:true}));$('add-text').click();
  record('INVALID_UNICODE_REJECTED',$('text-entry').getAttribute('aria-invalid')==='true'&&$('layers').options.length===2);
  record('ACCESSIBILITY_SUMMARY',$('concept-a11y-summary').textContent.length>15);
  record('NO_COMMERCE_LINKS',!document.querySelector('#tj34i-root form, #tj34i-root a[href^="/cart"], #tj34i-root a[href^="/checkout"]'));
 }catch(e){record('HARNESS_EXCEPTION',false);window.__checks.push({name:'EXCEPTION_DETAIL',pass:false,message:String(e)});}
 const result=document.createElement('pre');result.id='browser-smoke-result';result.textContent=JSON.stringify(window.__checks);document.body.append(result);
},1500));
</script>`;
const html=`<!doctype html><html><head><meta charset="utf-8"><link rel="stylesheet" href="/assets/tj34i-demo-studio.css"><link rel="stylesheet" href="/assets/tj34i-demo-static-preview.css"></head><body><h1>Existing Main storefront title</h1>${body}${harness}</body></html>`;
const server=createServer(async(req,res)=>{
 let name;
 try{name=decodeURIComponent((req.url||'').split('?')[0]);}catch{res.writeHead(400);res.end();return;}
 if(req.method!=='GET'){res.writeHead(405);res.end();return;}
 res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self'; img-src data:; connect-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'");
 res.setHeader('X-Content-Type-Options','nosniff');
 if(name==='/'){res.writeHead(200,{'content-type':'text/html; charset=utf-8'});res.end(html);return;}
 if(!/^\/assets\/tj34i-[a-z0-9-]+\.(?:js|css)$/.test(name)){res.writeHead(404);res.end();return;}
 try{const b=await readFile(resolve(base,name.slice(1)));res.writeHead(200,{'content-type':extname(name)==='.js'?'text/javascript':'text/css'});res.end(b);}catch{res.writeHead(404);res.end();}
});
await new Promise(ok=>server.listen(0,'127.0.0.1',ok));
const port=server.address().port;
const browser=process.env.CHROMIUM||'/usr/bin/chromium';
let stdout='',stderr='';
const child=spawn(browser,['--headless=new','--no-sandbox','--disable-gpu','--disable-dev-shm-usage','--disable-background-networking','--no-first-run','--disable-extensions','--disable-features=MediaRouter','--virtual-time-budget=9000','--dump-dom',`http://127.0.0.1:${port}/`],{stdio:['ignore','pipe','pipe']});
child.stdout.on('data',x=>stdout+=x);child.stderr.on('data',x=>stderr+=x);
const timer=setTimeout(()=>child.kill('SIGKILL'),30000);
const code=await new Promise(ok=>child.on('close',ok));clearTimeout(timer);server.close();
const raw=stdout.match(/<pre id="browser-smoke-result">([^<]+)<\/pre>/)?.[1];
if(!raw){console.error('CHROMIUM_NO_HARNESS_RESULT',code,stderr.slice(-900));process.exit(1);}
const checks=JSON.parse(raw.replaceAll('&quot;','"').replaceAll('&amp;','&').replaceAll('&lt;','<').replaceAll('&gt;','>'));
for(const c of checks)console.log(`${c.pass?'PASS':'FAIL'} ${c.name}${c.message?' '+c.message:''}`);
console.log(`BROWSER_SMOKE ${checks.filter(c=>c.pass).length}/${checks.length} PASS, Chromium exit ${code}, Shopify writes NONE`);
if(code!==0||checks.some(c=>!c.pass)||checks.length<12)process.exit(1);
