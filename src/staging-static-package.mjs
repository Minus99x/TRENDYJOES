/** Offline, fail-closed Shopify STAGING theme bundle candidate. No network or Shopify writes. */
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {posix,resolve} from 'node:path';
import {collectPreviewAssetManifest,verifyPreviewAssetManifest} from './preview-asset-manifest.mjs';

export const BUNDLE_SCOPE='TJ_STATIC_PREVIEW_STAGING_CANDIDATE_ONLY';
export const ROOT_ID='tj34i-root';
export const PREFIX='tj34i-';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const fail=code=>{throw new Error(code);};
const isSafePath=p=>typeof p==='string'&&/^(demo|src)\/[a-z0-9-]+\.(mjs|css)$/.test(p);
export function themeAssetName(path){
 if(!isSafePath(path))fail('UNSAFE_STAGING_SOURCE_PATH');
 return PREFIX+path.replaceAll('/','-').replace(/\.(mjs|css)$/,(s,ext)=>ext==='mjs'?'.js':'.css');
}
export function rewriteThemeModule(source,path,mapping){
 if(typeof source!=='string'||!isSafePath(path)||!path.endsWith('.mjs'))fail('INVALID_THEME_MODULE');
 if(/\bimport\s*\(|\bimport\.meta\b|\brequire\s*\(/.test(source))fail('UNSUPPORTED_THEME_IMPORT');
 let count=0;
 const rewritten=source.replace(/(^|\n)(\s*(?:import|export)\s+(?:[^'"\n]*?\sfrom\s*)?)(['"])([^'"\n]+)\3/g,(full,line,lead,quote,spec)=>{
  count++;
  if(!/^\.{1,2}\/[a-z0-9./-]+\.mjs$/.test(spec)||spec.includes('?')||spec.includes('#'))fail('NONLOCAL_THEME_IMPORT');
  const target=posix.normalize(posix.join(posix.dirname(path),spec));
  if(!mapping.has(target))fail('MISSING_THEME_DEPENDENCY');
  return `${line}${lead}${quote}./${mapping.get(target)}${quote}`;
 });
 const declarationCount=(source.match(/(?:^|\n)\s*(?:import|export)\s+(?:[^'"\n]*?\sfrom\s*)?['"]/g)||[]).length;
 if(count!==declarationCount)fail('UNREWRITTEN_THEME_IMPORT');
 // Only the staging copy is modified. The standalone local demo is unchanged.
 if(path==='demo/static-preview.mjs'){
  const marker='const $=id=>document.getElementById(id);';
  if(!rewritten.includes(marker)||rewritten.split(marker).length!==2)fail('MISSING_SCOPED_DOM_HOOK');
  return rewritten.replace(marker,`const $=id=>document.getElementById('${PREFIX}'+id);`);
 }
 return rewritten;
}
function scopeSelector(selector){
 const s=selector.trim();
 if(!s||s.startsWith('@')||/[{}]/.test(s))fail('INVALID_CSS_SELECTOR');
 if(s===':root'||s==='body')return `#${ROOT_ID}`;
 if(s==='*')return `#${ROOT_ID} *`;
 const replaced=s.replace(/#([a-zA-Z][\w-]*)/g,(_,id)=>'#'+PREFIX+id);
 return `#${ROOT_ID} ${replaced}`;
}
export function scopeThemeCss(input){
 if(typeof input!=='string'||/\@import\b|url\s*\(|expression\s*\(/i.test(input))fail('UNSAFE_THEME_CSS');
 const source=input.replace(/\/\*[\s\S]*?\*\//g,'');
 function parse(block){
  let i=0,out='';
  while(i<block.length){
   const open=block.indexOf('{',i);
   if(open<0){if(block.slice(i).trim())fail('UNBALANCED_THEME_CSS');break;}
   const head=block.slice(i,open).trim();let depth=1,j=open+1;
   for(;j<block.length;j++){if(block[j]==='{')depth++;else if(block[j]==='}'&&!--depth)break;}
   if(depth!==0)fail('UNBALANCED_THEME_CSS');
   const inner=block.slice(open+1,j);
   if(/^@media\s*\(/.test(head))out+=head+'{'+parse(inner)+'}';
   else if(head.startsWith('@'))fail('UNSUPPORTED_THEME_CSS_AT_RULE');
   else out+=head.split(',').map(scopeSelector).join(',')+'{'+inner+'}';
   i=j+1;
  }
  return out;
 }
 return `#${ROOT_ID}{box-sizing:border-box;}\n`+parse(source)+'\n';
}
export function themeSectionFromHtml(html,cssNames,jsName){
 if(typeof html!=='string'||!Array.isArray(cssNames)||cssNames.length!==2||!cssNames.every(x=>/^tj34i-[a-z0-9-]+\.css$/.test(x))||!/^tj34i-[a-z0-9-]+\.js$/.test(jsName))fail('INVALID_STAGING_SECTION_INPUT');
 const match=html.match(/<body>([\s\S]*?)<\/body>\s*<\/html>/i);
 if(!match||html.match(/<body>/gi)?.length!==1)fail('INVALID_STATIC_HTML');
 let body=match[1];
 const script=/<script type="module" src="\.\/static-preview\.mjs"><\/script>/g;
 if([...body.matchAll(script)].length!==1)fail('INVALID_STATIC_ENTRY_SCRIPT');
 body=body.replace(script,'');
 if(/<script\b|<form\b|<input[^>]+type=["']file|\bon\w+\s*=|\bhref=["']\/(?:cart|checkout)/i.test(body))fail('UNSAFE_STATIC_MARKUP');
 const ids=[...body.matchAll(/\bid="([^"]+)"/g)].map(x=>x[1]);
 if(new Set(ids).size!==ids.length||ids.some(id=>!/^[a-z][a-z0-9-]*$/.test(id)))fail('INVALID_STATIC_IDS');
 // The host storefront already owns the page's sole main landmark. Keep the
 // standalone demo unchanged, but turn its main into a named group in staging.
 if((body.match(/<main\s+class="workspace">/g)||[]).length!==1||(body.match(/<\/main>/g)||[]).length!==1)fail('INVALID_EMBEDDED_MAIN_LANDMARK');
 body=body.replace('<main class="workspace">','<div class="workspace" role="group" aria-label="Customization workspace">').replace('</main>','</div>');
 body=body.replace(/\b(id|for|aria-labelledby|aria-describedby|aria-controls)="([^"]+)"/g,(_,attr,value)=>`${attr}="${value.split(/\s+/).map(id=>PREFIX+id).join(' ')}"`);
 const styleTags=cssNames.map(name=>`{{ '${name}' | asset_url | stylesheet_tag }}`).join('\n');
 return `{% comment %} Objective 34I: UNPUBLISHED staging candidate only; no sales, storage, checkout or auth. {% endcomment %}\n${styleTags}\n<section id="${ROOT_ID}" data-tj-static34i aria-label="Design Works concept preview">\n${body.trim()}\n</section>\n<script type="module" src="{{ '${jsName}' | asset_url }}"></script>\n{% schema %}\n${JSON.stringify({name:'Design Works preview',limit:1,settings:[],presets:[{name:'Design Works preview'}]},null,2)}\n{% endschema %}\n`;
}
export async function buildStagingStaticBundle({root}){
 const manifestPath=resolve(root,'integrations/shopify/static-preview-asset-manifest.json');
 const manifest=JSON.parse(await readFile(manifestPath,'utf8'));
 const graph=await collectPreviewAssetManifest({root,entryFiles:['demo/static-preview.html','demo/studio.css','demo/static-preview.css','demo/static-preview.mjs']});
 const expected={...graph,schema:'TJ-STATIC-CLIENT-ASSET-INVENTORY-1',scope:'EPHEMERAL_CLIENT_ONLY',backendRequirement:'NONE_CLIENT_ONLY',hostedPreviewReady:false,blockedHostedFeatures:['PRIVATE_DRAFT_SAVE','PRIVATE_ARTWORK_UPLOAD','MODEL_UPLOAD','AUTHENTICATED_REVISIONS','CUSTOMER_STORAGE','CART_AND_CHECKOUT']};
 verifyPreviewAssetManifest(manifest,expected);
 if(manifest.assets.length!==13)fail('UNEXPECTED_STATIC_ASSET_GRAPH');
 const sourceAssets=manifest.assets.filter(a=>a.path!=='demo/static-preview.html');
 const mapping=new Map(sourceAssets.map(a=>[a.path,themeAssetName(a.path)]));
 if(new Set(mapping.values()).size!==mapping.size)fail('STAGING_ASSET_COLLISION');
 const files=new Map();
 for(const asset of sourceAssets){
  const bytes=await readFile(resolve(root,asset.path));
  if(sha(bytes)!==asset.sha256||bytes.length!==asset.bytes)fail('TAMPERED_STATIC_SOURCE');
  const code=bytes.toString('utf8');
  const result=asset.path.endsWith('.mjs')?rewriteThemeModule(code,asset.path,mapping):scopeThemeCss(code);
  files.set('assets/'+mapping.get(asset.path),result);
 }
 const html=await readFile(resolve(root,'demo/static-preview.html'),'utf8');
 const section=themeSectionFromHtml(html,[mapping.get('demo/studio.css'),mapping.get('demo/static-preview.css')],mapping.get('demo/static-preview.mjs'));
 files.set('sections/tj-static-preview-34i.liquid',section);
 const entries=[...files].sort(([a],[b])=>a.localeCompare(b,'en')).map(([path,contents])=>({path,bytes:Buffer.byteLength(contents),sha256:sha(contents)}));
 const packageVersion=JSON.parse(await readFile(resolve(root,'package.json'),'utf8')).version;
 if(typeof packageVersion!=='string'||!/^\d+\.\d+\.\d+$/.test(packageVersion))fail('INVALID_SOURCE_VERSION');
 const output={schema:'TJ-STAGING-STATIC-PREVIEW-PACKAGE-1',scope:BUNDLE_SCOPE,sourceVersion:packageVersion,hostedPreviewReady:false,shopifyThemeInstalled:false,shopifyAccepted:false,checkoutEnabled:false,customerStorageEnabled:false,requiresMainEngineeringAcceptance:true,entries};
 return {files,manifest:output};
}
