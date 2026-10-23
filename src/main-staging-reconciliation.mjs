/**
 * Objective 35E: reproducible, OFFLINE Main/Night Watch reconciliation candidate.
 * Consumes pinned Main35/Main36 read-back fixtures, never Shopify state or credentials.
 * Does not replace the generated Night Watch staging bundle or any live theme.
 */
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {buildStagingStaticBundle} from './staging-static-package.mjs';
const sha=s=>createHash('sha256').update(s).digest('hex');
const fail=code=>{throw new Error(code);};
const F='fixtures/main-staging-reconciliation/';
const PINNED_MAIN35_MANIFEST='ee1585a38a7929ac3627f67edfed2986599714770f1dfce96a4548dd84ce3a0b';
const PINNED_MAIN36_MANIFEST='563a89db9e6e7868e4e7d8e3b32fb6897b8630f3d95d356a6cbc9c9998cb879c';
const MAIN_CSS='assets/tj34i-demo-studio.css';
const MAIN_SECTION='sections/tj-static-preview-34i.liquid';
const MAIN_ARTWORK_LINK='<p class="fineprint"><a href="#tj-try-studio">Need to preview your own artwork? Open our separate 2D artwork tryout below.</a></p>';
const MAIN_ARTWORK_NOTE='<p class="fineprint">Artwork uploads, GLB imports, saved drafts, account recovery and manufacturing worksheets are intentionally unavailable in this static demonstration.</p>';
const FONT_LINK_CSS='\n#tj34i-root .panel .fineprint a{color:#7A2A30;font-weight:750;text-underline-offset:3px}#tj34i-root .panel .fineprint a:focus-visible{outline:3px solid #52697A;outline-offset:3px}\n';
const onlyOnce=(s,needle,code)=>{if(typeof s!=='string'||s.split(needle).length!==2)fail(code);};
const requireSha=(bytes,expected,code)=>{if(typeof expected!=='string'||!/^([0-9a-f]{64})$/.test(expected)||sha(bytes)!==expected)fail(code);};
const exactKeys=(value,keys,code)=>{
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join('|')!==[...keys].sort().join('|'))fail(code);
};
const fixtureRead=async(root,path)=>readFile(resolve(root,F+path),'utf8');
const assetHash=(manifest,path)=>manifest?.files?.[path]?.sha256;

/** Pure reconciliation: test callers can inject adversarial fixture mutations. */
export function reconcileMainStaging({night,main35,main36,mainManifest,main36Manifest}){
 if(!(night instanceof Map)||!main35||!main36||!mainManifest||!main36Manifest)fail('MISSING_RECONCILIATION_SOURCE');
 if(sha(JSON.stringify(mainManifest))!==PINNED_MAIN35_MANIFEST)fail('MAIN35_PROVENANCE_MISMATCH');
 if(sha(JSON.stringify(main36Manifest))!==PINNED_MAIN36_MANIFEST)fail('MAIN36_PROVENANCE_MISMATCH');
 if(mainManifest.objective!=='Main Objective 35'||mainManifest.upstream!=='Night Watch v0.30.85 Objective34O')fail('MAIN35_PROVENANCE_MISMATCH');
 if(main36Manifest.objective!=='36 - selective reconciliation of Night Watch 35B/35C'||main36Manifest.nightSourceSha256!=='dc51f84ad4d2d8b450e1ca570fb5df41779aecafa4c6ff839d1bd054e9c3f3e7')fail('MAIN36_PROVENANCE_MISMATCH');
 const expected35=[MAIN_CSS,'assets/tj34i-demo-static-preview.css',MAIN_SECTION];
 const expected36=['assets/tj34i-src-static-preview-contract.js','assets/tj34i-demo-static-preview.js'];
 exactKeys(main35,expected35,'MAIN35_FIXTURE_SET_MISMATCH');
 exactKeys(main36,expected36,'MAIN36_FIXTURE_SET_MISMATCH');
 for(const path of expected35)requireSha(main35[path],assetHash(mainManifest,path),'MAIN35_FIXTURE_TAMPER');
 for(const path of expected36)requireSha(main36[path],main36Manifest.files?.[path]?.deployedSha256,'MAIN36_FIXTURE_TAMPER');
 if(night.size!==13)fail('NIGHT_ASSET_GRAPH_MISMATCH');
 for(const path of [...expected35,...expected36])if(!night.has(path))fail('NIGHT_ASSET_MISSING');
 // Prove the intended Main35 delta is exactly heading/typography/artwork-link.
 const mainSection=main35[MAIN_SECTION];
 onlyOnce(mainSection,'<h2>Ideas made <em>yours.</em></h2>','MAIN35_HEADING_CONFLICT');
 onlyOnce(mainSection,MAIN_ARTWORK_NOTE+MAIN_ARTWORK_LINK,'MAIN35_ARTWORK_CONFLICT');
 if(/<h1\b/i.test(mainSection)||!mainSection.includes('href="#tj-try-studio"'))fail('MAIN35_SECTION_CONFLICT');
 const css=main35[MAIN_CSS];
 onlyOnce(css,FONT_LINK_CSS,'MAIN35_CSS_CONFLICT');
 onlyOnce(css,'#tj34i-root .masthead h2{','MAIN35_TYPOGRAPHY_CONFLICT');
 onlyOnce(css,'#tj34i-root .masthead h2 em{','MAIN35_TYPOGRAPHY_CONFLICT');
 const mainStaticCss=main35['assets/tj34i-demo-static-preview.css'];
 if(!mainStaticCss.includes('#tj34i-root')||/\@import\b|url\s*\(/i.test(mainStaticCss))fail('MAIN35_CSS_CONFLICT');
 const files=new Map(night);
 let section=files.get(MAIN_SECTION);
 onlyOnce(section,'<h1>Ideas made <em>yours.</em></h1>','NIGHT_HEADING_CONFLICT');
 onlyOnce(section,MAIN_ARTWORK_NOTE,'NIGHT_ARTWORK_ANCHOR_CONFLICT');
 if(section.includes(MAIN_ARTWORK_LINK))fail('DUPLICATE_MAIN_ARTWORK_LINK');
 section=section.replace('<h1>Ideas made <em>yours.</em></h1>','<h2>Ideas made <em>yours.</em></h2>')
                .replace(MAIN_ARTWORK_NOTE,MAIN_ARTWORK_NOTE+MAIN_ARTWORK_LINK);
 files.set(MAIN_SECTION,section);
 let studioCss=files.get(MAIN_CSS);
 onlyOnce(studioCss,'#tj34i-root .masthead h1{','NIGHT_TYPOGRAPHY_CONFLICT');
 onlyOnce(studioCss,'#tj34i-root .masthead h1 em{','NIGHT_TYPOGRAPHY_CONFLICT');
 if(studioCss.includes(FONT_LINK_CSS))fail('DUPLICATE_MAIN_TYPOGRAPHY');
 studioCss=studioCss.replace('#tj34i-root .masthead h1{','#tj34i-root .masthead h2{')
                    .replace('#tj34i-root .masthead h1 em{','#tj34i-root .masthead h2 em{')+FONT_LINK_CSS;
 files.set(MAIN_CSS,studioCss);
 // Every other byte remains from the newer verified Night Watch release.
 if([...files].some(([path,code])=>typeof code!=='string'||!(/^(assets\/tj34i-[a-z0-9-]+\.(?:css|js)|sections\/tj-static-preview-34i\.liquid)$/.test(path))))fail('UNSAFE_CANDIDATE_FILE');
 if(!files.get(MAIN_SECTION).includes('id="tj34i-concept-a11y-summary"')||
    !files.get(MAIN_SECTION).includes('id="tj34i-review-help"')||
    !files.get('assets/tj34i-demo-static-preview.js').includes('staticPreviewReviewAvailability')||
    !files.get('assets/tj34i-src-static-preview-contract.js').includes('assertStaticPreviewIntegrity'))fail('NIGHT_GUARDS_MISSING');
 if(/<form\b|href=["']\/(?:cart|checkout)|\btype=["']submit["']/i.test(files.get(MAIN_SECTION)))fail('COMMERCE_MARKUP_FORBIDDEN');
 const entries=[...files].sort(([a],[b])=>a.localeCompare(b,'en')).map(([path,content])=>({path,bytes:Buffer.byteLength(content),sha256:sha(content)}));
 const manifest={schema:'TJ-MAIN35-NIGHT35E-OFFLINE-CANDIDATE-1',scope:'OFFLINE_RECONCILIATION_NOT_INSTALLED',
  nightVersion:'0.30.136',mainBase:'Main Objective 35',main36Guard:'Main Objective 36 verified fixture',
  sourcePolicy:'NIGHT_ASSETS_PLUS_PINNED_MAIN_HEADING_ARTWORK_TYPOGRAPHY',shopifyWrites:0,
  hostedAuthentication:false,customerStorage:false,checkoutEnabled:false,manufacturingApproved:false,
  mainEngineeringAcceptanceRequired:true,entries};
 return {files,manifest};
}
export async function buildMainStagingReconciliation({root}){
 const [night,mainManifest,main36Manifest]=await Promise.all([
  buildStagingStaticBundle({root}),
  fixtureRead(root,'main35/MAIN_OBJECTIVE35_INTEGRATION_MANIFEST.json').then(JSON.parse),
  fixtureRead(root,'main36/manifest.json').then(JSON.parse)
 ]);
 const main35={},main36={};
 for(const p of [MAIN_CSS,'assets/tj34i-demo-static-preview.css',MAIN_SECTION])main35[p]=await fixtureRead(root,'main35/'+p);
 for(const p of ['assets/tj34i-src-static-preview-contract.js','assets/tj34i-demo-static-preview.js'])main36[p]=await fixtureRead(root,'main36/staging/'+p);
 return reconcileMainStaging({night:night.files,main35,main36,mainManifest,main36Manifest});
}
