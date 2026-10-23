import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runInNewContext} from 'node:vm';
import {buildMainStagingReconciliation} from '../src/main-staging-reconciliation.mjs';
import {validateOfflineMobileInteraction} from '../src/offline-mobile-interaction.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const SECTION='sections/tj-static-preview-34i.liquid',CSS='assets/tj34i-demo-static-preview.css',JS='assets/tj34i-demo-static-preview.js';
const source=await readFile(resolve(root,'demo/static-preview.mjs'),'utf8');
const candidate=async()=>(await buildMainStagingReconciliation({root})).files;
async function altered(path,fn){const f=new Map(await candidate());f.set(path,fn(f.get(path)));return f;}
async function rejected(path,fn,code){const f=await altered(path,fn);assert.throws(()=>validateOfflineMobileInteraction(f),new RegExp(code));}
function helper(activeInside=true){
 const snippet=source.slice(source.indexOf('function restoreFocusBeforeHiding('),source.indexOf('\nfunction invalidateReview(){'));
 assert.ok(snippet.startsWith('function restoreFocusBeforeHiding('));
 const active={id:'active'},other={id:'other'};
 const document={activeElement:active};let calls=0,options;
 const region={contains(el){return activeInside&&el===active;}};
 const fallback={disabled:false,isConnected:true,focus(opts){calls++;options=opts;document.activeElement=fallback;}};
 const fn=runInNewContext(`(${snippet})`,{document});
 return {fn,document,region,fallback,active,other,calls:()=>calls,options:()=>options};
}
test('35G accepted offline Main candidate has mobile scroll and focus recovery',async()=>{
 assert.deepEqual(validateOfflineMobileInteraction(await candidate()),{scrollPolicy:'pan-y',canvasRole:'group',focusRecovery:true,shopifyWrites:0,nativeBrowserVerified:false});
});
test('35G rejects non-map asset graph',()=>assert.throws(()=>validateOfflineMobileInteraction({}),/MOBILE_ASSET_GRAPH_REQUIRED/));
test('35G rejects missing section',async()=>{const f=await candidate();f.delete(SECTION);assert.throws(()=>validateOfflineMobileInteraction(f),/MOBILE_ASSET_MISSING/);});
test('35G rejects missing CSS',async()=>{const f=await candidate();f.delete(CSS);assert.throws(()=>validateOfflineMobileInteraction(f),/MOBILE_ASSET_MISSING/);});
test('35G rejects missing JS',async()=>{const f=await candidate();f.delete(JS);assert.throws(()=>validateOfflineMobileInteraction(f),/MOBILE_ASSET_MISSING/);});
test('35G rejects 3D touch scroll lock',()=>rejected(CSS,s=>s.replace('stage-3d{height:100%;width:100%;min-height:340px;touch-action:pan-y','stage-3d{height:100%;width:100%;min-height:340px;touch-action:none'),'MOBILE_VERTICAL_SCROLL_BLOCKED'));
test('35G rejects hidden touch-action override appended to CSS',()=>rejected(CSS,s=>s+'\n#tj34i-root #tj34i-stage-3d{touch-action:none!important}', 'MOBILE_VERTICAL_SCROLL_BLOCKED'));
test('35G rejects 2D touch scroll lock',()=>rejected(CSS,s=>s.replace('stage{display:block;max-height:620px;max-width:100%;touch-action:pan-y','stage{display:block;max-height:620px;max-width:100%;touch-action:none'),'MOBILE_VERTICAL_SCROLL_BLOCKED'));
test('35G rejects misleading image role on interactive canvas',()=>rejected(SECTION,s=>s.replace('stage-3d" role="group"','stage-3d" role="img"'),'MOBILE_CANVAS_SEMANTICS_INVALID'));
test('35G rejects removed canvas keyboard tab stop',()=>rejected(SECTION,s=>s.replace('stage-3d" role="group" tabindex="0"','stage-3d" role="group" tabindex="-1"'),'MOBILE_CANVAS_SEMANTICS_INVALID'));
test('35G rejects broken canvas described-by link',()=>rejected(SECTION,s=>s.replace('aria-describedby="tj34i-camera-help tj34i-concept-a11y-summary"','aria-describedby="missing-help"'),'MOBILE_CANVAS_SEMANTICS_INVALID'));
test('35G rejects missing mobile vertical scroll guidance',()=>rejected(SECTION,s=>s.replace('swipe vertically to scroll the page','drag to rotate vertically'),'MOBILE_GESTURE_HELP_MISSING'));
test('35G rejects missing keyboard help',()=>rejected(SECTION,s=>s.replace('Keyboard: focus the model','Focus the model'),'MOBILE_GESTURE_HELP_MISSING'));
test('35G rejects removed focus recovery helper',()=>rejected(JS,s=>s.replace('function restoreFocusBeforeHiding(region,fallback)','function unusedRestoreFocus(region,fallback)'),'MOBILE_REVIEW_FOCUS_RECOVERY_MISSING'));
test('35G rejects deleted focus containment check',()=>rejected(JS,s=>s.replace('region.contains(document.activeElement)','true'),'MOBILE_REVIEW_FOCUS_RECOVERY_MISSING'));
test('35G rejects deleted preventScroll focus',()=>rejected(JS,s=>s.replace('fallback.focus({preventScroll:true})','fallback.focus()'),'MOBILE_REVIEW_FOCUS_RECOVERY_MISSING'));
test('35G rejects review panel hiding without focus recovery',()=>rejected(JS,s=>s.replace("restoreFocusBeforeHiding($('preview-summary-panel'),$('text-entry'))",'// removed'),'MOBILE_REVIEW_FOCUS_RECOVERY_MISSING'));
test('35G rejects hiding a focused canvas without focus recovery',()=>rejected(JS,s=>s.replace("if(state.mode==='2d')restoreFocusBeforeHiding($('stage-3d'),$('mode-2d'))",'// removed'),'MOBILE_CANVAS_FOCUS_RECOVERY_MISSING'));
test('35G rejects continue-edit returning focus to action button',()=>rejected(JS,s=>s.replace("invalidateReview();$('text-entry').focus({preventScroll:true})","invalidateReview();$('add-text').focus()"),'MOBILE_EDIT_FOCUS_INVALID'));
test('35G helper moves focus from hidden region to safe target',()=>{const h=helper();assert.equal(h.fn(h.region,h.fallback),true);assert.equal(h.calls(),1);assert.equal(h.document.activeElement,h.fallback);assert.equal(h.options().preventScroll,true);});
test('35G helper does not steal focus outside hidden region',()=>{const h=helper(false);assert.equal(h.fn(h.region,h.fallback),false);assert.equal(h.calls(),0);});
test('35G helper rejects missing active element',()=>{const h=helper();h.document.activeElement=null;assert.equal(h.fn(h.region,h.fallback),false);assert.equal(h.calls(),0);});
test('35G helper rejects disabled fallback',()=>{const h=helper();h.fallback.disabled=true;assert.equal(h.fn(h.region,h.fallback),false);assert.equal(h.calls(),0);});
test('35G helper rejects detached fallback',()=>{const h=helper();h.fallback.isConnected=false;assert.equal(h.fn(h.region,h.fallback),false);assert.equal(h.calls(),0);});
test('35G helper rejects missing region',()=>{const h=helper();assert.equal(h.fn(null,h.fallback),false);assert.equal(h.calls(),0);});
test('35G helper rejects missing fallback',()=>{const h=helper();assert.equal(h.fn(h.region,null),false);assert.equal(h.calls(),0);});
test('35G helper rejects non-descendant active focus',()=>{const h=helper();h.document.activeElement=h.other;assert.equal(h.fn(h.region,h.fallback),false);assert.equal(h.calls(),0);});
test('35G candidate stays offline and disallows checkout',async()=>{const f=await candidate();const section=f.get(SECTION);assert.match(section,/disabled class="disabled-checkout"/);assert.doesNotMatch(section,/<form\b|type="file"|href="\/checkout"/);});
