/** Objective 35G: offline-only customer interaction accessibility acceptance.
 * Static contract, not a native browser or WCAG conformance certificate.
 */
const fail=code=>{throw new Error(code);};
const SECTION='sections/tj-static-preview-34i.liquid';
const CSS='assets/tj34i-demo-static-preview.css';
const JS='assets/tj34i-demo-static-preview.js';
export function validateOfflineMobileInteraction(files){
 if(!(files instanceof Map))fail('MOBILE_ASSET_GRAPH_REQUIRED');
 const section=files.get(SECTION),css=files.get(CSS),js=files.get(JS);
 if([section,css,js].some(s=>typeof s!=='string'))fail('MOBILE_ASSET_MISSING');
 for(const id of ['stage','stage-3d']){
  const re=new RegExp(`#tj34i-root #tj34i-${id}\\{[^}]*touch-action:pan-y(?:[;}])`);
  if(!re.test(css))fail('MOBILE_VERTICAL_SCROLL_BLOCKED');
 }
 if(/touch-action\s*:\s*none\b/i.test(css))fail('MOBILE_VERTICAL_SCROLL_BLOCKED');
 if(!/<canvas id="tj34i-stage-3d" role="group" tabindex="0" aria-describedby="tj34i-camera-help tj34i-concept-a11y-summary"/.test(section))fail('MOBILE_CANVAS_SEMANTICS_INVALID');
 if(!/<p id="tj34i-camera-help"[^>]*>[^<]*swipe vertically to scroll the page[^<]*Keyboard:/.test(section))fail('MOBILE_GESTURE_HELP_MISSING');
 if(!js.includes('function restoreFocusBeforeHiding(region,fallback)')||
    !js.includes('region.contains(document.activeElement)')||
    !js.includes('fallback.focus({preventScroll:true})')||
    !js.includes("restoreFocusBeforeHiding($('preview-summary-panel'),$('text-entry'))"))fail('MOBILE_REVIEW_FOCUS_RECOVERY_MISSING');
 if(!js.includes("if(state.mode==='2d')restoreFocusBeforeHiding($('stage-3d'),$('mode-2d'))"))fail('MOBILE_CANVAS_FOCUS_RECOVERY_MISSING');
 if(!js.includes("$('review-edit').addEventListener('click',()=>{invalidateReview();$('text-entry').focus({preventScroll:true})"))fail('MOBILE_EDIT_FOCUS_INVALID');
 return Object.freeze({scrollPolicy:'pan-y',canvasRole:'group',focusRecovery:true,shopifyWrites:0,nativeBrowserVerified:false});
}
