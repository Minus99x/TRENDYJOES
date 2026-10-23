import {PRODUCT_MANIFESTS,MANIFEST_BY_ID,getFootwearConceptView} from '../src/catalog.mjs';
import {resolvePreviewEntry} from '../src/preview-entry.mjs';
import {hasCustomerWork,eligibleSnapshotEntries,mayApplyDelayedEntry} from '../src/preview-catalog-merge.mjs';
import {normalizePreviewSelection,getPreviewOptions,describePreviewSelection} from '../src/preview-product-options.mjs';
import {validateComposition} from '../src/core.mjs';
import {nudgePreviewLayer,previewNudgeKeyAction} from '../src/preview-keyboard-position.mjs';
import {duplicatePreviewLayerToSurface} from '../src/preview-surface-copy.mjs';
import {savePreviewSession,loadPreviewSession,clearPreviewSession} from '../src/preview-session-recovery.mjs';
import {buildPreviewDesignSummary} from '../src/preview-design-summary.mjs';
import {createConceptMesh} from '../src/geometry3d.mjs';
import {render3D} from '../src/viewer3d.mjs';
import {inspectGlb} from '../src/model-assets.mjs';
import {createModelImportLifecycle} from '../src/preview-model-import-lifecycle.mjs';
import {validateLocalModelInspection} from '../src/preview-model-receipt.mjs';
import {readBoundedLocalGlb} from '../src/preview-glb-file-read.mjs';
import {buildConceptUvReport} from '../src/preview-uv-report.mjs';
import {reviewConceptCalibration} from '../src/preview-calibration-review.mjs';
import {buildConceptReviewPacket} from '../src/preview-concept-review-packet.mjs';
import {permittedPreviewMode,previewModelStatus} from '../src/preview-mode-policy.mjs';
import {describeActivePreview} from '../src/preview-merchandise-a11y.mjs';
import {buildPrivateConceptDesignEvidence} from '../src/preview-private-design-evidence.mjs';
import {preparePrivateConceptExport} from '../src/preview-private-export-gate.mjs';
import {createCalibrationWorksheet} from '../src/calibration.mjs';
import {editorSnapshot,savedDraftMatchesEditor,reviewSelectionMatches} from '../src/preview-editor-state.mjs';
import {createLocalMultiDesignReview} from '../src/preview-multidesign-review.mjs';
import {createLocalMultiReviewRecovery,createReviewChecklist} from '../src/preview-multidesign-resume.mjs';
import {createLocalRecoveryConfirmation} from '../src/preview-multidesign-confirmation.mjs';
import {createLocalMultiReviewTransition} from '../src/preview-multidesign-ui-transition.mjs';
import {replaceReviewListPreservingFocus} from '../src/preview-multidesign-dom-focus.mjs';
import {createPreviewEditorAsyncGate,validateLocalArtworkReceipt} from '../src/preview-editor-async-gate.mjs';
import {commitPrivateReceiptRestore} from '../src/preview-private-receipt-transaction.mjs';
const $=id=>document.getElementById(id);
const availableManifests=Object.assign(Object.create(null),MANIFEST_BY_ID);
const shopifyEntries=new Map();
// Private local owner grants stay in JS memory only, never in the review DOM.
const readLocalReadiness=async input=>{
 const {ownerToken,...body}=input;
 const response=await fetch('/api/shopify/cart-readiness',{method:'POST',
  headers:{'Content-Type':'application/json','Authorization':`Bearer ${ownerToken}`},body:JSON.stringify(body)});
 if(!response.ok)throw Error('LOCAL_READINESS_REFUSED');
 return response.json();
};
const multiReview=createLocalMultiDesignReview({readReadiness:readLocalReadiness});
const multiReviewTransition=createLocalMultiReviewTransition({review:multiReview});
const multiRecovery=createLocalMultiReviewRecovery({readReadiness:readLocalReadiness});
const recoveryConfirmation=createLocalRecoveryConfirmation({recovery:multiRecovery});
let conceptExportRevision=0;
const state={product:PRODUCT_MANIFESTS[0],surface:'front',previewSelection:normalizePreviewSelection(PRODUCT_MANIFESTS[0]),layers:[],selected:null,artUrls:new Map(),artGrants:new Map(),zoom:1,saved:null,savedSnapshot:null,calibrationSignature:null,mode:'3d',camera:{yaw:.18,pitch:.10,zoom:1},imported:null,calibration:null};
const modelImportLifecycle=createModelImportLifecycle({readContext:()=>({productId:state.product.id,surfaceId:state.surface,variantId:$('shopify-variant').value})});
const editorAsyncGate=createPreviewEditorAsyncGate({readBinding:()=>({
 productManifestId:state.product.id,surfaceId:state.surface,variantGid:$('shopify-variant').value,
 reference:state.saved?.reference??null,revision:state.saved?.revision??null})});
// A measurement worksheet is scoped to one exact product/surface/variant/model and
// to the input values that were validated. No prior measurements can be exported
// after a context change or an edited field, even if a UI event was missed.
const calibrationInputIds=['blank-sku','print-width-mm','print-height-mm','blank-width-mm',
 'blank-height-mm','measurement-source','technician','measurement-date','fixture-reference'];
function calibrationFingerprint(){
 return JSON.stringify({product:state.product.id,surface:state.surface,
  selection:state.previewSelection,modelSha256:state.imported?.sha256||null,
  fields:calibrationInputIds.map(id=>$(id).value)});
}
function invalidateCalibration(message,{clearFields=false}={}){
 state.calibration=null;state.calibrationSignature=null;
 $('export-calibration').disabled=true;
 if(clearFields)for(const id of calibrationInputIds)$(id).value='';
 $('calibration-result').textContent=message;
}
for(const id of calibrationInputIds){
 $(id).addEventListener('input',()=>{
  if(state.calibration)invalidateCalibration('Measurements changed. Validate this draft worksheet again.');
 });
 $(id).addEventListener('change',()=>{
  if(state.calibration)invalidateCalibration('Measurements changed. Validate this draft worksheet again.');
 });
}
const svgNS='http://www.w3.org/2000/svg';
const shapes={
 crew:'<path d="M303 84L258 105 197 133 128 246 209 292 260 235 271 555 529 555 540 235 591 292 672 246 603 133 542 105 497 84Q400 159 303 84Z"/>',
 vneck:'<path d="M303 84L258 105 197 133 128 246 209 292 260 235 271 555 529 555 540 235 591 292 672 246 603 133 542 105 497 84 400 191Z"/>',
 longsleeve:'<path d="M303 84L258 105 202 137 104 465 186 491 259 269 271 555 529 555 541 269 614 491 696 465 598 137 542 105 497 84Q400 159 303 84Z"/>',
 hoodie:'<path d="M339 76Q273 112 271 184L214 158 124 355 208 398 259 284 271 557 529 557 541 284 592 398 676 355 586 158 529 184Q527 112 461 76Q400 42 339 76Z"/><path d="M339 76Q400 185 461 76M378 186L378 249M422 186L422 249M337 441Q400 458 463 441L463 515 337 515Z" fill="none"/>',
 tumbler:'<path d="M287 115L513 115 485 540Q400 564 315 540Z"/><ellipse cx="400" cy="115" rx="113" ry="26"/><path d="M513 137Q530 150 528 179" fill="none"/>',
 backpack:'<path d="M327 163C322 70 478 70 473 163M304 184Q400 147 496 184Q545 208 541 289L541 529Q400 563 259 529L259 289Q255 208 304 184Z"/><path d="M321 195Q400 171 479 195M299 414Q400 382 501 414L501 513Q400 533 299 513Z" fill="none"/>',
 rug:'<rect x="110" y="137" width="580" height="355" rx="12"/><path d="M120 160H680M120 470H680M145 135V492M655 135V492" fill="none"/>'
};
const colorByCategory={apparel:'#52697A',drinkware:'#D0A378',accessories:'#B17F65',home:'#B7A38D'};
function el(type,attrs={}){const n=document.createElementNS(svgNS,type);for(const [k,v] of Object.entries(attrs))n.setAttribute(k,String(v));return n;}
function updateControls(){
 if(state.calibration&&state.calibrationSignature!==calibrationFingerprint())
  invalidateCalibration('Product, surface, variant or measurement context changed. Revalidate the draft worksheet.');
 $('product-heading').textContent=state.product.label; $('summary-product').textContent=state.product.label;
 const surface=state.product.surfaces.find(s=>s.id===state.surface);
 $('surface-badge').textContent=surface.label.toUpperCase();$('summary-surface').textContent=surface.label;
 $('summary-layers').textContent=String(state.layers.length);
 const {colors,sizes}=getPreviewOptions(state.product);
 const described=describePreviewSelection(state.product,state.previewSelection);
 $('concept-color').replaceChildren(...(colors.length?colors.map(c=>new Option(c.label,c.id)):[new Option('Supplier color not specified','')]));
 $('concept-size').replaceChildren(...(sizes.length?sizes.map(s=>new Option(s.label,s.id)):[new Option('Size / format not specified','')]));
 $('concept-color').disabled=!colors.length;$('concept-size').disabled=!sizes.length;
 $('concept-color').value=state.previewSelection.colorId||'';$('concept-size').value=state.previewSelection.sizeId||'';
 $('concept-swatch').style.backgroundColor=described.color?.hex||'#D4CDC3';
 $('concept-color-note').textContent=described.color?.label||'No color options mapped to this draft product.';
 $('summary-color').textContent=described.color?.label||'Not specified';
 $('summary-size').textContent=described.size?.label||'Not specified';
 $('mode-3d').disabled=!state.imported&&!createConceptMesh(state.product);
 $('model-status').textContent=previewModelStatus({product:state.product,imported:state.imported});
 // UV preview diagnostics must reflect the CURRENT design, not import-time layers.
 const uvInfo=state.imported?buildConceptUvReport({product:state.product,layers:state.layers,inspection:state.imported}):null;
 $('uv-diagnostic-live').textContent=uvInfo?.previewChecked?
  `Unverified UV concept: ${uvInfo.issues.length} warning(s), ${uvInfo.details.length} design element(s) inspected. Sampled coverage is NOT production approval.`:
  'No verified UV concept report. Import a local model or correct its mapping; checkout remains disabled.';
 $('surface').replaceChildren(...state.product.surfaces.map(s=>{const o=document.createElement('option');o.value=s.id;o.textContent=s.label;return o;}));$('surface').value=state.surface;
 // Only expose editable layers on the visible surface. Other surfaces retain their layers.
 const visibleLayers=state.layers.filter(l=>l.surfaceId===state.surface);
 if(state.selected&&!visibleLayers.some(l=>l.id===state.selected))state.selected=null;
 const options=[new Option('Choose an element on this surface',''),...visibleLayers.map((l,i)=>new Option(`${i+1}. ${l.type==='text'?l.value.substring(0,26):'Reference artwork'}`,l.id))];
 $('layers').replaceChildren(...options);$('layers').value=state.selected||'';
 const layer=visibleLayers.find(l=>l.id===state.selected);
 const count=visibleLayers.length;
 $('surface-edit-context').textContent=describeActivePreview({product:state.product,surfaceId:state.surface,layers:state.layers,selectedId:state.selected,mode:state.mode});
 $('stage').setAttribute('aria-label',`${state.product.label}, ${surface.label}, 2D concept preview. ${count} element${count===1?'':'s'} on this surface. ${layer?`Element ${visibleLayers.indexOf(layer)+1} selected. Arrow keys move it.`:'Select an element using the design element menu before using arrow keys.'}`);$('rotation').value=layer?.rotationDeg||0;$('rotation').disabled=!layer;$('scale').disabled=!layer;$('remove').disabled=!layer;
 $('rotation-output').textContent=`${layer?.rotationDeg||0}°`;
 $('scale-output').textContent=`${Math.round((layer?.scaleFactor||1)*100)}%`;
 const canNudge=state.mode==='2d'&&!!layer&&layer.surfaceId===state.surface;
 for(const button of document.querySelectorAll('[data-nudge]'))button.disabled=!canNudge;
 // Cross-surface copying is a concept edit, never a persisted or production grant.
 const targets=state.product.surfaces.filter(s=>s.id!==state.surface);
 const targetSelect=$('copy-target-surface'),priorTarget=targetSelect.value;
 targetSelect.replaceChildren(...targets.map(s=>new Option(s.label,s.id)));
 if(targets.some(s=>s.id===priorTarget))targetSelect.value=priorTarget;
 targetSelect.disabled=!selectedOnCurrentSurface()||targets.length===0;
 $('copy-selected-surface').disabled=targetSelect.disabled;
 $('copy-placement').disabled=targetSelect.disabled;
 function selectedOnCurrentSurface(){return !!layer&&layer.surfaceId===state.surface;}

 $('status').textContent=state.layers.length?'Preview valid for local editing only.':'Select a style and add a design.';
}
function render(){
 conceptExportRevision++; // invalidates in-flight redacted export even after ABA editor changes
 if(state.mode==='3d'&&!state.imported&&!createConceptMesh(state.product))state.mode='2d';
 invalidatePreviewReview();
 editorAsyncGate.invalidate();
 persistOptedInSession();
 updateControls();const svg=$('stage');svg.replaceChildren();const p=state.product;
 const shape=el('g',{fill:describePreviewSelection(p,state.previewSelection).color?.hex||colorByCategory[p.category]||'#8B776C',stroke:'#231F20','stroke-width':'6','stroke-linejoin':'round'});
 // These strings are static SVG templates controlled by the developer, never user content.
 shape.innerHTML=getFootwearConceptView(p,state.surface)?.shapeMarkup||shapes[p.geometry.previewShape]||'<rect x="135" y="120" width="530" height="395" rx="15"/><text x="400" y="323" text-anchor="middle" font-size="24" fill="#F3E9D7" stroke="none">2D CONCEPT ONLY</text>';svg.append(shape);
 const s=p.surfaces.find(s=>s.id===state.surface), z=s.previewRect;
 const zone=el('rect',{x:z.x*800,y:z.y*640,width:z.width*800,height:z.height*640,rx:7,class:'print-zone'});svg.append(zone);
 for(const layer of state.layers.filter(l=>l.surfaceId===state.surface)){
  const x=(z.x+layer.x*z.width)*800,y=(z.y+layer.y*z.height)*640,w=layer.width*z.width*800,h=layer.height*z.height*640;
  const g=el('g',{'data-layer':layer.id,class:'art-layer'+(layer.id===state.selected?' selected':'')});
  g.setAttribute('transform',`rotate(${layer.rotationDeg||0} ${x+w/2} ${y+h/2})`);
  if(layer.type==='artwork'){
   const image=el('image',{x,y,width:w,height:h,preserveAspectRatio:'xMidYMid meet',href:state.artUrls.get(layer.artworkId)||''});g.append(image);
  }else{
   const t=el('text',{x:x+w/2,y:y+h*.74,'font-family':'Georgia,serif','font-size':Math.min(h*.86,52),'text-anchor':'middle',fill:'#231F20','font-weight':700,'textLength':Math.max(10,w*.92),'lengthAdjust':'spacingAndGlyphs'});t.textContent=layer.value;g.append(t);
  }
  if(layer.id===state.selected)g.append(el('rect',{x,y,width:w,height:h,class:'layer-boundary'}));
  svg.append(g);
 }
 svg.style.transform=`scale(${state.zoom})`;
 update3DMode();showSaved();
}
function addLayer(type,extra){const l={id:`layer-${Date.now()}-${Math.random().toString(36).slice(2,7)}`,type,surfaceId:state.surface,x:.25,y:.32,width:.45,height:type==='text'?.17:.4,rotationDeg:0,scaleFactor:1,...extra};
 const errors=validateComposition(state.product,{layers:[...state.layers,l]});if(errors.length){$('status').textContent=errors.map(e=>e.message).join('; ');return;}
 state.layers.push(l);state.selected=l.id;render();return true;}
function newProduct({force=false}={}){const p=availableManifests[$('product').value];if(!p)return;
 if(p.id===state.product.id)return;
 if(!force&&hasCustomerWork({...state,defaultSelection:normalizePreviewSelection(state.product)})&&!window.confirm('Switching products will discard this preview and its unsaved or locally saved draft. Continue?')){
  $('product').value=state.product.id;return;
 }
 for(const url of state.artUrls.values())URL.revokeObjectURL(url);state.artUrls.clear();state.artGrants.clear();
 // Reset layers because different products have distinct geometry and surfaces.
 modelImportLifecycle.invalidate();editorAsyncGate.invalidate();
 state.product=p;state.surface=p.surfaces[0].id;state.previewSelection=normalizePreviewSelection(p);state.layers=[];state.selected=null;state.saved=null;state.savedSnapshot=null;state.imported=null;invalidateCalibration('New product selected; measurements are not carried over.',{clearFields:true});$('model-file').value='';$('clear-model').disabled=true;$('model-import-summary').textContent='No model imported. GLB files are inspected locally, never approved for manufacturing.';state.camera={yaw:0,pitch:p.geometry.kind==='flat'?.95:.10,zoom:1};state.mode=permittedPreviewMode({requestedMode:state.mode,product:p,imported:null});showSaved();render();}
let lastRenderRequest=0;
function draw3DNow(){
 const metadata=render3D($('stage-3d'),state.product,state.layers,state.artUrls,state.camera,()=>schedule3D(),state.imported?.asset||null,describePreviewSelection(state.product,state.previewSelection).color?.hex||null);
 if(!metadata.supported){$('model-status').textContent='2D fallback only';}
}
function schedule3D(){if(state.mode!=='3d')return;if(lastRenderRequest)return;lastRenderRequest=requestAnimationFrame(()=>{lastRenderRequest=0;draw3DNow();});}
function update3DMode(){
 state.mode=permittedPreviewMode({requestedMode:state.mode,product:state.product,imported:state.imported});const three=state.mode==='3d';$('stage-3d').hidden=!three;if(three)$('stage').setAttribute('hidden','');else $('stage').removeAttribute('hidden');$('orbit-tools').hidden=!three;
 $('mode-3d').setAttribute('aria-pressed',String(three));$('mode-2d').setAttribute('aria-pressed',String(!three));
 if(three)schedule3D();
}
$('mode-3d').addEventListener('click',()=>{if($('mode-3d').disabled)return;state.mode='3d';render();});
$('mode-2d').addEventListener('click',()=>{state.mode='2d';render();});
$('view-front').addEventListener('click',()=>{state.camera.yaw=0;state.camera.pitch=state.product.geometry.kind==='flat'?.95:.10;schedule3D();});
$('view-back').addEventListener('click',()=>{state.camera.yaw=Math.PI;state.camera.pitch=state.product.geometry.kind==='flat'?.95:.10;schedule3D();});
$('orbit-left').addEventListener('click',()=>{state.camera.yaw-=Math.PI/8;schedule3D();});
$('orbit-right').addEventListener('click',()=>{state.camera.yaw+=Math.PI/8;schedule3D();});
$('view-reset').addEventListener('click',()=>{state.camera={yaw:0,pitch:state.product.geometry.kind==='flat'?.95:.10,zoom:1};$('orbit-zoom').value='100';schedule3D();});
$('orbit-zoom').addEventListener('input',e=>{state.camera.zoom=+e.target.value/100;schedule3D();});
let orbit=null;
$('stage-3d').addEventListener('pointerdown',e=>{if(state.mode!=='3d')return;orbit={x:e.clientX,y:e.clientY,yaw:state.camera.yaw,pitch:state.camera.pitch};$('stage-3d').setPointerCapture(e.pointerId);});
$('stage-3d').addEventListener('pointermove',e=>{if(!orbit)return;state.camera.yaw=orbit.yaw+(e.clientX-orbit.x)*.012;state.camera.pitch=Math.max(-.2,Math.min(1.42,orbit.pitch+(e.clientY-orbit.y)*.009));schedule3D();});
$('stage-3d').addEventListener('pointerup',()=>orbit=null);
$('stage-3d').addEventListener('pointercancel',()=>orbit=null);
window.addEventListener('resize',schedule3D);
$('product').replaceChildren(...PRODUCT_MANIFESTS.map(p=>new Option(p.label,p.id)));$('product').value=state.product.id;
$('product').addEventListener('change',()=>newProduct());
function applyPreviewEntry(){
 const entry=resolvePreviewEntry(window.location.search,availableManifests);
 if(entry.status==='SELECTED'){
  if(state.product.id!==entry.manifestId){$('product').value=entry.manifestId;newProduct({force:true});}
  $('entry-feedback').textContent=`Previewing ${state.product.label}. Save a private local draft to inspect the non-purchasing readiness summary.`;
 }else if(entry.status==='INVALID_LINK'||entry.status==='UNKNOWN_PRODUCT'){
  $('entry-feedback').textContent='This product link is unavailable or contains unsupported parameters. Showing the default concept; no account or order was opened.';
 }else $('entry-feedback').textContent='Choose any concept canvas to begin a private, non-purchasing preview.';
}
applyPreviewEntry();
// The initial URL may refer to an opt-in local draft snapshot that has not loaded yet.
// Preserve the entire initial editor state and disallow late automatic navigation after user input.
const initialEntryStatus=resolvePreviewEntry(window.location.search,availableManifests).status;
const initialProductId=state.product.id;
const initialSnapshot=editorSnapshot(state.product.id,state.layers,state.previewSelection);
let userInteracted=false;
for(const eventName of ['pointerdown','keydown','input','change'])document.addEventListener(eventName,()=>{userInteracted=true;},true);

$('model-file').addEventListener('change',async e=>{
 const file=e.target.files?.[0];e.target.value='';if(!file)return;
 const ticket=modelImportLifecycle.begin(),product=state.product;
 $('model-import-summary').textContent='Inspecting GLB structure, mesh geometry and printable UV surface bindings…';
 try{
  const model=await inspectGlb(await readBoundedLocalGlb(file),product);
  if(!modelImportLifecycle.current(ticket))return;
  validateLocalModelInspection(model,product);
  modelImportLifecycle.commit(ticket,()=>{
   state.imported=model;invalidateCalibration('3D model changed. Revalidate physical measurements before exporting.');
   $('clear-model').disabled=false;
   const uv=buildConceptUvReport({product,layers:state.layers,inspection:model});
   $('model-import-summary').textContent=`IMPORTED / UNVERIFIED · ${model.triangleCount} triangles · ${model.mappedSurfaces.length} mapped surface(s) · missing: ${model.missingSurfaces.join(', ')||'none'} · UV concept diagnostic: ${uv.issues.length} warning(s), sampled only, NOT production approval · SHA-256 ${model.sha256.slice(0,16)}… Local browser memory only.`;
   render();
  });
 }catch(err){if(modelImportLifecycle.current(ticket))$('model-import-summary').textContent=`GLB rejected (${err.code||'IMPORT'}): ${err.message}. Previous preview preserved.`;}
});
$('clear-model').addEventListener('click',()=>{modelImportLifecycle.invalidate();state.imported=null;invalidateCalibration('3D model cleared. Revalidate physical measurements.');$('clear-model').disabled=true;state.mode=permittedPreviewMode({requestedMode:state.mode,product:state.product,imported:null});$('model-import-summary').textContent='Procedural concept restored. Import was never a manufacturing approval.';render();});
$('validate-calibration').addEventListener('click',()=>{
 const num=id=>$(`${id}`).value===''?null:Number($(`${id}`).value);
 const zone=state.product.surfaces.find(x=>x.id===state.surface);
 const draft=createCalibrationWorksheet(state.product,[{surfaceId:zone.id,widthMm:num('print-width-mm'),heightMm:num('print-height-mm'),blankWidthMm:num('blank-width-mm'),blankHeightMm:num('blank-height-mm'),processCode:zone.allowableMethods[0]||'',fixtureReference:$('fixture-reference').value}],{
 blankSku:$('blank-sku').value,measuredBy:$('technician').value,sourceDocument:$('measurement-source').value,measuredAt:$('measurement-date').value,modelSha256:state.imported?.sha256});
 const reviewed=reviewConceptCalibration({worksheet:draft,product:state.product,
  surfaceId:state.surface,modelSha256:state.imported?.sha256??null});
 state.calibration=draft;state.calibrationSignature=draft.issues.length||!reviewed.canEstimatePlacement?null:calibrationFingerprint();
 $('export-calibration').disabled=!!draft.issues.length||!reviewed.canEstimatePlacement;persistOptedInSession();
 $('calibration-result').textContent=draft.issues.length?'Incomplete: '+draft.issues.map(i=>i.message).join(' · '):`DRAFT only: ${zone.id} ${draft.zones[0].printableWidthMm} × ${draft.zones[0].printableHeightMm} mm. Physical verification, materials, pricing, and production review still required.`;
});
$('export-calibration').addEventListener('click',()=>{
 if(!state.calibration||state.calibration.issues.length)return;
 if(state.calibrationSignature!==calibrationFingerprint()){
  invalidateCalibration('Measurement context changed. Revalidate before exporting.');return;
 }
 const url=URL.createObjectURL(new Blob([JSON.stringify(state.calibration,null,2)],{type:'application/json'}));
 const a=document.createElement('a');a.href=url;a.download='trendyjoes-calibration-DRAFT.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),2000);
});

$('download-concept-evidence').addEventListener('click',async()=>{
 const button=$('download-concept-evidence');button.disabled=true;
 const snapshot=()=>buildPrivateConceptDesignEvidence({product:state.product,surfaceId:state.surface,
  previewSelection:state.previewSelection,layers:state.layers,availableArtworkIds:[...state.artUrls.keys()],inspection:state.imported});
 try{
  const packet=await preparePrivateConceptExport({readSnapshot:snapshot,readRevision:()=>conceptExportRevision});
  const raw=JSON.stringify(packet,null,2);
  const url=URL.createObjectURL(new Blob([raw],{type:'application/json'}));
  const a=document.createElement('a');a.href=url;a.download='trendyjoes-private-concept-evidence.json';a.click();
  setTimeout(()=>URL.revokeObjectURL(url),2000);
  $('concept-evidence-status').textContent='Private redacted concept evidence downloaded. No order or manufacturing approval.';
 }catch(err){$('concept-evidence-status').textContent=`Concept export refused: ${err.code||'UNVERIFIED_PREVIEW'}. Your editor was not changed.`;}
 finally{button.disabled=false;}
});
// This is a local redacted REVIEW, never a production or ordering approval.
$('download-concept-review').addEventListener('click',async()=>{
 const button=$('download-concept-review');button.disabled=true;
 const revision=conceptExportRevision,calibrationSignature=calibrationFingerprint(),worksheet=state.calibration;
 try{
  const packet=await buildConceptReviewPacket({product:state.product,surfaceId:state.surface,
   previewSelection:state.previewSelection,layers:state.layers,availableArtworkIds:[...state.artUrls.keys()],
   inspection:state.imported,worksheet:worksheet&&state.calibrationSignature===calibrationSignature?worksheet:null});
  if(revision!==conceptExportRevision||calibrationSignature!==calibrationFingerprint()||
   state.calibration!==worksheet)throw Object.assign(new Error('REVIEW_STALE_EDITOR'),{code:'REVIEW_STALE_EDITOR'});
  const url=URL.createObjectURL(new Blob([JSON.stringify(packet,null,2)],{type:'application/json'}));
  const a=document.createElement('a');a.href=url;a.download='trendyjoes-private-concept-review.json';a.click();
  setTimeout(()=>URL.revokeObjectURL(url),2000);
  $('concept-review-status').textContent=`Redacted review downloaded with ${packet.issues.length} unresolved readiness warning(s). No manufacturing approval or order.`;
 }catch(err){$('concept-review-status').textContent=`Review refused: ${err.code||'UNVERIFIED_PREVIEW'}. No checkout enabled.`;}
 finally{button.disabled=false;}
});
$('surface').addEventListener('change',e=>{
 if(!state.product.surfaces.some(s=>s.id===e.target.value))return;
 modelImportLifecycle.invalidate();editorAsyncGate.invalidate();state.surface=e.target.value;state.selected=null;
 invalidateCalibration('Design surface changed; measurements are not carried over.',{clearFields:true});render();
});
$('concept-color').addEventListener('change',e=>{
 try{state.previewSelection=normalizePreviewSelection(state.product,{...state.previewSelection,colorId:e.target.value});invalidateCalibration('Concept color changed; revalidate physical measurements.');render();}
 catch{$('status').textContent='Unsupported concept color';}
});
$('concept-size').addEventListener('change',e=>{
 try{state.previewSelection=normalizePreviewSelection(state.product,{...state.previewSelection,sizeId:e.target.value});invalidateCalibration('Concept size changed; revalidate physical measurements.');render();}
 catch{$('status').textContent='Unsupported concept size / format';}
});
$('add-text').addEventListener('click',()=>addLayer('text',{value:$('text-entry').value.trim()||'Your design'}));
$('artwork').addEventListener('change',async e=>{
 const f=e.target.files?.[0];if(!f)return;e.target.value='';
 if(!['image/jpeg','image/png','image/webp'].includes(f.type)||f.size>5*1024*1024){$('status').textContent='Please select PNG/JPG/WebP up to 5 MB';return;}
 const ticket=editorAsyncGate.begin('artwork');
 $('status').textContent='Inspecting and saving to local development storage…';
 try{
  const response=await fetch('/api/artworks',{method:'POST',headers:{'Content-Type':f.type},body:f});
  const data=await response.json();if(!response.ok)throw Error(data.error||'Upload failed');
  if(!editorAsyncGate.current(ticket))return; // Old product, surface, variant, revision or newer upload.
  const receipt=validateLocalArtworkReceipt(data,{mediaType:f.type,bytes:f.size});
  const result=editorAsyncGate.commit(ticket,()=>{
   if(state.artUrls.has(receipt.id))throw Error('Duplicate local artwork reference');
   const url=URL.createObjectURL(f),previousSelection=state.selected,previousLength=state.layers.length;
   state.artUrls.set(receipt.id,url);state.artGrants.set(receipt.id,receipt.grant);
   let added=false;
   try{added=addLayer('artwork',{artworkId:receipt.id})===true;return added;}
   finally{if(!added){state.layers.length=previousLength;state.selected=previousSelection;
    state.artUrls.delete(receipt.id);state.artGrants.delete(receipt.id);URL.revokeObjectURL(url);}}
  });
  if(result.applied&&result.value)$('status').textContent=`Artwork stored in private local test service (${receipt.width} × ${receipt.height}px).`;
  else if(result.applied)$('status').textContent='Artwork uploaded to local test storage, but placement was refused; no artwork grant retained in this editor.';
 }catch(err){if(editorAsyncGate.current(ticket))$('status').textContent=`Local upload unavailable: ${err.message}`;}
});
$('layers').addEventListener('change',e=>{state.selected=e.target.value||null;render();});
$('remove').addEventListener('click',()=>{state.layers=state.layers.filter(l=>l.id!==state.selected);state.selected=null;render();});
$('copy-selected-surface').addEventListener('click',()=>{
 const targetSurfaceId=$('copy-target-surface').value;
 const placement=$('copy-placement').value;
 const result=duplicatePreviewLayerToSurface({product:state.product,layers:state.layers,
  selectedId:state.selected,sourceSurfaceId:state.surface,targetSurfaceId,placement,
  newId:`copy-${Date.now()}-${Math.random().toString(36).slice(2,10)}`});
 if(!result.applied){$('status').textContent='Copy refused: '+result.reason+'. Existing design unchanged.';return;}
 state.layers=result.layers;state.surface=result.targetSurfaceId;state.selected=result.selectedId;
 state.saved=null;state.savedSnapshot=null;state.mode='2d';
 render();$('layers').focus({preventScroll:true});
 $('status').textContent=placement==='center'?'Design element copied and centered in the target concept zone. Original preserved; not production calibrated.':'Design element copied with relative placement preserved. Original preserved; not production calibrated.';
});
$('rotation').addEventListener('input',e=>{const l=state.layers.find(x=>x.id===state.selected);if(!l)return;
 const angle=+e.target.value;const cand={...l,rotationDeg:angle};const errs=validateComposition(state.product,{layers:state.layers.map(x=>x===l?cand:x)});
 if(!errs.length){l.rotationDeg=angle;render();}else $('status').textContent='Rotation extends outside the selected zone';});
$('scale').addEventListener('input',e=>{const l=state.layers.find(x=>x.id===state.selected);if(!l)return;
 const next=+e.target.value/100,ratio=next/(l.scaleFactor||1),w=l.width*ratio,h=l.height*ratio;
 const cand={...l,x:l.x+(l.width-w)/2,y:l.y+(l.height-h)/2,width:w,height:h,scaleFactor:next};
 if(validateComposition(state.product,{layers:state.layers.map(x=>x===l?cand:x)}).length===0)Object.assign(l,cand);
 else $('status').textContent='Size would exceed selected zone';render();});
$('zoom').addEventListener('input',e=>{state.zoom=+e.target.value/100;render();});
$('reset').addEventListener('click',()=>{clearPreviewSession(tabRecoveryStorage());$('session-recovery-opt-in').checked=false;$('session-recovery-status').textContent='Tab preview forgotten. Recovery is off.';state.layers=[];state.selected=null;state.saved=null;state.savedSnapshot=null;invalidateCalibration('Preview reset; measurements cleared.',{clearFields:true});showSaved();render();});
function invalidatePreviewReview(){
 $('preview-summary-panel').hidden=true;
 for(const id of ['review-product','review-surface','review-color','review-size','review-surfaces','review-layers','review-draft','review-model','review-blockers'])$(id).textContent='';
}
$('review-preview').addEventListener('click',()=>{
 invalidatePreviewReview();
 try{
  const availableArtworkIds=[...state.artUrls.keys()].filter(id=>state.artGrants.has(id));
  const review=buildPreviewDesignSummary({productManifestId:state.product.id,surfaceId:state.surface,
   previewSelection:state.previewSelection,layers:state.layers,saved:state.saved,savedSnapshot:state.savedSnapshot,
   availableArtworkIds,importedModelPresent:!!state.imported},availableManifests);
  $('review-product').textContent=review.productLabel;
  $('review-surface').textContent=review.surfaceLabel;
  $('review-color').textContent=review.colorLabel;
  $('review-size').textContent=review.formatLabel;
  $('review-surfaces').textContent=review.designedSurfaces.join(', ');
  $('review-layers').textContent=`${review.layerCount} total · ${review.textLayerCount} lettering · ${review.artworkLayerCount} private reference artwork`;
  $('review-draft').textContent=review.draftState==='LOCAL_REVISION_CURRENT'?`Local-only revision ${review.revision}, not hosted`:'Unsaved preview · not backed up';
  $('review-model').textContent=review.modelStatus==='IMPORTED_UNVERIFIED'?'Imported model · unverified':'Concept model · unverified';
  $('review-blockers').textContent='Manufacturing, price, customer authentication, and checkout are not approved or connected.';
  $('preview-summary-panel').hidden=false;
  $('preview-summary-heading').focus({preventScroll:true});
  $('preview-summary-panel').scrollIntoView({block:'start',behavior:'smooth'});
 }catch(error){$('status').textContent=`Review unavailable: ${error.message}. Add a valid design before reviewing.`;}
});
$('review-edit').addEventListener('click',()=>{invalidatePreviewReview();$('review-preview').focus();});
function renderMultiReview(){
 const list=multiReview.list();
 const bridge=shopifyEntries.get(state.product.id);
 const current=savedDraftMatchesEditor({productManifestId:state.product.id,layers:state.layers,
  previewSelection:state.previewSelection,saved:state.saved,savedSnapshot:state.savedSnapshot});
 $('multi-add').disabled=!(bridge&&current&&bridge.variantGids.includes($('shopify-variant').value));
 $('multi-review').disabled=multiReviewTransition.status().busy||list.filter(e=>e.selected).length<2;
 const fragment=document.createDocumentFragment();
 for(const item of list){
  const li=document.createElement('li'),label=document.createElement('label');
  const checkbox=document.createElement('input');checkbox.type='checkbox';checkbox.checked=item.selected;
  checkbox.setAttribute('aria-label',`Include ${item.productLabel} saved revision ${item.revision}`);
  checkbox.setAttribute('data-review-reference',item.reference);checkbox.setAttribute('data-review-action','select');
  checkbox.addEventListener('change',()=>{multiReview.select(item.reference,checkbox.checked);multiReviewTransition.invalidate();renderMultiReview();
   $('multi-results').replaceChildren();$('multi-status').textContent='Selection changed. Recheck all saved drafts.';});
  const name=document.createElement('span');name.textContent=` ${item.productLabel} · saved revision ${item.revision} · ${item.reference}`;
  label.append(checkbox,name);
  const remove=document.createElement('button');remove.type='button';remove.className='secondary';
  remove.textContent='Remove';remove.setAttribute('aria-label',`Remove ${item.productLabel} from review list`);
  remove.setAttribute('data-review-reference',item.reference);remove.setAttribute('data-review-action','remove');
  remove.addEventListener('click',()=>{multiReview.remove(item.reference);multiReviewTransition.invalidate();renderMultiReview();
   $('multi-results').replaceChildren();$('multi-status').textContent='Draft removed from this tab review list.';});
  li.append(label,remove);fragment.append(li);
 }
 replaceReviewListPreservingFocus({document,list:$('multi-list'),replace:()=>$('multi-list').replaceChildren(fragment),fallback:$('multi-status')});
 $('multi-clear').disabled=list.length===0&&multiRecovery.list().length===0;
 $('multi-export').disabled=list.length===0;
 const pending=document.createDocumentFragment();
 for(const item of multiRecovery.list()){
  const li=document.createElement('li');
  li.textContent=`${item.productLabel} · revision ${item.revision} · reopen its private receipt to revalidate`;
  pending.append(li);
 }
 $('multi-pending').replaceChildren(pending);
 const progress=recoveryConfirmation.status();
 $('multi-progress').textContent=progress.cancelled
  ?'Cancellation requested. Waiting for the private readiness check to settle; no review access will be granted.'
  :progress.total
  ?`${progress.completed} of ${progress.total} private receipts confirmed; ${progress.pending} still require reopening and confirmation. No purchase is possible.`
  :'No imported recovery checklist. Private receipts are never stored in the checklist.';
 $('multi-confirm').disabled=!progress.staged||progress.busy||
  state.saved?.reference!==progress.staged.reference||
  state.saved?.revision!==progress.staged.revision||
  state.product.id!==progress.staged.productManifestId;
 $('multi-cancel').disabled=(!progress.staged&&!progress.busy)||progress.cancelled;
}
$('multi-add').addEventListener('click',()=>{
 const bridge=shopifyEntries.get(state.product.id);
 if(!bridge||!state.saved||!savedDraftMatchesEditor({productManifestId:state.product.id,
  layers:state.layers,previewSelection:state.previewSelection,saved:state.saved,savedSnapshot:state.savedSnapshot})||
  !bridge.variantGids.includes($('shopify-variant').value))return;
 try{
  multiReview.add({reference:state.saved.reference,revision:state.saved.revision,ownerToken:state.saved.ownerToken,
   productManifestId:state.product.id,productLabel:state.product.label,
   productGid:bridge.productGid,variantGid:$('shopify-variant').value});
  multiReviewTransition.invalidate();
  $('multi-results').replaceChildren();$('multi-status').textContent='Saved draft added to this tab only. Add another saved design to compare.';
  renderMultiReview();
 }catch{$('multi-status').textContent='Draft could not be added. Check the saved revision and local catalog.';}
});
$('multi-review').addEventListener('click',async()=>{
 const button=$('multi-review');if(button.disabled)return;
 let operation;
 try{operation=multiReviewTransition.start();}catch{return;}
 button.disabled=true;
 $('multi-results').replaceChildren();$('multi-status').textContent='Rechecking selected private local drafts twice…';
 $('multi-status').focus({preventScroll:true});
 try{
  const result=await operation.promise;
  if(!multiReviewTransition.current(operation.ticket))return;
  const fragment=document.createDocumentFragment();
  for(const item of result.lines){const li=document.createElement('li');
   li.textContent=`${item.productLabel} · saved revision ${item.revision} · locally checked; checkout and manufacturing blocked.`;
   fragment.append(li);}
  $('multi-results').replaceChildren(fragment);
  $('multi-status').textContent=`${result.lineCount} saved designs locally rechecked. No cart, order, payment or production approval created.`;
 }catch{
  if(!multiReviewTransition.current(operation.ticket))return;
  $('multi-results').replaceChildren();
  $('multi-status').textContent='Review refused: a saved draft, identity, variant or selection may have changed. Reopen or resave the draft before retrying. No cart or order created.';
 }finally{
  if(multiReviewTransition.current(operation.ticket)){
   renderMultiReview();$('multi-status').focus({preventScroll:true});
  }
 }
});
$('multi-export').addEventListener('click',()=>{
 try{
  const raw=createReviewChecklist(multiReview.checklistEntries());
  const url=URL.createObjectURL(new Blob([raw],{type:'application/json'}));
  const a=document.createElement('a');a.href=url;a.download='trendyjoes-review-CHECKLIST-NO-ACCESS.json';a.click();
  setTimeout(()=>URL.revokeObjectURL(url),1500);
  $('multi-status').textContent='Non-authorizing checklist exported. To resume, import it within 30 minutes and separately reopen each PRIVATE recovery receipt.';
 }catch{$('multi-status').textContent='Could not export review checklist. No private grants exported.';}
});
let privateReceiptOpenEpoch=0;
$('multi-import').addEventListener('change',async e=>{
 const file=e.target.files?.[0];e.target.value='';if(!file)return;
 const importing=++privateReceiptOpenEpoch;recoveryConfirmation.cancel();
 try{
  if(multiReview.list().length||multiRecovery.list().length||file.size>16384)throw Error('RECOVERY_REJECTED');
  const raw=await file.text();if(importing!==privateReceiptOpenEpoch)throw Error('IMPORT_SUPERSEDED');
  const entries=multiRecovery.importChecklist(raw);
  recoveryConfirmation.reset();
  $('multi-status').textContent=`${entries.length} checklist entries pending. Reopen each PRIVATE recovery receipt separately. No draft was restored automatically.`;
 }catch{if(importing===privateReceiptOpenEpoch)$('multi-status').textContent='Checklist refused (expired, altered, too large or existing review not cleared). No access granted.';}
 if(importing===privateReceiptOpenEpoch)renderMultiReview();
});
$('multi-clear').addEventListener('click',()=>{privateReceiptOpenEpoch++;multiReviewTransition.invalidate();multiReview.clear();multiRecovery.clear();recoveryConfirmation.reset();renderMultiReview();
 $('multi-results').replaceChildren();$('multi-status').textContent='Review list and its local owner grants forgotten from this tab.';
 $('multi-status').focus({preventScroll:true});});
function showSaved(){
 const bridge=shopifyEntries.get(state.product.id);
 const current=savedDraftMatchesEditor({productManifestId:state.product.id,layers:state.layers,previewSelection:state.previewSelection,saved:state.saved,savedSnapshot:state.savedSnapshot});
 $('shopify-bridge').hidden=!bridge;
 $('review-shopify').disabled=!(bridge&&current);
 $('review-cart').disabled=!(bridge&&current);
 const previousVariant=$('shopify-variant').value;
 $('shopify-variant').replaceChildren(...(bridge?.variantGids||[]).map(id=>new Option(id.split('/').at(-1),id)));
 if(bridge?.variantGids.includes(previousVariant))$('shopify-variant').value=previousVariant;
 if(state.saved&&!current){
  $('shopify-binding-result').textContent='Unsaved changes: save the updated design before checking this binding.';
  $('cart-readiness-result').textContent='Unsaved changes: cart readiness is disabled until this revision is saved.';
 }
 $('saved-project').hidden=!state.saved;
 $('saved-reference').textContent=state.saved?`${state.saved.reference} · Revision ${state.saved.revision} · ${current?'Current saved preview':'UNSAVED CHANGES — save before reviewing Shopify'}`:'';
 renderMultiReview();
}
function uploadGrants(){
 const used=new Set(state.layers.filter(l=>l.type==='artwork').map(l=>l.artworkId));
 return Object.fromEntries([...used].filter(id=>state.artGrants.has(id)).map(id=>[id,state.artGrants.get(id)]));
}
function requestStillMatches(body){
 const entry=shopifyEntries.get(state.product.id);
 return reviewSelectionMatches({productManifestId:state.product.id,layers:state.layers,previewSelection:state.previewSelection,saved:state.saved,savedSnapshot:state.savedSnapshot,productGid:entry?.productGid,variantGid:$('shopify-variant').value,requested:body});
}
const saveOperation={current:0};
async function saveToLocal(){
 invalidatePreviewReview();
 const previous=$('save-local').disabled; if(previous)return;
 const ticket=editorAsyncGate.begin('save');
 const attempt=++saveOperation.current;
 $('save-local').disabled=true;$('status').textContent='Saving private draft…';
 try{
  const body={productManifestId:state.product.id,layers:state.layers,previewSelection:state.previewSelection,artworkGrants:uploadGrants()};
  const snapshot=editorSnapshot(body.productManifestId,body.layers,body.previewSelection);
  const edit=!!state.saved;
  const endpoint=edit?`/api/designs/${state.saved.reference}/revisions`:'/api/designs';
  const response=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json',...(edit?{'Authorization':`Bearer ${state.saved.ownerToken}`}:{})},body:JSON.stringify(edit?{...body,expectedRevision:state.saved.revision}:body)});
  const data=await response.json();if(!response.ok)throw Error(data.error||'Save failed');
  if(!editorAsyncGate.current(ticket))return; // A newer editor must never inherit this private revision.
  editorAsyncGate.commit(ticket,()=>{state.saved={reference:data.reference,revision:data.revision,ownerToken:data.ownerToken||state.saved?.ownerToken};
  state.savedSnapshot=snapshot;showSaved();});
  $('shopify-binding-result').textContent='Saved revision changed: review the updated design to refresh this binding.';
  $('cart-readiness-result').textContent='Saved revision changed: run a new cart-readiness check. No purchase created.';
  $('status').textContent=`Draft revision ${data.revision} saved locally. Not ready for manufacture or checkout.`;
 }catch(err){if(editorAsyncGate.current(ticket))$('status').textContent=`Save failed: ${err.message}`;}
 finally{if(attempt===saveOperation.current)$('save-local').disabled=false;}
}
$('save-local').addEventListener('click',saveToLocal);
$('shopify-variant').addEventListener('change',()=>{editorAsyncGate.invalidate();$('shopify-binding-result').textContent='Variant changed; binding must be checked again.';$('cart-readiness-result').textContent='Variant changed; cart readiness must be checked again.';renderMultiReview();});
$('review-shopify').addEventListener('click',async()=>{
 const entry=shopifyEntries.get(state.product.id);
 if(!entry||!savedDraftMatchesEditor({productManifestId:state.product.id,layers:state.layers,previewSelection:state.previewSelection,saved:state.saved,savedSnapshot:state.savedSnapshot}))return;
 $('shopify-binding-result').textContent='Checking local owner token, revision, actual Shopify identities, and composition…';
 try{
  const body={reference:state.saved.reference,expectedRevision:state.saved.revision,productGid:entry.productGid,variantGid:$('shopify-variant').value};
  const r=await fetch('/api/shopify/preview-binding',{method:'POST',headers:{'Content-Type':'application/json','Authorization':`Bearer ${state.saved.ownerToken}`},body:JSON.stringify(body)});
  const result=await r.json();if(!r.ok)throw Error(result.error||'Binding refused');
  if(!requestStillMatches(body))return; // Async response belongs to an older onscreen design/variant.
  $('shopify-binding-result').textContent=`Authenticated local binding for revision ${result.revision}. Product/variant matched snapshot. BLOCKED for checkout: ${result.blockers.join(', ')}. No Shopify cart or order created.`;
 }catch(err){if(requestStillMatches(body))$('shopify-binding-result').textContent=`Binding declined: ${err.message}. No checkout available.`;}
});

$('review-cart').addEventListener('click',async()=>{
 const entry=shopifyEntries.get(state.product.id);
 if(!entry||!savedDraftMatchesEditor({productManifestId:state.product.id,layers:state.layers,previewSelection:state.previewSelection,saved:state.saved,savedSnapshot:state.savedSnapshot}))return;
 $('cart-readiness-result').textContent='Revalidating saved revision and offline Shopify catalog identities…';
 try{
  const body={reference:state.saved.reference,expectedRevision:state.saved.revision,productGid:entry.productGid,variantGid:$('shopify-variant').value};
  const response=await fetch('/api/shopify/cart-readiness',{method:'POST',headers:{'Content-Type':'application/json','Authorization':`Bearer ${state.saved.ownerToken}`},body:JSON.stringify(body)});
  const result=await response.json();if(!response.ok)throw Error(result.error||'Readiness check rejected');
  if(!requestStillMatches(body))return; // Never display a mismatched earlier response.
  const results=result.checks.map(c=>`${c.id.replaceAll('_',' ')}: ${c.status}`).join(' · ');
  $('cart-readiness-result').textContent=`Revision ${result.revision} verified locally. ${results}. No cart, payment, or order was created.`;
 }catch(error){if(requestStillMatches(body))$('cart-readiness-result').textContent=`Cart readiness refused: ${error.message}. No cart created.`;}
});
$('recovery-receipt').addEventListener('click',()=>{
 if(!state.saved)return;
 const receipt={format:'TJ-LOCAL-RECOVERY-1',notice:'PRIVATE OWNER TOKEN—handle as a password; never share publicly',...state.saved,artworkGrants:uploadGrants()};
 const blob=new Blob([JSON.stringify(receipt,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob);
 const a=document.createElement('a');a.href=url;a.download=`${state.saved.reference}-PRIVATE-recovery.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1500);
});
$('resume-project').addEventListener('change',async e=>{
 const f=e.target.files?.[0];e.target.value='';if(!f)return;
 editorAsyncGate.invalidate();const opening=++privateReceiptOpenEpoch;recoveryConfirmation.cancel();
 const ensureOpening=()=>{if(opening!==privateReceiptOpenEpoch)throw Error('PRIVATE_RECEIPT_SUPERSEDED');};
 const provisionalUrls=[];
 try{
  if(f.size>200000)throw Error('Recovery receipt too large');
  const receipt=JSON.parse(await f.text());ensureOpening();
  if(receipt.format!=='TJ-LOCAL-RECOVERY-1'||!/^TJ-[A-F0-9]{24}$/.test(receipt.reference||'')||!/^[a-f0-9]{64}$/.test(receipt.ownerToken||''))throw Error('Invalid recovery receipt');
  const response=await fetch(`/api/designs/${receipt.reference}`,{headers:{'Authorization':`Bearer ${receipt.ownerToken}`}});
  const design=await response.json();ensureOpening();if(!response.ok)throw Error('PRIVATE_RECOVERY_REFUSED');
  if(!Number.isSafeInteger(receipt.revision)||receipt.revision<1||
   design?.reference!==receipt.reference||design.revision!==receipt.revision)
   throw Error('PRIVATE_RECOVERY_REVISION_MISMATCH');
  const p=availableManifests[design.productManifestId];if(!p)throw Error('Unsupported product in saved draft');
  const grants=new Map(Object.entries(receipt.artworkGrants||{}));const urls=new Map();
  for(const layer of design.layers){if(layer.type!=='artwork')continue;
   const grant=grants.get(layer.artworkId);if(!grant)throw Error('Missing private artwork token');
   const artResponse=await fetch(`/api/artworks/${layer.artworkId}`,{headers:{'Authorization':`Bearer ${grant}`}});
   if(!artResponse.ok)throw Error('Artwork access expired or denied');
   const blob=await artResponse.blob();ensureOpening();
   const url=URL.createObjectURL(blob);provisionalUrls.push(url);urls.set(layer.artworkId,url);
  }
  // Complete every potentially throwing data validation before changing the
  // current draft or releasing its existing object URLs.
  const selection=normalizePreviewSelection(p,design.previewSelection);
  const snapshot=editorSnapshot(design.productManifestId,design.layers,selection);
  const next={product:p,surface:p.surfaces[0].id,previewSelection:selection,layers:design.layers,
   selected:null,savedSnapshot:snapshot,saved:{reference:receipt.reference,
    ownerToken:receipt.ownerToken,revision:design.revision},artGrants:grants,artUrls:urls,
   imported:null,calibration:null};
  ensureOpening();
  commitPrivateReceiptRestore({state,next,
   render:()=>{$('product').value=state.product.id;render();},
   revokeOldUrl:url=>URL.revokeObjectURL(url)});
  provisionalUrls.length=0;
  invalidateCalibration('Recovered draft has no verified measurement worksheet.',{clearFields:true});
  $('clear-model').disabled=true;
  $('status').textContent=`Recovered private draft revision ${design.revision}. Preview only.`;
  // A public checklist never carries owner credentials. Only an explicit private
  // receipt reopening may resume its exact saved revision and product/variant.
  const pending=multiRecovery.list().find(e=>e.reference===receipt.reference);
  if(pending){
   try{
    const bridge=shopifyEntries.get(p.id);
    if(!bridge||bridge.productGid!==pending.productGid||
     !bridge.variantGids.includes(pending.variantGid))throw Error('STALE_CATALOG_BINDING');
    recoveryConfirmation.stage({reference:receipt.reference,revision:design.revision,
     ownerToken:receipt.ownerToken,productManifestId:p.id,productLabel:p.label,
     productGid:bridge.productGid,variantGid:pending.variantGid});
    $('shopify-variant').value=pending.variantGid;
    $('multi-status').textContent='Private receipt reopened. Confirm this exact saved revision to add it to the local review; no checkout is available.';
   }catch{
    recoveryConfirmation.cancel();
    $('multi-status').textContent='Receipt cannot be staged: revision, owner or catalog binding refused. No review access granted.';
   }
   renderMultiReview();
   if(recoveryConfirmation.status().staged)$('multi-confirm').focus({preventScroll:true});
  }
 }catch{
  for(const url of provisionalUrls)URL.revokeObjectURL(url);
  if(opening===privateReceiptOpenEpoch)$('status').textContent='Could not reopen private draft. Check the receipt and saved revision, then retry. No review access granted.';
 }
});
$('multi-confirm').addEventListener('click',async()=>{
 if($('multi-confirm').disabled)return;
 const confirming=privateReceiptOpenEpoch;
 $('multi-confirm').disabled=true;
 $('multi-status').textContent='Verifying private receipt and saved design twice. Do not change drafts during confirmation.';
 try{
  const operation=recoveryConfirmation.confirm((entry,selected)=>{
   if(state.saved?.reference!==entry.reference||state.saved?.revision!==entry.revision||
    state.saved?.ownerToken!==entry.ownerToken||state.product.id!==entry.productManifestId||
    !savedDraftMatchesEditor({productManifestId:state.product.id,layers:state.layers,
     previewSelection:state.previewSelection,saved:state.saved,savedSnapshot:state.savedSnapshot}))
    throw Error('EDITOR_CHANGED_DURING_RECOVERY');
   const bridge=shopifyEntries.get(state.product.id);
   if(!bridge||bridge.productGid!==entry.productGid||
    !bridge.variantGids.includes(entry.variantGid))throw Error('CATALOG_CHANGED_DURING_RECOVERY');
   multiReview.restore(entry,selected);
   multiReviewTransition.invalidate();
  });
  // Confirmation is pending now: keyboard users must be able to cancel it.
  renderMultiReview();
  if(!$('multi-cancel').disabled)$('multi-cancel').focus({preventScroll:true});
  const result=await operation;
  if(confirming!==privateReceiptOpenEpoch)return;
  $('multi-results').replaceChildren();
  $('multi-status').textContent=`Saved revision ${result.revision} confirmed for this local review. ${result.pending} private receipts remain. No cart, order or payment created.`;
 }catch{
  if(confirming===privateReceiptOpenEpoch)$('multi-status').textContent='Confirmation refused: private receipt, revision, design or catalog changed. Reopen the private receipt to retry. No review access granted.';
 }finally{renderMultiReview();if(confirming===privateReceiptOpenEpoch)$('multi-status').focus({preventScroll:true});}
});
$('multi-cancel').addEventListener('click',()=>{
 privateReceiptOpenEpoch++;
 recoveryConfirmation.cancel();renderMultiReview();
 $('multi-status').textContent='Confirmation cancelled. The checklist remains pending; no design was added.';
 $('multi-status').focus({preventScroll:true});
});
$('save-json').addEventListener('click',()=>{
 const out={format:'TJ-DESIGN-DRAFT-1',productManifestId:state.product.id,previewSelection:state.previewSelection,previewOnly:true,
 manufacturingApproved:false,layers:state.layers.map(({artworkId,...rest})=>rest),
 warning:'Artwork files are NOT embedded or stored. No production or price approval.'};
 const url=URL.createObjectURL(new Blob([JSON.stringify(out,null,2)],{type:'application/json'}));
 const a=document.createElement('a');a.href=url;a.download='trendyjoes-design-DRAFT.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),250);
});
// Text-only, explicitly opted-in tab recovery; no owner tokens, artwork, GLBs or worksheets.
function tabRecoveryStorage(){try{return window.sessionStorage;}catch{return {getItem(){throw Error('STORAGE_DENIED');},setItem(){throw Error('STORAGE_DENIED');},removeItem(){throw Error('STORAGE_DENIED');}};}}
function refreshSessionRestore(){
 const result=loadPreviewSession(tabRecoveryStorage(),MANIFEST_BY_ID);
 $('session-recovery-restore').disabled=result.status!=='AVAILABLE';
 return result;
}
function persistOptedInSession(){
 if(!$('session-recovery-opt-in').checked)return;
 const result=savePreviewSession(tabRecoveryStorage(),state,MANIFEST_BY_ID);
 if(result.status==='SAVED'){
  $('session-recovery-status').textContent='Text-only changes kept in this tab for up to 30 minutes. Not an account backup.';
 }else{
  clearPreviewSession(tabRecoveryStorage());$('session-recovery-opt-in').checked=false;
  $('session-recovery-status').textContent='Tab recovery turned off: private artwork, imported models, measurements or unsupported state cannot be cached.';
 }
 refreshSessionRestore();
}
$('session-recovery-opt-in').addEventListener('change',()=>{
 if($('session-recovery-opt-in').checked)persistOptedInSession();
 else{clearPreviewSession(tabRecoveryStorage());$('session-recovery-status').textContent='Tab preview forgotten. Recovery is off.';refreshSessionRestore();}
});
$('session-recovery-forget').addEventListener('click',()=>{
 $('session-recovery-opt-in').checked=false;clearPreviewSession(tabRecoveryStorage());refreshSessionRestore();
 $('session-recovery-status').textContent='Tab preview forgotten. Recovery is off.';
});
$('session-recovery-restore').addEventListener('click',()=>{
 const result=refreshSessionRestore();
 if(result.status!=='AVAILABLE'){$('session-recovery-status').textContent='No valid, unexpired tab preview to restore.';return;}
 if(hasCustomerWork({...state,defaultSelection:normalizePreviewSelection(state.product)})&&
   !window.confirm('Restoring this tab preview will discard your current unsaved work. Continue?'))return;
 const draft=result.draft,product=MANIFEST_BY_ID[draft.productManifestId];
 for(const url of state.artUrls.values())URL.revokeObjectURL(url);
 state.artUrls.clear();state.artGrants.clear();state.product=product;state.surface=draft.surfaceId;
 state.previewSelection=draft.previewSelection;state.layers=draft.layers;state.selected=null;
 state.saved=null;state.savedSnapshot=null;state.imported=null;state.calibration=null;
 $('model-file').value='';$('clear-model').disabled=true;
 $('model-import-summary').textContent='No imported model recovered. Tab recovery stores text-only geometry.';
 invalidateCalibration('No calibration worksheet recovered.',{clearFields:true});
 $('product').value=product.id;$('session-recovery-opt-in').checked=true;
 render();$('status').textContent='Restored text-only tab preview. Save privately to the local test server if needed.';
});
refreshSessionRestore();
function nudgeSelected(action){
 if(state.mode!=='2d')return false;
 const result=nudgePreviewLayer({product:state.product,layers:state.layers,selectedId:state.selected,
  surfaceId:state.surface,...action});
 if(!result.applied){
  $('status').textContent=result.reason==='ZONE_BOUNDARY'?'Cannot move outside the concept design zone.':
   'Choose a design element on the current surface before moving it.';
  return false;
 }
 state.layers=result.layers;
 render();
 $('status').textContent=`Selected design element moved ${action.direction} ${Math.round(action.step*100)}% of the concept zone. Not production calibrated.`;
 return true;
}
for(const button of document.querySelectorAll('[data-nudge]')){
 button.addEventListener('click',()=>nudgeSelected({direction:button.dataset.nudge,step:.01}));
}
$('stage').addEventListener('keydown',event=>{
 const action=previewNudgeKeyAction(event);
 if(!action||state.mode!=='2d'||!state.layers.some(l=>l.id===state.selected&&l.surfaceId===state.surface))return;
 event.preventDefault();nudgeSelected(action);
});
let drag=null;
$('stage').addEventListener('pointerdown',e=>{const id=e.target.closest('[data-layer]')?.getAttribute('data-layer');if(!id)return;
 const layer=state.layers.find(l=>l.id===id);if(!layer)return;state.selected=id;
 const s=state.product.surfaces.find(s=>s.id===state.surface);const bounds=$('stage').getBoundingClientRect();
 drag={id,x:layer.x,y:layer.y,clientX:e.clientX,clientY:e.clientY,rect:bounds,surface:s};render();});
window.addEventListener('pointermove',e=>{if(!drag)return;
 const l=state.layers.find(x=>x.id===drag.id);if(!l)return;
 const dx=(e.clientX-drag.clientX)/(drag.rect.width*drag.surface.previewRect.width),dy=(e.clientY-drag.clientY)/(drag.rect.height*drag.surface.previewRect.height);
 const candidate={...l,x:drag.x+dx,y:drag.y+dy};
 if(!validateComposition(state.product,{layers:state.layers.map(x=>x.id===l.id?candidate:x)}).length){l.x=candidate.x;l.y=candidate.y;render();}
});
window.addEventListener('pointerup',()=>drag=null);
render();
// Developer opt-in: the loopback server may load a read-only Shopify draft snapshot.
// Snapshots supplement concept manifests; no live Shopify API request or checkout is performed here.
(async function loadStagingSnapshot(){
 try{
  const res=await fetch('/api/shopify/staging-products');if(!res.ok)return;
  const body=await res.json();
  for(const entry of eligibleSnapshotEntries(body.entries,availableManifests)){
   availableManifests[entry.manifest.id]=entry.manifest;
   shopifyEntries.set(entry.manifest.id,entry);
   $('product').add(new Option(`[SHOPIFY DRAFT] ${entry.title}`,entry.manifest.id));
   // Only an unflagged local snapshot entry may augment the concept list.
  }
  const delayed=resolvePreviewEntry(window.location.search,availableManifests);
  const pristine=editorSnapshot(state.product.id,state.layers,state.previewSelection);
  if(mayApplyDelayedEntry({initialEntryStatus,resolvedEntry:delayed,userInteracted,currentProductId:state.product.id,
     initialProductId,currentSnapshot:pristine,initialSnapshot,
     hasWork:hasCustomerWork({...state,defaultSelection:normalizePreviewSelection(state.product)})})){
   $('product').value=delayed.manifestId;newProduct({force:true});
   $('entry-feedback').textContent=`Previewing ${state.product.label} from a local draft snapshot. No order or checkout is available.`;
  }else if(initialEntryStatus==='UNKNOWN_PRODUCT'&&delayed.status==='SELECTED'){
   $('entry-feedback').textContent='The draft catalog loaded. Your current preview was preserved; select another product manually to switch.';
  }
  showSaved();
 }catch{} // Standalone file previews and default no-snapshot mode retain all original concepts.
})();
// Objective 34G: explicit local-only browser acceptance. No default telemetry,
// remote script, Shopify request, or automated mutation of customer designs.
if (window.location.protocol==='http:' && ['localhost','127.0.0.1','[::1]','::1'].includes(window.location.hostname) &&
    new URLSearchParams(window.location.search).get('tj_acceptance')==='1') {
 import('./browser-acceptance.mjs').then(module=>module.runBrowserAcceptance()).catch(error=>{
  window.__TJ_BROWSER_ACCEPTANCE__={status:'FAIL',error:String(error.message||error),shopifyAccepted:false};
 });
}
