/** Objective 34H. Strictly static, ephemeral, non-purchasing editor.
 * No fetch, XMLHttpRequest, WebSocket, storage, cookies, uploads or checkout.
 */
import {PRODUCT_MANIFESTS,MANIFEST_BY_ID} from './tj34i-src-catalog.js';
import {getPreviewOptions,describePreviewSelection} from './tj34i-src-preview-product-options.js';
import {createStaticPreviewState,updateStaticPreview,reviewStaticPreview,staticPreviewHasPendingWork,STATIC_PREVIEW_CAPABILITIES} from './tj34i-src-static-preview-contract.js';
import {render3D,updateConceptPreviewCamera,conceptPreviewKeyAction,CONCEPT_PREVIEW_CAMERA_DEFAULT,conceptCameraForSurface,beginConceptPointerDrag,moveConceptPointerDrag,endConceptPointerDrag} from './tj34i-src-viewer3d.js';
const $=id=>document.getElementById('tj34i-'+id);
let state=createStaticPreviewState(window.location.search);
const camera={...CONCEPT_PREVIEW_CAMERA_DEFAULT};
const ns='http://www.w3.org/2000/svg';
const outlines={
 crew:'M303 84L258 105 197 133 128 246 209 292 260 235 271 555 529 555 540 235 591 292 672 246 603 133 542 105 497 84Q400 159 303 84Z',
 vneck:'M303 84L258 105 197 133 128 246 209 292 260 235 271 555 529 555 540 235 591 292 672 246 603 133 542 105 497 84 400 191Z',
 longsleeve:'M303 84L258 105 202 137 104 465 186 491 259 269 271 555 529 555 541 269 614 491 696 465 598 137 542 105 497 84Q400 159 303 84Z',
 hoodie:'M339 76Q273 112 271 184L214 158 124 355 208 398 259 284 271 557 529 557 541 284 592 398 676 355 586 158 529 184Q527 112 461 76Q400 42 339 76Z',
 tumbler:'M287 115L513 115 485 540Q400 564 315 540Z',
 backpack:'M304 184Q400 147 496 184Q545 208 541 289L541 529Q400 563 259 529L259 289Q255 208 304 184Z',
 rug:'M110 137H690V492H110Z'
};
function svgEl(type,attrs={}){const n=document.createElementNS(ns,type);for(const [k,v] of Object.entries(attrs))n.setAttribute(k,String(v));return n;}
function message(text){$('status').textContent=text;}
function invalidateReview(){$('preview-summary-panel').hidden=true;for(const id of ['review-product','review-surface','review-color','review-size','review-layers'])$(id).textContent='';}
function apply(action){try{state=updateStaticPreview(state,action);if(state.mode!=='3d'||action.type==='SELECT_PRODUCT'||action.type==='RESET'||action.type==='SELECT_SURFACE')cancelDrag();
  if(['SELECT_PRODUCT','RESET','SELECT_SURFACE'].includes(action.type)){
   const zoom=action.type==='SELECT_SURFACE'?camera.zoom:1;
   Object.assign(camera,conceptCameraForSurface(MANIFEST_BY_ID[state.productManifestId],state.surfaceId,{zoom}));
  }
  render();return true;}catch(error){message(`Change rejected: ${error.message}`);return false;}}
function render2D(){
 const p=MANIFEST_BY_ID[state.productManifestId],surface=p.surfaces.find(s=>s.id===state.surfaceId),z=surface.previewRect;
 const svg=$('stage');svg.replaceChildren();
 const color=describePreviewSelection(p,state.previewSelection).color?.hex||'#52697A';
 svg.append(svgEl('path',{d:outlines[p.geometry.previewShape]||outlines.rug,fill:color,stroke:'#231F20','stroke-width':6}));
 svg.append(svgEl('rect',{x:z.x*800,y:z.y*640,width:z.width*800,height:z.height*640,rx:7,class:'print-zone'}));
 for(const l of state.layers.filter(l=>l.surfaceId===state.surfaceId)){
  const x=(z.x+l.x*z.width)*800,y=(z.y+l.y*z.height)*640,w=l.width*z.width*800,h=l.height*z.height*640;
  const g=svgEl('g',{transform:`rotate(${l.rotationDeg} ${x+w/2} ${y+h/2})`});
  const text=svgEl('text',{x:x+w/2,y:y+h*.73,'font-family':'Georgia,serif','font-size':Math.min(h*.86,52),'text-anchor':'middle',fill:'#231F20','font-weight':700,'textLength':Math.max(10,w*.92),'lengthAdjust':'spacingAndGlyphs'});
  text.textContent=l.value;g.append(text);
  if(l.id===state.selectedLayerId)g.append(svgEl('rect',{x,y,width:w,height:h,class:'layer-boundary'}));
  svg.append(g);
 }
}
let frame=0;
function schedule3D(){if(frame||state.mode!=='3d')return;frame=requestAnimationFrame(()=>{frame=0;if(state.mode==='3d')render3D($('stage-3d'),MANIFEST_BY_ID[state.productManifestId],state.layers,new Map(),camera,()=>schedule3D(),null,describePreviewSelection(MANIFEST_BY_ID[state.productManifestId],state.previewSelection).color?.hex||null);});}
function render(){
 invalidateReview();const p=MANIFEST_BY_ID[state.productManifestId],surface=p.surfaces.find(s=>s.id===state.surfaceId);
 $('product').value=p.id;$('product-heading').textContent=p.label;$('summary-product').textContent=p.label;
 $('surface').replaceChildren(...p.surfaces.map(s=>new Option(s.label,s.id)));$('surface').value=state.surfaceId;
 $('surface-badge').textContent=surface.label.toUpperCase();$('summary-surface').textContent=surface.label;
 const {colors,sizes}=getPreviewOptions(p);
 $('concept-color').replaceChildren(...colors.map(c=>new Option(c.label,c.id)));
 $('concept-color').disabled=!colors.length;$('concept-color').value=state.previewSelection.colorId||'';
 $('concept-size').replaceChildren(...(sizes.length?sizes.map(s=>new Option(s.label,s.id)):[new Option('Not specified','')]));
 $('concept-size').disabled=!sizes.length;$('concept-size').value=state.previewSelection.sizeId||'';
 $('layers').replaceChildren(new Option('Choose a layer',''),...state.layers.filter(l=>l.surfaceId===state.surfaceId).map(l=>new Option(l.value.slice(0,28),l.id)));
 $('layers').value=state.selectedLayerId||'';$('summary-layers').textContent=String(state.layers.length);
 const selected=state.layers.find(l=>l.id===state.selectedLayerId);
 $('rotation').disabled=!selected;$('scale').disabled=!selected;$('remove').disabled=!selected;
 $('rotation').value=selected?.rotationDeg??0;$('rotation-output').textContent=`${selected?.rotationDeg??0}°`;
 $('scale').value=Math.round((selected?.scaleFactor??1)*100);$('scale-output').textContent=`${Math.round((selected?.scaleFactor??1)*100)}%`;
 $('stage-3d').hidden=state.mode!=='3d';$('stage').hidden=state.mode!=='2d';$('orbit-tools').hidden=state.mode!=='3d';$('camera-help').hidden=state.mode!=='3d';
 $('mode-3d').setAttribute('aria-pressed',String(state.mode==='3d'));$('mode-2d').setAttribute('aria-pressed',String(state.mode==='2d'));
 if(state.mode==='2d')render2D();else schedule3D();
 message('Temporary concept preview only · nothing saved or transmitted.');
}
$('product').replaceChildren(...PRODUCT_MANIFESTS.map(p=>new Option(p.label,p.id)));
$('product').addEventListener('change',event=>{
 const id=event.target.value;
 const confirmed=!staticPreviewHasPendingWork(state,$('text-entry').value)||window.confirm('Changing products will discard your unsaved preview. Continue?');
 if(!confirmed){event.target.value=state.productManifestId;return;}
 apply({type:'SELECT_PRODUCT',productManifestId:id,confirmed});
});
$('surface').addEventListener('change',e=>apply({type:'SELECT_SURFACE',surfaceId:e.target.value}));
$('concept-color').addEventListener('change',e=>apply({type:'SELECT_COLOR',colorId:e.target.value}));
$('concept-size').addEventListener('change',e=>apply({type:'SELECT_SIZE',sizeId:e.target.value}));
$('add-text').addEventListener('click',()=>{if(apply({type:'ADD_TEXT',value:$('text-entry').value}))$('text-entry').value='';});
$('layers').addEventListener('change',e=>apply({type:'SELECT_LAYER',layerId:e.target.value||null}));
$('rotation').addEventListener('input',e=>{if(!apply({type:'ROTATE_LAYER',degrees:Number(e.target.value)}))e.target.value=state.layers.find(l=>l.id===state.selectedLayerId)?.rotationDeg||0;});
$('scale').addEventListener('input',e=>{if(!apply({type:'SCALE_LAYER',percent:Number(e.target.value)}))e.target.value=Math.round((state.layers.find(l=>l.id===state.selectedLayerId)?.scaleFactor||1)*100);});
$('remove').addEventListener('click',()=>apply({type:'REMOVE_LAYER'}));
$('mode-3d').addEventListener('click',()=>apply({type:'SET_MODE',mode:'3d'}));
$('mode-2d').addEventListener('click',()=>apply({type:'SET_MODE',mode:'2d'}));
function adjustCamera(action){
 try{Object.assign(camera,action.type==='RESET'?conceptCameraForSurface(MANIFEST_BY_ID[state.productManifestId],state.surfaceId):updateConceptPreviewCamera(camera,action));schedule3D();
  message('3D concept camera adjusted · no design saved or transmitted.');
 }catch(error){message(`Camera change rejected: ${error.message}`);}
}
$('orbit-left').addEventListener('click',()=>adjustCamera({type:'ORBIT',yawDelta:-.3,pitchDelta:0}));
$('orbit-right').addEventListener('click',()=>adjustCamera({type:'ORBIT',yawDelta:.3,pitchDelta:0}));
$('zoom-in').addEventListener('click',()=>adjustCamera({type:'ZOOM',factor:1.2}));
$('zoom-out').addEventListener('click',()=>adjustCamera({type:'ZOOM',factor:1/1.2}));
$('view-reset').addEventListener('click',()=>adjustCamera({type:'RESET'}));
// The canvas is intentionally keyboard-focusable. Tab/Enter remain browser-owned.
$('stage-3d').addEventListener('keydown',event=>{
 if(event.altKey||event.ctrlKey||event.metaKey)return;
 const action=conceptPreviewKeyAction(event.key);
 if(!action)return;
 event.preventDefault();adjustCamera(action);
});
let drag=null;
function cancelDrag(){
 const previous=drag;drag=null;
 if(previous){
  const canvas=$('stage-3d');
  try{if(canvas.hasPointerCapture?.(previous.pointerId))canvas.releasePointerCapture(previous.pointerId);}catch{/* capture may already be lost */}
 }
}
$('stage-3d').addEventListener('pointerdown',event=>{
 if(state.mode!=='3d')return;
 const next=beginConceptPointerDrag(drag,event);
 if(!next)return;
 try{event.currentTarget.setPointerCapture(next.pointerId);drag=next;}
 catch{drag=null;message('Pointer capture unavailable; use the camera buttons or keyboard.');}
});
$('stage-3d').addEventListener('pointermove',event=>{
 if(state.mode!=='3d'){cancelDrag();return;}
 const next=moveConceptPointerDrag(drag,event);
 if(drag && !next.gesture)cancelDrag();else drag=next.gesture;
 if(next.action)adjustCamera(next.action);
});
function endDrag(event){
 const next=endConceptPointerDrag(drag,event);
 if(drag && !next)cancelDrag();
}
$('stage-3d').addEventListener('pointerup',endDrag);
$('stage-3d').addEventListener('pointercancel',endDrag);
$('stage-3d').addEventListener('lostpointercapture',endDrag);
window.addEventListener('blur',cancelDrag);
document.addEventListener('visibilitychange',()=>{if(document.hidden)cancelDrag();});
// Resize the canvas backing pixels on responsive layout changes; avoid stale,
// stretched 3D output after rotation, mobile resizing or theme column changes.
if(typeof ResizeObserver==='function'){
 new ResizeObserver(()=>schedule3D()).observe($('stage-3d'));
}else window.addEventListener('resize',()=>schedule3D(),{passive:true});
$('review-preview').addEventListener('click',()=>{
 try{const review=reviewStaticPreview(state);invalidateReview();
  $('review-product').textContent=review.productLabel;$('review-surface').textContent=review.surfaceLabel;
  $('review-color').textContent=review.colorLabel;$('review-size').textContent=review.formatLabel;
  $('review-layers').textContent=`${review.layerCount} lettering element(s), ${review.designedSurfaces.join(', ')}`;
  $('preview-summary-panel').hidden=false;$('preview-summary-heading').focus({preventScroll:true});
 }catch(error){message(`Review unavailable: ${error.message}`);}
});
$('review-edit').addEventListener('click',()=>{invalidateReview();$('add-text').focus();});
$('reset').addEventListener('click',()=>{if(state.layers.length&&!window.confirm('Clear all temporary design elements?'))return;apply({type:'RESET'});});
$('entry-feedback').textContent=state.entryStatus==='SELECTED'?'Concept selected from link. Customize and review without saving.':state.entryStatus==='DEFAULT'?'Choose any concept product to explore.':'Invalid or unknown product link ignored; default concept selected.';
if(STATIC_PREVIEW_CAPABILITIES.checkoutEnabled!==false)throw new Error('STATIC_COMMERCE_GATE_FAILURE');
render();
