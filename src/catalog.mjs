/** Objective 35AR — trusted, fixed 2D footwear concept views.
 * These are normalized visual zones, NOT supplier print dimensions or UV maps.
 * Deliberately no 3D procedural mesh is fabricated for footwear.
 */
const sideOutline='<path d="M106 446Q131 418 181 408L236 374Q268 334 319 311L385 289Q441 294 476 332L526 366Q576 397 646 409L693 436Q707 454 698 487L680 514Q408 542 144 516L104 483Z"/><path d="M109 481Q407 511 698 482L680 514Q408 542 144 516Z" fill="#F3E9D7"/><path d="M242 379L475 360M284 352L489 381M327 326L506 398" fill="none" stroke="#F3E9D7" stroke-width="8" stroke-linecap="round"/>';
const tongueOutline='<path d="M316 510Q300 461 313 395L323 240Q326 167 355 132Q400 112 445 132Q474 167 477 240L487 395Q500 461 484 510Q400 539 316 510Z"/><path d="M355 163Q400 148 445 163L448 432Q400 453 352 432Z" fill="none" stroke="#F3E9D7" stroke-width="10"/><path d="M347 280H453M344 314H456M342 348H458M344 382H456" fill="none" stroke="#F3E9D7" stroke-width="8" stroke-linecap="round"/>';
const definitions=[
 {id:'outer-side',label:'Outer side · 2D concept',previewRect:{x:.28,y:.56,width:.42,height:.11},shapeMarkup:sideOutline,description:'Outside side profile, conceptual design rectangle'},
 {id:'inner-side',label:'Inner side · 2D concept',previewRect:{x:.28,y:.56,width:.42,height:.11},shapeMarkup:`<g transform="translate(800 0) scale(-1 1)">${sideOutline}</g>`,description:'Inside side profile, mirrored conceptual design rectangle'},
 {id:'tongue',label:'Tongue · 2D concept',previewRect:{x:.45,y:.34,width:.10,height:.30},shapeMarkup:tongueOutline,description:'Front tongue view, conceptual design rectangle'}
];
export const FOOTWEAR_CONCEPT_SURFACES=Object.freeze(definitions.map(s=>Object.freeze({...s,previewRect:Object.freeze({...s.previewRect})})));
/** Return only a fixed, declared concept view. Never fall back to another surface. */
export function getFootwearConceptView(product,surfaceId){
 if(product?.id!=='concept-sneaker'||product.geometry?.subtype!=='low-top-sneaker'||!Array.isArray(product.surfaces))return null;
 const view=FOOTWEAR_CONCEPT_SURFACES.find(s=>s.id===surfaceId);
 const surface=product.surfaces.find(s=>s.id===surfaceId);
 if(!view||!surface||!Object.keys(view.previewRect).every(k=>surface.previewRect?.[k]===view.previewRect[k]))return null;
 return view;
}

/**
 * ILLUSTRATIVE MANIFESTS ONLY. No garment fit, dimensions, print methods,
 * color availability, 3D assets, equipment calibration, or prices are approved.
 * shopifyProductGid MUST come from a live Shopify lookup before activation.
 * Surface rectangles are normalized PREVIEW coordinates, not printable sizes.
 */
export const CONCEPT_SWATCHES=[
  {id:'oxblood',label:'Oxblood red · concept',hex:'#7A2A30'},
  {id:'slate',label:'Slate blue · concept',hex:'#52697A'},
  {id:'parchment',label:'Warm cream · concept',hex:'#F3E9D7'},
  {id:'ink',label:'Deep charcoal · concept',hex:'#231F20'}
];
export const CONCEPT_APPAREL_FORMATS=[
  {id:'s',label:'Small · concept'}, {id:'m',label:'Medium · concept'},
  {id:'l',label:'Large · concept'}, {id:'xl',label:'XL · concept'},
  {id:'2xl',label:'2XL · concept'}
];
const item=(id,label,category,kind,subtype,route,surfaces,shape)=>({
  schemaVersion:'1.0', id, label, category,
  // Designer-only concept options. Neither blank SKUs nor available Shopify variants.
  previewOptions:{
    colors:CONCEPT_SWATCHES.map(c=>({...c})),
    sizes:category==='apparel'?CONCEPT_APPAREL_FORMATS.map(s=>({...s})):[]
  },
  geometry:{kind,subtype,modelAsset:null,uvMaps:{},previewShape:shape},
  surfaces:surfaces.map(([surfaceId,surfaceLabel,rect])=>({
    id:surfaceId,label:surfaceLabel,previewRect:rect,
    printableWidthMm:null,printableHeightMm:null,
    allowableMethods:route?[route]:[],uvRegion:null,calibrated:false
  })),
  manufacturing:{candidateMethods:route?[route]:[],approvedMethods:[],commissioningStatus:'PRE-COMMISSIONING',materialsVerified:false},
  commerce:{shopifyProductGid:null,variantIds:[],pricingVerified:false},
  lifecycle:'CONCEPT'
});
const zone=(x,y,width,height)=>({x,y,width,height});
export const PRODUCT_MANIFESTS=[
  item('concept-crew-tee','Crew-neck T-shirt','apparel','garment','crew-short-sleeve','DTF-TEXTILE',[
    ['front','Front',zone(.30,.26,.40,.45)],['back','Back',zone(.31,.20,.38,.47)],['sleeve-left','Left sleeve',zone(.08,.34,.20,.17)]], 'crew'),
  item('concept-v-tee','V-neck T-shirt','apparel','garment','v-neck-short-sleeve','DTG-TEXTILE',[
    ['front','Front',zone(.31,.31,.38,.39)],['back','Back',zone(.30,.21,.40,.47)]], 'vneck'),
  item('concept-long-sleeve','Long-sleeve shirt','apparel','garment','crew-long-sleeve','DTF-TEXTILE',[
    ['front','Front',zone(.29,.27,.42,.44)],['back','Back',zone(.3,.24,.40,.46)],['sleeve-left','Left sleeve',zone(.09,.29,.16,.52)]], 'longsleeve'),
  item('concept-hoodie','Pullover hoodie','apparel','garment','hooded-pullover','DTF-TEXTILE',[
    ['front','Front',zone(.31,.32,.38,.35)],['back','Back',zone(.29,.28,.42,.41)]], 'hoodie'),
  item('concept-tumbler','Custom tumbler','drinkware','cylinder','tapered-cylinder','UV-ROTARY',[
    ['wrap','Wrap',zone(.37,.27,.26,.50)]], 'tumbler'),
  item('concept-backpack','Custom backpack','accessories','irregular','backpack',null,[
    ['front-panel','Front panel',zone(.32,.33,.36,.36)]], 'backpack'),
  item('concept-rug','Custom rug','home','flat','rectangular-textile',null,[
    ['top','Top face',zone(.14,.24,.72,.52)]], 'rug'),
  // Concept-only footwear: independent 2D views; no invented 3D geometry, print method or supplier zone.
  item('concept-sneaker','Low-top sneaker · 2D concept','footwear','other','low-top-sneaker',null,
    FOOTWEAR_CONCEPT_SURFACES.map(s=>[s.id,s.label,{...s.previewRect}]),'sneaker')
];
export const MANIFEST_BY_ID=Object.fromEntries(PRODUCT_MANIFESTS.map(x=>[x.id,x]));
