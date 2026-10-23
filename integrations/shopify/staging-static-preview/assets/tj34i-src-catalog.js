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
    ['top','Top face',zone(.14,.24,.72,.52)]], 'rug')
];
export const MANIFEST_BY_ID=Object.fromEntries(PRODUCT_MANIFESTS.map(x=>[x.id,x]));
