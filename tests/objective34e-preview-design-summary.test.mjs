import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {PRODUCT_MANIFESTS,MANIFEST_BY_ID} from '../src/catalog.mjs';
import {buildPreviewDesignSummary} from '../src/preview-design-summary.mjs';
import {editorSnapshot} from '../src/preview-editor-state.mjs';
const p=PRODUCT_MANIFESTS[0];
const select=(m=p)=>({colorId:m.previewOptions.colors[0]?.id??null,sizeId:m.previewOptions.sizes[0]?.id??null});
const layer={id:'layer-1',type:'text',surfaceId:p.surfaces[0].id,x:.2,y:.3,width:.5,height:.2,rotationDeg:0,scaleFactor:1,value:'SECRET PERSONAL WORDING'};
const make=(overrides={})=>({productManifestId:p.id,surfaceId:p.surfaces[0].id,previewSelection:select(),layers:[{...layer}],...overrides});
const build=(o)=>buildPreviewDesignSummary(make(o));
const reject=(o,code)=>assert.throws(()=>build(o),new RegExp(code));
test('34E real apparel selection to validated preview summary',()=>{const r=build();assert.equal(r.schema,'TJ-PREVIEW-DESIGN-SUMMARY-1');assert.equal(r.productLabel,p.label);assert.equal(r.layerCount,1);assert.equal(r.textLayerCount,1);assert.equal(r.draftState,'UNSAVED_PREVIEW');});
test('34E every supported concept merchandise family can review a valid design',()=>{
 for(const m of PRODUCT_MANIFESTS){const l={...layer,surfaceId:m.surfaces[0].id};const r=buildPreviewDesignSummary({productManifestId:m.id,surfaceId:m.surfaces[0].id,previewSelection:select(m),layers:[l]});assert.equal(r.productManifestId,m.id);assert.equal(r.productLabel,m.label);}
});
test('34E a current local saved revision is explicitly local-only',()=>{const args=make();const saved={reference:'TJ-TEST',revision:7,ownerToken:'NEVER_EXPOSE_THIS'};const r=build({saved,savedSnapshot:editorSnapshot(args.productManifestId,args.layers,args.previewSelection)});assert.equal(r.draftState,'LOCAL_REVISION_CURRENT');assert.equal(r.revision,7);assert.doesNotMatch(JSON.stringify(r),/NEVER_EXPOSE_THIS|TJ-TEST/);});
test('34E a stale saved revision is marked UNSAVED and cannot masquerade as current',()=>{const r=build({saved:{reference:'TJ-TEST',revision:3,ownerToken:'SECRET'},savedSnapshot:'outdated'});assert.equal(r.draftState,'UNSAVED_PREVIEW');assert.equal(r.revision,null);});
test('34E design changes after a save invalidate current revision',()=>{const args=make();const saved={reference:'TJ-TEST',revision:2,ownerToken:'SECRET'};const savedSnapshot=editorSnapshot(args.productManifestId,args.layers,args.previewSelection);const r=build({saved,savedSnapshot,layers:[{...layer,value:'CHANGED'}]});assert.equal(r.draftState,'UNSAVED_PREVIEW');});
test('34E cross-product layer substitution is refused',()=>reject({productManifestId:'concept-rug'},'INVALID_SURFACE'));
test('34E missing or forged product is refused',()=>{reject({productManifestId:'fake-product'},'UNKNOWN_PRODUCT');reject({productManifestId:'__proto__'},'UNKNOWN_PRODUCT');});
test('34E product lookup must have matching manifest identity',()=>assert.throws(()=>buildPreviewDesignSummary(make(),{[p.id]:{...p,id:'forged'}}),/INVALID_PRODUCT/));
test('34E unknown current surface is refused',()=>reject({surfaceId:'other-product-surface'},'INVALID_SURFACE'));
test('34E malformed selection is refused rather than silently defaulted',()=>{reject({previewSelection:undefined},'INVALID_OPTIONS');reject({previewSelection:{colorId:'oxblood'}},'INVALID_OPTIONS');reject({previewSelection:{...select(),ownerToken:'SECRET'}},'INVALID_OPTIONS');});
test('34E substituted concept color and size are refused',()=>{reject({previewSelection:{...select(),colorId:'fake-color'}},'Invalid concept');reject({previewSelection:{...select(),sizeId:'fake-size'}},'Invalid concept');});
test('34E empty and oversized layer arrays cannot yield a review',()=>{reject({layers:[]},'INVALID_LAYERS');reject({layers:Array.from({length:101},(_,i)=>({...layer,id:`l${i}`}))},'INVALID_LAYERS');});
test('34E duplicate layer IDs are refused',()=>reject({layers:[{...layer},{...layer}]},'INVALID_COMPOSITION'));
test('34E out-of-zone and invalid transforms are refused',()=>{reject({layers:[{...layer,x:1.2}]},'INVALID_COMPOSITION');reject({layers:[{...layer,width:NaN}]},'INVALID_COMPOSITION');});
test('34E missing private artwork grant prevents a misleading summary',()=>{const art={...layer,type:'artwork',artworkId:'PRIVATE_ART_123'};delete art.value;reject({layers:[art]},'PRIVATE_ARTWORK_UNAVAILABLE');});
test('34E present private artwork is counted without disclosing its identifier',()=>{const art={...layer,type:'artwork',artworkId:'PRIVATE_ART_123'};delete art.value;const r=build({layers:[art],availableArtworkIds:['PRIVATE_ART_123']});assert.equal(r.artworkLayerCount,1);assert.doesNotMatch(JSON.stringify(r),/PRIVATE_ART_123/);});
test('34E artwork evidence must be bounded and typed',()=>{reject({availableArtworkIds:[42]},'INVALID_ARTWORK_PROOF');reject({availableArtworkIds:Array(101).fill('x')},'INVALID_ARTWORK_PROOF');});
test('34E summary never leaks wording, tokens, artwork IDs, variant IDs, or customer fields',()=>{const r=build({saved:{reference:'REF_SECRET',revision:2,ownerToken:'TOKEN_SECRET'},savedSnapshot:'stale'});const output=JSON.stringify(r);for(const secret of ['SECRET PERSONAL WORDING','TOKEN_SECRET','REF_SECRET','gid://shopify/'])assert.equal(output.includes(secret),false);});
test('34E production and checkout are always explicitly blocked, including imported models',()=>{const r=build({importedModelPresent:true});assert.equal(r.modelStatus,'IMPORTED_UNVERIFIED');for(const k of ['manufacturingApproved','priceApproved','shopifyCustomerAuthenticated','checkoutEnabled'])assert.equal(r[k],false);assert.equal(r.cartLine,null);assert.equal(r.orderId,null);assert.equal(r.blockers.length,4);});
test('34E editor has a real interactive review step and invalidates stale summaries on edits',()=>{
 const js=readFileSync(new URL('../demo/studio.mjs',import.meta.url),'utf8');const html=readFileSync(new URL('../demo/index.html',import.meta.url),'utf8');
 assert.match(js,/buildPreviewDesignSummary\(/);assert.match(js,/\$\('review-preview'\)\.addEventListener\('click'/);assert.match(js,/function render\(\)\{[\s\S]{0,220}invalidatePreviewReview\(\)/);assert.match(js,/function saveToLocal\(\)/);assert.match(js,/\$\('preview-summary-heading'\)\.focus/);
 for(const id of ['review-preview','preview-summary-panel','review-product','review-edit','review-blockers'])assert.match(html,new RegExp(`id="${id}"`));
 assert.match(html,/NO PURCHASE, CART, PAYMENT, OR ORDER HAS BEEN CREATED/);
});
