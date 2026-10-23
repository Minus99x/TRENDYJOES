/**
 * Objective 34F: offline contract for Main Engineering's unpublished Shopify
 * theme integration. Does NOT assert that a Shopify page or hosted editor exists.
 * Main must verify and install the preview page before enabling these links.
 */
import {PRODUCT_MANIFESTS,MANIFEST_BY_ID} from './catalog.mjs';
const PREVIEW_PAGE='/pages/design-works-preview';
const own=(obj,key)=>Object.prototype.hasOwnProperty.call(obj,key);
const reject=(code)=>{throw new Error(code);};
export const STAGING_PREVIEW_PAGE=PREVIEW_PAGE;
export function buildStagingPreviewNavigation({previewPageVerified=false}={}){
 if(typeof previewPageVerified!=='boolean')reject('INVALID_PREVIEW_GATE');
 return Object.freeze({schema:'TJ-STAGING-PREVIEW-NAV-1',scope:'UNPUBLISHED_THEME_PREVIEW_ONLY',
  previewPageVerified,commerceEnabled:false,checkoutEnabled:false,requiresMainEngineeringIntegration:true,
  entries:PRODUCT_MANIFESTS.map(m=>Object.freeze({manifestId:m.id,label:m.label,category:m.category,
   href:previewPageVerified?`${PREVIEW_PAGE}?product=${encodeURIComponent(m.id)}`:null,
   status:previewPageVerified?'STAGING_PREVIEW_LINK':'NOT_CONNECTED'}))});
}
export function resolveStagingPreviewNavigation(input,{previewPageVerified=false}={}){
 if(previewPageVerified!==true)return {status:'NOT_CONNECTED',manifestId:null};
 if(typeof input!=='string'||input.length>256||!input.startsWith(PREVIEW_PAGE+'?'))return {status:'INVALID_LINK',manifestId:null};
 if(/%(?![0-9a-fA-F]{2})/.test(input)||/[#\\]/.test(input))return {status:'INVALID_LINK',manifestId:null};
 const query=input.slice(PREVIEW_PAGE.length+1);
 const pairs=[...new URLSearchParams(query).entries()];
 if(pairs.length!==1||pairs[0][0]!=='product')return {status:'INVALID_LINK',manifestId:null};
 const id=pairs[0][1];
 if(!/^[a-z][a-z0-9-]{0,63}$/.test(id)||!own(MANIFEST_BY_ID,id)||MANIFEST_BY_ID[id]?.id!==id)return {status:'INVALID_LINK',manifestId:null};
 return {status:'SELECTED',manifestId:id};
}
