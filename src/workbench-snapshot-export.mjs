import {assertWorkbenchDraft} from './workbench-draft-state.mjs';
/** Whitelist-only private design snapshot; never export session grants, file contents, identifiers of customers or commerce tokens. */
export function exportWorkbenchSnapshot(d){assertWorkbenchDraft(d);const safeLayers=d.layers.map(l=>({id:l.id,kind:l.kind,surfaceId:l.surfaceId,x:l.x,y:l.y,width:l.width,height:l.height,rotation:l.rotation,color:l.color,text:l.text,visible:l.visible,locked:l.locked}));
 const payload={schema:'TJ-WORKBENCH-SNAPSHOT-1',productId:d.productId,surfaces:[...d.surfaces],activeSurface:d.activeSurface,layers:safeLayers,revision:d.revision,localOnly:true,manufacturingApproved:false,checkoutEnabled:false,priceApproved:false};
 const text=JSON.stringify(payload);if(text.length>120000)throw new RangeError('WORKBENCH_EXPORT_SIZE');return text;
}
