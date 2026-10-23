/**
 * Objective 31: owner-authenticated, NON-AUTHORIZING customer-to-cart readiness.
 * Reads only the existing saved-design record and an offline Shopify snapshot.
 * It never emits a Shopify cart line, an order, a payment link, or a checkout permit.
 */
import {prepareStagingBinding} from './shopify-intents.mjs';

function check(id,status,reason){return {id,status,reason};}

export async function reviewCustomerCartReadiness({store,registry,reference,ownerToken,expectedRevision,productGid,variantGid}){
 const binding=await prepareStagingBinding({store,registry,reference,ownerToken,expectedRevision,productGid,variantGid});
 const entry=registry.entries.find(e=>e.product.id===productGid);
 // No caller-controlled 'priceApproved', 'liveAuthenticated', or 'productionReady' switches.
 // A cached Admin snapshot cannot prove current catalog, inventory, or selling permission.
 const checks=[
  check('LOCAL_DESIGN_OWNER','LOCAL_ONLY','The private local owner capability and exact saved revision were checked; not Shopify customer authentication.'),
  check('LOCAL_PRODUCT_VARIANT','SNAPSHOT_ONLY','Product and variant identities match a validated offline catalog snapshot; not a current authenticated Shopify session.'),
  check('CURRENT_CATALOG','BLOCKED','A live, authenticated Shopify product, variant, inventory and selling-plan check is required.'),
  check('ACTIVE_PURCHASABLE_VARIANT','BLOCKED',entry.product.status==='ACTIVE'?'Active in snapshot only; current saleability remains unverified.':`Product snapshot status is ${entry.product.status}; it is not a verified saleable item.`),
  check('AUTHORITATIVE_PRICE','BLOCKED','Approved manufacturing costs, current Shopify price, shipping and tax handling are not verified.'),
  check('CUSTOMER_AUTHENTICATION','BLOCKED','Hosted Shopify customer/guest ownership and durable session authorization do not exist.'),
  check('PRIVATE_ARTWORK_STORAGE','BLOCKED','Private local artwork is not a hosted, durable, access-controlled production asset service.'),
  check('MANUFACTURING_APPROVAL','BLOCKED','Physical calibration, equipment commissioning and approved printable surfaces remain unverified.'),
  check('CHECKOUT_ORDER_RECONCILIATION','BLOCKED','No trusted Shopify cart-to-order/payment workflow is connected or authorized.')
 ];
 return {
  schema:'TJ-CUSTOMER-CART-READINESS-1',scope:'OFFLINE_PREVIEW_ONLY',
  reference:binding.reference,revision:binding.revision,
  productGid:binding.productGid,variantGid:binding.variantGid,
  compositionSha256:binding.compositionSha256,
  previewValid:true,localOwnerChecked:true,shopifyCustomerAuthenticated:false,
  catalogCurrent:false,priceApproved:false,productionReady:false,checkoutEnabled:false,
  cartLine:null,cartMutation:null,checkoutUrl:null,shopifyOrderId:null,
  blockers:checks.filter(c=>c.status==='BLOCKED').map(c=>c.id),checks
 };
}
