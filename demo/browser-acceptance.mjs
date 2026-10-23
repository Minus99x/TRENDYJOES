/**
 * Objective 34G: opt-in, in-browser acceptance checks for the actual local editor DOM.
 * This is never a hosted-auth, manufacturing, checkout or Shopify acceptance test.
 * It runs ONLY when explicitly requested on loopback and never saves/uploads data.
 */
const allowedHosts=new Set(['localhost','127.0.0.1','[::1]','::1']);
const synthetic='TJ34G-SYNTHETIC-LOCAL-CHECK';
const $=id=>document.getElementById(id);
const tick=()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
const assert=(condition,message)=>{if(!condition)throw new Error(message);};
const click=id=>{const element=$(id);assert(element,`MISSING_${id}`);element.click();};
const setSelect=(id,value)=>{const element=$(id);assert(element,`MISSING_${id}`);element.value=value;element.dispatchEvent(new Event('change',{bubbles:true}));};

export async function runBrowserAcceptance(){
 if(location.protocol!=='http:'||!allowedHosts.has(location.hostname)||new URLSearchParams(location.search).get('tj_acceptance')!=='1'){
  return {status:'NOT_RUN',reason:'LOOPBACK_EXPLICIT_OPT_IN_REQUIRED'};
 }
 const panel=document.createElement('section');panel.id='tj-browser-acceptance';panel.setAttribute('role','status');panel.setAttribute('aria-live','polite');
 panel.style.cssText='position:relative;max-width:920px;margin:24px auto;padding:18px;background:#f3e9d7;color:#231f20;border:3px solid #7a2a30;font:16px/1.5 system-ui,sans-serif';
 const heading=document.createElement('h2');heading.textContent='LOCAL BROWSER ACCEPTANCE · NOT SHOPIFY PROOF';panel.append(heading);
 const result=document.createElement('pre');result.style.cssText='white-space:pre-wrap;overflow-wrap:anywhere';panel.append(result);
 document.body.prepend(panel);
 const outcomes=[];
 const check=async(name,fn)=>{
  try{await fn();outcomes.push({name,status:'PASS'});}catch(e){outcomes.push({name,status:'FAIL',reason:String(e.message||e).slice(0,180)});}
  result.textContent=outcomes.map(x=>`${x.status}: ${x.name}${x.reason?' — '+x.reason:''}`).join('\n');
 };
 try{
  await check('Editor controls and seven concept products render',()=>{
   assert($('product')?.options.length>=7,'PRODUCTS_MISSING');
   assert($('product-heading')?.textContent?.length>0,'HEADING_MISSING');
   assert($('review-preview')&&!$('review-preview').disabled,'REVIEW_MISSING');
  });
  await check('3D and 2D mode controls respond to real DOM clicks',async()=>{
   click('mode-2d');await tick();assert($('mode-2d').getAttribute('aria-pressed')==='true','TWO_D_NOT_ACTIVE');
   assert(!$('stage').hasAttribute('hidden'),'TWO_D_STAGE_HIDDEN');
   click('mode-3d');await tick();assert($('mode-3d').getAttribute('aria-pressed')==='true','THREE_D_NOT_ACTIVE');
  });
  await check('Changing concept product updates the editor and surface',async()=>{
   setSelect('product','concept-tumbler');await tick();
   assert($('product').value==='concept-tumbler','PRODUCT_SELECTION_FAILED');
   assert($('product-heading').textContent.toLowerCase().includes('tumbler'),'PRODUCT_HEADING_STALE');
   assert($('surface').options.length>0,'SURFACES_MISSING');
  });
  await check('Synthetic lettering becomes a real editable layer',async()=>{
   $('text-entry').value=synthetic;click('add-text');await tick();
   assert($('summary-layers').textContent==='1','LAYER_NOT_CREATED');
   assert($('layers').options.length===2,'LAYER_SELECTOR_NOT_UPDATED');
  });
  await check('Preview-only review displays a redacted design summary',async()=>{
   click('review-preview');await tick();
   assert(!$('preview-summary-panel').hidden,'REVIEW_NOT_OPEN');
   assert($('review-layers').textContent.includes('1 total'),'REVIEW_LAYER_COUNT');
   const summary=$('preview-summary-panel').textContent;
   assert(!summary.includes(synthetic),'PRIVATE_LETTERING_LEAK');
   assert(/NO PURCHASE, CART, PAYMENT, OR ORDER/i.test(summary),'PURCHASE_WARNING_MISSING');
  });
  await check('Editing invalidates the previous review',async()=>{
   $('text-entry').value='SECOND SYNTHETIC LAYER';click('add-text');await tick();
   assert($('preview-summary-panel').hidden,'STALE_REVIEW_REMAINED_VISIBLE');
   assert($('summary-layers').textContent==='2','SECOND_LAYER_MISSING');
  });
  await check('Checkout stays disabled and session recovery remains opt-in',()=>{
   assert(document.querySelector('.disabled-checkout')?.disabled===true,'CHECKOUT_ENABLED');
   assert($('session-recovery-opt-in').checked===false,'RECOVERY_OPTED_IN_WITHOUT_CONSENT');
  });
 }finally{
  // This harness only manipulates its own synthetic in-memory preview. It never
  // saves a design, uploads artwork, opens a checkout, or changes Shopify state.
  try{click('reset');}catch{}
  const passed=outcomes.filter(x=>x.status==='PASS').length;
  const report=Object.freeze({schema:'TJ-LOCAL-BROWSER-ACCEPTANCE-1',status:passed===outcomes.length?'PASS':'FAIL',passed,failed:outcomes.length-passed,
   browserEvidenceOnly:true,shopifyAccepted:false,hostedAuthVerified:false,checkoutEnabled:false,checks:outcomes});
  window.__TJ_BROWSER_ACCEPTANCE__=report;
  result.textContent+='\n\n'+`${passed}/${outcomes.length} passed. LOCAL BROWSER ONLY; no Shopify staging, hosted auth, checkout, or manufacturing proof.`;
 }
 return window.__TJ_BROWSER_ACCEPTANCE__;
}
