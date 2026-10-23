/** Objective 35Q: preserve keyboard focus when the local review list is rebuilt.
 * Never interpolate a customer-controlled reference into a CSS selector; use
 * DOM attributes only. This module grants no review, cart or order authority.
 */
const fail=()=>{throw Object.assign(new Error('MULTI_PREVIEW_FOCUS_CONFIGURATION'),{code:'MULTI_PREVIEW_FOCUS_CONFIGURATION'});};
const refOf=node=>node?.getAttribute?.('data-review-reference')??null;
const actionOf=node=>node?.getAttribute?.('data-review-action')??null;
const eligible=node=>node&&typeof node.focus==='function'&&!node.disabled;

export function replaceReviewListPreservingFocus({document,list,replace,fallback}={}){
 if(!document||!list||typeof list.contains!=='function'||typeof list.querySelectorAll!=='function'||typeof replace!=='function')fail();
 const active=document.activeElement;
 const inside=!!active&&list.contains(active);
 const reference=inside?refOf(active):null;
 const action=inside?actionOf(active):null;
 replace();
 if(!inside)return Object.freeze({hadListFocus:false,restored:false});
 const controls=[...list.querySelectorAll('[data-review-reference][data-review-action]')].filter(eligible);
 const exact=reference!==null&&action!==null?controls.find(n=>refOf(n)===reference&&actionOf(n)===action):null;
 // Removed row: prefer the same kind of control on another row. If no rows
 // survive, focus the status message rather than leaving focus on <body>.
 const neighbor=action!==null?controls.find(n=>actionOf(n)===action):null;
 const target=exact||neighbor||controls[0]||(eligible(fallback)?fallback:null);
 if(target)target.focus({preventScroll:true});
 return Object.freeze({hadListFocus:true,restored:!!target});
}
