import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {replaceReviewListPreservingFocus} from '../src/preview-multidesign-dom-focus.mjs';
import {createLocalMultiReviewTransition} from '../src/preview-multidesign-ui-transition.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const ref=n=>`TJ-${String(n).padStart(24,'0')}`;
function dom(rows=[ref(1),ref(2)]){
 const document={activeElement:null};
 const control=(reference,action,disabled=false)=>({
  reference,action,disabled,lastFocus:null,
  getAttribute(key){return key==='data-review-reference'?reference:key==='data-review-action'?action:null;},
  focus(opts){this.lastFocus=opts;document.activeElement=this;}
 });
 const controls=refs=>refs.flatMap(reference=>[control(reference,'select'),control(reference,'remove')]);
 const list={nodes:controls(rows),contains(node){return this.nodes.includes(node);},
  querySelectorAll(selector){assert.equal(selector,'[data-review-reference][data-review-action]');return this.nodes;},
  replaceChildren(nodes){this.nodes=nodes;}};
 const status={disabled:false,focus(opts){this.lastFocus=opts;document.activeElement=this;}};
 const render=refs=>replaceReviewListPreservingFocus({document,list,replace:()=>list.replaceChildren(controls(refs)),fallback:status});
 return {document,list,status,render,control};
}
test('35Q checkbox selection re-render keeps keyboard focus on same saved revision',()=>{
 const d=dom();d.document.activeElement=d.list.nodes[0];const result=d.render([ref(1),ref(2)]);
 assert.deepEqual(result,{hadListFocus:true,restored:true});assert.equal(d.document.activeElement,d.list.nodes[0]);
 assert.deepEqual(d.document.activeElement.lastFocus,{preventScroll:true});
});
test('35Q remove control re-render keeps focus on same revision',()=>{
 const d=dom();d.document.activeElement=d.list.nodes[3];d.render([ref(1),ref(2)]);
 assert.equal(d.document.activeElement,d.list.nodes[3]);
});
test('35Q removed row restores focus to surviving same-action control',()=>{
 const d=dom();d.document.activeElement=d.list.nodes[1];d.render([ref(2)]);
 assert.equal(d.document.activeElement.action,'remove');assert.equal(d.document.activeElement.reference,ref(2));
});
test('35Q removed checkbox restores focus to next surviving checkbox',()=>{
 const d=dom();d.document.activeElement=d.list.nodes[2];d.render([ref(1)]);
 assert.equal(d.document.activeElement.action,'select');assert.equal(d.document.activeElement.reference,ref(1));
});
test('35Q removing final row restores focus to accessible status',()=>{
 const d=dom([ref(1)]);d.document.activeElement=d.list.nodes[1];d.render([]);
 assert.equal(d.document.activeElement,d.status);assert.deepEqual(d.status.lastFocus,{preventScroll:true});
});
test('35Q list rerender does not steal focus from external keyboard target',()=>{
 const d=dom();const external={focus(){throw Error('should not focus');}};d.document.activeElement=external;
 assert.deepEqual(d.render([ref(2)]),{hadListFocus:false,restored:false});assert.equal(d.document.activeElement,external);
});
test('35Q focus recovery excludes disabled controls',()=>{
 const d=dom();d.document.activeElement=d.list.nodes[0];
 const result=replaceReviewListPreservingFocus({document:d.document,list:d.list,
  replace:()=>{d.list.replaceChildren([d.control(ref(1),'select',true),d.control(ref(2),'remove')]);},fallback:d.status});
 assert.equal(result.restored,true);assert.equal(d.document.activeElement.reference,ref(2));
});
test('35Q disabled fallback is not focused',()=>{
 const d=dom([ref(1)]);d.document.activeElement=d.list.nodes[0];d.status.disabled=true;
 const result=d.render([]);assert.equal(result.restored,false);
});
test('35Q focus restoration handles arbitrary references without selector interpolation',()=>{
 const d=dom(['TJ-" ] body:has(*)']);d.document.activeElement=d.list.nodes[0];d.render(['TJ-" ] body:has(*)']);
 assert.equal(d.document.activeElement.reference,'TJ-" ] body:has(*)');
});
test('35Q missing DOM contract refuses before replacement',()=>{
 let touched=false;assert.throws(()=>replaceReviewListPreservingFocus({document:{},list:{},replace:()=>{touched=true;}}),
  {code:'MULTI_PREVIEW_FOCUS_CONFIGURATION'});assert.equal(touched,false);
});
test('35Q invalidating async review preserves focus restored by later list mutation',async()=>{
 let release;const gate=new Promise(resolve=>{release=resolve;});
 const transition=createLocalMultiReviewTransition({review:{review:()=>gate}});
 const d=dom();const old=transition.start();d.document.activeElement=d.list.nodes[0];
 transition.invalidate();d.render([ref(1),ref(2)]);const restored=d.document.activeElement;
 release({lineCount:2});await assert.rejects(old.promise,{code:'MULTI_PREVIEW_UI_STALE'});
 assert.equal(d.document.activeElement,restored);assert.equal(transition.status().busy,false);
});
test('35Q stale rejection cannot move focus after new selection',async()=>{
 let reject;const gate=new Promise((_,no)=>{reject=no;});
 const transition=createLocalMultiReviewTransition({review:{review:()=>gate}});
 const d=dom();const old=transition.start();transition.invalidate();d.document.activeElement=d.list.nodes[2];d.render([ref(1),ref(2)]);
 const restored=d.document.activeElement;reject(Error('offline refused'));
 await assert.rejects(old.promise,{code:'MULTI_PREVIEW_UI_STALE'});assert.equal(d.document.activeElement,restored);
});
test('35Q actual browser source wires stable reference/action attributes and guarded replacement',async()=>{
 const js=await readFile(resolve(root,'demo/studio.mjs'),'utf8');
 assert.match(js,/checkbox\.setAttribute\('data-review-reference',item\.reference\)/);
 assert.match(js,/checkbox\.setAttribute\('data-review-action','select'\)/);
 assert.match(js,/remove\.setAttribute\('data-review-reference',item\.reference\)/);
 assert.match(js,/remove\.setAttribute\('data-review-action','remove'\)/);
 assert.match(js,/replaceReviewListPreservingFocus\(\{document,list:\$\('multi-list'\),replace:\(\)=>\$\('multi-list'\)\.replaceChildren\(fragment\),fallback:\$\('multi-status'\)\}\)/);
});
test('35Q disabled review and clear operations restore status focus, not body',async()=>{
 const js=await readFile(resolve(root,'demo/studio.mjs'),'utf8');
 assert.match(js,/button\.disabled=true;[\s\S]*?Rechecking selected private local drafts twice…';\s*\$\('multi-status'\)\.focus\(\{preventScroll:true\}\)/);
 assert.match(js,/Review list and its local owner grants forgotten from this tab\.';\s*\$\('multi-status'\)\.focus\(\{preventScroll:true\}\)/);
});
test('35Q helper never persists bearer grants, fetches, or authorizes commerce',async()=>{
 const js=await readFile(resolve(root,'src/preview-multidesign-dom-focus.mjs'),'utf8');
 assert.doesNotMatch(js,/ownerToken|Authorization|fetch\(|localStorage|sessionStorage|\/cart\/add|checkoutEnabled\s*:\s*true|shopifyOrderId|innerHTML/);
});
