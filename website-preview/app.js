/* TrendyJoes Design Works: read-only, browser-local concept demonstrator.
   No Shopify SDK, network submission, production authority, cart or price paths. */
(()=>{'use strict';
const $=id=>document.getElementById(id);
const CDN='https://cdn.shopify.com/s/files/1/0769/0587/3543/files/';
const products=[
 {name:'Apparel',display:'Crew-neck T-shirt',img:'tj-designworks-apparel.webp?v=1792210429',subtitle:'Custom apparel concepts',color:'#52697a'},
 {name:'Shoes & Bags',display:'Sneakers & Bags',img:'tj-designworks-shoes-bags.webp?v=1792210433',subtitle:'Accessories and everyday carry',color:'#7a2a30'},
 {name:'Drinkware',display:'Personalized Tumbler',img:'tj-designworks-drinkware.webp?v=1792210438',subtitle:'Cups, drinkware and accessories',color:'#7a2a30'},
 {name:'Home Goods',display:'Home Goods & Décor',img:'tj-designworks-homegoods.webp?v=1792210443',subtitle:'Home and comfort',color:'#d2bd9f'},
 {name:'Business Branding',display:'Business Branding',img:'tj-designworks-business.webp?v=1792210447',subtitle:'Office, gifts and promotion',color:'#282a2e'},
 {name:'3D & Specialty',display:'3D & Specialty',img:'tj-designworks-specialty-3d.webp?v=1792210451',subtitle:'Specialty concepts, not verified 3D production',color:'#52697a'}
];
const views=['home','collections','studio','about','contact'];
function showPage(page){if(!views.includes(page))page='home';document.querySelectorAll('[data-page]').forEach(n=>n.hidden=n.dataset.page!==page);document.querySelectorAll('[data-nav]').forEach(a=>{a.classList.toggle('active',a.hash==='#'+page);if(a.hash==='#'+page)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current')});$('nav').classList.remove('open');$('menu-toggle').setAttribute('aria-expanded','false');window.scrollTo({top:0,behavior:'instant'});document.title=(page==='home'?'TrendyJoes Design Works':page.charAt(0).toUpperCase()+page.slice(1)+' — TrendyJoes Design Works')+' | Private Preview';}
function route(){showPage(location.hash.replace('#','').split('?')[0])}window.addEventListener('hashchange',route);$('menu-toggle').addEventListener('click',()=>{let nav=$('nav');nav.classList.toggle('open');$('menu-toggle').setAttribute('aria-expanded',String(nav.classList.contains('open')))});
function cards(target){products.forEach((p,i)=>{const a=document.createElement('a');a.className='collection-card';a.href='#studio';a.dataset.idx=String(i);const frame=document.createElement('span');frame.className='card-image';frame.style.background=`linear-gradient(125deg,${p.color},#211c1e)`;const w=document.createElement('span');w.className='fallback-word';w.textContent=p.name;const img=new Image();img.src=CDN+p.img;img.alt=p.subtitle;img.loading='lazy';img.onerror=()=>img.remove();frame.append(w,img);const label=document.createElement('span');label.className='card-name';label.textContent=p.name;a.append(frame,label);a.addEventListener('click',()=>{selectProduct(i);});target.append(a);});}
cards($('home-cards'));cards($('collections-cards'));document.querySelectorAll('.image-with-fallback img').forEach(i=>i.onerror=()=>i.classList.add('failed'));
products.forEach((p,i)=>{const opt=document.createElement('option');opt.value=String(i);opt.textContent=p.display;$('product').append(opt)});
// Studio layer data are plain objects. Image bytes stay in this tab unless the user explicitly saves locally.
let sessionDraft=null;const W=800,H=800;const canvas=$('design-canvas'),ctx=canvas.getContext('2d');
// Each product/surface is an independent concept canvas. Keep all canvases in undo/redo and local exports.
const defaultBlank='#52697A';
let state={product:0,surface:'Front',blank:defaultBlank,layers:[],selected:null,designs:{}};
let past=[],future=[],drag=null;const imageCache=new Map();let hasReviewed=false;
const designKey=(product=state.product,surface=state.surface)=>`${product}:${surface}`;
function rememberCanvas(){state.designs[designKey()]={blank:state.blank,layers:clone(state.layers)};}
function openCanvas(product,surface){
 const entry=state.designs[designKey(product,surface)];
 state.product=product;state.surface=surface;state.blank=entry?.blank||defaultBlank;
 state.layers=clone(entry?.layers||[]);state.selected=state.layers.at(-1)?.id||null;
 restoreImages();render();
}
function allDesigns(){const map=clone(state.designs);map[designKey()]={blank:state.blank,layers:clone(state.layers)};return map;}
function draftSummary(){const map=allDesigns();return Object.entries(map).filter(([,d])=>d.layers.length).map(([key,d])=>{
 const [i,surface]=key.split(':');return `${products[Number(i)].display} · ${surface}: ${d.layers.length} layer${d.layers.length===1?'':'s'}`;
 });}

const nextId=()=>Math.random().toString(36).slice(2)+Date.now().toString(36);
const clone=s=>JSON.parse(JSON.stringify(s));
function snapshot(){past.push(clone(state));if(past.length>50)past.shift();future=[];hasReviewed=false;$('design-report').textContent='Design changed. Review again before export.';}
function baseLayer(type,extra={}){return {id:nextId(),type,x:400,y:400,scale:1,rotation:0,color:'#7a2a30',...extra};}
function status(s){$('editor-status').textContent=s;}
function selected(){return state.layers.find(l=>l.id===state.selected)}
function colorControls(){const s=selected();$('font-size').disabled=!s||s.type!=='text';$('layer-color').disabled=!s||s.type!=='text';$('layer-angle').disabled=!s;$('layer-scale').disabled=!s||s.type!=='image';if(s){$('layer-angle').value=s.rotation;$('layer-angle-display').textContent=s.rotation+'°';$('layer-scale').value=s.scale*100;$('layer-scale-display').textContent=Math.round(s.scale*100)+'%';}if(s&&s.type==='text'){$('font-size').value=s.fontSize;$('font-size-display').value=s.fontSize;$('font-size-display').textContent=s.fontSize;$('layer-color').value=s.color;}}
function drawProduct(){ctx.save();ctx.translate(0,0);ctx.fillStyle='#eee5d5';ctx.fillRect(0,0,W,H);ctx.strokeStyle='#bfad9a';ctx.setLineDash([5,7]);ctx.lineWidth=2;ctx.strokeRect(60,60,680,680);ctx.setLineDash([]);ctx.lineJoin='round';ctx.strokeStyle='#47383b';ctx.lineWidth=9;ctx.fillStyle=state.blank;const p=state.product;
 ctx.beginPath();
 if(p===0){ctx.moveTo(270,165);ctx.lineTo(340,128);ctx.lineTo(460,128);ctx.lineTo(535,165);ctx.lineTo(655,240);ctx.lineTo(600,355);ctx.lineTo(545,322);ctx.lineTo(545,640);ctx.lineTo(255,640);ctx.lineTo(255,322);ctx.lineTo(200,355);ctx.lineTo(145,240);ctx.closePath();}
 else if(p===1){ctx.moveTo(178,440);ctx.quadraticCurveTo(260,380,370,425);ctx.lineTo(555,398);ctx.quadraticCurveTo(625,396,642,460);ctx.lineTo(651,520);ctx.quadraticCurveTo(630,564,558,575);ctx.lineTo(177,575);ctx.quadraticCurveTo(130,531,178,440);ctx.closePath();}
 else if(p===2){ctx.moveTo(270,185);ctx.quadraticCurveTo(400,150,530,185);ctx.lineTo(510,624);ctx.quadraticCurveTo(400,654,290,624);ctx.closePath();}
 else if(p===3){ctx.rect(170,215,460,390)}
 else if(p===4){ctx.rect(255,155,290,490)}
 else {const n=6,r=260;for(let i=0;i<n;i++){let a=-Math.PI/2+i*Math.PI*2/n;let x=400+Math.cos(a)*r,y=400+Math.sin(a)*r;i?ctx.lineTo(x,y):ctx.moveTo(x,y);}ctx.closePath()}
 ctx.fill();ctx.stroke();ctx.strokeStyle='#efdbc2';ctx.lineWidth=10;ctx.beginPath();if(p===0){ctx.moveTo(338,128);ctx.quadraticCurveTo(400,215,462,128)}else if(p===2){ctx.ellipse(400,188,130,26,0,0,Math.PI*2)}else if(p===1){ctx.moveTo(215,504);ctx.lineTo(611,504)}else {ctx.moveTo(260,270);ctx.lineTo(540,270)}ctx.stroke();
 ctx.save();ctx.strokeStyle='#f7eeceaa';ctx.lineWidth=2;ctx.setLineDash([5,6]);ctx.strokeRect(245,268,310,270);ctx.restore();ctx.restore();}
function drawLayers(){state.layers.forEach(l=>{ctx.save();ctx.translate(l.x,l.y);ctx.rotate(l.rotation*Math.PI/180);ctx.globalAlpha=1;let w=180,h=60;if(l.type==='text'){const fs=l.fontSize||36;ctx.font=`bold ${fs}px Georgia, serif`;const words=(l.text||'').split('\n').slice(0,3);w=Math.max(18,...words.map(x=>ctx.measureText(x).width));h=fs*1.28*words.length;ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillStyle=l.color||'#7a2a30';words.forEach((s,i)=>ctx.fillText(s,0,(i-(words.length-1)/2)*fs*1.28,440));}
 else if(l.type==='image'&&l.data){const img=imageCache.get(l.id);if(img?.complete&&img.naturalWidth){const scale=Math.min(280/img.naturalWidth,240/img.naturalHeight);w=img.naturalWidth*scale*l.scale;h=img.naturalHeight*scale*l.scale;ctx.drawImage(img,-w/2,-h/2,w,h)}else{w=160;h=110;ctx.fillStyle='#c6b2a2';ctx.fillRect(-80,-55,160,110);}}
 if(state.selected===l.id){ctx.strokeStyle='#f7e7c8';ctx.lineWidth=6;ctx.setLineDash([9,7]);ctx.strokeRect(-w/2-6,-h/2-6,w+12,h+12);ctx.strokeStyle='#812e34';ctx.lineWidth=2;ctx.strokeRect(-w/2-6,-h/2-6,w+12,h+12);}ctx.restore()})}
function render(){drawProduct();drawLayers();$('preview-title').textContent=products[state.product].display;$('surface-label').textContent=state.surface.toUpperCase();$('position-readout').textContent=`${state.layers.length} current · ${draftSummary().length} designed surface(s)`;$('surface-summary').textContent=draftSummary().join(' | ')||'No surfaces personalized yet.';$('product').value=String(state.product);$('surface').value=state.surface;$('blank').value=state.blank;const list=$('layer-list');list.replaceChildren();state.layers.forEach((l,i)=>{const b=document.createElement('button');b.type='button';b.textContent=(l.type==='text'?'T':'▣')+' · '+(l.type==='text'?(l.text||'Text').slice(0,25):l.filename||'Artwork');b.setAttribute('aria-pressed',String(l.id===state.selected));b.addEventListener('click',()=>{state.selected=l.id;render()});list.prepend(b)});if(!state.layers.length){const p=document.createElement('p');p.className='fineprint';p.textContent='Add wording or artwork to begin.';list.append(p)}colorControls()}
function selectProduct(i){if(!Number.isInteger(i)||i<0||i>=products.length)return;snapshot();rememberCanvas();openCanvas(i,state.surface);status(`${products[i].display} selected. Previously designed surfaces are retained.`)}
$('product').addEventListener('change',e=>selectProduct(Number(e.target.value)));
$('surface').addEventListener('change',e=>{const target=e.target.value;if(!['Front','Back','Side'].includes(target))return;snapshot();rememberCanvas();openCanvas(state.product,target);status(`${target} design opened; other surfaces remain saved in this concept.`)});
$('blank').addEventListener('change',e=>{snapshot();state.blank=e.target.value;render();status('Concept blank color updated.')});
$('add-text').addEventListener('click',()=>{const text=$('text-entry').value.trim();if(!text){status('Enter wording before adding a text layer.');return}snapshot();const l=baseLayer('text',{text:text.slice(0,120),fontSize:Number($('font-size').value),color:$('layer-color').value,y:380+state.layers.length*25});state.layers.push(l);state.selected=l.id;render();status('Text layer added. Drag it on the canvas to reposition.')});
$('font-size').addEventListener('change',e=>{$('font-size-display').textContent=e.target.value;const l=selected();if(l?.type==='text'){snapshot();l.fontSize=Number(e.target.value);render()}});
$('layer-color').addEventListener('change',e=>{const l=selected();if(l?.type==='text'){snapshot();l.color=e.target.value;render()}});
$('layer-angle').addEventListener('change',e=>{const l=selected();if(!l)return;snapshot();l.rotation=Number(e.target.value);render();status('Layer rotation adjusted.');});
$('layer-scale').addEventListener('change',e=>{const l=selected();if(l?.type!=='image')return;snapshot();l.scale=Number(e.target.value)/100;render();status('Artwork scale adjusted.');});
$('duplicate-layer').addEventListener('click',()=>{const l=selected();if(!l){status('Select a layer first.');return}snapshot();const copy=clone(l);copy.id=nextId();copy.x=Math.min(650,copy.x+25);copy.y=Math.min(650,copy.y+25);state.layers.push(copy);state.selected=copy.id;if(copy.type==='image'&&copy.data)loadArtwork(copy);render();status('Layer duplicated.')});
$('remove-layer').addEventListener('click',()=>{if(!selected()){status('Select a layer first.');return}snapshot();imageCache.delete(state.selected);state.layers=state.layers.filter(l=>l.id!==state.selected);state.selected=state.layers.at(-1)?.id||null;render();status('Layer removed.')});
$('undo').addEventListener('click',()=>{if(!past.length){status('No changes to undo.');return}future.push(clone(state));state=past.pop();hasReviewed=false;restoreImages();render();status('Undid the last change.')});
$('redo').addEventListener('click',()=>{if(!future.length){status('No changes to redo.');return}past.push(clone(state));state=future.pop();hasReviewed=false;restoreImages();render();status('Redid the change.')});
function loadArtwork(l){if(!l?.data)return;const i=new Image();i.onload=render;i.src=l.data;imageCache.set(l.id,i)}function restoreImages(){imageCache.clear();state.layers.forEach(loadArtwork)}
$('artwork').addEventListener('change',async e=>{const file=e.target.files?.[0];if(!file)return;if(!['image/png','image/jpeg','image/webp'].includes(file.type)||file.size>4*1024*1024){status('Choose PNG, JPEG, or WebP artwork no larger than 4MB.');e.target.value='';return}try{const data=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(String(reader.result));reader.onerror=()=>reject(Error('read failure'));reader.readAsDataURL(file)});snapshot();const layer=baseLayer('image',{data,filename:file.name.slice(0,70),y:415});state.layers.push(layer);state.selected=layer.id;loadArtwork(layer);render();status('Artwork added locally; drag to position. Nothing has been uploaded.')}catch(_){status('Artwork could not be read.')}finally{e.target.value=''}});
function inCanvas(evt){const r=canvas.getBoundingClientRect();return {x:(evt.clientX-r.left)/r.width*W,y:(evt.clientY-r.top)/r.height*H}}
function pick(x,y){return [...state.layers].reverse().find(l=>Math.abs(l.x-x)<(l.type==='image'?125:180)&&Math.abs(l.y-y)<(l.type==='image'?120:55))}
canvas.addEventListener('keydown',e=>{
 const step=e.shiftKey?10:2;const delta={ArrowLeft:[-step,0],ArrowRight:[step,0],ArrowUp:[0,-step],ArrowDown:[0,step]}[e.key];
 if(!delta)return;const l=selected();if(!l)return;e.preventDefault();snapshot();l.x=Math.max(125,Math.min(675,l.x+delta[0]));l.y=Math.max(170,Math.min(650,l.y+delta[1]));render();status(`Layer moved to ${l.x}, ${l.y} (illustrative).`);
});
canvas.addEventListener('pointerdown',e=>{const p=inCanvas(e),l=pick(p.x,p.y);if(l){snapshot();state.selected=l.id;drag={id:l.id,dx:p.x-l.x,dy:p.y-l.y};canvas.setPointerCapture(e.pointerId);render()} });
canvas.addEventListener('pointermove',e=>{if(!drag)return;let p=inCanvas(e),l=state.layers.find(x=>x.id===drag.id);if(!l)return;l.x=Math.round(Math.max(125,Math.min(675,p.x-drag.dx)));l.y=Math.round(Math.max(170,Math.min(650,p.y-drag.dy)));render()});
canvas.addEventListener('pointerup',()=>{if(drag){drag=null;status('Placement updated. Review before export.')}});canvas.addEventListener('pointercancel',()=>{drag=null});
function review(){const problems=[];if(!state.layers.length)problems.push('No artwork or wording has been added.');for(const l of state.layers){if(l.x<245||l.x>555||l.y<268||l.y>538)problems.push('One or more layers fall outside the conceptual design guide.');if(l.type==='text'&&l.text.length>38)problems.push('A long text layer may not fit a real print zone.')}const data=[`PRODUCT: ${products[state.product].display}`,`SURFACE: ${state.surface}`,`CONCEPT COLOR: ${state.blank}`,`LAYERS: ${state.layers.length}`,`DESIGNED SURFACES: ${draftSummary().length}`,`CHECKS: ${problems.length?problems.join(' | '):'No illustrative placement flags'}`,'PRODUCTION APPROVED: NO','PRICE VERIFIED: NO','CHECKOUT ENABLED: NO'];$('design-report').textContent=data.join('\n');hasReviewed=true;status('Concept review complete. This is not a manufacturing approval.')}
$('review-design').addEventListener('click',review);
function exportFile(name,blob){const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),7000)}
function safeDraft(){return {schema:'tj-design-concept-2026-10-v2',localOnly:true,manufacturingApproved:false,priceApproved:false,checkoutEnabled:false,product:state.product,surface:state.surface,blank:state.blank,layers:clone(state.layers),designs:allDesigns()}}
function validLayers(layers){
 if(!Array.isArray(layers)||layers.length>32)return false;
 const ids=new Set();let imageBytes=0;
 for(const l of layers){
  if(!l||typeof l!=='object'||!['text','image'].includes(l.type)||typeof l.id!=='string'||!l.id||l.id.length>120||ids.has(l.id))return false;
  ids.add(l.id);
  if(!Number.isFinite(l.x)||!Number.isFinite(l.y)||l.x<0||l.x>800||l.y<0||l.y>800||!Number.isFinite(l.rotation)||Math.abs(l.rotation)>360||!Number.isFinite(l.scale)||l.scale<.05||l.scale>10)return false;
  if(l.type==='text'&&(typeof l.text!=='string'||l.text.length>120||!Number.isFinite(l.fontSize)||l.fontSize<1||l.fontSize>200||!/^#[0-9a-f]{6}$/i.test(l.color)))return false;
  if(l.type==='image'){if(typeof l.data!=='string'||!/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(l.data)||l.data.length>6000000)return false;imageBytes+=l.data.length;}
 }
 return imageBytes<=12000000;
}
function readDraft(raw){
 if(typeof raw!=='string'||raw.length>15000000)throw Error('Draft too large');
 const d=JSON.parse(raw);
 if(!d||!['tj-design-concept-2026-10','tj-design-concept-2026-10-v2'].includes(d.schema)||!d.localOnly||
 !Number.isInteger(d.product)||d.product<0||d.product>=products.length||!['Front','Back','Side'].includes(d.surface)||
 !/^#[0-9a-f]{6}$/i.test(d.blank)||d.manufacturingApproved!==false||d.priceApproved!==false||d.checkoutEnabled!==false||!validLayers(d.layers))throw Error('Invalid draft');
 const designs={};
 if(d.schema==='tj-design-concept-2026-10-v2'){
  if(!d.designs||typeof d.designs!=='object'||Array.isArray(d.designs)||Object.keys(d.designs).length>18)throw Error('Invalid canvas index');
  for(const [key,value] of Object.entries(d.designs)){
   const match=/^([0-5]):(Front|Back|Side)$/.exec(key);
   if(!match||!value||!/^#[0-9a-f]{6}$/i.test(value.blank)||!validLayers(value.layers))throw Error('Invalid canvas');
   designs[key]={blank:value.blank,layers:value.layers};
  }
 }
 // Active surface is authoritative if an older program saved duplicate state.
 designs[designKey(d.product,d.surface)]={blank:d.blank,layers:d.layers};
 if(JSON.stringify(designs).length>14500000)throw Error('Too much artwork');
 return {...d,designs};
}
$('import-json').addEventListener('change',async e=>{
 const file=e.target.files?.[0];e.target.value='';if(!file)return;
 if(file.size>15000000||file.size===0){status('Concept file rejected: maximum 15MB.');return;}
 try{
  const raw=await file.text();const d=readDraft(raw);
  // Preserve the current editor on any failed input, including tampered approval claims.
  snapshot();state={product:d.product,surface:d.surface,blank:d.blank,layers:clone(d.layers),selected:d.layers.at(-1)?.id||null,designs:clone(d.designs)};
  restoreImages();render();status(`Imported ${draftSummary().length} designed surface(s) locally. Nothing was sent to Shopify.`);
 }catch(_){status('Concept file was rejected. Your current work is unchanged.');}
});
$('export-brief').addEventListener('click',()=>{
 const rows=draftSummary();const text=['TRENDYJOES DESIGN WORKS — CONCEPT REQUEST BRIEF',
 'Not a production order or manufacturing proof.',
 ...rows.map(x=>'• '+x),rows.length?'Review the attached exported design JSON for concept layer details.':'No surfaces designed yet.',
 'Product sourcing, sizes, materials, printing method, quantity, and prices require manual confirmation.'];
 exportFile('TrendyJoes-custom-project-brief.txt',new Blob([text.join('\n')+'\n'],{type:'text/plain'}));
 status('Downloaded a concept request brief. No order was placed.');
});
$('export-json').addEventListener('click',()=>{const b=new Blob([JSON.stringify(safeDraft(),null,2)],{type:'application/json'});exportFile('TrendyJoes-design-concept.json',b);status('Downloaded a concept-only JSON file.')});
$('export-png').addEventListener('click',()=>{if(!canvas.toBlob){status('This browser cannot export PNG.');return}canvas.toBlob(b=>{if(b){exportFile('TrendyJoes-concept-preview.png',b);status('Downloaded a concept preview PNG.')}else status('PNG export failed.')},'image/png')});
$('save-draft').addEventListener('click',()=>{const data=JSON.stringify(safeDraft());sessionDraft=data;try{localStorage.setItem('tj-preview-draft-v1',data);status('Draft saved to this device only.')}catch(_){status('Draft saved in this tab only; persistent browser storage is unavailable.')}});
$('load-draft').addEventListener('click',()=>{try{
 let raw=sessionDraft;try{raw=localStorage.getItem('tj-preview-draft-v1')||sessionDraft;}catch(_){}
 if(!raw){status('No local saved draft found.');return}
 const d=readDraft(raw);snapshot();state={product:d.product,surface:d.surface,blank:d.blank,layers:clone(d.layers),selected:d.layers.at(-1)?.id||null,designs:clone(d.designs)};
 restoreImages();render();status(`Device concept loaded with ${draftSummary().length} designed surface(s).`);
 }catch(_){status('Saved draft was rejected or unavailable. Your current work is unchanged.')}});
$('clear-draft').addEventListener('click',()=>{snapshot();state={product:0,surface:'Front',blank:defaultBlank,layers:[],selected:null,designs:{}};imageCache.clear();$('text-entry').value='MAKE IT YOURS';render();$('design-report').textContent='No review completed.';status('Started a fresh local concept. Saved drafts are untouched.')});
// Copyable inquiry brief. No network submission, identity collection, or invented contact details.
$('inquiry').addEventListener('submit',e=>{e.preventDefault();const name=$('inquiry-name').value.trim().slice(0,80),product=$('inquiry-product').value,detail=$('inquiry-detail').value.trim().slice(0,3000);$('inquiry-result').textContent=`TREN DYJOES DESIGN WORKS — PROJECT INQUIRY\nName: ${name||'(not provided)'}\nProduct: ${product}\nConcept:\n${detail||'(not provided)'}\n\nPrepared locally. Not sent.`.replace('TREN DYJOES','TRENDYJOES')});
$('copy-inquiry').addEventListener('click',async()=>{const data=$('inquiry-result').textContent;try{await navigator.clipboard.writeText(data);$('copy-inquiry').textContent='Copied'}catch(_){const el=$('inquiry-result');const r=document.createRange();r.selectNodeContents(el);const s=window.getSelection();s.removeAllRanges();s.addRange(r);$('copy-inquiry').textContent='Select and copy text above'}});
render();route();
})();
