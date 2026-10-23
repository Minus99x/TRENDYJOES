"""35AR offline Chromium acceptance: explicit footwear 2D fallback in both editors.
No Shopify, hosted storefront, external network, secrets or commerce writes.
"""
from pathlib import Path
from urllib.parse import urljoin
from playwright.sync_api import sync_playwright
import json,re
root=Path(__file__).resolve().parent.parent
results=[]
def check(name,ok):
 results.append({'name':name,'pass':bool(ok)})
 if not ok:print('FAIL',name)
def setup(page,html_path,entry,manifest_path):
 manifest=json.loads((root/manifest_path).read_text())
 mods={}
 for path in [a['path'] for a in manifest['assets'] if a['path'].endswith('.mjs')]:
  src=(root/path).read_text()
  def rewrite(m):
   quote,spec=m.group(1),m.group(2)
   if not spec.startswith('.'):return m.group(0)
   return m.group(0).replace(quote+spec+quote,quote+urljoin('https://offline.invalid/'+path,spec)+quote)
  src=re.sub(r'''\bfrom\s+(['"])([^'"\n]+)\1''',rewrite,src)
  src=re.sub(r'''\bimport\s+(['"])([^'"\n]+)\1''',rewrite,src)
  mods['https://offline.invalid/'+path]=src
 html=(root/html_path).read_text()
 # In-memory blob-module harness requires a relaxed test document CSP; the shipped CSP stays unchanged.
 html=re.sub(r'<meta\s+http-equiv="Content-Security-Policy"[^>]*>', '', html)
 html=re.sub(r'<script\s+type="module"[^>]*></script>','',html)
 html=re.sub(r'<link rel="stylesheet" href="([^"]+)">',lambda m:'<style>'+(root/'demo'/m.group(1)).read_text()+'</style>',html)
 page.set_content(html,wait_until='domcontentloaded')
 page.evaluate('''([mods,entry])=>{
  const imports={imports:{}};
  for(const [name,source] of Object.entries(mods))imports.imports[name]=URL.createObjectURL(new Blob([source],{type:'text/javascript'}));
  const map=document.createElement('script');map.type='importmap';map.textContent=JSON.stringify(imports);document.head.append(map);
  const module=document.createElement('script');module.type='module';module.textContent='import "https://offline.invalid/'+entry+'";';document.head.append(module);
 }''',[mods,entry])
 page.wait_for_timeout(750)
with sync_playwright() as p:
 browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox','--disable-background-networking'])
 for label,html,entry,manifest in [
  ('LOCAL','demo/index.html','demo/studio.mjs','integrations/shopify/preview-asset-manifest.json'),
  ('STATIC','demo/static-preview.html','demo/static-preview.mjs','integrations/shopify/static-preview-asset-manifest.json')]:
  page=browser.new_page(viewport={'width':1280,'height':850})
  errors=[];external=[]
  page.on('pageerror',lambda e:errors.append(str(e)))
  page.on('console',lambda m:errors.append('CONSOLE:'+m.text) if m.type=='error' else None)
  page.on('request',lambda r:external.append(r.url) if r.url.startswith('http') else None)
  page.on('dialog',lambda d:d.accept())
  setup(page,html,entry,manifest)
  check(label+'_EDITOR_BOOTED',page.locator('#product option').count()==8)
  if page.locator('#product option').count()!=8:
   print(label+'_BOOT_ERRORS',errors)
   raise AssertionError('Editor failed to boot')
  page.locator('#product').select_option('concept-sneaker',timeout=3000)
  page.wait_for_timeout(120)
  check(label+'_FOOTWEAR_SELECTED',page.locator('#product').input_value()=='concept-sneaker')
  check(label+'_THREE_DECLARED_SURFACES',page.locator('#surface option').count()==3)
  check(label+'_STARTS_2D',page.locator('#mode-2d').get_attribute('aria-pressed')=='true')
  check(label+'_3D_DISABLED',page.locator('#mode-3d').is_disabled())
  check(label+'_2D_VISIBLE',page.locator('#stage').is_visible())
  check(label+'_3D_HIDDEN',not page.locator('#stage-3d').is_visible())
  outer=page.locator('#stage').inner_html()
  check(label+'_SIDE_CONCEPT_VISIBLE','M106 446' in outer)
  page.locator('#surface').select_option('inner-side')
  inner=page.locator('#stage').inner_html()
  check(label+'_INNER_MIRROR','scale(-1 1)' in inner and inner!=outer)
  page.locator('#surface').select_option('tongue')
  tongue=page.locator('#stage').inner_html()
  check(label+'_TONGUE_DIFFERENT','M316 510' in tongue and tongue!=inner)
  if label=='STATIC':page.locator('#text-entry').fill('TEST FOOTWEAR')
  page.locator('#add-text').click()
  check(label+'_LAYER_ADDED',page.locator('#summary-layers').inner_text()=='1')
  check(label+'_ZONE_RENDERED',page.locator('#stage .print-zone').count()==1)
  if label=='LOCAL':
   check(label+'_COPY_ENABLED',page.locator('#copy-selected-surface').is_enabled())
   page.locator('#copy-target-surface').select_option('outer-side')
   page.locator('#copy-placement').select_option('center')
   page.locator('#copy-selected-surface').click()
   check(label+'_COPY_TWO_SURFACES',page.locator('#summary-layers').inner_text()=='2')
   check(label+'_FOCUS_RETURNED',page.evaluate('document.activeElement?.id')=='layers')
   check(label+'_NO_PRODUCTION_APPROVAL','not production calibrated' in page.locator('#status').inner_text().lower())
  else:
   check(label+'_REVIEW_AVAILABLE',page.locator('#review-preview').is_enabled())
  check(label+'_CHECKOUT_DISABLED',page.locator('.disabled-checkout').is_disabled())
  check(label+'_NO_PAGE_ERRORS',not errors)
  check(label+'_NO_EXTERNAL_HTTP',not external)
  if errors:print(label+'_ERRORS',errors)
  if external:print(label+'_HTTP',external)
  page.close()
 browser.close()
summary={'pass':sum(x['pass'] for x in results),'total':len(results),'results':results,'mode':'offline in-memory Chromium; not hosted Shopify'}
print(json.dumps(summary,indent=2))
assert summary['pass']==summary['total']
