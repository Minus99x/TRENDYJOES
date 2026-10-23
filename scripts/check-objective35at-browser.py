"""35AT offline Chromium: cross-category surface focus and draft worksheet invalidation.
Synthetic test measurements; no actual physical calibration, server, commerce, or Shopify.
"""
from pathlib import Path
from urllib.parse import urljoin
from playwright.sync_api import sync_playwright
import json,re
root=Path(__file__).resolve().parent.parent
results=[]
def check(name,ok):
 results.append({'name':name,'pass':bool(ok)})
 if not ok: print('FAIL',name)
def setup(page):
 manifest=json.loads((root/'integrations/shopify/preview-asset-manifest.json').read_text())
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
 html=(root/'demo/index.html').read_text()
 html=re.sub(r'<meta\s+http-equiv="Content-Security-Policy"[^>]*>', '', html)
 html=re.sub(r'<script\s+type="module"[^>]*></script>','',html)
 html=re.sub(r'<link rel="stylesheet" href="([^"]+)">',lambda m:'<style>'+(root/'demo'/m.group(1)).read_text()+'</style>',html)
 page.set_content(html,wait_until='domcontentloaded')
 page.evaluate('''([mods])=>{
  const imports={imports:{}};
  for(const [name,source] of Object.entries(mods))imports.imports[name]=URL.createObjectURL(new Blob([source],{type:'text/javascript'}));
  const map=document.createElement('script');map.type='importmap';map.textContent=JSON.stringify(imports);document.head.append(map);
  const module=document.createElement('script');module.type='module';module.textContent='import "https://offline.invalid/demo/studio.mjs";';document.head.append(module);
 }''',[mods]);page.wait_for_timeout(650)
def fill_calibration(page):
 for k,v in {'blank-sku':'TEST-ONLY-BLANK','print-width-mm':'80','print-height-mm':'60','blank-width-mm':'120','blank-height-mm':'100','measurement-source':'SYNTHETIC OFFLINE TEST','technician':'TEST OPERATOR','measurement-date':'2026-10-22','fixture-reference':'TEST FIXTURE'}.items():
  page.locator('#'+k).fill(v)
 page.locator('#validate-calibration').click()
with sync_playwright() as p:
 browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox','--disable-background-networking'])
 page=browser.new_page(viewport={'width':1280,'height':850})
 errors=[];external=[]
 page.on('pageerror',lambda e:errors.append(str(e)))
 page.on('console',lambda m:errors.append('CONSOLE:'+m.text) if m.type=='error' else None)
 page.on('request',lambda r:external.append(r.url) if r.url.startswith('http') else None)
 page.on('dialog',lambda d:d.accept())
 setup(page)
 products=['concept-crew-tee','concept-v-tee','concept-long-sleeve','concept-hoodie','concept-tumbler','concept-backpack','concept-rug','concept-sneaker']
 check('35AT_BOOTED',page.locator('#product option').count()==len(products))
 for product in products:
  page.locator('#product').select_option(product)
  page.locator('#mode-2d').click()
  page.locator('#text-entry').fill('TEST '+product)
  page.locator('#add-text').click()
  check(product+'_LAYER_ADDED',page.locator('#summary-layers').inner_text()=='1')
  check(product+'_SELECTED_SURFACE',page.locator('#layers option').count()==2 and page.locator('#layers').input_value()!='')
  check(product+'_ACCESSIBLE_STAGE',product!='concept-sneaker' and '2D concept preview' in page.locator('#stage').get_attribute('aria-label') or product=='concept-sneaker' and '2D concept preview' in page.locator('#stage').get_attribute('aria-label'))
  stage=page.locator('#stage');before=float(page.locator('#stage .layer-boundary').get_attribute('x'))
  stage.focus();page.keyboard.press('ArrowRight')
  after=float(page.locator('#stage .layer-boundary').get_attribute('x'))
  check(product+'_KEYBOARD_MOVES',after>before and abs(after-before)<10)
  check(product+'_FOCUS_RETAINED',page.evaluate('document.activeElement.id')=='stage')
  check(product+'_CHECKOUT_DISABLED',page.locator('.disabled-checkout').is_disabled())
  if page.locator('#surface option').count()>1:
   second=page.locator('#surface option').nth(1).get_attribute('value')
   page.locator('#surface').select_option(second)
   check(product+'_CROSS_SURFACE_SELECTION_CLEARED',page.locator('#layers option').count()==1 and page.locator('#layers').input_value()=='')
   check(product+'_CROSS_SURFACE_LAYER_RETAINED',page.locator('#summary-layers').inner_text()=='1')
   check(product+'_CROSS_SURFACE_NUDGE_DISABLED',page.locator('#nudge-right').is_disabled())
   page.locator('#surface').select_option(page.locator('#surface option').first.get_attribute('value'))
   check(product+'_ORIGINAL_LAYER_RESELECTABLE',page.locator('#layers option').count()==2)
 check('35AT_FINAL_PRODUCT_ONLY_ONE_LAYER',page.locator('#summary-layers').inner_text()=='1')
 page.locator('#product').select_option('concept-crew-tee')
 page.locator('details.calibration-tool summary').click()
 fill_calibration(page)
 check('35AT_DRAFT_VALIDATED',page.locator('#export-calibration').is_enabled() and 'DRAFT only' in page.locator('#calibration-result').inner_text())
 page.locator('#measurement-source').fill('SYNTHETIC CHANGED')
 check('35AT_EDIT_INVALIDATES_EXPORT',page.locator('#export-calibration').is_disabled())
 fill_calibration(page)
 check('35AT_REVALIDATION_REENABLES',page.locator('#export-calibration').is_enabled())
 page.locator('#surface').select_option('back')
 check('35AT_SURFACE_INVALIDATES_EXPORT',page.locator('#export-calibration').is_disabled())
 check('35AT_SURFACE_CLEARS_MEASUREMENTS',page.locator('#blank-sku').input_value()=='' and page.locator('#print-width-mm').input_value()=='')
 fill_calibration(page)
 check('35AT_SECOND_SURFACE_DRAFT_VALID',page.locator('#export-calibration').is_enabled())
 page.locator('#product').select_option('concept-v-tee')
 check('35AT_PRODUCT_INVALIDATES_EXPORT',page.locator('#export-calibration').is_disabled())
 check('35AT_PRODUCT_CLEARS_MEASUREMENTS',page.locator('#blank-sku').input_value()=='' and page.locator('#print-width-mm').input_value()=='')
 fill_calibration(page)
 check('35AT_NEW_PRODUCT_REVALIDATES',page.locator('#export-calibration').is_enabled())
 colors=page.locator('#concept-color option').count()
 if colors>1:
  next_color=page.locator('#concept-color option').nth(1).get_attribute('value')
  page.locator('#concept-color').select_option(next_color)
  check('35AT_VARIANT_INVALIDATES_EXPORT',page.locator('#export-calibration').is_disabled())
 check('35AT_NO_PAGE_ERRORS',not errors)
 check('35AT_NO_EXTERNAL_HTTP',not external)
 if errors:print('PAGE_ERRORS',errors)
 if external:print('EXTERNAL',external)
 browser.close()
summary={'pass':sum(x['pass'] for x in results),'fail':sum(not x['pass'] for x in results),'total':len(results),'results':results,'mode':'offline in-memory Chromium; synthetic measurements only'}
print(json.dumps(summary,indent=2))
assert summary['fail']==0
