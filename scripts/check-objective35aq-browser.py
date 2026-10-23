"""Chromium in-memory offline DOM acceptance for explicit target positioning; no Shopify."""
from playwright.sync_api import sync_playwright
from pathlib import Path
from urllib.parse import urljoin
import json,re
root=Path(__file__).resolve().parent.parent
manifest=json.loads((root/'integrations/shopify/preview-asset-manifest.json').read_text())
paths=[a['path'] for a in manifest['assets'] if a['path'].endswith('.mjs')]
mods={}
for path in paths:
 src=(root/path).read_text()
 def rewrite(m):
  quote,spec=m.group(1),m.group(2)
  if not spec.startswith('.'):return m.group(0)
  return m.group(0).replace(quote+spec+quote,quote+urljoin('https://offline.invalid/'+path,spec)+quote)
 src=re.sub(r'''\bfrom\s+(['"])([^'"\n]+)\1''',rewrite,src)
 src=re.sub(r'''\bimport\s+(['"])([^'"\n]+)\1''',rewrite,src)
 mods['https://offline.invalid/'+path]=src
html=(root/'demo/index.html').read_text()
html=re.sub(r'<script\s+type="module"[^>]*></script>','',html)
html=re.sub(r'<link rel="stylesheet" href="([^"]+)">',lambda m:'<style>'+(root/'demo'/m.group(1)).read_text()+'</style>',html)
checks=[]
def check(name,ok):
 checks.append({'name':name,'pass':bool(ok)})
 if not ok:print('FAIL',name)
with sync_playwright() as p:
 browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox','--disable-background-networking'])
 page=browser.new_page(viewport={'width':1280,'height':850})
 errors=[];external=[]
 page.on('pageerror',lambda e:errors.append(str(e)))
 page.on('request',lambda r:external.append(r.url) if r.url.startswith('http') else None)
 page.on('dialog',lambda d:d.accept())
 page.set_content(html,wait_until='domcontentloaded')
 page.evaluate('''(modules)=>{
  const imports={imports:{}};
  for(const [name,source] of Object.entries(modules))imports.imports[name]=URL.createObjectURL(new Blob([source],{type:'text/javascript'}));
  const map=document.createElement('script');map.type='importmap';map.textContent=JSON.stringify(imports);document.head.append(map);
  const entry=document.createElement('script');entry.type='module';entry.textContent='import "https://offline.invalid/demo/studio.mjs";';document.head.append(entry);
 }''',mods)
 page.wait_for_timeout(850)
 copy=page.locator('#copy-selected-surface');target=page.locator('#copy-target-surface')
 check('COPY_DISABLED_WITH_NO_SELECTION',copy.is_disabled())
 placement=page.locator('#copy-placement')
 check('POSITION_DISABLED_WITH_NO_SELECTION',placement.is_disabled())
 page.locator('#add-text').click()
 check('LAYER_ADDED',page.locator('#layers option').count()==2)
 check('AVAILABLE_DIFFERENT_TARGET',target.is_enabled() and target.input_value()!='front')
 check('COPY_ENABLED',copy.is_enabled())
 check('POSITION_ENABLED_WITH_SELECTION',placement.is_enabled())
 check('DEFAULT_IS_PRESERVE',placement.input_value()=='preserve')
 placement.select_option('center')
 check('EXPLICIT_CENTER_SELECTED',placement.input_value()=='center')
 before=page.locator('#layers option').count()
 copy.click()
 check('COPY_ADDS_ONE_NEW_LAYER',page.locator('#summary-layers').inner_text()=='2')
 check('TARGET_SELECTED',page.locator('#surface').input_value()=='back')
 check('COPIED_LAYER_IS_CURRENT',page.locator('#layers option').count()==2 and bool(page.locator('#layers').input_value()) and page.locator('#summary-layers').inner_text()=='2')
 check('FOCUS_RESTORED',page.evaluate('document.activeElement?.id')=='layers')
 check('COPY_NOT_PRODUCTION_APPROVAL','not production calibrated' in page.locator('#status').inner_text().lower())
 check('CENTER_ACTION_ANNOUNCED','centered' in page.locator('#status').inner_text().lower())
 check('ORIGINAL_SURFACE_UNTOUCHED',page.locator('#surface').select_option('front')==['front'] and page.locator('#layers option').count()==2 and page.locator('#summary-layers').inner_text()=='2')
 check('PLACEMENT_REMAINS_DISCOVERABLE',page.locator('#copy-placement option').count()==2)
 check('PRESERVED_2D',page.locator('#mode-2d').get_attribute('aria-pressed')=='true')
 check('CHECKOUT_DISABLED',page.locator('.disabled-checkout').is_disabled())
 check('NO_PAGE_ERRORS',not errors)
 check('NO_EXTERNAL_HTTP',not external)
 browser.close()
summary={'pass':sum(c['pass'] for c in checks),'total':len(checks),'results':checks,'pageErrors':errors,'externalRequests':external,'mode':'Chromium offline in-memory import maps, explicit center target, NOT hosted Shopify'}
print(json.dumps(summary,indent=2))
assert all(c['pass'] for c in checks)
