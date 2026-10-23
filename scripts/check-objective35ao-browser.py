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
  target=urljoin('https://offline.invalid/'+path,spec)
  return m.group(0).replace(quote+spec+quote,quote+target+quote)
 src=re.sub(r'''\bfrom\s+(['"])([^'"\n]+)\1''',rewrite,src)
 src=re.sub(r'''\bimport\s+(['"])([^'"\n]+)\1''',rewrite,src)
 mods['https://offline.invalid/'+path]=src
html=(root/'demo/index.html').read_text()
html=re.sub(r'<script\s+type="module"[^>]*></script>','',html)
html=re.sub(r'<link rel="stylesheet" href="([^"]+)">',lambda m:'<style>'+(root/'demo'/m.group(1)).read_text()+'</style>',html)
results=[]
def check(name,condition):
 results.append({'name':name,'pass':bool(condition)})
 if not condition:print('FAIL',name)
with sync_playwright() as p:
 browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox','--disable-background-networking'])
 page=browser.new_page(viewport={'width':1280,'height':850})
 errors=[];external=[]
 page.on('pageerror',lambda e:errors.append(str(e)))
 page.on('dialog',lambda d:d.accept())
 page.on('request',lambda r:external.append(r.url) if r.url.startswith('http') else None)
 page.set_content(html,wait_until='domcontentloaded')
 page.evaluate('''(modules)=>{
  const imports={imports:{}};
  for(const [name,source] of Object.entries(modules))imports.imports[name]=URL.createObjectURL(new Blob([source],{type:'text/javascript'}));
  const map=document.createElement('script');map.type='importmap';map.textContent=JSON.stringify(imports);document.head.append(map);
  const entry=document.createElement('script');entry.type='module';entry.textContent='import "https://offline.invalid/demo/studio.mjs";';document.head.append(entry);
 }''',mods)
 page.wait_for_timeout(900)
 check('MODULES_INITIALIZED',page.locator('#product option').count()>=7)
 check('BUTTONS_START_DISABLED',page.locator('#nudge-right').is_disabled())
 page.locator('#add-text').click()
 check('LAYER_ADDED',page.locator('#layers option').count()==2)
 page.locator('#mode-2d').click()
 check('NUDGE_ENABLED',page.locator('#nudge-right').is_enabled())
 before=page.locator('#stage .art-layer').first.get_attribute('transform')
 page.locator('#nudge-right').click()
 after=page.locator('#stage .art-layer').first.get_attribute('transform')
 check('BUTTON_NUDGE_MOVED',before!=after)
 page.locator('#stage').focus()
 page.keyboard.press('Shift+ArrowUp')
 after_key=page.locator('#stage .art-layer').first.get_attribute('transform')
 check('KEYBOARD_COARSE_MOVED',after_key!=after)
 check('FOCUS_RETAINED',page.evaluate("document.activeElement?.id")=='stage')
 page.keyboard.press('Control+ArrowRight')
 check('MODIFIER_NOT_CAPTURED',page.locator('#stage .art-layer').first.get_attribute('transform')==after_key)
 check('LIVE_STATUS','Not production calibrated' in page.locator('#status').inner_text())
 check('CHECKOUT_DISABLED',page.locator('.disabled-checkout').is_disabled())
 # Adversarial: repeated UI nudges must stop at the print-zone boundary.
 for _ in range(90): page.locator('#nudge-right').click()
 boundary=page.locator('#stage .art-layer').first.get_attribute('transform')
 page.locator('#nudge-right').click()
 check('ZONE_BOUNDARY_REFUSES_MOVE',page.locator('#stage .art-layer').first.get_attribute('transform')==boundary)
 check('ZONE_BOUNDARY_ANNOUNCED','Cannot move outside' in page.locator('#status').inner_text())
 page.locator('#mode-3d').click()
 check('3D_DISALLOWS_2D_NUDGE',page.locator('#nudge-right').is_disabled())
 page.locator('#mode-2d').click()
 page.locator('#product').select_option('concept-rug')
 check('SWITCH_CLEARS_LAYERS',page.locator('#layers option').count()==1 and page.locator('#nudge-right').is_disabled())
 check('NO_PAGE_ERRORS',not errors)
 check('NO_EXTERNAL_REQUESTS',not external)
 browser.close()
summary={'pass':sum(r['pass'] for r in results),'total':len(results),'results':results,'errors':errors,'external':external,'mode':'Chromium embedded offline modules; not hosted Shopify'}
# Output evidence is captured by caller; do not modify the immutable source tree.
print(json.dumps(summary,indent=2))
assert all(r['pass'] for r in results)
