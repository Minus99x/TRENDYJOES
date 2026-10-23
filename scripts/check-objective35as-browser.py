"""35AS per-surface editor focus and screen-reader status acceptance, local in-memory only."""
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
 page=browser.new_page(viewport={'width':1280,'height':850})
 errors=[];external=[]
 page.on('pageerror',lambda e:errors.append(str(e)))
 page.on('console',lambda m:errors.append('CONSOLE:'+m.text) if m.type=='error' else None)
 page.on('request',lambda r:external.append(r.url) if r.url.startswith('http') else None)
 page.on('dialog',lambda d:d.accept())
 setup(page,'demo/index.html','demo/studio.mjs','integrations/shopify/preview-asset-manifest.json')
 check('35AS_BOOTED',page.locator('#product option').count()==8)
 page.locator('#product').select_option('concept-sneaker')
 page.locator('#surface').select_option('tongue')
 page.locator('#text-entry').fill('TONGUE MARK')
 page.locator('#add-text').click()
 check('35AS_TONGUE_VISIBLE_LAYER',page.locator('#layers option').count()==2 and 'TONGUE MARK' in page.locator('#layers').inner_text())
 check('35AS_TONGUE_CONTEXT', 'Tongue' in page.locator('#surface-edit-context').inner_text() and '1 design element' in page.locator('#surface-edit-context').inner_text())
 page.locator('#surface').select_option('outer-side')
 check('35AS_HIDDEN_TONGUE_NOT_SELECTABLE',page.locator('#layers option').count()==1 and page.locator('#layers').input_value()=='')
 check('35AS_HIDDEN_TONGUE_RETAINED',page.locator('#summary-layers').inner_text()=='1')
 check('35AS_EMPTY_SURFACE_NUDGE_DISABLED',page.locator('#nudge-right').is_disabled())
 check('35AS_ACCESSIBLE_SURFACE_LABEL', 'Outer side' in page.locator('#stage').get_attribute('aria-label') and '0 elements' in page.locator('#stage').get_attribute('aria-label'))
 page.locator('#text-entry').fill('OUTER MARK')
 page.locator('#add-text').click()
 check('35AS_OUTER_ONLY_PICKER',page.locator('#layers option').count()==2 and 'OUTER MARK' in page.locator('#layers').inner_text() and 'TONGUE MARK' not in page.locator('#layers').inner_text())
 check('35AS_SELECTED_STAGE_ANNOUNCEMENT', 'Element 1 selected' in page.locator('#stage').get_attribute('aria-label'))
 stage=page.locator('#stage')
 before=float(page.locator('#stage .layer-boundary').get_attribute('x'))
 stage.focus();page.keyboard.press('ArrowRight')
 after=float(page.locator('#stage .layer-boundary').get_attribute('x'))
 check('35AS_ARROW_MOVES_1_PERCENT',abs(after-before-3.36)<.01)
 check('35AS_KEYBOARD_FOCUS_PRESERVED',page.evaluate('document.activeElement.id')=='stage')
 top=float(page.locator('#stage .layer-boundary').get_attribute('y'))
 page.keyboard.press('Shift+ArrowDown')
 bottom=float(page.locator('#stage .layer-boundary').get_attribute('y'))
 check('35AS_SHIFT_ARROW_MOVES_5_PERCENT',abs(bottom-top-3.52)<.01)
 page.locator('#surface').select_option('tongue')
 check('35AS_TONGUE_RESELECTABLE',page.locator('#layers option').count()==2 and 'TONGUE MARK' in page.locator('#layers').inner_text() and 'OUTER MARK' not in page.locator('#layers').inner_text())
 check('35AS_GLOBAL_COUNT_UNCHANGED',page.locator('#summary-layers').inner_text()=='2')
 page.locator('#surface').select_option('inner-side')
 check('35AS_THIRD_SURFACE_EMPTY',page.locator('#layers option').count()==1 and 'Inner side' in page.locator('#surface-edit-context').inner_text())
 check('35AS_3D_UNVERIFIED_DISABLED',page.locator('#mode-3d').is_disabled())
 check('35AS_CHECKOUT_UNAVAILABLE',page.locator('.disabled-checkout').is_disabled())
 check('35AS_NO_PAGE_ERRORS',not errors)
 check('35AS_NO_EXTERNAL_HTTP',not external)
 if errors:print('PAGE_ERRORS',errors)
 if external:print('EXTERNAL',external)
 page.close();browser.close()
summary={'pass':sum(x['pass'] for x in results),'total':len(results),'results':results,'mode':'offline in-memory Chromium; not hosted Shopify'}
print(json.dumps(summary,indent=2))
assert summary['pass']==summary['total']
