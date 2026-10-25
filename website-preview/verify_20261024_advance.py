"""Customer-facing Chromium acceptance: multi-surface retention and portable concept files.
All checks run on the new standalone HTML bundle, not a previous release.
"""
from pathlib import Path
from playwright.sync_api import sync_playwright
import json, tempfile
from PIL import Image
ROOT=Path(__file__).parent
report={'suite':'TrendyJoes private preview / multi-surface regression','checks':[],'browserErrors':[]}
def preview_html():
 html=(ROOT/'index.html').read_text()
 css=(ROOT/'styles.css').read_text()
 app=(ROOT/'app.js').read_text()
 assert html.count('<link rel="stylesheet" href="styles.css">')==1
 assert html.count('<script src="app.js" defer></script>')==1
 assert '</script>' not in app
 return html.replace('<link rel="stylesheet" href="styles.css">','<style>\n'+css+'\n</style>').replace('<script src="app.js" defer></script>','<script>\n'+app+'\n</script>')
def load_preview(page):
 html=preview_html()
 page.route('http://preview.test/**',lambda route:route.fulfill(status=200,content_type='text/html',body=html))
 page.route('https://cdn.shopify.com/**',lambda route:route.abort())
 page.goto('http://preview.test/',wait_until='domcontentloaded')
def verify(statement,label):
 assert statement,label
 report['checks'].append(label); print('PASS:',label,flush=True)
with sync_playwright() as p:
 browser=p.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox','--disable-dev-shm-usage'])
 page=browser.new_page(viewport={'width':1440,'height':900},accept_downloads=True)
 page.on('pageerror',lambda e: report['browserErrors'].append(str(e)))
 load_preview(page)
 page.get_by_role('link',name='Enter the Studio').first.click()
 page.wait_for_timeout(250)
 verify(page.locator('[data-page="studio"]').is_visible(),'Studio opens from approved homepage CTA')
 page.locator('#text-entry').fill('FRONT DESIGN')
 page.locator('#add-text').click()
 verify(page.locator('#layer-list button').count()==1,'Front text created')
 page.locator('#surface').select_option('Back')
 verify(page.locator('#layer-list button').count()==0,'Back starts clean')
 page.locator('#text-entry').fill('BACK DESIGN')
 page.locator('#add-text').click()
 page.locator('#surface').select_option('Front')
 verify('FRONT DESIGN' in page.locator('#layer-list').inner_text(),'Front artwork preserved after switching')
 page.locator('#surface').select_option('Back')
 verify('BACK DESIGN' in page.locator('#layer-list').inner_text(),'Back artwork preserved after switching')
 page.locator('#product').select_option('2')
 verify(page.locator('#layer-list button').count()==0,'Distinct product starts clean')
 page.locator('#text-entry').fill('MUG DESIGN')
 page.locator('#add-text').click()
 page.locator('#product').select_option('0')
 verify('BACK DESIGN' in page.locator('#layer-list').inner_text(),'Returning to original product restores artwork')
 page.locator('#surface').select_option('Front')
 verify('FRONT DESIGN' in page.locator('#layer-list').inner_text(),'Original product Front artwork retained')
 page.locator('#design-canvas').focus()
 page.keyboard.press('Shift+ArrowRight')
 verify('Layer moved' in page.locator('#editor-status').inner_text(),'Keyboard layer nudging works')
 page.locator('#layer-angle').fill('35')
 page.locator('#layer-angle').dispatch_event('change')
 verify('35°' in page.locator('#layer-angle-display').inner_text(),'Text rotation control responds')
 page.locator('#review-design').click()
 verify('DESIGNED SURFACES: 3' in page.locator('#design-report').inner_text(),'Review spans three design surfaces')
 with page.expect_download() as d:page.locator('#export-json').click()
 download=d.value
 path=ROOT/'ported-concept.json';download.save_as(path)
 obj=json.loads(path.read_text())
 verify(obj['schema']=='tj-design-concept-2026-10-v2' and len([d for d in obj['designs'].values() if d['layers']])==3,'Portable JSON contains all designed surfaces')
 verify(obj['manufacturingApproved'] is False and obj['checkoutEnabled'] is False,'Export never fabricates commercial authorization')
 with page.expect_download() as d:page.locator('#export-brief').click()
 brief=ROOT/'project-brief.txt';d.value.save_as(brief)
 verify('FRONT' in brief.read_text().upper() and 'BACK' in brief.read_text().upper() and 'NOT A PRODUCTION ORDER' in brief.read_text().upper(),'Project brief lists surfaces and guardrails')
 page.locator('#save-draft').click()
 page.locator('#clear-draft').click()
 verify(page.locator('#layer-list button').count()==0,'Clear starts new concept')
 page.locator('#load-draft').click()
 verify('FRONT DESIGN' in page.locator('#layer-list').inner_text(),'Device draft restores current surface')
 page.locator('#surface').select_option('Back')
 verify('BACK DESIGN' in page.locator('#layer-list').inner_text(),'Device draft restores other surfaces')
 page.locator('#clear-draft').click()
 page.locator('#import-json').set_input_files(str(path))
 page.wait_for_timeout(220)
 verify('FRONT DESIGN' in page.locator('#layer-list').inner_text(),'Portable JSON import restores active design')
 page.locator('#surface').select_option('Back')
 verify('BACK DESIGN' in page.locator('#layer-list').inner_text(),'Portable JSON import restores inactive surfaces')
 tampered=json.loads(path.read_text());tampered['manufacturingApproved']=True
 bad=ROOT/'tampered.json';bad.write_text(json.dumps(tampered))
 page.locator('#import-json').set_input_files(str(bad))
 page.wait_for_timeout(160)
 verify('rejected' in page.locator('#editor-status').inner_text().lower(),'Forged manufacturing approval rejected')
 verify('BACK DESIGN' in page.locator('#layer-list').inner_text(),'Rejected import leaves current design intact')
 # Backwards-compatible v1 import: old single surface designs are accepted but never granted checkout.
 legacy={k:obj[k] for k in ['localOnly','manufacturingApproved','priceApproved','checkoutEnabled','product','surface','blank','layers']}
 legacy['schema']='tj-design-concept-2026-10'
 lg=ROOT/'legacy-concept.json';lg.write_text(json.dumps(legacy))
 page.locator('#import-json').set_input_files(str(lg));page.wait_for_timeout(160)
 verify('FRONT DESIGN' in page.locator('#layer-list').inner_text(),'Prior v1 local concept can be imported')
 # Check image scale and rotation, all retained across product swaps.
 image_path=ROOT/'image-artwork-test.png';Image.new('RGB',(80,60),(150,37,43)).save(image_path)
 page.locator('#artwork').set_input_files(str(image_path))
 page.wait_for_timeout(180)
 verify(page.locator('#layer-list button').count()==2,'Uploaded artwork added as separate layer')
 page.locator('#layer-scale').fill('175');page.locator('#layer-scale').dispatch_event('change')
 verify('175%' in page.locator('#layer-scale-display').inner_text(),'Artwork resizing works')
 page.locator('#product').select_option('1');page.locator('#product').select_option('0')
 verify(page.locator('#layer-list button').count()==2,'Text and artwork retained across product switch')
 page.locator('#undo').click()
 verify(page.locator('#product').input_value()=='1','Undo across product switch retains history')
 page.locator('#redo').click()
 verify(page.locator('#product').input_value()=='0','Redo across product switch works')
 # Show real mobile Studio for visual QA.
 mobile=browser.new_page(viewport={'width':390,'height':844},is_mobile=True,has_touch=True,accept_downloads=True)
 mobile.on('pageerror',lambda e: report['browserErrors'].append('mobile: '+str(e)))
 load_preview(mobile)
 mobile.locator('#menu-toggle').click();mobile.locator('#nav a[href="#studio"]').click();mobile.wait_for_timeout(200)
 verify(mobile.locator('[data-page="studio"]').is_visible(),'Mobile menu navigates to Studio')
 verify(mobile.evaluate('document.documentElement.scrollWidth<=innerWidth+2'),'No horizontal overflow on narrow mobile')
 print('MOBILE_SCREENSHOT',flush=True);mobile.screenshot(path=str(ROOT/'advance-studio-mobile.png'),full_page=True,animations='disabled',timeout=10000)
 verify(not report['browserErrors'],'No uncaught JavaScript page errors')
 for f in (path,brief,bad,lg,image_path):f.unlink(missing_ok=True)
 browser.close()
(ROOT/'advance-test-results.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'result':'PASS','checks':len(report['checks']),'labels':report['checks']},indent=2))
