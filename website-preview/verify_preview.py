from playwright.sync_api import sync_playwright
from pathlib import Path
import json
ROOT=Path(__file__).parent
js=[]
def preview_html():
 html=(ROOT/'index.html').read_text()
 css=(ROOT/'styles.css').read_text()
 app=(ROOT/'app.js').read_text()
 assert html.count('<link rel="stylesheet" href="styles.css">')==1
 assert html.count('<script src="app.js" defer></script>')==1
 assert '</script>' not in app
 return html.replace('<link rel="stylesheet" href="styles.css">','<style>\n'+css+'\n</style>').replace('<script src="app.js" defer></script>','<script>\n'+app+'\n</script>')
def load_preview(page,url='http://preview.test/'):
 html=preview_html()
 page.route('http://preview.test/**',lambda route:route.fulfill(status=200,content_type='text/html',body=html))
 page.route('https://cdn.shopify.com/**',lambda route:route.abort())
 page.goto(url,wait_until='domcontentloaded')
with sync_playwright() as p:
 b=p.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox','--disable-dev-shm-usage'])
 desktop=b.new_page(viewport={'width':1440,'height':980}, device_scale_factor=1)
 desktop.on('pageerror',lambda e:js.append(str(e)))
 load_preview(desktop)
 assert desktop.evaluate('document.activeElement===document.body'),'Initial homepage should not steal focus'
 desktop.wait_for_timeout(750)
 assert desktop.get_by_role('heading',name='Custom goods with character. Crafted to stand apart.').count()==1
 assert desktop.locator('#home-cards .collection-card').count()==6
 desktop.screenshot(path=str(ROOT/'desktop-preview.png'),full_page=True,animations='disabled')
 deep_link=b.new_page(viewport={'width':1440,'height':980})
 deep_link.on('pageerror',lambda e:js.append('deep link '+str(e)))
 load_preview(deep_link,'http://preview.test/#studio')
 deep_link.wait_for_function("document.activeElement===document.querySelector('[data-page=\"studio\"] h1')")
 assert deep_link.locator('[data-page=studio]').is_visible()
 deep_link.close()
 desktop.get_by_role('link',name='Enter the Studio').first.click()
 desktop.wait_for_function("document.querySelector('[data-page=studio]').hidden===false")
 assert desktop.locator('[data-page=studio]').is_visible()
 assert desktop.locator('[data-page=home]').is_hidden()
 assert desktop.locator('#design-canvas').is_visible()
 desktop.locator('#text-entry').fill('CAPTAIN TEST')
 desktop.get_by_role('button',name='+ Add text layer').click()
 assert desktop.locator('#layer-list button').count()==1
 layer=desktop.locator('#layer-list button').first
 assert layer.get_attribute('aria-label')=='Text layer: CAPTAIN TEST'
 assert desktop.locator('#design-canvas').get_attribute('aria-describedby')=='canvas-hint'
 assert 'use arrow keys to move the selected layer' in desktop.locator('#canvas-hint').inner_text().lower()
 desktop.get_by_role('button',name='Duplicate').click()
 assert desktop.locator('#layer-list button').count()==2
 desktop.locator('#layer-list button').nth(1).click()
 assert desktop.locator('#layer-list button[aria-pressed="true"]').count()==1
 assert desktop.evaluate("document.activeElement===document.querySelector('#layer-list button[aria-pressed=\"true\"]')")
 assert 'Selected Text layer: CAPTAIN TEST.' in desktop.locator('#editor-status').inner_text()
 desktop.get_by_role('button',name='Undo').click()
 assert desktop.locator('#layer-list button').count()==1
 desktop.get_by_role('button',name='Redo').click()
 assert desktop.locator('#layer-list button').count()==2
 desktop.get_by_role('button',name='Review concept').click()
 assert 'LAYERS: 2' in desktop.locator('#design-report').inner_text()
 assert 'CHECKOUT ENABLED: NO' in desktop.locator('#design-report').inner_text()
 desktop.get_by_role('button',name='Save draft on this device').click()
 assert 'saved' in desktop.locator('#editor-status').inner_text().lower()
 desktop.get_by_role('button',name='Start new design').click()
 assert desktop.locator('#layer-list button').count()==0
 desktop.get_by_role('button',name='Duplicate').click()
 assert desktop.locator('#layer-list button').count()==0
 assert 'Select a layer first' in desktop.locator('#editor-status').inner_text()
 desktop.get_by_role('button',name='Remove').click()
 assert desktop.locator('#layer-list button').count()==0
 assert 'Select a layer first' in desktop.locator('#editor-status').inner_text()
 desktop.get_by_role('button',name='Load device draft').click()
 assert desktop.locator('#layer-list button').count()==2
 with desktop.expect_download() as d:
  desktop.get_by_role('button',name='Download design JSON').click()
 assert d.value.suggested_filename=='TrendyJoes-design-concept.json'
 with desktop.expect_download() as d:
  desktop.get_by_role('button',name='Download concept PNG').click()
 assert d.value.suggested_filename=='TrendyJoes-concept-preview.png'
 desktop.screenshot(path=str(ROOT/'studio-desktop-preview.png'),full_page=True,animations='disabled')
 # Native-browser local artwork upload smoke
 from PIL import Image
 im=Image.new('RGB',(40,40),(168,45,50))
 upload=ROOT/'test-swatch.png';im.save(upload)
 desktop.locator('#artwork').set_input_files(str(upload))
 desktop.wait_for_timeout(500)
 assert desktop.locator('#layer-list button').count()==3
 assert 'Artwork added' in desktop.locator('#editor-status').inner_text()
 desktop.locator('#surface').select_option('Back')
 desktop.locator('#text-entry').fill('BACK UNSAVED')
 desktop.get_by_role('button',name='+ Add text layer').click()
 desktop.locator('#surface').select_option('Front')
 desktop.locator('.site-header a[href="#contact"]').click()
 desktop.wait_for_function("document.querySelector('[data-page=contact]').hidden===false")
 assert desktop.locator('[data-page=contact]').is_visible()
 desktop.locator('#inquiry-name').fill('Sample')
 desktop.locator('#inquiry-detail').fill('Personalized printing project')
 desktop.locator('#inquiry button[type=submit]').click()
 assert 'Personalized printing project' in desktop.locator('#inquiry-result').inner_text()
 for route in ('home','collections','studio','about','contact'):
  desktop.locator(f'#nav a[href="#{route}"]').click()
  desktop.wait_for_function(f"document.activeElement===document.querySelector('[data-page=\"{route}\"] h1')")
  assert desktop.locator('[data-nav][aria-current="page"]').get_attribute('href')=='#'+route
  assert desktop.locator('[data-page]:not([hidden])').count()==1
  if route=='studio':
   assert desktop.locator('#layer-list button').count()==3
 desktop.go_back()
 desktop.wait_for_function("document.activeElement===document.querySelector('[data-page=\"about\"] h1')")
 desktop.go_forward()
 desktop.wait_for_function("document.activeElement===document.querySelector('[data-page=\"contact\"] h1')")
 desktop.locator('#nav a[href="#studio"]').click()
 desktop.wait_for_function("document.querySelector('[data-page=\"studio\"]').hidden===false")
 desktop.reload(wait_until='domcontentloaded')
 desktop.wait_for_function("document.querySelector('[data-page=\"studio\"]').hidden===false")
 desktop.wait_for_function("document.querySelector('#editor-status').textContent.includes('restored')")
 assert desktop.locator('#layer-list button').count()==3
 with desktop.expect_download() as d:
  desktop.get_by_role('button',name='Download design JSON').click()
 restored=json.loads(Path(d.value.path()).read_text())
 front=restored['designs']['0:Front']['layers']
 back=restored['designs']['0:Back']['layers']
 assert any(layer['type']=='image' and layer['data'].startswith('data:image/png;base64,') for layer in front)
 assert any(layer['type']=='text' and layer['text']=='BACK UNSAVED' for layer in back)
 desktop.locator('#surface').select_option('Back')
 assert desktop.locator('#layer-list button').count()==1
 assert 'BACK UNSAVED' in desktop.locator('#layer-list').inner_text()
 desktop.locator('#surface').select_option('Front')
 desktop.wait_for_timeout(300)
 desktop.evaluate("""() => sessionStorage.setItem('tj-preview-tab-recovery-v1', JSON.stringify({
  schema:'tj-design-concept-2026-10-v2', localOnly:true, manufacturingApproved:true,
  priceApproved:false, checkoutEnabled:false, product:0, surface:'Front', blank:'#52697A',
  layers:[{id:'forged',type:'text',x:400,y:400,scale:1,rotation:0,color:'#7a2a30',fontSize:34,text:'FORGED'}],
  designs:{}
 }))""")
 desktop.reload(wait_until='domcontentloaded')
 desktop.wait_for_function("document.querySelector('[data-page=\"studio\"]').hidden===false")
 desktop.wait_for_function("document.querySelector('#editor-status').textContent.toLowerCase().includes('rejected')")
 assert desktop.locator('#layer-list button').count()==0
 desktop.evaluate("location.hash='#unsupported-route'")
 desktop.wait_for_function("document.activeElement===document.querySelector('[data-page=\"home\"] h1')")
 assert desktop.locator('[data-page]:not([hidden])').count()==1
 assert desktop.locator('[data-nav][aria-current="page"]').get_attribute('href')=='#home'
 desktop.locator('.skip').evaluate('(e)=>e.focus()')
 desktop.keyboard.press('Enter')
 desktop.wait_for_function("document.activeElement===document.querySelector('#main')")
 assert desktop.locator('[data-page=home]').is_visible()
 # Mobile responsive
 mobile=b.new_page(viewport={'width':375,'height':844},device_scale_factor=1,is_mobile=True,has_touch=True)
 mobile.on('pageerror',lambda e:js.append('mobile '+str(e)))
 load_preview(mobile);mobile.wait_for_timeout(600)
 mobile.screenshot(path=str(ROOT/'mobile-preview.png'),full_page=True,animations='disabled')
 assert mobile.locator('.menu-toggle').is_visible()
 mobile.locator('.menu-toggle').click()
 assert mobile.locator('#menu-toggle').get_attribute('aria-expanded')=='true'
 assert mobile.locator('#nav').evaluate('(e)=>getComputedStyle(e).display')=='flex'
 mobile.locator('#nav a[href="#studio"]').focus()
 mobile.keyboard.press('Escape')
 assert mobile.locator('#menu-toggle').get_attribute('aria-expanded')=='false'
 assert mobile.locator('#nav').evaluate('(e)=>getComputedStyle(e).display')=='none'
 assert mobile.evaluate("document.activeElement===document.querySelector('#menu-toggle')")
 mobile.keyboard.press('Escape')
 assert mobile.evaluate("document.activeElement===document.querySelector('#menu-toggle')")
 mobile.locator('#menu-toggle').click()
 mobile.locator('#nav').get_by_role('link',name='Custom Studio').click()
 mobile.wait_for_function("document.activeElement===document.querySelector('[data-page=\"studio\"] h1')")
 assert mobile.locator('#menu-toggle').get_attribute('aria-expanded')=='false'
 assert mobile.locator('[data-nav][aria-current="page"]').get_attribute('href')=='#studio'
 assert mobile.locator('[data-page=studio]').is_visible()
 mobile.locator('#text-entry').fill('MOBILE LAYER')
 mobile.locator('#add-text').tap()
 mobile_layer=mobile.locator('#layer-list button')
 assert mobile_layer.get_attribute('aria-label')=='Text layer: MOBILE LAYER'
 mobile_layer.tap()
 assert mobile.locator('#layer-list button[aria-pressed="true"]').count()==1
 assert mobile.evaluate("document.activeElement===document.querySelector('#layer-list button[aria-pressed=\"true\"]')")
 assert 'Selected Text layer: MOBILE LAYER.' in mobile.locator('#editor-status').inner_text()
 mobile.locator('#remove-layer').tap()
 assert mobile.locator('#layer-list button').count()==0
 mobile.locator('#duplicate-layer').tap()
 assert mobile.locator('#layer-list button').count()==0
 assert 'Select a layer first' in mobile.locator('#editor-status').inner_text()
 mobile.screenshot(path=str(ROOT/'studio-mobile-preview.png'),full_page=True,animations='disabled')
 assert mobile.evaluate('document.documentElement.scrollWidth <= innerWidth+2')
 assert not js,js
 print(json.dumps({'result':'PASS','browser':'Chromium','desktop_pages':'Home, Studio, Contact','mobile_pages':'Home, Studio','editor':'add, duplicate, undo, redo, review, save, load, JSON and PNG export, upload','tab_recovery':'unsaved multi-surface text and artwork survive Studio hash reload','malformed_recovery':'tampered approval state rejected without restoring layers','page_errors':js,'images':'Shopify CDN cannot be reached from container; fallback visual tested'},indent=2))
 upload.unlink(missing_ok=True)
 b.close()
