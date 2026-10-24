from playwright.sync_api import sync_playwright
from pathlib import Path
import json
ROOT=Path(__file__).parent
js=[]
with sync_playwright() as p:
 b=p.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox','--disable-dev-shm-usage'])
 desktop=b.new_page(viewport={'width':1440,'height':980}, device_scale_factor=1)
 desktop.on('pageerror',lambda e:js.append(str(e)))
 desktop.set_content((ROOT/'TrendyJoes_Approved_Interactive_Preview.html').read_text(),wait_until='domcontentloaded')
 desktop.wait_for_timeout(750)
 assert desktop.get_by_role('heading',name='Custom goods with character. Crafted to stand apart.').count()==1
 assert desktop.locator('#home-cards .collection-card').count()==6
 desktop.screenshot(path=str(ROOT/'desktop-preview.png'),full_page=True,animations='disabled')
 desktop.get_by_role('link',name='Enter the Studio').first.click()
 assert desktop.locator('[data-page=studio]').is_visible()
 assert desktop.locator('[data-page=home]').is_hidden()
 assert desktop.locator('#design-canvas').is_visible()
 desktop.locator('#text-entry').fill('CAPTAIN TEST')
 desktop.get_by_role('button',name='+ Add text layer').click()
 assert desktop.locator('#layer-list button').count()==1
 desktop.get_by_role('button',name='Duplicate').click()
 assert desktop.locator('#layer-list button').count()==2
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
 desktop.locator('.site-header a[href="#contact"]').click()
 print('CONTACT DEBUG',desktop.evaluate('location.href'),desktop.locator('[data-page=home]').is_visible(),desktop.locator('[data-page=studio]').is_visible(),desktop.locator('[data-page=contact]').is_visible()); desktop.wait_for_timeout(300); assert desktop.locator('[data-page=contact]').is_visible()
 desktop.locator('#inquiry-name').fill('Sample')
 desktop.locator('#inquiry-detail').fill('Personalized printing project')
 desktop.locator('#inquiry button[type=submit]').click()
 assert 'Personalized printing project' in desktop.locator('#inquiry-result').inner_text()
 # Mobile responsive
 mobile=b.new_page(viewport={'width':390,'height':844},device_scale_factor=1,is_mobile=True,has_touch=True)
 mobile.on('pageerror',lambda e:js.append('mobile '+str(e)))
 mobile.set_content((ROOT/'TrendyJoes_Approved_Interactive_Preview.html').read_text(),wait_until='domcontentloaded');mobile.wait_for_timeout(600)
 mobile.screenshot(path=str(ROOT/'mobile-preview.png'),full_page=True,animations='disabled')
 assert mobile.locator('.menu-toggle').is_visible()
 mobile.locator('.menu-toggle').click()
 assert mobile.locator('#nav').evaluate('(e)=>getComputedStyle(e).display')=='flex'
 mobile.locator('#nav').get_by_role('link',name='Custom Studio').click()
 mobile.wait_for_timeout(350);print('MOBILE DEBUG',mobile.evaluate('location.href'),mobile.locator('[data-page=studio]').is_visible());assert mobile.locator('[data-page=studio]').is_visible()
 mobile.screenshot(path=str(ROOT/'studio-mobile-preview.png'),full_page=True,animations='disabled')
 assert mobile.evaluate('document.documentElement.scrollWidth <= innerWidth+2')
 assert not js,js
 print(json.dumps({'result':'PASS','browser':'Chromium','desktop_pages':'Home, Studio, Contact','mobile_pages':'Home, Studio','editor':'add, duplicate, undo, redo, review, save, load, JSON and PNG export, upload','page_errors':js,'images':'Shopify CDN cannot be reached from container; fallback visual tested'},indent=2))
 upload.unlink(missing_ok=True)
 b.close()
