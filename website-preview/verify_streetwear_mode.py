"""Chromium acceptance for the real 48-look, embedded-SVG streetwear mode.

Tests rendered SVGs, browse/filter, paired preview and local downloads.
Does not contact Shopify or imply production approval.
"""
from pathlib import Path
import json
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).parent
HTML=(ROOT/'streetwear-mode.html').read_text(encoding='utf-8')
INDEX=(ROOT/'index.html').read_text(encoding='utf-8')
assert 'href="streetwear-mode.html"' in INDEX
assert 'NO CHECKOUT' in HTML
assert HTML.count('data:image/svg+xml;charset=utf-8')==96

with sync_playwright() as pw:
    browser=pw.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox','--disable-dev-shm-usage'])
    for mobile in (False,True):
        page=browser.new_page(viewport={'width':390 if mobile else 1440,'height':844 if mobile else 960},
                              is_mobile=mobile,has_touch=mobile,accept_downloads=True)
        errors=[]
        page.on('pageerror',lambda err:errors.append(str(err)))
        page.set_content(HTML,wait_until='domcontentloaded')
        page.locator('.look').first.wait_for()
        assert page.locator('.look').count()==48
        assert page.locator('.look img.shirt-design').count()==96
        assert page.locator('.look img.shirt-design').first.evaluate('(img)=>img.complete && img.naturalWidth>0')
        page.locator('[data-filter="night"]').click()
        assert page.locator('.look').count()==24
        page.locator('[data-filter="all"]').click()
        page.locator('#search').fill('I FORGOT TO CARE')
        assert page.locator('.look').count()==2
        page.get_by_role('button',name='Customize I FORGOT TO CARE. garage shirt').click()
        assert page.locator('#modal-pair img').count()==2
        assert page.locator('#modal-pair img').first.evaluate('(img)=>img.complete && img.naturalWidth>0')
        page.locator('#swatches button').nth(2).click()
        assert page.locator('#swatches button').nth(2).get_attribute('aria-pressed')=='true'
        page.locator('#front-scale').fill('120')
        page.locator('#custom-text').fill('MY OWN WORDING')
        assert page.locator('#modal-pair').get_by_text('MY OWN WORDING').count()==1
        with page.expect_download() as saved:
            page.locator('#brief').click()
        brief=json.loads(Path(saved.value.path()).read_text())
        assert brief['sku']=='M04-A'
        assert brief['front_scale_percent']==120
        assert brief['extra_wording']=='MY OWN WORDING'
        assert brief['manufacturing_approved'] is False
        assert brief['checkout_enabled'] is False
        with page.expect_download() as source:
            page.locator('#front-download').click()
        assert source.value.suggested_filename=='M04-A-FRONT.svg'
        assert '<svg' in Path(source.value.path()).read_text()
        page.locator('#close').click()
        assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth+1')
        assert not errors,errors
        page.close()
    browser.close()
print('PASS: 48 paired streetwear looks, SVG source, style/search, customizer, downloads, desktop/mobile, no checkout')
