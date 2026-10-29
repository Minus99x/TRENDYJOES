"""Browser regression for the standalone 48-look source module.

The hosted source intentionally does not include binary transfers yet; the owner
ZIP contains 288 real DTF/UV/SVG files. This test checks behavior and layout,
not image hosting, print or checkout readiness.
"""
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).parent
PAGE=(ROOT/'streetwear-mode-source.html').read_text(encoding='utf-8')
assert 'NO CHECKOUT' in PAGE or 'NOT LIVE FOR PURCHASE' in PAGE
assert 'const collection=JSON.parse' in PAGE

with sync_playwright() as pw:
    browser=pw.chromium.launch(headless=True,executable_path='/usr/bin/chromium',
                              args=['--no-sandbox','--disable-dev-shm-usage'])
    for mobile in (False,True):
        page=browser.new_page(viewport={'width':390 if mobile else 1440,'height':844 if mobile else 900},
                             has_touch=mobile,is_mobile=mobile,accept_downloads=True)
        errors=[]
        page.on('pageerror',lambda error:errors.append(str(error)))
        page.set_content(PAGE,wait_until='domcontentloaded')
        assert page.locator('.look-card').count()==48
        assert page.locator('#selected-code').inner_text()=='M04-A'
        page.locator('[data-style="night"]').click()
        assert page.locator('.look-card').count()==24
        page.locator('[data-style="all"]').click()
        page.locator('#search').fill('WHO ASKED?')
        assert page.locator('.look-card').count()==2
        page.locator('[data-code="M01-A"] .choose-look').click()
        assert page.locator('#selected-code').inner_text()=='M01-A'
        assert page.locator('#download-front').get_attribute('href').endswith('M01-A-FRONT_900x900.png')
        assert page.locator('#download-back').get_attribute('href').endswith('M01-A-BACK_3600x4500.png')
        page.locator('[data-look="B"]').click()
        assert page.locator('#selected-code').inner_text()=='M01-B'
        page.locator('#shirt-options [data-shirt="hoodie"]').click()
        assert page.locator('.garment-detail').count()==2
        page.locator('[data-color="bone"]').click()
        assert page.locator('#color-name').inner_text()=='Vintage bone'
        page.locator('[data-surface="back"]').click()
        page.locator('#scale').fill('120')
        assert 'scale(1.2)' in page.locator('#studio-back').get_attribute('style')
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
        assert not errors,errors
        page.close()
    browser.close()
print('PASS: separate streetwear source gallery and local concept controls desktop/mobile; NO print asset hosting claimed')
