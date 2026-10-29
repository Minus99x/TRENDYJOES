"""End-to-end test for original TrendyJoes apparel preset gallery.
Does not create orders, contact Shopify, or assert any print calibration.
"""
from pathlib import Path
from playwright.sync_api import sync_playwright
import json

ROOT=Path(__file__).parent
html=(ROOT/'index.html').read_text().replace(
    '<link rel="stylesheet" href="styles.css">',
    '<style>'+ (ROOT/'styles.css').read_text() +'</style>'
).replace(
    '<script src="app.js" defer></script>',
    '<script>'+ (ROOT/'app.js').read_text() +'</script>'
)
assert '<script src="app.js"' not in html

with sync_playwright() as pw:
    browser=pw.chromium.launch(headless=True,executable_path='/usr/bin/chromium',
                               args=['--no-sandbox','--disable-dev-shm-usage'])
    for mobile in (False,True):
        page=browser.new_page(viewport={'width':390 if mobile else 1440,'height':844 if mobile else 960},
                              is_mobile=mobile,has_touch=mobile,accept_downloads=True)
        errors=[]
        page.on('pageerror',lambda error:errors.append(str(error)))
        page.route('https://cdn.shopify.com/**',lambda route:route.abort())
        page.route('http://preview.test/**',lambda route:route.fulfill(status=200,
                   content_type='text/html',body=html))
        page.goto('http://preview.test/#studio',wait_until='domcontentloaded')
        assert page.locator('#tj-design-cards .tj-design-card').count()==12
        assert page.locator('#tj-design-count').inner_text().startswith('Showing 12')
        for category,n in [('Funny',4),('Love',4),('Sweet',2),('Colorful',2),('All',12)]:
            page.locator('[data-design-filter="'+category+'"]').click()
            assert page.locator('.tj-design-card:visible').count()==n,(category,n)
            assert page.locator('[data-design-filter="'+category+'"]').get_attribute('aria-pressed')=='true'
        page.locator('[data-design-filter="Funny"]').click()
        page.get_by_role('button',name='Preview Snack Support Club on the currently selected product').click()
        page.wait_for_function("document.querySelector('#layer-list button')!==null")
        assert page.locator('#layer-list button').count()==1
        with page.expect_download() as downloaded:
            page.locator('#export-json').click()
        concept=json.loads(Path(downloaded.value.path()).read_text())
        assert concept['layers'][0]['type']=='image'
        assert concept['layers'][0]['data'].startswith('data:image/png;base64,')
        assert concept['manufacturingApproved'] is False
        assert concept['checkoutEnabled'] is False
        assert not errors,errors
        page.close()
    browser.close()
print('PASS: 12 original design cards, category filters, apply-to-canvas, PNG persistence, mobile, no checkout')
