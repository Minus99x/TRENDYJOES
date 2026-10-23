"""35AX browser acceptance of explicit local concept export. No Shopify, purchases, or network."""
from pathlib import Path
from playwright.sync_api import sync_playwright
import json,re,sys
root=Path(__file__).resolve().parent.parent
exec((root/'scripts/check-objective35at-browser.py').read_text().split('with sync_playwright() as p:')[0].replace('results=[]','results=[]'),globals())
with sync_playwright() as p:
 browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox','--disable-background-networking'])
 page=browser.new_page(accept_downloads=True,viewport={'width':1280,'height':850})
 errs=[];requests=[]
 page.on('pageerror',lambda e:errs.append(str(e)))
 page.on('request',lambda r:requests.append(r.url) if r.url.startswith('http') and not r.url.startswith('https://offline.invalid/') else None)
 page.on('dialog',lambda d:d.accept())
 setup(page)
 # about:blank is not a secure browser origin here, so WebCrypto is unavailable.
 # UI/DOM/download flow is tested with an explicit digest stub. Real SHA-256
 # is separately verified in Node tests; this is NOT browser crypto proof.
 page.evaluate('''()=>Object.defineProperty(crypto,'subtle',{configurable:true,value:{digest:async()=>new Uint8Array(32).buffer}})''')
 check('35AX_EDITOR_LOADED',page.locator('#product option').count()>=8)
 check('35AX_PRIVATE_EXPORT_CONTROL',page.locator('#download-concept-evidence').count()==1)
 check('35AX_CHECKOUT_BLOCKED',page.locator('.disabled-checkout').is_disabled())
 page.locator('#download-concept-evidence').click()
 check('35AX_EMPTY_DESIGN_REFUSED','Concept export refused' in page.locator('#concept-evidence-status').inner_text())
 page.locator('#mode-2d').click()
 page.locator('#text-entry').fill('PRIVATE CUSTOMER TEXT 123')
 page.locator('#add-text').click()
 with page.expect_download(timeout=8000) as d:
  page.locator('#download-concept-evidence').click()
 dl=d.value;name=dl.suggested_filename
 check('35AX_LOCAL_DOWNLOAD_FILENAME',name=='trendyjoes-private-concept-evidence.json')
 saved=root/'demo'/'temporary-local-35ax-evidence.json'
 dl.save_as(saved)
 raw=saved.read_text();saved.unlink()
 packet=json.loads(raw)
 check('35AX_REDACTED_TEXT','PRIVATE CUSTOMER TEXT 123' not in raw and 'TEXT_REDACTED' in raw)
 check('35AX_NOBUY',packet['checkoutEnabled'] is False and packet['manufacturingApproved'] is False and packet['orderId'] is None)
 check('35AX_STUB_DIGEST_SHAPE',bool(re.fullmatch('[0-9a-f]{64}',packet['integrity']['digestSha256'])))
 check('35AX_DIGEST_BYTES',packet['integrity']['bytes']>0)
 check('35AX_SCREENREADER_STATUS','Private redacted concept evidence downloaded' in page.locator('#concept-evidence-status').inner_text())
 check('35AX_3D_PREVIEW_UNCHANGED',page.locator('#mode-3d').is_enabled())
 check('35AX_NO_PAGE_ERRORS',not errs)
 check('35AX_NO_EXTERNAL_HTTP',not requests)
 print(json.dumps({'pass':sum(v['pass'] for v in results),'fail':sum(not v['pass'] for v in results),'total':len(results),'pageErrors':errs,'externalRequests':requests,'results':results},indent=2))
 browser.close()
 assert all(v['pass'] for v in results)
