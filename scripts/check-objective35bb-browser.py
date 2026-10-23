"""Real Chromium negative test: insecure offline about:blank refuses SHA operations.
No mock, injected digest or network request; this is NOT secure-origin acceptance.
"""
from pathlib import Path
from playwright.sync_api import sync_playwright
import struct,json
root=Path(__file__).resolve().parent.parent
# Reuse the same in-memory offline editor module loader, without any crypto stub.
exec((root/'scripts/check-objective35at-browser.py').read_text().split('with sync_playwright() as p:')[0],globals())
# The fixture builder is extracted from the source without executing its browser run.
source=(root/'scripts/check-objective35ba-browser.py').read_text()
exec('def make_glb():'+source.split('def make_glb():')[1].split('def setup(page):')[0],globals())
with sync_playwright() as p:
 browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox','--disable-background-networking'])
 page=browser.new_page(accept_downloads=True)
 errors=[];requests=[];downloads=[]
 page.on('pageerror',lambda e:errors.append(str(e)))
 page.on('request',lambda r:requests.append(r.url) if r.url.startswith('http') else None)
 page.on('download',lambda d:downloads.append(d.suggested_filename))
 page.on('dialog',lambda d:d.accept())
 setup(page)
 check('35BB_TRUE_INSECURE_CONTEXT',page.evaluate('!isSecureContext && !crypto.subtle'))
 page.locator('#mode-2d').click()
 page.locator('#text-entry').fill('TEST SENSITIVE USER CONTENT')
 page.locator('#add-text').click()
 page.locator('#download-concept-evidence').click()
 page.wait_for_function('document.getElementById("concept-evidence-status").textContent.includes("CONCEPT_EVIDENCE_SECURE_CONTEXT_REQUIRED")',timeout=9000)
 check('35BB_EXPORT_REFUSED','CONCEPT_EVIDENCE_SECURE_CONTEXT_REQUIRED' in page.locator('#concept-evidence-status').inner_text())
 check('35BB_EXPORT_BUTTON_RECOVERS',page.locator('#download-concept-evidence').is_enabled())
 page.locator('#download-concept-review').click()
 page.wait_for_function('document.getElementById("concept-review-status").textContent.includes("CONCEPT_EVIDENCE_SECURE_CONTEXT_REQUIRED")',timeout=9000)
 check('35BJ_REVIEW_REFUSED','CONCEPT_EVIDENCE_SECURE_CONTEXT_REQUIRED' in page.locator('#concept-review-status').inner_text())
 check('35BJ_REVIEW_CONTROL_RECOVERS',page.locator('#download-concept-review').is_enabled())
 page.locator('#model-file').set_input_files({'name':'model.glb','mimeType':'model/gltf-binary','buffer':make_glb()})
 page.wait_for_function('document.getElementById("model-import-summary").textContent.includes("GLB_SECURE_CONTEXT_REQUIRED")',timeout=9000)
 check('35BB_MODEL_REFUSED','GLB_SECURE_CONTEXT_REQUIRED' in page.locator('#model-import-summary').inner_text())
 check('35BB_NO_MODEL_ACTIVATED',page.locator('#clear-model').is_disabled())
 check('35BB_NO_FILE_DOWNLOADED',not downloads)
 check('35BB_CHECKOUT_DISABLED',page.locator('.disabled-checkout').is_disabled())
 check('35BB_NO_RUNTIME_ERRORS',not errors)
 check('35BB_NO_HTTP',not requests)
 summary={'pass':sum(x['pass'] for x in results),'fail':sum(not x['pass'] for x in results),'checks':results,'pageErrors':errors,'externalRequests':requests,'secureContext':False}
 print(json.dumps(summary,indent=2));browser.close()
 assert summary['fail']==0
