# Objective 35R — cancellation-safe local editor results

**Scope:** Offline Universal Studio v0.30.114, no Shopify access or deployment. This is a browser-side correctness boundary, not hosted authentication, private cloud storage, checkout authority, or manufacturing approval.

## Defect and correction

The previous artwork upload handler read `state.surface`, `state.product`, and variant *after* an asynchronous `/api/artworks` response. Switching product/surface/variant, clearing a preview, reopening a private receipt, or starting a newer file operation while the old request was pending could attach the old upload and its local grant to the wrong on-screen design. Rejected geometry could also leave an unused grant/blob URL in the editor. The GLB import and local save completion handlers had analogous stale-result hazards: an older model could replace the current preview or an old private draft owner token could be bound to a newly selected product.

`src/preview-editor-async-gate.mjs` now issues single-use, in-memory operation tickets bound to product manifest, surface, selected offline variant, saved reference, and revision. It refuses stale, substituted, replayed, getter-backed, or cross-operation tickets. All normal editor renders, explicit variant changes, and private-receipt opening invalidate pending operations. `demo/studio.mjs` guards artwork uploads, GLB imports, and local save completions before mutation. Artwork upload receipts are validated against the local test service's exact response schema, media type, byte count, and safe identity/grant format; rejected placement revokes its blob URL and removes its grant from memory.

The gate deliberately does **not** cancel or erase a server-side upload/save that may already have completed; it only prevents stale browser state changes. The local development service has no DELETE artwork route, so an orphan upload may persist in disposable local test storage. Real lifecycle/retention policy remains an external production gate.

## Adversarial verification

`tests/objective35r-editor-async-binding.test.mjs` exercises the **actual extracted event-handler code** in an isolated, stubbed DOM/network environment; this is not a native browser run. It tests successful matching commits, stale product/surface/variant/model/save results, replay and ABA protection, strict artwork receipt validation, grant non-retention, rejected placement URL revocation, and duplicate artwork ID protection. Existing v0.5+ geometry, 2D/3D, model import/calibration, and multi-design review code remains in place.

## Reproduction

```sh
node --version
node --test tests/objective35r-editor-async-binding.test.mjs
node --test tests/objective35p-async-review-transition.test.mjs tests/objective35q-dom-focus-and-review.test.mjs tests/objective35r-editor-async-binding.test.mjs
npm test
node scripts/build-preview-asset-manifest.mjs --check
node scripts/build-static-preview-assets.mjs --check
node scripts/build-staging-static-bundle.mjs --check
node scripts/build-main-staging-reconciliation.mjs --check
node scripts/check-main-staging-browser.mjs --static-check
```

## Unresolved gates

Actual native Chromium/browser event acceptance, screen readers, production owner authentication, durable private artwork storage/retention, manufacturer-approved print-zone/GLB geometry, authoritative prices/catalog, and real cart/checkout/order integration are **NOT VERIFIED**. Shopify reads/writes: **ZERO**. Main Engineering Objective37 independently corrected its UNPUBLISHED staging Concept Lab artwork clipping and load cancellation. This offline full-Studio patch does not modify or supersede that installed source. Main Engineering must explicitly reconcile both workstreams before any staging integration; this release is not installed.
