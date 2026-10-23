# Objective 35K — Local multi-design customer review (offline prototype)

Version 0.30.107. This objective adds a functioning, opt-in, multi-product saved-design review to the **loopback-only** Studio editor. It does not create Shopify carts, orders, receipts, payments, or manufacturing approvals.

## Actual customer interaction

1. In the local editor, select an eligible draft template from the offline snapshot, add a valid design, and save it privately to the local test server.
2. Choose **Add this saved design to review list**. This action captures the exact saved reference, immutable revision, product/variant snapshot binding, and a private local owner capability in **tab memory only**. It does not persist the capability in the DOM or browser storage.
3. Switch products, create and save another design, then add it. The review list supports up to 25 distinct saved references. A checkbox can exclude a draft; Remove and Forget discard its local grant from the review list.
4. With at least two selected designs, choose **Recheck selected saved designs · no purchase**. The editor calls only its loopback `/api/shopify/cart-readiness` API for each saved revision, twice. It rejects stale revisions, changed bindings, mismatched local owners, forged approval fields, tampered checks, and selection changes during asynchronous work. It renders only an allowlisted, non-authorizing result and moves focus to an accessible status region.
5. The existing recovery-receipt flow can reopen a private local draft; the user must explicitly add the recovered saved revision to the list. No private receipt is stored in the review UI.

## Security properties and limits

- The review controller is intentionally **not** an order coordinator. It never calls the offline synthetic lineage commit APIs, and never issues/consumes a cart receipt or nonce. The UI has no enabled checkout controls.
- Private local owner capabilities are kept in a closure and sent only as an Authorization header to the loopback readiness endpoint; they are excluded from visible text, the returned review, and local/session storage.
- Strict input and response allowlists reject unknown authorization flags and all implied production readiness. Two passes check for changes across sequential reads; this is **not an atomic snapshot** and cannot substitute for trusted server-side checkout/order CAS.
- Only saved revisions with an offline catalog product/variant binding may enter the review list. The offline draft snapshot is not a current saleable Shopify catalog.
- Browser acceptance in a real mobile browser, hosted authentication, production asset storage, current catalog/price verification, approved print geometry, calibrated GLB models, and real checkout remain unverified.

## Reproduce

`node --test tests/objective35k-multidesign-customer-review.test.mjs`

`npm test`

`node scripts/build-preview-asset-manifest.mjs --check`

`node scripts/build-static-preview-assets.mjs --check`

`node scripts/build-staging-static-bundle.mjs --check`

`node scripts/build-main-staging-reconciliation.mjs --check`

All operations are offline or local loopback. Do not install this release or its static staging candidate into Shopify without Main Engineering review and explicit Captain approval.
