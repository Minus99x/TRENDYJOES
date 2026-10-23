# Objective 35F — Offline Main/Night DOM Acceptance

This is a local-only pre-browser and pre-Main-acceptance contract, **not** hosted
Shopify, native browser, checkout, authentication, customer storage or production
acceptance. No storefront writes are performed.

The v0.30.102 source adds `validateOfflineMainDom` and
`verifyOfflineMainAssetBytes` to independently check the pinned 13-asset
Main35/Night35E reconciliation candidate before a browser smoke run. The
contract checks 44 unique DOM IDs, 14 local label/ARIA references, one
explicit Main artwork anchor, two stylesheets, one local module, 2D/3D
surfaces, disabled initial review/checkout, no commerce forms or file inputs,
no unexpected Liquid, no inline handlers, and no remote CSS references.
The Main artwork anchor `#tj-try-studio` is intentionally *external to this
section* and must be verified in Main's actual storefront separately.

The optional browser harness now checks source-versus-disk candidate bytes
before serving and uses a loopback-only server, deny-by-default CSP,
no-network directives and malformed-URL rejection. A static acceptance
command is available even when native Chromium cannot launch:

```sh
node scripts/check-main-staging-browser.mjs --static-check
node --test tests/objective35f-offline-dom-acceptance.test.mjs
node scripts/build-main-staging-reconciliation.mjs --check
npm test
```

The static command explicitly prints `NATIVE_BROWSER_NOT_RUN`; it is not a
browser substitute. The optional native smoke remains:

```sh
node scripts/check-main-staging-browser.mjs
```

Main Engineering must independently verify its current staging assets and
artwork anchor, perform actual browser/mobile QA, and explicitly approve any
integration. Never blindly install the candidate, and never modify the live
Horizon theme or unpublished staging from Night Watch.
