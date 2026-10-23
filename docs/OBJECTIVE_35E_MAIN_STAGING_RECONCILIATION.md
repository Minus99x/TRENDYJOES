# Objective 35E — Offline Main/Night Watch staged-client reconciliation

This objective **does not** modify Shopify, either the published Horizon theme or the unpublished staging theme. It generates a separate, local, **NOT INSTALLED** candidate from verified Night Watch source v0.30.101 and the pinned Main Objective 35/36 read-back fixtures. Do not deploy it without Main Engineering reconciliation, native Shopify preview acceptance, and explicit authorization.

## Verified provenance and exact scope

- Night parent: `trendyjoes-universal-studio-v0.30.100-objective35d.zip`, SHA-256 `c12b817bc058f781d492a0aa0e51b156e1b4463df6b29048aab206661e6b7158`; 407-member CRC-verified source ZIP, Node 22.16.0 `npm test` 3841/3841 passed before edits.
- Main 35 offline source: `TRENDYJOES_MAIN_v0.35_STAGING_INTEGRATION.zip`, SHA-256 `5823ed2d8e2d2d5560ee44bb63bed41916ade5f8290a83a9ce8047b56db0ea99`; source manifests and three modified Main-specific files are pinned in `fixtures/main-staging-reconciliation/main35`.
- Main 36 snapshot: `TRENDYJOES_MAIN_OBJECTIVE36_STAGING_STATE_GUARDS.zip`; the read-back snapshot includes **two** selectively integrated state-guard assets. These two patched bytes are pinned and checked against their own manifest in `fixtures/main-staging-reconciliation/main36`.
- Reconciliation uses all **13** latest Night Watch staging client assets and preserves Main-specific **H2 heading** (to avoid a second storefront H1), **artwork tryout anchor**, and **scoped link typography/focus CSS**. All other candidate files are byte-identical to Night Watch source. Main36's 35B/35C protections are covered by the newer Night source and focused regressions; its older JS bytes are **not** blindly copied over later improvements.
- No external network, Shopify read/write, theme write, storefront integration, checkout, authenticated customer storage, manufacturing approval or real-order workflow.

## Commands

```bash
node scripts/build-main-staging-reconciliation.mjs --check
node --test tests/objective35e-main-reconciliation.test.mjs
npm test
node scripts/check-main-staging-browser.mjs  # OPTIONAL; requires functional Chromium and local loopback
```

The candidate directory is `integrations/shopify/main-staging-reconciliation-candidate/`. It includes its own immutable file-hash manifest. The builder fails closed for missing/changed Main snapshots, changed manifest provenance, unsafe paths, duplicate artwork links, unsupported commerce markup, and missing Night accessibility/review guards. All fixtures are offline snapshots; they are **not** claims about current Shopify theme contents.

## Remaining gates

Native Chromium/browser smoke in this execution environment could not start successfully (DBus/sandbox/startup timeout); do not claim browser acceptance. Main Engineering must verify exact current staging theme asset hashes and all Main-specific customizations, browser interaction across mobile/desktop, Liquid/CSP/CDN, accessibility, private artwork tryout link destination, actual customer identity/storage/checkout/manufacturing gates, and any production deployment. This candidate is a selective offline handoff only.
