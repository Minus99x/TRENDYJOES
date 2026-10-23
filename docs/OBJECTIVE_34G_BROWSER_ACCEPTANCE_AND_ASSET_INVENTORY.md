# Objective 34G — local browser acceptance and deterministic asset inventory

**Scope:** OFFLINE PREVIEW ONLY. Nothing here is a Shopify theme, hosted editor, production security decision, customer authentication, manufacturing approval, cart, checkout, or public deployment.

## Actual engineering changes

- `demo/browser-acceptance.mjs` is an explicit loopback-only, opt-in browser DOM acceptance harness. It exercises the real editor's product controls, 2D/3D toggle, product selection, synthetic text layer, privacy-safe design review, review invalidation, disabled checkout and opt-in-only session recovery. It cleans up its synthetic design without uploading, saving, or transmitting it. The report is exposed as `window.__TJ_BROWSER_ACCEPTANCE__` and displayed in-page. **No browser execution is claimed until an actual browser reports PASS.**
- `src/preview-asset-manifest.mjs` and `scripts/build-preview-asset-manifest.mjs` enumerate and SHA256-hash the browser dependency graph, including a literal dynamic import. They fail closed on nonlocal or unbounded imports, unsupported files, symlinks, missing modules, path escapes, or changed bytes.
- `integrations/shopify/preview-asset-manifest.json` is an **offline handoff inventory**, not an installed Shopify asset. It explicitly declares that the existing editor uses loopback APIs for private drafts and artwork. Copying the assets to Shopify would NOT create a functional hosted service or secure customer account.

## Reproduction

```bash
npm run preview:assets:check
node --test tests/objective34g-browser-acceptance-assets.test.mjs
npm test
npm run serve
```

With the local server running, open `http://127.0.0.1:8000/demo/?tj_acceptance=1` in a genuine interactive browser. The page should show an opt-in acceptance panel with **7/7 PASS** if the actual DOM interactions succeed. Inspect `window.__TJ_BROWSER_ACCEPTANCE__` in the browser console. The browser harness is not run by `npm test`; Node tests verify the static asset graph, exact HTTP bytes, opt-in wiring and fail-closed packaging boundaries, not real browser interaction.

The editor is an offline prototype and intentionally has no live Shopify product or order route. The local API may issue local-only owner tokens for synthetic draft tests; **never expose it on the public internet or use it as a production backend**.

## Main Engineering handoff and actual launch blockers

Main Engineering should compare this inventory with the latest Main v0.32 source and staging theme before integration. First demonstrate the complete local editor interaction in an actual browser, then design a proper hosted-preview deployment with safe server-side authentication, durable private storage and origin protections. A Shopify theme cannot directly host the existing loopback Node backend. Build or select a separately authorized hosted service before enabling customer accounts or saved designs. Main should perform native Shopify staging preview on 390/768/1440 widths and record exact routes, theme compilation, keyboard/focus and accessibility evidence. Leave preview gateway links disabled until a real editor route exists and works.

No Shopify read/write, product change, theme edit, trial upgrade, paid install, customer data, checkout, deployment or production authorization occurred in Night Watch Objective 34G.
