# Objective 34I — Offline staging-safe static preview bundle

This is a **generated, reviewable candidate** for Main Engineering. It is not a Shopify theme installation, real hosted test, customer authentication, persistent design store, commerce function, manufacturing proof, or production release. Night Watch makes **NO Shopify writes**.

## Integration deliverables

Run `npm run preview:staging:build` to deterministically generate the files under `integrations/shopify/staging-static-preview/`. Run `npm run preview:staging:check` to fail if any generated asset or SHA-256 inventory differs from its source. Generated bundle includes 12 flat `.js` / `.css` files and `sections/tj-static-preview-34i.liquid`, with a 13-entry integrity manifest. The source static demo remains unchanged.

The adapter rewrites local ESM imports to flat, same-directory JavaScript theme assets and converts `.mjs` to `.js` for theme compatibility. It rejects external, missing, traversal, and dynamic imports. CSS selectors are scoped to `#tj34i-root`, including nested mobile media queries; all DOM IDs and their label/ARIA references are prefixed with `tj34i-`. The generated section uses `asset_url` for the two stylesheets and entry module, with one-section limit. All links and preview capabilities remain non-purchasing. Source hashes are checked against the verified 34H static asset inventory before generation.

## Main Engineering acceptance — NOT yet performed

1. Verify source SHA and compare this candidate with Main v0.32 and the actual unpublished staging theme; resolve any naming or CSS conflicts before any staging edit.
2. Verify Shopify accepts the generated theme asset extensions and ESM imports, serves all files with valid MIME types, and compiles the generated Liquid section. Relative module imports assume the theme asset CDN serves flat files at a shared path; this must be verified on actual staging, not inferred from Node tests.
3. Preview homepage -> product concept -> text edit -> 2D/3D -> review at 390/768/1440px, keyboard/mobile interaction, confirmation on product change, no network writes and no checkout. Verify one-section-only installation and inspect Horizon header conflicts.
4. Retain explicit warnings: no uploads, GLB import, authenticated saved drafts, inventory, manufacturing approval, payment, or checkout in this static demo. Full local editor capabilities remain in the original offline application, not this restricted theme candidate.
5. Do not modify published Horizon, activate products, upgrade trial, enable checkout, access customers, or deploy without the Captain's separate authorization.

## Reproduce

```sh
sha256sum trendyjoes-universal-studio-v0.30.79-objective34i.zip
unzip -tq trendyjoes-universal-studio-v0.30.79-objective34i.zip
npm run preview:static:assets:check
npm run preview:staging:check
node --test tests/objective34i-staging-static-bundle.test.mjs
npm test
```

No actual Shopify preview or browser acceptance is claimed. This candidate is strictly offline and must be evaluated by Main Engineering before any staging integration.
