# Objective 34S — Preserve customer intent when switching concept products

**Offline only · v0.30.89 · no Shopify writes, hosted identity, durable storage or checkout.**

## Reproduced defect

The previous client-side discard guard considered only committed lettering layers and typed-but-unadded text. A customer could change the illustrative color or size of a concept product, then change products or select **Clear design** without being warned. At the source-contract boundary, `SELECT_PRODUCT` also accepted a product substitution without `confirmed:true` when there were no text layers, even if color/size selections differed from defaults.

## Repair

`staticPreviewHasPendingWork(state,textDraft)` now detects changed color and size against the exact product manifest's default selection. It preserves the existing private-text and layer guards and fails closed on malformed or unknown product/option state. The `SELECT_PRODUCT` contract enforces explicit confirmation for option-only work; the existing product selector and Clear design controls already use the shared guard and retain their cancel behavior. Reverting selections to defaults avoids unnecessary confirmation. 2D/3D view mode alone is not customer personalization.

This is a local customer-experience protection, **not** authorization or production state management. It never saves or transmits options or customer text. Product options remain illustrative, not inventory or verified variants. Main Engineering must selectively reconcile with its independently modified unpublished staging integration; do not replace the existing theme.

## Verification

`node --test tests/objective34s-option-discard-guard.test.mjs` (19 focused cases); `npm test` (complete suite); `npm run preview:assets:check`, `npm run preview:static:assets:check`, `npm run preview:staging:check` after deterministic offline asset rebuild. Native browser, Liquid compilation, CDN/CSP, production manufacturing, customer storage and real checkout remain unverified.
