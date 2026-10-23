# Objective 34P — Review readiness and multi-surface accuracy

Offline customer-experience repair. Reproduced on v0.30.85: the review button was enabled with no layers even though the review contract rejected an empty design with `INVALID_LAYERS`. A front/back design review also gave only a total count and surface names, not the number of lettering elements on each surface.

The new pure `staticPreviewReviewAvailability` projects only `ready` and an allowlisted reason, fail-closing malformed and private-artwork states. The standalone and generated staging UI disable review when not eligible and display a visible, accessible hint. Valid reviews include redacted per-surface counts in manifest order; no wording, artwork, customer ID, price, or order details are included. Changes are local static preview only. Full editor, 2D/3D, GLB, calibration, and manufacturing contracts are untouched. No Shopify write, hosted auth, checkout, or production acceptance.

Reproduce: `node --test tests/objective34p-review-readiness.test.mjs`; `npm test`; `npm run preview:assets:check`; `npm run preview:static:assets:check`; `npm run preview:staging:check`.
