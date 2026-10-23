# Objective 34U — Keep unadded customer wording on its intended surface

**Offline client-only Studio v0.30.91. No Shopify access, storage, checkout, or deployment.**

## Reproduced customer defect

In v0.30.90, a customer could type wording while viewing the front of a product, change the selected surface to the back, and then click **Add lettering**. The draft remained in the composer and was committed to the *back* without warning, despite having been entered while the front was active. This was reproduced through executable DOM-event simulation before the repair. A canceled surface switch was impossible because no confirmation was requested.

## Repair

The pure `staticPreviewSurfaceDraftTransition(state, textDraft, targetSurfaceId)` decision contract validates the known product, available surfaces, selection, and composition, returning only `SAME_SURFACE`, `SAFE`, `DISCARD_CONFIRMATION_REQUIRED`, or `REJECTED`. It never returns customer text or identity. The actual surface selector event handler now requires an explicit discard confirmation whenever the temporary text composer is nonempty. Cancel restores the original surface and leaves the private wording untouched; confirmation switches the surface and clears the composer. Invalid targets restore the prior selection. Empty composers switch normally. Existing committed lettering remains attached to its original surface.

This protection applies to all configured merchandise surface types, not just shirts. It is a local customer-workflow safeguard, not authenticated server-side authorization or a manufacturing approval. The caller-controlled text draft is never transmitted, saved, or added to commerce metadata.

## Reproducible verification

Run `node --test tests/objective34u-surface-composer-boundary.test.mjs`, `npm test`, `npm run preview:assets:check`, `npm run preview:static:assets:check`, and `npm run preview:staging:check`. The 34U suite includes pure-contract adversarial cases and simulated real editor DOM events. It is **not** a native browser/assistive-tech acceptance test. Main Engineering must selectively integrate source changes and rebuild generated assets against its own unpublished staging source; never replace its customized theme with this offline candidate.
