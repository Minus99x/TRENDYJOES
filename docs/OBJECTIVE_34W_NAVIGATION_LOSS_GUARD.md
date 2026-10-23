# Objective 34W — Unsaved navigation-loss guard (offline)

## Customer defect
The static Design Works preview intentionally has no storage. A customer could add temporary lettering, type unadded private wording, or change a concept color/size and then accidentally refresh, close, or navigate away without an attempted warning. In-page product/surface/reset actions already had discard guards, but browser navigation did not.

## Repair
The actual static preview registers a browser `beforeunload` handler. It calls the existing fail-closed `staticPreviewHasPendingWork` guard with the current ephemeral state and composer value. It requests the browser's generic native navigation confirmation only when unsaved lettering, unadded wording, or changed illustrative options exist. The handler never embeds wording, tokens, or identifiers in the event or stores/transmits data. Empty/default previews and mode-only exploration do not request confirmation. Clearing the concept or a confirmed product change removes the pending-work condition.

## Acceptance and limitations
Adversarial DOM tests exercise every conceptual merchandise family, pristine versus dirty transitions, color-only and size-only work, whitespace-only drafts, reset, confirmed/cancelled product changes, and absence of private content in the event. Generated offline staging assets are rebuilt and checked. Native browser dialogs are **not guaranteed**: user activation, browser settings, mobile OS tab termination, crashes and forced closure can suppress `beforeunload`. This feature is a best-effort loss warning, not persistence, recovery, hosted acceptance, or an authorization mechanism.

No Shopify reads/writes, no external network, no local/session storage, no customer data, no checkout or production deployment. Main Engineering must selectively reconcile the change with its current unpublished staging work.
