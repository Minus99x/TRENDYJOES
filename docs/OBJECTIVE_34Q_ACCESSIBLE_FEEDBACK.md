# Objective 34Q — accessible customer feedback, surface context and safe input recovery

Scope: **offline, ephemeral, non-purchasing static Design Works preview only**. This objective builds on verified v0.30.86 Objective 34P and does not touch Shopify, Main Engineering's published/unpublished themes, customer accounts or other projects.

## Reproduced gaps in parent source

1. The 2D silhouette and keyboard-focusable 3D canvas had static generic accessible labels. A nonvisual customer could not determine the active front/back design surface or how many lettering layers were present from either preview's accessible description.
2. Every editor rerender reset the polite live status to the same generic "nothing saved" text. Adding wording, changing surfaces, removing lettering and switching modes had no distinct outcome announcement.
3. An invalid wording attempt exposed internal exception codes in the live status but did not mark the textarea invalid, explain how to recover or return focus to the input.

## Implemented changes

- `staticPreviewAccessibilitySummary(state)` derives a safe description from **approved product/surface labels, counts, current mode and selected-layer ordinal**. It never projects raw wording, layer IDs, artwork, identity or variants. Malformed, cross-surface selected or forged states fail closed to a neutral description.
- The 2D SVG and keyboard-focusable 3D canvas reference a visually hidden shared description through `aria-describedby`; the 3D canvas retains its existing camera help. The summary is **not** a live region, preventing redundant announcements during continuous slider movement.
- `staticPreviewActionAnnouncement(action,state)` provides finite, safe status updates for customer actions. Rotation and scaling deliberately return `null`: native range input value changes are already available to assistive technology and should not trigger repeated generic announcements.
- `staticPreviewErrorAnnouncement(error)` maps invalid wording, layer limits and out-of-bounds edits to actionable text without exposing internal exception strings or customer-supplied values. Invalid wording marks the textarea `aria-invalid`, exposes a visible hint and returns focus; correcting the input clears the error state.
- Regenerated all deterministic static/staging asset manifests and scoped integration assets. This is a **candidate only**, not a deployment or native Shopify acceptance.

## Safety and Main Engineering integration

No fetch, customer storage, credentials, uploads, carts, checkout or Shopify writes. The 2D/3D editor, model imports, calibration, manufacturing geometry and all conceptual merchandise categories remain intact. Main Engineering Objective 35 already staged a customized v0.30.85 bundle, including a single-H1 adjustment and legacy 2D artwork fallback. **Do not replace those staged files wholesale** with this offline candidate. Reconcile the new accessibility changes against the actual staging version and independently test native Shopify CDN/CSP/Liquid and assistive technology before any staged updates. Main Engineering owns staging; Captain owns release decisions.

## Verification

Run `node --test tests/objective34q-accessible-workflow.test.mjs`, `npm test`, and the three `npm run preview:*:check` scripts. Browser automation was attempted with headless Chromium but returned exit 124 without DOM; no interactive browser acceptance is claimed.
