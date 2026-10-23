# Objective 35G — Offline Mobile Interaction and Keyboard Focus

**Scope:** ephemeral static concept preview and uninstalled Main35/Night Watch reconciliation candidate only. No Shopify access or commerce authorization.

## User-visible defects addressed

1. The 2D and 3D static concept canvases disabled all touch scrolling (`touch-action:none`), trapping vertical mobile gestures inside a large preview region. The static preview now allows `pan-y`; horizontal gestures continue to orbit the 3D concept, while vertical touch gestures scroll the page and can cancel the pointer capture. Camera buttons remain available for users who cannot drag. The separate full editor retains its own interaction CSS.
2. A focused interactive 3D canvas advertised itself as an image. The static concept canvas now has group semantics with its existing keyboard description and tab stop. The camera help explicitly explains touch scrolling, drag direction, keyboard rotation and zoom.
3. Hiding the review panel or 3D canvas could leave keyboard focus inside an invisible region. A focused region now restores focus to a visible control before hiding. The “Continue editing” action returns focus to the wording textarea, not the add button.

## Acceptance contract

`src/offline-mobile-interaction.mjs` validates the reconciled, generated offline candidate's 2D/3D `pan-y` policy, keyboard-accessible canvas semantics, touch instructions, and review/canvas focus recovery. `scripts/check-main-staging-browser.mjs --static-check` now enforces this contract before any browser attempt. Adversarial tests mutate the candidate and exercise the actual focus helper in a minimal isolated document fixture. The optional native Chromium smoke includes review-edit focus, canvas focus recovery, touch CSS and role assertions **if it runs**.

The acceptance contract is a static regression boundary plus a minimal isolated function test, **not native mobile browser proof**, a WCAG audit, production Shopify verification, or a guarantee of touch gesture behavior across devices. Native browser acceptance remains a release gate until an actual browser run produces its harness result.

## Reproduce

```sh
node scripts/build-static-preview-assets.mjs --check
node scripts/build-staging-static-bundle.mjs --check
node scripts/build-main-staging-reconciliation.mjs --check
node scripts/check-main-staging-browser.mjs --static-check
node --test tests/objective35g-mobile-interaction.test.mjs
npm test
```

No external services, customer information, payment systems or hosted store credentials are involved.
