# Objective 35S — Offline private-receipt rollback and interrupted save isolation

**Scope:** Universal Studio local development preview only; no Shopify network access, deployment, real customer storage, or checkout authority.

## Defects addressed

1. The private receipt reopen handler previously revoked all existing artwork object URLs before it normalized the incoming selection, constructed the saved snapshot, and rendered the replacement. An exception during normalization or rendering could leave a partly replaced design, destroy existing artwork URLs, or strand the wrong owner grant in memory.
2. The handler trusted a receipt's reference without verifying that the loopback server's returned saved design carried the same reference **and exact revision**. A receipt for an old revision could therefore silently open the latest revision instead of refusing a stale binding.
3. The local save handler unconditionally re-enabled its button in `finally`, even when an older save had been superseded by a newer save for a different product. A stale completion could unlock the newer pending operation.
4. Importing a saved draft could leave an imported GLB and calibration worksheet from the previously selected product attached to the replacement preview.

## Implemented safeguards

- Normalize the incoming selection and construct the immutable saved snapshot **before** touching the existing editor state or revoking any old object URL.
- `commitPrivateReceiptRestore` stages an exact candidate state, rolls back all covered in-memory fields on render failure, attempts a best-effort old-preview rerender, and revokes displaced URLs only after successful rendering. A failed operation's provisional URLs are revoked by the existing handler cleanup.
- Refuse a stale or substituted local recovery receipt when the server's returned `reference` or `revision` differs from the private receipt. Existing owner authentication remains a loopback-server responsibility; this validation is an additional local binding check, not hosted authorization.
- Clear imported GLB and calibration metadata on successful draft replacement; retain them on failed restoration.
- Track save attempt generations and only release the Save button from the latest pending attempt.
- Add direct extracted-DOM-handler adversarial tests for stale revisions, mismatched references, missing artwork grants, partial artwork fetch failures, rendering rollback, superseded receipt operations, and stale-save completion.

## Limits

This transaction protects the local editor's in-memory state and object URL ownership. It **does not** claim a distributed transaction across browser rendering, opted-in session persistence, local-server file writes, or network requests. Rendering rollback is best effort if the DOM renderer itself repeatedly throws. Cleanup of old URLs is best effort. A completed-but-superseded upload may remain as an orphan in disposable local test storage. No browser/screen-reader or Shopify acceptance has been performed.

## Reproduction

```sh
node --test tests/objective35s-private-receipt-atomicity.test.mjs
node --test --test-concurrency=2 tests/objective35n-cancellable-recovery.test.mjs tests/objective35o-atomic-recovery.test.mjs tests/objective35p-async-review-transition.test.mjs tests/objective35q-dom-focus-and-review.test.mjs tests/objective35r-editor-async-binding.test.mjs tests/objective35s-private-receipt-atomicity.test.mjs
npm test
node scripts/build-preview-asset-manifest.mjs --check
node scripts/build-static-preview-assets.mjs --check
node scripts/build-staging-static-bundle.mjs --check
node scripts/build-main-staging-reconciliation.mjs --check
node scripts/check-main-staging-browser.mjs --static-check
```

**No store changes.** Main Engineering's Objective37 unpublished staging changes are independent and must be reconciled explicitly before any future integration.
