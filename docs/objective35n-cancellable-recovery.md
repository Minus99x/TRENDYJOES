# Objective 35N — cancellable private-receipt confirmation and stale UI fencing

Source release v0.30.110; parent v0.30.109 (35M). **OFFLINE PREVIEW ONLY.**

## Functional change

The prior editor disabled **Cancel receipt confirmation** while the two local-readiness
checks were in progress. It therefore had a controller-level cancellation safeguard
but no accessible cancellation action for the actual user during a pending check.

This objective keeps Cancel available during pending checks and moves keyboard focus
from the disabled Confirm button to Cancel. The cancellation is a veto: it invalidates
an in-flight confirmation epoch, blocks the review acceptance callback, and stops
subsequent bearer-authenticated readiness calls after the current response settles.
The local recovery contract accepts an optional third `shouldContinue` callback
which can **only deny**, never authorize, and defaults to true for existing callers.
It is checked before and after each asynchronous readiness request. Any veto fails
closed without consuming the pending checklist receipt.

An in-flight cancellation remains visibly pending until the outstanding local check
settles. The UI suppresses stale success/error messages after cancel, clear, or a
superseding receipt/import. A superseded private receipt's temporary artwork URLs
are still revoked. Reconfirmation requires reopening/staging the private receipt.

## Security and scope

No bearer tokens are returned by the status API. The public recovery checklist is
non-authorizing. No actual Shopify cart/order/customer calls are implemented; only
the local loopback readiness fixture is used. No deployment or production claim.
Browser interaction is not independently accepted unless a real browser run passes.

## Reproduce

```
node --test tests/objective35n-cancellable-recovery.test.mjs
node --test tests/objective35l-multidesign-review-recovery.test.mjs tests/objective35m-multidesign-recovery-confirmation.test.mjs tests/objective35n-cancellable-recovery.test.mjs
npm test
node scripts/build-preview-asset-manifest.mjs --check
node scripts/build-static-preview-assets.mjs --check
node scripts/build-staging-static-bundle.mjs --check
node scripts/build-main-staging-reconciliation.mjs --check
```

The browser acceptance gate remains open. Hosted identity/storage, manufacturing
approval, catalog/price/inventory authority and actual checkout remain blocked.
