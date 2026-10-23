# Objective 35J — durable, read-only synthetic multi-line observation recovery

Scope: offline-only local prototype. No Shopify I/O, hosted authentication, checkout, payment, manufacturing approval, or customer data.

## Problem reproduced

An offline multi-line observation can durably commit `ledger.json` and then lose its acknowledgment (e.g. simulated fault at `after-rename`). The customer-review coordinator returns `MULTI_REVIEW_OBSERVATION_REJECTED`, even though both nonce claims and the order event have committed. Reissuing receipts on blind retry is unsafe and can fail after a local revision change. Conversely, a `before-rename` interruption leaves no committed observation. These two cases must not be conflated.

## Implementation

`createOfflineDurableLedger().inspectCommittedMultiLineage(...)` is a single-snapshot, read-only durable lookup. It validates the entire stored ledger before checking the authenticated event ID/body digest, exact order/checkout/owner/session binding, and ordered 2–25 line design/variant/digest binding. It returns only `committed`, `absent`, or `conflict`; it never creates receipts, consumes nonces, edits the ledger, or assumes that a missing event is safe to retry. A cross-protocol ID or claimed order with a missing event is a conflict.

`createOfflineMultiLineage().recoverCommitted({verifiedEvent})` requires an unforgeable authenticated synthetic event object, an `ORDER_OBSERVED` action within the five-minute synthetic-event window, an independently resolved trusted offline checkout with the exact owner/session identity, and a configured server-owned `inspectCommitted` adapter. Only a verified `committed` outcome returns the strictly non-authorizing duplicate observation acknowledgment. `absent` and `conflict` fail closed. Recovery is **explicit and read-only**, never an automatic reissue/retry, and cannot recover a cloned event object or an independently signed altered event.

## Verification

`node --test tests/objective35j-durable-observation-recovery.test.mjs` tests a fresh independent Node process reading the same persisted ledger after simulated faults before and after rename, successful observations, missing observations, event-ID reuse, signed order and line substitution, owner/session mismatch, expiry, checkout authorization switches, ledger corruption, and cancellation-history compaction. No network is involved. Existing Objective 15–17, 35H–35I regression tests are run alongside the new tests.

The fixture signs synthetic events using ephemeral test-only keys, stores local designs in a temporary directory, and deletes that directory after tests. It does not use real customer information or store secrets.

## Remaining limitations

The fixture's filesystem ledger is not a production multi-host database. The recovery read is not independently witnessed or hosted, and the synthetic signed event is not a Shopify webhook. Production recovery needs durable hosted authentication, authoritative order identity, independently protected audit anchors, actual checkout/order event delivery and separate Main Engineering acceptance. No storefront or staging theme was modified.
