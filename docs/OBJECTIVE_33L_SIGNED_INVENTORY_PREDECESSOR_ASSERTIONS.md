# Objective 33L — pinned, signed inventory predecessor assertions (OFFLINE ONLY)

`src/offline-conflict-adjudication-inventory-ancestry.mjs` adds a strictly read-only verifier for **exactly two** Objective 33K signed host-head receipts and at most **32** consecutively signed predecessor links. It makes no Shopify requests or filesystem writes.

## Contract

`reconcileOfflineConflictInventoryAncestry({receiptArgs,links,linkPins})` first re-verifies both Objective 33K receipts against the exact independently supplied host keys, signed-receipt digests, namespace, journal scope, genesis, head pins, caller time and replay sets. For unequal heights, the higher host must sign every adjacent `fromHead → toHead` transition, where `toHead.count = fromHead.count + 1` and `recordDigest = toHead.headDigest`. Each signed link binds both host identities, scope, namespace, record digest, bounded observation/expiry and nonce. Every link requires independently retained digest and endpoint-head pins. Missing complete evidence is unresolved; partial supplied evidence, a broken chain, signature forgery, repinning, expiry, omission, duplicate nonce, noncanonical encoding and final-head mismatch fail closed.

The only affirmative result is **`authenticated-signed-predecessor-claims`**: authenticated claims by the higher host that its 33J inventory head advanced through a contiguous chain. This is **not independently verified inventory-record ancestry**. In particular, the verifier does not receive or revalidate 33J record bytes, their underlying signed adjudication transcripts, or the actual host filesystem. A malicious/compromised authorized higher host can sign fictitious transitions. External pins are independently trustworthy only when retained outside the supplied evidence channel.

Other results: `consistent-signed-heads`, `conflicting-same-height`, `unresolved-no-predecessor-evidence`, `unresolved-gap-exceeds-bound`. A difference in count alone never establishes ancestry. The result always declares `provesActualInventoryAncestry:false`, `independentlyWitnessedDisk:false`, `independentTimestamp:false`, `globallyComplete:false`, and all production/checkout/recovery/repair authorizations false.

## Usage and tests

Generate two valid 33K Ed25519 receipts with independent externally pinned host keys and receipt digests; provide 33L links signed by the higher host, in strictly increasing count order, and externally pinned link digests plus endpoints. The public `offlineConflictInventoryAncestryLinkBodyBytes` creates domain-separated canonical signing bytes; `offlineConflictInventoryAncestryLinkDigest` derives the portable signed-envelope digest. Never place private keys or tokens in cart/order metadata.

Run `node --test tests/objective33l-signed-inventory-ancestry.test.mjs` or `npm test`. The tests use ephemeral keys and simulated times, not remote hosts or trusted timestamps. The new API is deliberately opt-in and does not alter the existing editor, manufacturing profiles, GLB import/calibration, Shopify bridge or 33J durable registry.

## Remaining work

Independent acquisition of actual 33J record bytes and verification of their embedded signed transcript pairs; authenticated durable remote observation, separately published anchor pins, trusted time, protected keys, cross-host replay admission, global consistency, hosted identity, atomic recovery, production-calibrated manufacturing and Shopify end-to-end checkout are not established. **No Shopify writes or deployments.**
