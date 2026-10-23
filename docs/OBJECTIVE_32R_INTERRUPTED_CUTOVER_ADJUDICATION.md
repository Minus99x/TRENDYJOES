# Objective 32R — Authenticated interrupted reviewer-policy cutover adjudication

**Offline Linux-local development prototype only.** No hosted authentication, production approval, independently published anchors, trusted clock, hardware-backed keys, Shopify writes, real checkout, or cross-host atomicity.

## Contract

`journal.adjudicateInterruptedRecoveryPolicyCutover({...})` accepts an externally supplied and independently pinned 32P reviewer-policy history, a dual-majority Ed25519-signed 32R recovery decision, the independently supplied digest of that exact signed decision, cutover marker digest, pending marker byte digest, exchange-journal head, receipt head, an independently calculated durable resolution-receipt digest, and an explicit `nowMs`. The 32P history is reverified against both reviewer rosters and actual local receipt inventory; the exchange journal head is verified under the existing Linux `flock` cross-process lock.

The decision is canonical, domain-separated, and bound to the exact genesis, reviewer policy digests, cutover digest, pending bytes, exchange journal head, receipt head, expiry, nonce, and `abort` or `finalize` action. Both outgoing and incoming reviewer majorities must independently sign the same bytes. Unknown fields, invalid signatures, insufficient quorums, mismatched pins, and expired decisions are rejected.

**Physical-state restrictions:** `abort` is only permitted if the pending cutover file is an unlinked inode and no active marker exists. `finalize` is only permitted when the pending and active marker names are hard links to the same inode. A pending-only marker cannot be finalized; a linked marker cannot be aborted. All reads use `O_NOFOLLOW` and file mode, owner, inode, hard-link, canonical JSON, and digest checks.

Before removing the pending marker, the journal writes an exclusive, `0600`, fsynced resolution-attempt receipt with a domain-separated SHA-256 digest; it fsyncs the containing directory, unlinks the pending marker, and fsyncs the directory again. The receipt is **an authorization/attempt record**, not proof of physical power-loss durability. The `inspectRecoveryPolicyCutoverResolution({expectedResolutionDigest})` method independently verifies the receipt and local marker consistency. Crash after receipt fsync but before unlink **fails closed**: subsequent adjudication refuses to replay and does not auto-remove the pending file. A completed abort leaves a durable resolution marker and prevents silent cutover reactivation. A completed finalize leaves the active marker and durable resolution receipt.

## Threat boundaries and remaining gates

This is not a recovery of every uncertain state. If the receipt exists while pending remains, manual independently authorized reconciliation is required; no automatic retry. If the receipt or active marker is deleted by an attacker with local filesystem write access, independently retained external pins are necessary to detect omission. The API cannot establish globally unique history, external witness publication, monotonic time, remote identity, immutable offsite retention, or distributed transaction atomicity. Signing-key custody and externally published anchors remain production blockers. A signed receipt does not prove external physical manufacturing or payment/order fulfillment.

## Verification

`node --test tests/objective32r-cutover-adjudication.test.mjs`

`npm test`

Adversarial coverage includes real independent Node child-process competition for the Linux lock, real child-process termination after durable receipt sync, simulated faults after unlink, dual-quorum forgery/minority rejection, expired decisions, stale and substituted pins, tampered/symlinked files, abort/finalize state confusion, replay, receipt tampering, and state inconsistency. Tests do **not** simulate a hardware power loss.
