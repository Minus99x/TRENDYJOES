# Objective 32S — authenticated cutover-resolution proof and uncertain-state inspection

Scope: OFFLINE local-only verification, no Shopify writes, no network, no production authorization.

## New portable audit API

`src/offline-conflict-cutover-resolution-proof.mjs` exports:

- `offlineConflictCutoverResolutionProofDigest(proof)` — SHA-256 domain-separated canonical JSON digest of a bounded portable evidence bundle.
- `verifyOfflineConflictCutoverResolutionProof({proof,pins,nowMs})` — fail-closed retrospective verification of a 32R **resolution attempt** against independently supplied pins. It checks the complete signed 32P epoch transition and receipt history, cutover marker canonical pending bytes, the 32R outgoing/incoming Ed25519 quorums, the decision's historical validity at the resolution receipt timestamp, resolution receipt digest, action binding, journal head and historical head continuity. It does **not** claim the unlink finished.

`proof` exact keys: `schema`, `history`, `cutoverMarker`, `pendingMarkerBase64url`, `decision`, `resolutionReceipt`. `history` must contain JSON-serializable PEM public keys, not private keys. `pins` exact keys: `proofDigest`, `decisionDigest`, `resolutionDigest`, `cutoverDigest`, `pendingBytesDigest`, `genesisExchangeDigest`, `transitionHead`, `receiptHead`, `finalPolicyDigest`, `exchangeJournalHead`. Every pin must come from an independently trusted channel; a digest copied from the proof is not an independent anchor. Proof digest is computed over canonical JSON in its original key order; preserving original byte order is required for round-trip verification. All bundle records are bounded and validated against their cryptographic dependencies.

**Retrospective audit:** the 32R signed decision is verified at the recorded `resolvedAt` (which must fall within the signed validity window), not at the later audit time. `nowMs` must be >= the recorded resolution timestamp. This is not a trusted timestamp or proof that the receipt was generated at the claimed time.

## New read-only local inspection

`createOfflineConflictExchangeJournal(...).inspectRecoveryPolicyCutoverResolutionEvidence({expectedResolutionDigest})` runs under the existing Linux local cross-process lock and returns either:

- `status:'uncertain-pending'`, `completionProvenLocally:false`: authenticated durable receipt exists, but pending marker still exists. Validates canonical pending bytes against receipt digest, file safety and action-specific link/active-marker state. Never retries or unlinks anything.
- `status:'locally-completed'`, `completionProvenLocally:true`: pending marker absent and receipt/active marker locally consistent. This is *not* independently witnessed completion, and it can be defeated by a privileged host rollback absent offsite anchors.

Existing `inspectRecoveryPolicyCutoverResolution` retains fail-closed behavior on any pending marker.

## Adversarial regressions

`node --test tests/objective32s-resolution-proof.test.mjs` exercises 34 cases: dual-quorum proof verification, re-pinned forged signatures, minority quorum, omitted transition, substituted external anchors, rollback, conflicting action, expired decision, future/early receipt timestamp, canonical encoding and unapproved fields, crash before pending unlink, read-only uncertain versus locally completed status, pending tampering/symlink and action/link inconsistency.

`npm test` runs the complete historical regression. Simulated process crashes and local filesystem observations are not power-loss, multi-host, trusted-time or independent-publication proofs.

## Gates / next objective

Still missing independent pin publication, protected reviewer keys, trusted timestamps, offsite immutable evidence, hosted identity, multi-host atomicity and end-to-end manufacturing/Shopify verification. No automatic repair of uncertain receipts.

Next **32T**: independently pinned portable evidence inventories across multiple local resolution attempts and adversarial omission/equivocation checks; preserve read-only fail-closed semantics and single-cutover limits until multi-cutover protocol is formally designed.
