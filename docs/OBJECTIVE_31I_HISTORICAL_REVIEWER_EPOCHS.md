# Objective 31I-A — Historical reviewer epochs and portable forensic verification

**Offline contract only. Not a production identity, recovery, reviewer, or independent witness service.** Main Engineering's UI development remains separate.

## What changed

`createOfflineForensicReviewJournal` now accepts optional, caller-pinned `reviewerEpochs`, an ordered sequence of `{startIndex,reviewers,quorum}`. Epoch 1 starts at event 1; later epochs start at exact journal event indices. Existing callers without epochs retain the Objective 31H single-policy behavior. The constructor requires its existing `reviewers` and `reviewQuorum` to match the final epoch. Every stored event is verified with the quorum and public keys effective at its event index, rather than incorrectly re-verifying all history against the current keys. New appends are checked against the correct epoch before disk mutation.

A reviewer ID may rotate to a fresh Ed25519 public key, but a key cannot be reassigned to another ID or returned to service after retirement. Reviewer signing keys from **every** historical epoch are barred from use as independent journal witness keys. The supplied epoch policy is copied on construction to avoid later array mutations. There is **no in-band approval of a rotation**: an independent, trusted operator must pin and retain the epoch policy outside the journal. Do not infer it from untrusted journal contents.

`verifyOfflineForensicEvidenceBundle` is a pure offline verification API. It takes the complete event array from `inspectHistory()`, a caller-pinned `{count,headDigest}`, the caller-pinned reviewer epochs, registry identity and anchor type. It verifies every historical signature at its recorded observation time, evidence bytes and SHA-256 digests, canonical event hash-chain, monotonic timestamps, unique authorization digests/challenges, and exact expected head. It rejects missing/reordered/tampered events, forged old signing policies, and stale or mismatched externally pinned heads. It does **not** assert that the caller's head or epoch policy came from an independent witness.

```js
const reviewerEpochs = [
  {startIndex:1,reviewers:oldReviewers,quorum:2},
  {startIndex:2,reviewers:newReviewers,quorum:2}
];
const journal = createOfflineForensicReviewJournal({
  directory,registryId,anchorType:'registry',
  reviewers:newReviewers,reviewQuorum:2,reviewerEpochs
});
const snapshot = await journal.inspectHistory();
const verified = verifyOfflineForensicEvidenceBundle({
  registryId,anchorType:'registry',events:snapshot.events,
  reviewerEpochs,expectedHead:{count:externalPinnedCount,headDigest:externalPinnedDigest}
});
```

## Threat model and deployment gates

- **Trusted input required:** epoch definitions and head must be independently pinned. A malicious operator who supplies both an invented policy and a fabricated matching history can fool a local-only verifier. No remote witness publication, WORM/offsite retention, or monotonic trusted clock is implemented.
- **Historical key compromise:** if a retired private key is later stolen, signatures can be forged for historical times. An independently retained head and trusted time are needed to constrain backdating; local event timestamps are not trusted timestamps.
- **Rotation authorization:** no cross-signed transition certificate, independent epoch-policy signature, key revocation service, or protected key custody exists. Rotation is not a production workflow.
- **Durability:** the existing Linux-only journal still uses fsync, rename, flock, and fail-closed ambiguous crash semantics. This change does not add an atomic journal/ledger/anchor transaction.
- **Portable bundle:** this API does not publish, sign, encrypt, transmit, or durably retain the bundle; do not export actual customer evidence to an untrusted recipient. Synthetic test fixtures only.

## Next objective

**31I-B:** independently signed witness-head publication and retention/rotation-policy attestation, with rollback/clock/crash and key-compromise adversarial testing. Retain the Objective 31H forensic journal and all prior verified releases; do not deploy or alter Shopify.
