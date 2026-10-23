# Objective 33H — Signed read-only adjudication of interrupted 33G acceptance

This is a local, opt-in, Linux-only evidence-inspection contract. It never removes a `.pending.json` marker, retries acceptance, resolves an equivocation, changes the acceptance journal, authorizes recovery, or calls Shopify.

## API

`createOfflineConflictEquivocationAcceptanceRegistry({...}).adjudicatePendingReadOnly({decision, reviewerGroupA, reviewerGroupB, expectedReviewerGroupADigest, expectedReviewerGroupBDigest, expectedDecisionDigest, expectedPendingBytesDigest, expectedPreHead, nowMs})`

- The 33H decision body binds namespace, journal scope, externally pinned pre-head, canonical pending bytes digest, pending record digest/index, claimed state (`pending-only` or `pending-linked`), two reviewer policy digests, issuance/expiry and nonce. `action` is always `inspect-only`.
- Each reviewer group contains **three distinct, sorted Ed25519 public keys**. The verifier requires **at least two distinct valid signatures per group**, six disjoint identities/keys across groups, independent group digests, a pinned digest of the entire signed decision, and a caller-supplied time inside a maximum 10-minute decision window. The caller must retain policy, pre-head, pending, decision digests independently; supplying a newly forged pin alongside compromised keys does not establish an independent anchor.
- Under the existing 33G cross-process `flock` lock, the inspector validates owner-only directory, lock, and pending files; canonical UTF-8 JSON; SHA-256 pending bytes and record digest; namespace, predecessor, index, nonce and envelope continuity; and the complete existing acceptance journal. `pending-only` means the record was not linked and the pinned pre-head still matches. `pending-linked` requires the final record to share the same inode and exactly two hardlinks with the pending file, with a valid successor head.
- The inspector opens an existing lock read-only, creates no directory or lock, and makes no acceptance-file mutations. It deliberately fails closed on missing or unsafe evidence, stale heads, incorrect state claims, forged signatures, expired decisions, and unexpected journal entries. The ordinary `accept` and `inspect` paths remain blocked by pending markers.

## Reproduce

`node --test --test-name-pattern='^33H' tests/objective33e-authority-observer-reconciliation.test.mjs`

`npm test`

Tests exercise actual independent Node child SIGKILL at pending and hardlink durability boundaries, valid and invalid dual-group signatures, incorrect state claims, tamper, symlinks, permissions, forged pins, unexpected records and non-mutating inspection.

## Unresolved production gates

Time is **caller supplied**, not a trusted timestamp. External trust pins are **caller supplied**, not independently published. There is no protected key custody, globally consistent observer history, global fork prevention, offsite immutability, hosted customer authentication, or distributed atomic recovery. Signed adjudication classifies the local state only; it does not prove the original envelope exists off-host or authorize repair, production, checkout, payment, or deployment.
