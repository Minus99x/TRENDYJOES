# Objective 32P — Offline recovery-reviewer policy epochs and receipt continuity

Status: **local, read-only verification contract only**. This is not a policy change in the running journal, production approval, hosted identity, independent publication, recovery authority, or distributed atomic recovery.

## New offline APIs

`src/offline-conflict-recovery-policy-epochs.mjs` exports:

- `offlineConflictRecoveryPolicyEpochGenesisDigest({genesisExchangeDigest,initialPolicyDigest})` — domain-separated genesis candidate, binding the 32O receipt genesis head and initial reviewer roster digest.
- `offlineConflictRecoveryPolicyTransitionBytes(body)` — strict, domain-separated Ed25519 signing bytes for an epoch transition.
- `offlineConflictRecoveryPolicyTransitionDigest({transition})` — deterministic candidate digest for externally retaining the complete transition (including both signature sets). **A digest calculated from a received bundle is not an independently trusted pin.**
- `verifyOfflineConflictRecoveryPolicyEpochHistory(args)` — verifies full history against **caller-supplied, independently retained** `expectedTransitionHead`, `expectedFinalReceiptHead`, and `expectedFinalPolicyDigest`. Requires `genesisExchangeDigest`, `reviewerPolicies`, `transitions`, `segments`, and `nowMs`.

`createOfflineConflictExchangeJournal(...).inspectRecoveryPolicyEpochHistory(args)` additionally compares the independently pinned terminal receipt head with the local on-disk 32O inventory under the existing journal lock. This method is **read-only**, and does not modify recovery authorization or allow a new roster to adjudicate a pending journal operation.

## Evidence structure and enforcement

- `reviewerPolicies` has one external Ed25519 public-key roster per epoch (3–15 distinct reviewers). `transitions.length + 1` must equal the number of policies and receipt segments.
- Each `segments[i]` contains the **actual canonical 32O recovery-attempt receipt records** for epoch `i`, in exact append order. The verifier checks every receipt's digest, previous digest, index, genesis, nonce uniqueness, pending-bytes uniqueness, active reviewer-policy digest, and monotonic attempt times.
- Each transition is exactly `{body,outgoingSignatures,incomingSignatures}`. Its signed body contains a sequence, previous transition digest, genesis, outgoing/incoming policy digests, **the exact receipt head at the rotation boundary**, issue/expiry window, and nonce. Both outgoing and incoming **strict majorities** must sign identical canonical Ed25519 bytes. Signatures must be sorted and unique. Consecutive rosters must not reuse reviewer IDs or public keys.
- The transition hash chain binds each full signed transition. The caller must supply an independently retained final transition head, receipt head, and final reviewer-policy digest; otherwise verification fails closed. Missing history, changed evidence, forks, rollback, stale pins, replay, forged signatures, insufficient quorums, and policy substitution are rejected.
- Historical expiry windows are checked for structural validity, but the verifier is **not a live transition authorization endpoint** and cannot prove a transition was signed during its claimed time window. The local clock is not a trusted timestamp source.

## Limitations and remaining gates

The 32O receipts commit a signed-decision **digest** but do not embed original signed recovery decisions. Verifying receipt history therefore establishes only continuity of those stored attempt records, **not independent proof of the underlying decision signatures**. Actual 32O receipt creation separately verifies decisions. A receipt proves an attempted recovery, not successful completion.

This verifier does not enforce the rotated roster for `adjudicatePending`, persist a policy cutover, prevent a compromised host from hiding evidence absent independently published anchors, or perform offsite witness publication. Before any deployment, policy transitions need crash-safe, atomic persistence under the journal lock; independently trusted monotonic publication, protected signing keys, trusted timestamps, immutable offsite evidence, independent reviewer custody, and manual handling of uncertain commits. Hosted customer authentication, manufacturing GLB/print-zone approval, checkout/order integration and production authorization remain separate gates.

## Reproduce

```sh
node --version  # verified v22.16.0
node --test tests/objective32p-recovery-policy-epochs.test.mjs
npm test
```

The tests generate real Ed25519 reviewer signatures and actual 32O on-disk receipts; no Shopify, external services, customer data, or paid dependencies are used.
