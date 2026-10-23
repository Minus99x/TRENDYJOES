# Objective 31G — Independent offline recovery-outcome adjudication

**Status:** v0.30.7 offline prototype only. NOT production authorization or an independent adjudication service.

## Purpose and conservative behavior

Objective 31F deliberately blocks every subsequent recovery once any reservation is burned, because a crash between reservation and anchor recovery leaves the outcome ambiguous. Objective 31G adds an **explicit opt-in forensic-review quorum** to permit a new signed recovery authorization only after independent reviewers attest a complete, resolved outcome history. The original 31F behavior is unchanged when reviewers are not configured.

The review quorum does **not** itself prove the factual accuracy of the forensic investigation. Reviewers are externally injected offline `readLatest` implementations with independent Ed25519 keys. No reviewer service, protected key custody, external monotonic history, WORM evidence store, atomic two-resource transaction, customer authentication, Shopify checkout or deployment is provided.

## Integration contracts

`createOfflineRecoveryAuthorizationLedger` now offers `inspectHistory()` under its existing cross-process lock. This validates the complete append-only local reservation chain and returns its count, head digest, and full canonical events. A missing/tampered/pending event fails closed. This does not create an offsite anti-rollback guarantee.

`createOfflineRecoveryReconciliationGuard({... , reviewers, reviewQuorum})` accepts a strict-majority, distinct-key array of `{id, publicKey, readLatest}` independent reviewers. Reviewer keys may not duplicate anchor or recovery-ledger witness keys. Reviewers are optional; configuring only one of `reviewers` and `reviewQuorum` fails.

After validating a new recovery permit, the guard witnesses BOTH anchor and reservation-ledger heads, then reads the entire reservation history. For a nonempty ledger, `recoverOnce({authorization, forensicReview})` requires a `forensicReview` object with exactly:

- `caseDigest`: nonzero lowercase SHA-256 digest of externally reviewed case evidence.
- `outcomes`: one ordered record per historical reservation, with exactly `index`, `authorizationId`, `permitDigest`, `pendingDigest`, `result` (`RESOLVED_APPLIED` or `RESOLVED_NOT_APPLIED`), and nonzero `evidenceDigest`.

Every reviewer is called independently with a fresh random 256-bit challenge, current anchor state, full ledger history, all proposed outcomes, case digest, the **exact new signed recovery authorization**, and its digest. Reviewers must independently validate the proposed action and evidence; this library cannot verify their forensic procedures. Its signed response is a canonical `TJ-OFFLINE-RECOVERY-ADJUDICATION-1` Ed25519 receipt containing reviewer identity, registry and anchor domain, reservation count/head, full history digest, anchor-state digest, forensic case digest, outcome digest, new authorization digest, challenge, and short issued/expiry timestamps. All returned receipts must agree and pass signature verification. Invalid, missing, duplicate, expired, stale or equivocal receipts fail closed.

A previously `RESOLVED_APPLIED` reservation with the **same pending proposal digest** prevents reopening, even with a new signed permit. A prior `RESOLVED_NOT_APPLIED` result permits an independently authorized **new** attempt, never a retry of the burned authorization ID. After reviewer signing, the guard re-reads BOTH local resources and rejects any change. It then reserves the new permit under the ledger's existing locked head compare-and-swap **before** attempting recovery. A crash may still burn the new permit; there is no automatic retry.

The returned result includes `forensicReviewVerified` and `adjudicationDigest`. `inspectReconciliation()` remains conservative: it never automatically clears historical review-required dispositions, even if reviewer keys are configured.

## Unresolved gates — do not deploy

1. **Review evidence durability:** signed reviewer receipts and case evidence are **not automatically persisted** by this contract. Implement a crash-safe append-only review journal and externally anchored monotonic witness of its head. Without it, forensic proof can be lost in a crash.
2. **Independent services:** injected reviewer and witness mocks are not deployed, isolated, rate-limited, or independently audited. No production reviewer trust enrollment/rotation/revocation or protected signing keys.
3. **Privileged rollback:** a malicious privileged operator can replace local anchor, ledger, and review files. Offsite WORM/monotonic evidence is still needed.
4. **Cross-resource atomicity:** reviewer approval, ledger reservation, and anchor recovery are not one atomic transaction. An ambiguous crash always burns a permit and requires new independent forensic review.
5. **Mandatory boundary:** lower-level adapter methods remain callable outside the optional guard. This is an offline contract, not an enforced production security perimeter.
6. **Operational validation:** no live Shopify writes, actual customer authentication, checkout, manufacturing authorization, or deployed recovery process was exercised.

## Verification

Run `node --test tests/objective31g-recovery-adjudication.test.mjs` and `npm test` from the extracted project root. The focused suite includes real child-process exit after a durable reservation, a competing child-process ledger append during review, cross-domain key reuse, forged and stale signatures, full-history binding, unresolved and already-applied outcomes, permit replay, race rejection and positive independently reviewed recovery. These are synthetic offline fixtures, not production forensics.

**Next Objective 31H:** durable reviewer-evidence journal with crash-safe append and independently witnessed monotonic heads, plus forensic-proof replay/rollback tests. Never silently auto-recover or bypass a rejected safety gate.
