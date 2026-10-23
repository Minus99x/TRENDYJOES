# Objective 31F — Witnessed recovery-ledger head and fail-closed two-resource reconciliation

**Status:** Offline-only integration contract, v0.30.6. Not deployed; not production authorization.

This objective builds on 31E's independently witnessed *anchor* and one-time recovery authorization ledger. It adds a separate, challenge-bound Ed25519 witness quorum for the **recovery-ledger head** and an opt-in reconciliation guard that checks **both** local resources and **both** independently signed heads before any signed recovery attempt.

## Public interfaces

`src/offline-recovery-reconciliation.mjs` exports:

- `OFFLINE_RECOVERY_LEDGER_WITNESS_SCHEMA`: domain separator `TJ-OFFLINE-RECOVERY-LEDGER-WITNESS-1`.
- `verifyOfflineRecoveryLedgerWitnessQuorum({registryId,anchorType,witnesses,quorum,receipts,snapshot,challenge,now})`: verifies exact canonical signed receipt fields, independent distinct pinned Ed25519 keys, strict majority, freshness/expiry, 256-bit nonce, registry/type binding, exact count and SHA-256 head digest. Every supplied receipt must agree; no quorum override of equivocation.
- `createOfflineRecoveryReconciliationGuard({adapter,ledger,registryId,anchorType,anchorWitnesses,anchorQuorum,ledgerWitnesses,ledgerQuorum})`: provides `inspectReconciliation()` and `recoverOnce({authorization})`. Anchor and ledger witnesses **cannot reuse the same signing keys**.

The witness `readLatest({challenge,registryId,anchorType})` functions must be independent of the mutable local host, must retain their most recent accepted heads, and must only sign their latest independently retained state. Locally generated mock signers are **not** independent witnesses. Receipts are signed over `schema + NUL + JSON.stringify(canonical ordered body)` using Ed25519. The ledger witness body fields are `schema,witnessId,registryId,anchorType,count,headDigest,challenge,issuedAt,expiresAt`, with an additional `signature` field. Challenges are fresh random 32-byte base64url strings. Witness validity is at most five minutes.

`src/offline-recovery-authorization-ledger.mjs` extends `reserve` with optional `expectedHead:{count,headDigest}`. This is a **locked compare-and-reserve** precondition. Existing callers without `expectedHead` retain the 31E behavior. Stale expected heads reject before writing a reservation. The guard always supplies the witnessed head.

## Fail-closed state machine

1. `inspectReconciliation()` reads the local anchor recovery state and the local ledger head. A pending ledger write fails closed (`RECOVERY_LEDGER_PENDING_REVIEW_REQUIRED`).
2. Both independent witness sets receive different fresh challenges and must sign exactly matching heads. Invalid, missing, forged, stale, expired, or equivocating receipts fail closed.
3. Both local resources are re-read after the asynchronous witness round trip. A concurrent head or pending-state change fails closed (`RECOVERY_RECONCILIATION_CONCURRENT_CHANGE`).
4. The inspection result has one of three dispositions: `NO_PENDING_RESERVATIONS`, `PENDING_ANCHOR_REVIEW_REQUIRED`, or `RESERVATION_OUTCOME_REVIEW_REQUIRED`. A disposition is **diagnostic only**; it is never an authorization to auto-repair.
5. `recoverOnce` verifies the separate signed recovery permit, exact pending digest, both independent witness heads, and the second local reads. It refuses recovery if **any earlier ledger reservation exists**, even if re-witnessed (`RECOVERY_RECONCILIATION_REVIEW_REQUIRED`): earlier outcome cannot be inferred from a reservation alone.
6. For the first permitted recovery, `reserve(expectedHead)` durably burns the authorization under the ledger's cross-process lock **before** attempting the anchor repair. On success the response is `POST_RECOVERY_INDEPENDENT_REWITNESS_REQUIRED`. On crash or ambiguous failure, **never automatically retry**. Re-witnessing does not independently prove the outcome; further recoveries remain blocked pending a future separately authorized adjudication mechanism.

## Threats exercised

Adversarial tests include valid-prefix and complete ledger rollback, forged and duplicate witnesses, wrong identity/type/count/head/challenge, expired or noncanonical receipts, cross-domain signing-key reuse, concurrent changes during witness reads, stale compare-and-reserve races, signed-permit rejection before burning, real child-process crash after reservation but before anchor recovery, cross-process competing reservations, and fail-closed post-crash inspection. `node --test tests/objective31f-ledger-witness-reconciliation.test.mjs` runs the focused suite.

## Limitations / next engineering gate

This remains a **Linux single-host prototype** using cooperative `flock` and local `fsync`; the independent witness functions are injected test contracts, **not a deployed offsite witness**. There is no protected signing-key custody, WORM/offsite history, secure time source, trusted customer authentication, or atomic transaction across the anchor and ledger. A compromised independent witness that signs stale history defeats the premise. Direct use of the lower-level 31D/31E adapters bypasses this opt-in guard. The strict no-second-recovery policy is deliberate until a separately signed, independently retained outcome-adjudication record can distinguish a completed recovery from a crash window. There is no automatic repair, no Shopify activity, no production authority.

**Objective 31G:** design and test independently attested recovery-outcome adjudication, retained witness monotonicity and safe reopening without granting local operators an unchecked bypass. Do not modify Main Engineering's separate UX line or Shopify.
