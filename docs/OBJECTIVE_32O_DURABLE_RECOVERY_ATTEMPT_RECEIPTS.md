# Objective 32O — Durable signed-recovery attempt inventory

Scope: **offline-only** security infrastructure. No Shopify reads/writes.

## Threat boundary and opt-in usage

The Objective 32N recovery API remains available for historical regression
compatibility **only before a receipt inventory has been initialized**.
Once `.recovery-receipts/` exists, every subsequent `adjudicatePending`
requires `expectedReceiptHead`, supplied from independently retained evidence.
The caller must supply a reviewer roster and its independently trusted SHA-256
policy pin, the journal's independently trusted expected head, and a signed
unexpired recovery decision. Example, in pseudocode:

```js
const journal=createOfflineConflictExchangeJournal({directory,genesisExchangeDigest});
let receiptHead=journal.recoveryReceiptGenesisHead; // pin outside this host
const outcome=await journal.adjudicatePending({
 decision,reviewers,expectedReviewerPolicyDigest,nowMs,expectedHead,
 expectedReceiptHead:receiptHead
});
receiptHead=outcome.recoveryAttemptReceiptHead; // externally publish/pin yourself
```

**Never** treat a head obtained only from the local journal as independent
anchoring. `inspectRecoveryReceipts` verifies exact canonical records and the
hash chain against a caller-supplied head, not the global uniqueness of history.

## Durability and replay semantics

Under the journal's existing Linux `flock`-based exclusive lock, the recovery
path verifies signed quorum, journal history and inode state, and then writes
one numbered, private, canonical, SHA-256 hash-chained **attempt receipt**.
It fsyncs the receipt file and its directory before unlinking `.pending.json`.
Receipt fields bind the exact signed decision digest, nonce, reviewer-policy
pin, genesis, pre/post heads, pending record/byte digests, and attempt time.
The inventory rejects repeated nonces and repeated pending byte digests.

The receipt records **an authorized attempt, not successful completion**.
If power is lost before receipt sync, a partial or malformed inventory file
fails closed; operator intervention is required. If power is lost after sync
but before unlink, the pending file remains, but its nonce/pending bytes are
consumed. The implementation deliberately does **not** auto-retry or assert
that unlink occurred. If unlink completes but the process crashes before
returning, the receipt remains, and replay is still blocked.

This design favors fail-closed evidence preservation over automatic liveness.
It does **not** solve atomic cross-resource commit, host compromise, receipt
publication, witness independence, trusted timestamps, or global forks.

## Test and operating boundary

`node --test tests/objective32o-recovery-receipts.test.mjs`
`npm test`

Linux single-host local prototype only. No hosted authentication, no live
customer data, no real orders, no manufacturing authorization, no deployments.

## Remaining next gates

Independent receipt-head publication, crash-state operator recovery workflow,
reviewer-policy transition proofs, monotonic offsite nonce inventory, trusted
signing custody, and distributed recovery semantics. The existing legacy
unreceipted 32N recovery method remains an explicit limitation before first
receipt-ledger initialization; production integration must eliminate it.
