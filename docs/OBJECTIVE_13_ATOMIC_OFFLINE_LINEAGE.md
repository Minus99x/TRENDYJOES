# Objective 13 — Atomic offline receipt-to-lineage observation

**Version 0.13.0. OFFLINE, SINGLE-HOST PROTOTYPE ONLY. NO SHOPIFY ACCESS.**

This objective closes the specific v0.12 two-transaction crash gap **only in the newly wired atomic offline adapter**. It does not make the existing legacy adapter atomic, or establish real checkout/payment/fulfillment proof.

## New trust and transaction flow

1. `createOfflineVersionedMetadataAuthority.prepareForAtomicLineage()` authenticates signed v2 receipt, current synthetic principal, expected owner/shop/session, exact product/variant/revision/digest and server-owned current design. It **does not consume** the nonce. Its frozen proof is branded with a private WeakSet; `assertPreparedForAtomicLineage()` rejects fabricated copies and checks expiration again.
2. `createOfflineOrderLineage` optionally accepts **both** `prepareCartReceipt` and `commitAtomicObserved`. Missing one rejects configuration. It continues to authenticate a synthetic HMAC event and independently resolve a trusted offline checkout before preparing a receipt. Cancellation still uses the existing non-receipt transition.
3. The server-owned `commitAtomicObserved` adapter calls `ledger.commitLineageWithReceipt({...args,assertPreparedReceipt:authority.assertPreparedForAtomicLineage})`. The validator is trusted server-side code, never a browser-supplied function. Inside the **same filesystem lock and single `ledger.json` rename**, the ledger checks branded proof, expiry, tenant, owner, session digest, exact design CAS, nonce uniqueness, checkout/order/line/event conflicts and legacy claims, then writes nonce + lineage + event together. An error before rename leaves all three absent; after rename a repeated authenticated event is idempotently acknowledged.
4. The old `authority.verify()` and `ledger.commitLineageTransition()` remain for v0.11/v0.12 compatibility and regression coverage. **Those functions used together still have the two-transaction gap.** New integrations must use the paired atomic adapter and must not accidentally fall back to the old path.

## Verified adversarial cases

New tests exercise: single-snapshot atomicity, duplicate authenticated event, alternate event replay, forged proof, HMAC tampering, owner/session substitution, revision race after preparation, injected failures before and after rename, same-process adapter races, cross-process races, alternate receipt replay, cancellation isolation, old ledger migration, corrupt state, partial adapter misconfiguration, legacy nonce consumption, proof expiry, session/variant substitution, legacy cross-protocol claim, event ID conflict and non-authorizing states. The full original regression suite remains required.

## Explicit limitations

- Single-host filesystem lock with no lease recovery/fencing; no multi-host ACID database, encryption, KMS, key rotation service or distributed exactly-once guarantees. A killed process holding `.atomic-lock` can block future writes until an operator safely intervenes.
- The synthetic HMAC event is not a Shopify webhook; the checkout resolver and customer principal are injected test adapters, not Shopify authentication. No actual cart, checkout, payment, production, manufacturing or fulfillment authorization exists.
- `prepareForAtomicLineage` returns internal nonce proof material to **trusted server-side code only**. It must never be serialized to customer-facing cart properties, browser logs or external APIs. The ledger's `assertPreparedReceipt` callback must be bound to the genuine metadata authority, not to a caller-controlled stub.
- Receipt validity is checked before and during the atomic commit, but the source uses wall-clock time and the static offline key ring. Production requires durable key revocation and robust clock/identity infrastructure.
- This first seam handles a single customized line per synthetic order. Real Shopify retries, guest identities, multiple line items, payment/refund state, inventory, approved GLBs/print zones, artwork scanning, privacy retention and mobile/device QA are not verified.
- A power loss during filesystem/directory fsync is not equivalent to tested injected exceptions. Filesystem durability varies by platform; no real crash-consistency certification is claimed.

## Reproduce

```bash
node --version
node --test tests/objective13-atomic-lineage.test.mjs
npm test
```

No external npm dependencies, paid services, Shopify reads/writes or deployments are involved.
