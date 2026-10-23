# Objective 35AA — portable signed journal-head receipts (OFFLINE)

**Status:** Local read-only prototype; no hosted witness, trusted time, or production authority.

## Trust and storage boundaries

The Objective 35Z journal authenticates local signed artwork-review records and verifies an **externally pinned** exact head. Objective 35AA can then call the actual trusted journal's `inspect` method and issue an Ed25519-signed receipt over the journal schema, locally pinned artwork root, ordered record digests, head count/digest, observer identity/key identifier, caller-supplied observation timestamp, observer sequence, and preceding receipt digest. The signature is domain separated. No private keys, reviewer HMACs, customer data or bearer grants are serialized into receipts.

`issueLocalReviewObserverReceipt` requires a trusted local journal instance, out-of-band `expectedHead`, caller-trusted reviewer public-key resolver, observer private key, and root pin. It cannot establish that a malicious caller-provided `journal.inspect` object is genuine; the caller must instantiate 35Z locally from trusted code. The genesis receipt can be issued only when a real 35Z read-only inspect is possible or from a trusted initialized empty journal report; it is not a globally witnessed genesis.

`verifyLocalReviewObserverReceipt` authenticates a portable JSON receipt against caller-trusted Ed25519 public keys, with exact field schema and canonical serialization, strict digest/record history consistency, and root pin binding. The observer's `observedAt` is a **self-asserted timestamp, not trusted time**. Verification never calls Shopify or touches local artwork.

`reconcileLocalReviewObserverReceipts` requires at least one **caller-supplied, independently retained historical pin**. It checks all signatures, observer sequence/previous-receipt links (no unanchored gaps), key fingerprint uniqueness between different observers, prefix consistency of ordered record digests, equal-height split views, and rollback against every historical pin. Two cryptographically distinct keys do not prove independent physical custody. A malicious party able to replace all supplied external pins can defeat rollback detection. A receipt is not proof that an observer actually saw the underlying journal; signing-key custody and independent publication must be established out of band.

## Reproducible offline checks

```sh
node --test tests/objective35aa-observer-head-receipts.test.mjs
node --test --test-concurrency=2 tests/objective35{u,v,w,x,y,z}-*.test.mjs
npm test
```

The full regression can be executed as a **disjoint bounded batch partition** when a monolithic Node run is too slow; retain all TAP logs and verify that every `tests/*.test.mjs` is included exactly once. No skipped, cancelled or failed tests count as passing.

## Authority and deployment boundary

All outputs are read-only and explicitly `shopifyWritesAllowed:false`, `authorizesProduction:false`, `authorizesQuarantine:false`, and `authorizesDeletion:false`. This does not authorize hosted authentication, customer storage, Shopify checkout, order reconciliation, artwork deletion, manufacturing approval, production writes, or deployment. Main Engineering owns the independent visual/accessibility/staging candidate and must not overwrite Night Watch security code with older Main source.
