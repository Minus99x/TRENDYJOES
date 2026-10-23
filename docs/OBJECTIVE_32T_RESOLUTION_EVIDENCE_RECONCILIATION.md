# Objective 32T — Offline pinned resolution-evidence inventory reconciliation

**Status:** Local read-only prototype. Not deployed, not a production approval, and not an independent witness service.

## Threat and implementation

`src/offline-conflict-resolution-inventory.mjs` compares independently presented 32S authenticated *resolution-attempt* proofs from 2–8 named observers. Each view contains an exact, canonical inventory manifest and a positionally matched complete proof array. The **separately supplied** trust arguments include the exact sorted observer roster, each observer's SHA-256 inventory digest, an exact 32S proof-pin record for every evidence item, and the expected SHA-256 union digest. These pins must be obtained out of band and must be preserved independently of the potentially untrusted evidence; this code cannot provide or certify that trust channel.

Each proof is reverified by the existing 32S Ed25519 dual-quorum / historical 32P epoch / 32R resolution-attempt verifier, rather than relying on a digest-only match. Each entry binds genesis, cutover, signed decision, receipt, action, and proof digests. Exact field sets, strict lowercase hashes, bounded arrays, sorted entries, duplicate-genesis rejection, non-coercive string checks, and separate domain-separated SHA-256 inventory/union digests prevent silently accepted unknown claims and obvious omission/substitution attacks.

For a single genesis, this protocol permits **one cutover resolution attempt only**. Different fully authenticated proofs for the same genesis are treated as equivocation; it does not authorize a second cutover or automatic recovery. Multiple entries in one inventory represent *different independent genesis journals*, not multiple policy cutovers in one journal.

Every observer must provide exactly the same set of signed evidence. If a view is incomplete, reconciliation fails with `EXCHANGE32T_OBSERVER_OMISSION`; conflicting authenticated records fail with `EXCHANGE32T_EQUIVOCATION`. If all observers collude to omit an item, the independent complete-union pin is required to detect it. An observer omitted from the evidence and anchor set is rejected against the independent expected-observer roster. An unpinned, forged, missing, malformed, or substituted proof fails closed. No repairs, retries, filesystem writes, network access, signing, customer access, or Shopify API calls are performed.

## Reproduce

```sh
node --test tests/objective32t-resolution-inventory.test.mjs
npm test
```

Public interfaces:

- `offlineConflictResolutionInventoryDigest(manifest)` — canonical inventory commitment.
- `offlineConflictResolutionUnionDigest(union)` — complete expected evidence-set commitment.
- `verifyOfflineConflictResolutionInventories({views,anchors,expectedObserverIds,expectedUnionDigest,nowMs})` — reverify each proof and reconcile all independently pinned views.

## Important limits and remaining gates

A matching set of **caller-supplied** pins is not proof of independent publication, independent observers, physical evidence custody, timestamp authenticity, globally unique history, or an uncompromised machine. A 32R receipt records an authorized attempt, **not** that an interrupted unlink completed. This read-only verifier cannot certify local completion, global completeness, host power-loss safety, hosted authentication, Shopify checkout, or production readiness. Uncertain recovery attempts remain fail-closed pending manual authorized adjudication. Production would require protected keys, independent offsite anchor publication, trusted time, real witness deployment, immutable retention, multi-host atomic recovery, and separately authorized store integrations.
