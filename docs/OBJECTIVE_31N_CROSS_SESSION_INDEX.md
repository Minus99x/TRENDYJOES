# Objective 31N — Offline cross-session acquisition index

Scope: TrendyJoes Universal Studio **offline prototype only**. This is an append-only, externally pinned diagnostic index for previously completed Objective 31M acquisition sessions. It is not Shopify authentication, manufacturing authorization, payment approval, a deployed witness, or permission to retry a failed recovery.

## API

Import `createOfflineAcquisitionCrossSessionIndex` from `src/offline-acquisition-cross-session-index.mjs` and construct with `{directory}`. Linux with `/usr/bin/flock` is required. The index directory must be owned by the current process and inaccessible to group/others. No third-party dependencies or network calls.

- `append({expectedIndexHead, acquisitionId, sessionDirectory, sessionHead, manifest, independentPins, independentRetentionHead, forensicTrust, retentionTrust})`: under an OS file lock, verifies the complete signed Objective 31L manifest, the independently pinned Objective 31M session, the prior retained receipt head, absence of repeated acquisition IDs, and monotonic forensic/publication/outbox heads. Appends a compact hash-chained index record only after those checks pass. The index head is returned for **independent, durable retention outside this directory**. A head returned by the same mutable machine is not independent evidence.
- `inspect({expectedIndexHead})`: checks local structural chain, continuity, replay, monotonicity, unsafe filesystem substitutions, and exact external index pin. It **does not** validate signatures and returns `STRUCTURAL_ONLY`.
- `verify({expectedIndexHead, evidence, forensicTrust, retentionTrust})`: rechecks all index entries against an ordered, complete array of independently supplied session directories/pins/manifests/retention heads and externally supplied trust keys. Missing evidence, altered manifest serialization, missing sessions, stale pins, or invalid signatures fail closed. No verifier result authorizes acknowledgement, deletion, retry, checkout or production.

The first indexed acquisition must begin at retention receipt head `{count:0,headDigest:'0'.repeat(64)}`. Every later session must advance the signed retention history by exactly one PRE/POST pair. All acquisition IDs must be unique. Forensic/publication/outbox head counts may stay equal only if their digests stay equal; counts may never decrease. The existing 31L verifier independently enforces signature quorums, cross-acquisition receipt anti-replay, and signed head monotonicity.

## Durability and crash handling

Each record is written to an exclusive `.pending.json`, fsynced, and atomically renamed to a numbered committed file, followed by directory fsync. Any `.pending.json` after an interrupted write permanently prevents further indexing and verification; **no automatic cleanup, rollback, replay, resume, retry, or ACK path exists**. Actual child-process exits were tested immediately after pending fsync and immediately after committed fsync. Cross-process `flock` serializes competing writers. Symlink/hardlink and permissive directory attacks fail closed. Index history is bound to a caller-retained SHA-256 head; this is not a substitute for independently operated storage.

## Test commands

```sh
node --test tests/objective31n-cross-session-index.test.mjs
node --test --test-concurrency=4 tests/*.test.mjs
```

## Security limits and next gates

The external caller must safely retain index heads, session heads, receipt heads, reviewer/retention public keys, and complete manifests independently of the mutable local host. A privileged attacker can still destroy local files or deny service. Local fsync and a digest chain do not prove offsite retention, independent witnessing, trusted time, signing-key protection, or atomic cross-resource recovery. This module never calls Shopify and has no production grant. Next objective: portable independently attested index-head receipt and anti-equivocation review across competing index branches, without deploying services or altering the storefront.
