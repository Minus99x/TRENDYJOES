# Objective 31M — Durable offline forensic acquisition session journal

**Scope:** single-host Linux, opt-in, diagnostic only. No Shopify calls, customer records, signing secrets, hosted authentication, independent witnesses, deployment, recovery grants, or checkout operations.

`createOfflineAcquisitionSessionJournal({directory})` implements a single-use three-stage, append-only local evidence session:

1. `begin({acquisitionId,independentPins,priorRetentionHead,expectedSessionHead})` durably records the session identity, independently supplied forensic heads, and prior retention head. The empty session pin is `{count:0,headDigest:'0'.repeat(64)}`.
2. `record({manifest,independentPins,forensicTrust,retentionTrust,independentRetentionHead,expectedSessionHead})` first verifies the **entire** signed 31L manifest against out-of-band trust and pins, then persists the signed PRE receipt and complete POST manifest as separate durable events under one OS file lock. It does not create signatures or infer external pins.
3. `inspect({expectedSessionHead})` and `verify({...externalTrustAndPins,expectedSessionHead})` are read-only diagnostics. The latter cryptographically re-verifies the preserved signed evidence. Both require a caller-supplied independently retained session pin.

Each event is domain-separated SHA-256 chained, stored as canonical JSON with owner-only file permissions, O_NOFOLLOW and hardlink checks, an exclusive `.pending.json` file, file and directory fsync, and an OS `flock` lock held across the entire transition. A crash after pending fsync leaves an **uncertain** marker that is never automatically removed. A crash after BEGIN or PRE commit leaves a permanently review-required single-use session; there is **no resume or retry method**. A crash after POST commit may be inspected only with external pinned evidence. Replayed BEGIN/POST, stale pins, tampering, symlinks, hardlinks, group-writable directories, unknown files, forged signatures, and mismatched independent heads are rejected.

**Security limitations:** local filesystem history alone cannot prove anti-rollback or genuine external retention. Independently preserve session pins, witness keys, reviewer policies, retention heads and forensic source heads outside the session directory. `readOnly`, `mayRetry:false`, `mayAcknowledge:false`, `mayDeletePending:false`, and `productionApproved:false` are intentional. Do not delete a pending file, reinterpret diagnostic completeness as authorization, or use these APIs in Shopify checkout. A process or host with full control of the filesystem and external pins can defeat local guarantees. Locking depends on Linux `/usr/bin/flock`; production key custody, remote/WORM retention, atomic multi-resource recovery, and real trusted timestamps remain open.

Reproduce: `node --test tests/objective31m-acquisition-session.test.mjs`; `node --test --test-concurrency=4 tests/*.test.mjs`.
