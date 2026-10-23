# Objective 32D — Durable offline supervisory replay commitment

**Local prototype only.** This is an opt-in Linux filesystem-backed, one-successor-per-head replay registry for Objective 32C *review decisions*. It does not repair or delete forensic archives, change Shopify, authorize checkout, or grant production/manufacturing authority.

## Trust and atomicity boundary

`createOfflineSupervisorReplayCommit({directory,registryId,genesisBytes,expectedGenesisDigest})` requires a separately retained, canonical replay genesis and SHA-256 pin. For every commit, the caller MUST independently supply the current head digest, a trusted time source, a pinned 32B report and manifest/receipt-chain anchors, an independently pinned reviewer policy, and a genuine Ed25519 quorum-signed 32C decision.

The service reconstructs the entire append-only replay history from genesis, verifies canonical records and each transition's deterministic snapshot digest, and rejects an unexpected terminal head, disconnected commit files, tampering, unsafe files, missing evidence, and unresolved staging artifacts. A signed decision must reference the exact current replay digest; decision IDs and nonces cannot be reused.

A new canonical commit record is fsynced in a private staging file and then atomically **hardlinked** to `commit-<previousDigest>.json` using the filesystem's no-overwrite semantics. The successful link makes competing writers to the same predecessor fail. The commit directory is fsynced before reporting local success. After a crash, a linked stage may be finalized **only** after an independently pinned head has been verified and an explicit `supervisorConfirmed:true` is supplied; unlinked orphan stages fail closed and are never silently discarded. Finalization only removes an internal staging hardlink; it never alters archived evidence or signed receipts.

**Crucial limitation:** local success does not atomically update an external trust anchor. The caller MUST durably publish/retain the returned `nextDigest` independently before considering the head confirmed. Without independent pin custody, a same-UID adversary can delete or roll back the local log. The log verifies deterministic replay history and local atomicity, **not** cryptographic provenance of historic commit records by itself; independently retained head pins and prior signed decisions are required for trustworthy audit. The protocol is not safe across NFS, distributed filesystems, hostile same-UID writers, compromised local root, power-loss-prone storage without working fsync, or untrusted clocks. Do not treat `committed:true` as downstream authorization.

## API

- `inspect({expectedHeadDigest})`: recomputes the complete chain and returns a frozen non-authorizing head/count. It fails closed on unresolved stages.
- `commit({expectedHeadDigest,report,expectedPins,decision,reviewers,quorum,expectedReviewerPolicyDigest,nowMs})`: verifies Objective 32C and atomically commits a local at-most-one successor. Returns `nextDigest`, `externalPinUpdateRequired:true`, and no action authority.
- `finalizeLinkedStages({expectedHeadDigest,supervisorConfirmed:true})`: with an externally pinned terminal head, checks that leftover staging files are hardlinks to committed records, then removes only those staging links. Orphan/unlinked staging requires a separate manual review; this module will not delete it.

`faultHook` exists solely for isolated offline crash tests. No key generation, secrets, hosted auth, real customer data, or network access is performed by the module.

## Reproduction

```sh
node --test tests/objective32d-supervisor-replay-commit.test.mjs
npm test
```

Adversarial coverage includes actual independent Node-process contention and SIGKILL at three persistence boundaries; invalid report/identity/policy/signature/clock, duplicate IDs/nonces, stale external pins, corrupted records, symlink substitution, orphan commits, unexpected files, unsafe permissions, and supervised post-crash staging finalization.

## Remaining gates

Independent durable head-pin publication, independent witness/supervisor deployment, key custody, trusted timestamps, immutable offsite evidence retention, multi-resource atomic recovery, hosted authentication, manufacturing calibration and real Shopify integration are **not** implemented here.
