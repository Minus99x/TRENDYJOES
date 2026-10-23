# Objective 32Y — canonical, externally pinned interrupted-claim inspection transcript

**Offline only.** A transcript is a bounded, canonical UTF-8 byte representation of the **local state observed by the 32X dual-reviewer read-only inspector**. It is not a recovery receipt, a trusted timestamp, proof of offsite publication, evidence of completed acceptance, or a permit to repair/retry/clear `.pending.json`.

## Export and verify

Use the existing `createOfflineConflictManifestJournal({directory})` on Linux, with the same independently pinned 32X authorization inputs:

```js
const {bytes,transcriptDigest,snapshotDigest} =
  await journal.exportInterruptedClaimTranscriptReadOnly(authorized32XArgs);
// Persist the bytes and BOTH digest pins outside the local journal via a
// separately trusted process. This local prototype does NOT publish them.
```

The journal performs one 32X authorization and locked filesystem inspection before producing bytes. The encoder does not re-read the filesystem after lock release. No writes are made to the journal by export. Existing uncertain pending claims continue to block ordinary claims and inspection.

A separate offline verifier supplies `bytes`, `expectedTranscriptDigest`, `expectedSnapshotDigest`, the original `decision`, both reviewer public-key rosters, the independently retained decision/policy/head/pending-byte pins and invokes `verifyOfflineConflictManifestClaimTranscript(...)`. It re-verifies the original dual-majority Ed25519 authorization and snapshot/decision binding, without trusting digest fields embedded in the transcript. A locally generated transcript digest is **not** itself an independent anchor. Retain pins independently before relying on them.

The transcript is a strict single-schema JSON object in a fixed field order, maximum 4096 UTF-8 bytes, with domain-separated SHA-256 digests. Canonical reserialization rejects duplicate keys, whitespace, alternate key order, trailing data, BOM, malformed UTF-8, unapproved fields and ambiguous representations. Snapshot digest binds the exact prior head, observed head, pending record index/digest, raw pending byte digest, observed state, decision digest and caller-provided observation time. `pending-only` retains the prior head; `linked-pending` derives the observed head from the pending record digest and index. The observation time is **caller-supplied and not independently trusted**.

The immutable result always reports `requiresIndependentResolution: true`, `authorizesRepair: false`, `authorizesProduction: false`, `independentlyWitnessed: false`. Historical verification does not re-check the current journal filesystem. To compare with current local evidence, perform a fresh authorized export and compare it against **independently retained** pins; the signed decision may need a new time-bounded authorization. No automatic repair is implemented.

## Threat model and remaining gates

The exporter inherits the single-Linux-host locking, local filesystem ownership, permission and hardlink assumptions of Objective 32X. It cannot detect hostile privileged filesystem mutation during an inspection, compromised signing keys, dishonest local clock, independently omitted historical evidence without a trusted external anchor, or cross-host equivocation. External anchor publication, protected signing keys, trusted timestamps, hosted identity, immutable offsite evidence, distributed atomic recovery, manufacturing approval and actual Shopify checkout/order reconciliation are still absent.

No Shopify reads/writes, hosted authentication, customer data, paid services or deployment are involved. Synthetic Ed25519 fixtures are used for adversarial tests.
