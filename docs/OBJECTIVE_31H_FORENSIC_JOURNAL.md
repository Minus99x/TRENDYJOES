# Objective 31H — Durable offline forensic review journal

**Scope:** Optional Linux-only offline security prototype. **Not production authorization, not WORM storage, not independent reviewer deployment.** This is distinct from Main Engineering's v0.32 interface development.

## Purpose and trust boundaries

`createOfflineForensicReviewJournal` records the **complete signed 31G forensic reviewer receipt bundle**, canonical reservation history, anchor snapshot, and the **actual synthetic case/outcome evidence bytes**. SHA-256 checks bind those bytes to the reviewer-signed case and outcome digests. Each event has a monotonic index, previous-event digest, and domain-separated event digest. Every inspection revalidates **all** prior events and the original Ed25519 reviewer quorum against the recorded observation time. Expired historical signatures remain verifiable because the recorded time is checked against their signed validity window.

`inspectWitnessed({witnesses,quorum})` requests fresh 256-bit challenges from independently configured Ed25519 witnesses, requires a strict-majority quorum and no equivocation among supplied receipts, then rechecks the local head to detect concurrent changes. Reviewer keys cannot be reused as journal witness keys; callers must independently retain witness heads and signing keys. If all local files are rolled back, only an **externally preserved** head can detect it. The test witnesses are **in-memory simulations**, not independently operated services.

## API

```js
const journal=createOfflineForensicReviewJournal({
  directory:'/private/synthetic-forensic-journal',registryId,anchorType:'registry',
  reviewers,reviewQuorum:2,excludedKeys:[]
});
const before=await journal.inspectWitnessed({witnesses,quorum:2});
await journal.append({
  review:{history,anchor,caseDigest,outcomes,authorizationDigest,challenge,receipts},
  caseEvidence:Buffer.from('synthetic case evidence'),
  outcomeEvidence:[Buffer.from('synthetic outcome evidence')],
  expectedHead:{count:before.count,headDigest:before.headDigest}
});
```

The opt-in `createOfflineRecoveryReconciliationGuard` integration accepts `forensicJournal`, `forensicWitnesses`, and `forensicWitnessQuorum`. When enabled, reviewed recovery also requires `forensicEvidence:{caseEvidence,outcomeEvidence}`. The guard independently verifies the journal head, obtains fresh reviewer signatures, rechecks anchor/ledger state, **fsyncs the signed forensic record before reserving the recovery permit**, then reserves the permit before attempting recovery. If a crash occurs after forensic append but before ledger reservation, replaying the **same permit** is forbidden by the journal. A fresh signed permit and a new independent review are required. If the journal crashes with `.pending.json`, it **blocks all operations** until human forensic review; it never auto-repairs ambiguous state.

## Security properties tested

- Exact signed reviewer quorum; invalid signatures, missing reviewers, forged identity, expiry and cross-key reuse rejected.
- Real case and outcome evidence byte digests; substituted/missing evidence rejected.
- Monotonic index, chain digest, strict file mode/ownership, symlink protection, history gap and replay rejection.
- Crash durability via write, file fsync, directory fsync, atomic rename, directory fsync and process-level `flock`.
- Actual child-process exits after pending fsync and after committed fsync; competing independent child processes.
- Fresh challenge-bound independent journal witness receipts, stale head and prefix/full rollback detection with externally pinned witness state, and concurrent change detection.
- Recovery guard refuses missing evidence, persists journal first, and prevents same-permit replay when ledger reservation fails after journal fsync.
- Existing 31G behavior unchanged when journal is not explicitly enabled.

## Important limits and remaining gates

- No deployed reviewer/witness services, independent key custody, offsite monotonic head retention, trusted time source, WORM medium, or global anti-rollback. Root/admin access can replace local files and clocks; signed evidence is **an attestation**, not proof of real-world facts.
- No atomic distributed transaction across forensic journal, recovery authorization ledger, and anchor. Ambiguous failures **fail closed**; manual forensic review and a **fresh** permit are required. Do not delete `.pending.json` or hand-edit journal files as a workaround.
- No safe operator tooling for independently publishing heads or retention policies. A reviewer key rotation needs explicit historical-key preservation and versioned trust policy. Data limits are 1 MiB per event, 512 KiB evidence bytes per event, 1000 events; resource exhaustion fails closed.
- No customer information, Shopify credentials, production secrets, production writes, live order activity, or storefront deployment should enter this prototype.

**Next Objective 31I:** offline historical reviewer-key rotation and independent witness-head publication/retention contracts with signed checkpoints, recovery evidence export, and adversarial rollback tests. Production gates remain closed.
