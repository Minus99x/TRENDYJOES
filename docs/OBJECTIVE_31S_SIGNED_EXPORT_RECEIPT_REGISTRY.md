# Objective 31S — signed export-receipt registry (offline only)

This module adds a **durable, append-only local registry** of independently Ed25519-quorum-signed export receipts. It builds on Objective 31R's deterministic, bounded transport format and does **not** replace the underlying 31Q cryptographic acquisition-evidence verifier. No Shopify, browser, network, customer, production or manufacturing authority is involved.

## Integration contract

Import `createOfflineExportReceiptRegistry`, `offlineExportReceiptPolicyDigest`, `offlineExportReceiptSigningBytes` and `verifyOfflineExportReceipt` from `src/offline-acquisition-export-receipt-registry.mjs`. The caller must provide a private Linux directory, a stable registry ID, an **independently authenticated** witness public-key set (2–12 distinct Ed25519 keys, strict-majority quorum), a separately pinned `{count,headDigest}` and an independently trustworthy `nowMs` for each append. The registry never accepts private keys or generates its own signing authority. Construct a receipt body with schema `TJ-OFFLINE-ACQUISITION-EXPORT-RECEIPT-1`, registry ID, sequential index, prior head digest, unique export/acquisition IDs, exact SHA-256 and byte count of the 31R archive, issued/expiry timestamps (max seven days), unique nonce, and the policy digest. Sign the bytes returned by `offlineExportReceiptSigningBytes(body)` with a quorum of external keys; supply sorted `{witnessId,signature}` records.

`append({receipt,archiveBytes,expectedHead,nowMs})` first verifies the external head, receipt quorum and time, replay identifiers, and the **actual** 31R archive bytes using `verifyOfflineAcquisitionEvidenceExport`. Only then does it create a durable hash-chained registry record. `inspect({expectedHead})` independently verifies every persisted receipt's signatures, chronology, replay constraints and record chain against the supplied pin. Historical signatures remain verifiable after their issuance window expires, but no expired receipt can be newly appended. Both methods return non-authoritative offline-only results. The caller must store the **new head outside this mutable local directory** before treating it as an independent pin. Local storage alone cannot detect a complete coordinated rollback to an old head.

## Durability and security properties

- Owner-private Linux directory (0700), single-link regular files (0600), `O_NOFOLLOW`, inode checks, bounded canonical JSON, exact numbered file enumeration.
- Cross-process **held** `/usr/bin/flock` lock via child process and pipe throughout the full critical section, not a one-shot flock check.
- Exclusive `.pending.json` creation, file `fsync`, directory `fsync`, atomic rename to `0001.json`, directory `fsync`; no silent retry if a pending marker survives a crash. After committed fsync, a crash leaves a verifiable signed record. Manual investigation is required to resolve an uncertain pending operation; the API deliberately does not auto-repair it.
- Rejects forged/duplicate/minority signatures, unknown signers, trust substitution, modified receipt body, stale head, altered archive, incorrect acquisition binding, duplicate acquisition/export/nonce/digest, and unexpected filesystem entries.
- Per-registry witness policy is fixed; key rotation must be designed and independently verified before production. Test keypairs are ephemeral and never written into the archive.

## Limits and remaining gates

This is a **local offline prototype**. Signature validity proves that supplied keys signed the receipt, not that witnesses are independent, that a remote observer saw the evidence, or that the underlying acquisition claims are true. The caller must obtain public keys and time from independently trusted sources and separately run 31Q underlying forensic verification. Local flock/fsync is not WORM or offsite retention. Same-UID filesystem attackers, storage corruption, power-loss guarantees of the host filesystem, trusted timestamps, multi-resource atomicity, witness deployment, policy rotation, and production recovery are outside this objective. No release, manufacturing, payment, checkout, or Shopify authorization is conferred.

Reproduce: `node --test tests/objective31s-export-receipt-registry.test.mjs`; `npm test`.
