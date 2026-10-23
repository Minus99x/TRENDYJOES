# Objective 31V — durable one-epoch export-receipt witness cutover

**Scope:** offline Linux prototype, no Shopify access, no hosted authentication, no manufacturing authorization.

## What changed

`createOfflineExportReceiptCutoverRegistry` upgrades an existing **Objective 31S** receipt-record directory from one Ed25519 witness policy to a separately supplied second policy, without rewriting any existing signed receipts. It reuses the exact `.export-registry-lock` Linux `flock` critical section and existing numbered signed receipt records. Existing 31S code is not modified; once cutover is committed, 31S's original registry deliberately fails closed on the new certificate file rather than accepting records under retired keys.

`cutover({transition,expectedHead,expectedTransitionDigest,nowMs})` verifies a canonical Objective 31U transition certificate, outgoing witness quorum, proof of possession from **all** incoming witnesses, distinct witness identities and keys, original 31S chain head, strictly bounded issuance/expiry, and the **independently supplied** SHA-256 transition-chain digest. It writes a private pending file, fsyncs file and directory, creates a non-overwriting hardlink to the committed certificate, fsyncs, unlinks the pending marker, and fsyncs again. Crashes between phases leave a marker that blocks all subsequent reads/writes; recovery requires explicit external reconciliation, not silent repair.

`append({receipt,archiveBytes,expectedHead,expectedTransitionDigest,nowMs})` verifies every historic record against its correct epoch policy, checks the pinned transition, enforces retired-key rejection and replay sets across both epochs, verifies the actual acquisition-export bytes against the signed digest, and performs the same crash-consistent non-overwriting hardlink commit. `inspect` requires the independent receipt-head and transition-digest pins. No method stores signing keys, infers trusted pins from the local directory, repairs ambiguous commits, or grants production authority.

## Operational contract and limitations

- Caller must provide **trusted** public keys for both epochs, receipt head from outside the registry directory, pinned transition digest from outside the registry directory, and a trusted `nowMs`. The returned head must be durably retained by the caller independently **before** any later mutation. The code cannot guarantee that external retention happens.
- This implementation supports **one** policy transition, epoch 0 → 1, not an arbitrary rotation chain. It requires an existing signed receipt (`head.count >= 1`). Multi-transition durable policy migration remains future work.
- Only Linux, local owner-only directory/files and `/usr/bin/flock` are supported. Not safe for untrusted local processes with the same OS UID, adversarial privileged users, remote/network filesystems, or untrusted key custody.
- A transition's expiration is enforced when committing it; subsequent historical verification accepts a previously committed valid certificate after expiration, without authorizing new actions.
- Crash-uncertain pending records require an independently supervised recovery procedure; none is provided. Multi-resource atomicity, protected witness keys, trusted timestamps, offsite immutable storage, real production evidence authenticity and hosted auth remain unproven.
- All outputs explicitly indicate `productionApproved: false` and `mayManufacture: false`. Nothing touches Shopify or Main Engineering's separate v0.32 UI.

## Reproduce

```sh
node --test tests/objective31v-export-receipt-policy-cutover.test.mjs
node --test --test-concurrency=4 tests/*.test.mjs
```

Adversarial tests include forged outgoing/incoming signatures, retired-key reuse, replay across epochs, stale external pins, archive substitution, symlink/hardlink attacks, child-process SIGKILL before/after both durable commits, uncertain hardlink window, and two independent Node processes racing the same signed receipt.
