# Objective 32W — Local, fail-closed manifest acceptance journal

**Offline-only prototype.** `src/offline-conflict-resolution-manifest-journal.mjs` implements an opt-in, single-Linux-host, `flock`-serialized manifest acceptance journal. It wraps **actual Objective 32V signed chunk transport verification**, requiring independent 32V manifest, session and transport pins and downstream 32U/32T/32S observer, union, proof and Ed25519 checks. The caller's replay Set is replaced with the journal's verified on-disk inventory. This is not a trusted identity provider, hosted service, independent anchor, recovery authorization, Shopify integration, or production gate.

## API and trust boundaries

`offlineConflictManifestJournalGenesisHead()` yields a deterministic initial head. `createOfflineConflictManifestJournal({directory,lockTimeoutMs,injectFault})` returns `inspect({expectedHead})` and `claim({verificationArgs,expectedHead})`. The **caller must retain the last returned head outside the writable journal directory** and provide it for each operation. Do not take a new expected head from the same possibly compromised directory. `claim` verifies the full signed evidence *under the cross-process lock* before accepting. It stores only the SHA-256 manifest/transport pins, session, chunk count and linked record hashes; raw evidence, signing keys, customer data, and bearer credentials are not persisted.

Each append creates a mode-0600 `.pending.json` with `O_EXCL|O_NOFOLLOW`, fsyncs it and its directory, hard-links it to the numbered record, fsyncs the directory, removes the pending marker, and fsyncs again. The lock is a mode-0600 regular file and uses `/usr/bin/flock`; no unsafe in-memory fallback is provided. The directory must be private, owned by the running user, and canonical. Numbered records must be owner-only, regular, single-link files. Hash-chained sequence, uniqueness of manifest digest, **transport digest** and session ID, exact JSON bytes and caller-pinned head are checked at each access.

If a crash occurs with `.pending.json` present (before or after hard-link), **all subsequent inspection and claims fail closed**. No automatic repair or replay is attempted. A crash after the final fsync can leave a committed entry even when the caller lost its acknowledgement; the previous external head then fails closed. The next objective should address independently authorized adjudication with immutable evidence, rather than silently deleting markers. Local fsync does not prove remote durability or hardware honesty.

## Reproduce

```sh
node -v
node --test tests/objective32w-manifest-journal.test.mjs
npm test
```

## Explicit exclusions

No external monotonic witness or published anchor; no protected reviewer keys, trusted timestamp, globally atomic claim, hosted authentication, approved manufacturing geometry, real checkout/order reconciliation, or production authorization. Concurrent claims are serialized **only on one cooperating Linux filesystem/host**; do not assume safety on distributed/NFS mounts or against privileged filesystem attackers. A locally verified acceptance does not prove recovery completion. No Shopify reads or writes.

## Regression stability repair

During the first independent ZIP clean extraction, an existing Objective 32O negative signature test failed intermittently: the test overwrote the first base64url signature character with `A`, which was already `A` for that randomly generated key/signature. The same nondeterministic corruption existed in Objective 32N. Both negative tests now flip the first character to a *different* valid base64url character, guaranteeing a forged signature rather than occasionally leaving the original signature unchanged. The final archive must pass a fresh full-suite and independent clean-extraction run.
