# Objective 31K — portable, independently verified forensic publication review

**OFFLINE / DEVELOPMENT ONLY.** This module does not perform recovery, authorize a retry, clear a pending marker, sign a transaction, deploy a witness, or verify actual offsite retention.

## Purpose

A crash between outbox PREPARE, signed publication commit, and witness ACK creates a deliberately ambiguous state. Previous releases already refused automatic reconciliation; this release provides a **portable, data-only evidence envelope** and a **pure verifier** that can classify the uncertainty without changing any of the three underlying stores.

## New APIs

`createOfflineForensicPortableReviewBundle({registryId,anchorType,forensicEvents,publications,transitionCertificates,outboxEvents,declaredHeads})` creates a JSON-serializable `{payload,transportDigest,productionApproved:false}`. `transportDigest` is an ordinary SHA-256 checksum for accidental corruption detection, **not** a signature, remote retention receipt, or trusted head. The envelope has an 8 MiB cap. The caller must acquire snapshots from the journal, publication store, and outbox using their `inspectHistory` methods. The new outbox `inspectHistory({expectedOutboxHead})` refuses pending markers, corrupt files, gaps and mismatched externally pinned heads.

`verifyOfflineForensicPortableReviewBundle({envelope,independentPins,trust})` is pure, offline and read-only. `trust` contains the independently obtained registry/anchor identity, witness Ed25519 public keys, witness quorum, historical reviewer policies, and historical reviewer epochs (including `readLatest` functions required by the existing reviewer validation interface). `independentPins` must be a separately retained `{forensic:{count,headDigest},publication:{count,headDigest},outbox:{count,headDigest}}` object. **Never derive either trust or independentPins from the untrusted bundle**. All publication signatures, certificate transitions, forensic evidence digests, reviewer signatures, outbox chain hashes, and witness ACK signatures are verified with existing strict validators.

The result always has `readOnly:true`, `mayRetry:false`, `mayAcknowledge:false`, `mayDeletePending:false`, and `productionApproved:false`. `CONSISTENT_READ_ONLY` is **not** permission to proceed. Other classifications: `EMPTY_VERIFIED_NO_AUTHORITY`, `PREPARED_UNCERTAIN_REVIEW`, `PUBLISHED_UNACKNOWLEDGED_REVIEW`, `ORPHAN_PUBLICATION_REVIEW`, `MISSING_PUBLISHED_HISTORY_REVIEW`, `PUBLICATION_SUBSTITUTION_REVIEW`, `COUNT_MISMATCH_REVIEW`, and `UNPUBLISHED_FORENSIC_REVIEW`. Cryptographic/pin/format failures throw instead of returning a misleading review classification.

## Forensic handling procedure

1. **Quiesce writers externally**; capture forensic journal, signed publication, and outbox snapshots without modifying the stores. Capture any `.pending.json` and kernel/filesystem forensic state separately, with an operator-controlled chain of custody. Never delete a pending marker to make export succeed. The outbox API intentionally refuses a pending marker.
2. Obtain trust keys, reviewer policies, and all three expected heads from an **independent preexisting source** (separately retained witness record, not the local disk or bundle). If independent head evidence is missing, mark review **unverifiable**, not successful.
3. Assemble the portable JSON envelope, hash and preserve the raw bytes, then transfer it over a controlled channel. Treat all included timestamps as untrusted local assertions unless independently timestamped.
4. Independently verify using `verifyOfflineForensicPortableReviewBundle`. Save the exact envelope hash, verifier version, trust-key digests, independently pinned heads, outcome, and original crash/process logs in an append-only external case file.
5. Any `_REVIEW` classification, pending marker, mismatch, or failed verification requires human forensic adjudication against separately retained evidence. Do not automatically replay PREPARE, publish, ACK, delete, rename, restore, or issue another recovery authorization. Even `CONSISTENT_READ_ONLY` does not confer authorization.

## Important limitations

- Exporting three stores is not an atomic snapshot. A concurrent writer can cause a mismatch; this is evidence for review, not proof of wrongdoing. Quiesce writers and retain acquisition order and times.
- No trusted timestamp, offsite/WORM retention, protected production key custody, remote witness deployment, global monotonic head, or distributed atomic commit is implemented.
- No production authentication, Shopify mutation, checkout, payment, or manufacturing release authorization.
- A local attacker who controls both the local history and the supposed external trust/pins can still forge a consistent-looking bundle. The verifier cannot prove that an operator truly obtained trust independently.
- The verifier cannot determine a real-world recovery outcome from signatures alone; independent forensic review remains necessary.

## Reproduction

```sh
node --test tests/objective31k-portable-review.test.mjs
node --test --test-concurrency=4 tests/*.test.mjs
```

All tests use synthetic keys, offline fixtures, and isolated temporary directories; one test terminates a real child process after durable outbox PREPARE commit. No live network, Shopify, or customer operations are involved.
