# Objective 31L — signed retention receipts and portable acquisition provenance

**Offline, data-only contract. Not production authorization.**

`src/offline-forensic-acquisition-provenance.mjs` adds an independently authenticated retention-head history and a portable forensic acquisition manifest. This does not implement remote witness deployment, offsite retention, a trusted timestamp, production key management, a distributed transaction, or a guarantee that a signer actually observed the source system.

## Acquisition protocol (operator contract)

1. Establish independent trusted registry ID, anchor type, retention-witness Ed25519 public keys, majority quorum, reviewer/witness policies, and forensic/publication/outbox head pins. These are **not** copied from the manifest or exporter.
2. Have the independent retention quorum sign a **PRE** receipt binding the registry, acquisition ID, observed head triple, prior retention receipt digest, monotonic receipt index and observation time. Its bundle digest must be the all-zero sentinel.
3. Acquire the portable forensic bundle using existing Objective 31K safe inspection. Never clear a `.pending.json` crash marker to make inspection succeed. The source must provide an independently verified snapshot; no claim of atomic cross-store acquisition is made.
4. Have the retention quorum independently re-observe all three heads and sign a **POST** receipt with the exact portable bundle's transport digest. If any head changes, reject the acquisition and preserve evidence for review. PRE/POST cannot substitute an acquisition ID.
5. Retain the signed append-only receipt history and its latest `(count,headDigest)` **independently**. A local JSON file alone is not a trusted independent pin; no offsite retention is supplied here.
6. Build a transport manifest with `createOfflineForensicAcquisitionManifest`. Verify it using `verifyOfflineForensicAcquisitionManifest`, supplying independent receipt head, independent forensic pins and trusted public-key policies as **separate parameters**. The verifier first checks the entire signed retention history, then binds the final PRE/POST pair to the portable envelope, then runs the full Objective 31K cryptographic forensic review.

`offlineAcquisitionReceiptSigningBytes(body)` is the domain-separated Ed25519 signing contract. Private keys are never accepted by the library. `createOfflineAcquisitionReceipt` assembles externally signed receipts; it does not sign. The receipt chain binds each signed record's previous digest. Each pair has a unique acquisition ID; observed timestamps must increase but are **not trusted clock attestations**. Subsequent acquisitions cannot roll back a retained head count or change the digest at an unchanged count. The independent latest retention head is essential to detect an otherwise valid prefix rollback.

## Failure policy

Forged, duplicate, insufficient, wrong-key or noncanonical signatures, malformed records, PRE/POST mismatches, source-head changes, repeated acquisition IDs, rollback, replay, wrong external pins and envelope tampering fail closed. Incomplete PRE-only acquisitions are not verified as complete. A valid manifest yields a **read-only classification**, not permission to retry, acknowledge, clear pending markers, manufacture, check out, or deploy.

The retention signers are a proposed independent service integration boundary. Local test keys are synthetic. A compromised majority of independent retention keys or a malicious signer can fabricate assertions. Head observations are not atomic across resources. A separately anchored monotonic log, protected keys, trusted timestamping, offsite retention, independent service operations and forensic review remain prerequisites for higher assurance.

## Reproduce

```sh
node --check src/offline-forensic-acquisition-provenance.mjs
node --check tests/objective31l-acquisition-provenance.test.mjs
node --test tests/objective31l-acquisition-provenance.test.mjs
node --test --test-concurrency=4 tests/*.test.mjs
```

The composite verifier also rejects reuse of retention signing public keys as forensic publication witness or historical forensic reviewer keys. This is an offline separation-of-duties contract, not proof that real people or machines are independent.
