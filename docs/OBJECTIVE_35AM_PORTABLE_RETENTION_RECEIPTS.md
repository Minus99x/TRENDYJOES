# Night Watch Objective 35AM — portable append-only retention receipts

**Release v0.30.135 — OFFLINE ONLY. No Shopify reads or writes.**

Objective 35AM adds `src/preview-local-artwork-retention-receipts.mjs` and adversarial tests for **canonical, domain-separated Ed25519 receipts** of externally pinned historical epoch-provenance checkpoints. This is a portable evidence protocol, not a hosted retention service, and does **not** independently verify epoch provenance: callers must first use the Objective 35AL issuer-signed continuity verifier with separately retained pins. Never use this receipt layer as a substitute for the 35AL verifier.

## API and external custody contract

`createOfflineRetentionReceipt({streamId,sequence,observedAtMs,retainUntilMs,checkpoint,previousReceiptSha256,signingKey,publicKey})` emits `{bytes,sha256,signerFingerprint}`. `checkpoint` is exactly `{epoch,provenanceSha256,evidenceSha256,headSha256}`. Each signed canonical payload includes a stream ID, increasing sequence, observation and retention expiry times, the previous receipt SHA-256 (64 zeroes at genesis), and `authority:'NONE'`. Each receipt is signed using a domain-separated Ed25519 signature. Private keys belong only in an isolated trusted issuer, **never in browser/editor bundles**.

`verifyOfflineRetentionReceiptWindow({receiptBytes,externalPins,signerPublicKey,pruneCertificateBytes})` verifies a dense 1–128-receipt window. `externalPins` must be an **independently authenticated object**, not read from `receiptBytes` or a matching attacker-controlled archive:

- `mode`: `genesis`, `append`, or `pruned`.
- `streamId`, `signerFingerprint`, `trustedNowMs`.
- `expectedHead`: `{sequence,receiptSha256}`.
- `expectedAnchor`: `null` for genesis; otherwise `{sequence,receiptSha256,observedAtMs,retainUntilMs}` for the immediate predecessor.
- `expectedCheckpoints`: one per receipt, each `{checkpoint,observedAtMs,retainUntilMs}` with the exact checkpoint fields above.

A `genesis` window starts at sequence zero and must reach the independently pinned head. An `append` window must start exactly after the independently pinned anchor, and verifies the signed suffix; it **does not** prove earlier history. A `pruned` window additionally requires `createOfflineRetentionPruneCertificate(...)` evidence signed by the same independently pinned Ed25519 key, identifying the precise anchor sequence, hash, retention expiry, pruning time and first retained sequence. Pruning is rejected until the **independently trusted clock** passes the anchor retention deadline. Current window receipts must remain unexpired; expired windows fail closed. Strict SHA chaining, increasing sequence/time, canonical UTF-8/JSON, external checkpoint pin equality, head matching, signature/key validation, and schema/shape limits are enforced.

## Explicit non-guarantees and threat boundaries

- The protocol does **not** store receipts externally or establish that the caller has retained independent pins. Compromised pins or a compromised signing key defeat its assurances. The signer can create multiple signed forks; this verifier detects only a fork that conflicts with presented external pins, not undisclosed branches or cross-host consensus.
- A signed prune certificate and trusted anchor prove a **bounded suffix**, not the authenticity of an omitted prefix. The output deliberately sets `prunedPrefixVerified:false` and `completeHistoryVerified:false` for append/pruned modes. Do not call this a globally append-only database.
- Time is caller-supplied and not independently attested; offline test clocks are synthetic. This code has no replay-consumption registry, durable multi-host write lock, key rotation, actual external custody, customer authentication, hosted order lineage, GLB/manufacturing approval, or Shopify integration.
- The result explicitly includes `independentCustodyVerified:false`, `trustedClockIndependentlyVerified:false`, `authorizesProduction:false`. No cart, checkout, production, sales or manufacturing permission can be derived from these receipts.

## Reproduce

```sh
node --test tests/objective35am-retention-receipts.test.mjs
node --test tests/objective35aj-epoch-observer-evidence.test.mjs tests/objective35ak-epoch-transition-provenance.test.mjs tests/objective35al-retained-epoch-continuity.test.mjs tests/objective35am-retention-receipts.test.mjs
npm test
npm run preview:assets:check
npm run preview:static:assets:check
npm run preview:staging:check
node scripts/build-main-staging-reconciliation.mjs --check
```

The full Node corpus can exceed an execution time limit when invoked as one monolithic `npm test`. If so, execute **every** `tests/*.test.mjs` independently in bounded batches and retain all TAP logs. A timeout is not a successful test. This release remains an **offline prototype** and must be explicitly reconciled with Main Engineering's independently protected staging assets before any future authorized integration.
