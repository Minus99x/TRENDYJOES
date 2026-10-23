# Objective 32G — Offline portable witness receipt continuity and migration

**Version:** 0.30.34 (offline QA only). **Not a deployed witness service.**

## Deliverable

`src/offline-portable-replay-witness-history.mjs` implements an opt-in read-only verifier for a **bounded, externally pinned window** of consecutive Objective 32F witness receipts and their complete Objective 32E checkpoint/audit bundles. Each receipt is re-verified using the existing 32F cryptographic verifier; receipt `previousWitnessReceiptDigest` links are exact, sequence numbers have no gaps, registry/genesis identity is stable, and receipt observation times, historical commit counts and checkpoint sequences cannot regress.

A domain-separated SHA-256 history digest binds the ordered receipt digest, sequence, witness policy digest and transition digest for every entry. Caller MUST supply independently retained start predecessor, start/end sequence, final receipt head, history digest, and genesis pins. Supplying locally recomputed values does not establish independent publication or rollback resistance. The function does not claim full history back to genesis when verifying a window starting at sequence 19, or any other non-genesis start.

## Witness policy migration

Each transition is a strictly shaped, domain-separated, Ed25519-signed certificate containing registry, first incoming receipt sequence, previous receipt digest, outgoing/incoming policy digests and claimed observation time. The verifier requires **both** a majority of the outgoing policy and an independent majority of the incoming policy (proof of possession). All signers must be unique and sorted, and the incoming policy cannot reuse any outgoing Ed25519 public key. Each policy digest and transition digest is independently supplied as a pin; policy epochs must be visited in order without skips or unused policies. Existing 32F constraints also prevent witness keys from doubling as historical auditors/reviewers.

The transition timestamp is an attested integer, **not a trusted clock**. It must lie between the last outgoing and first incoming signed receipt observations. Verification never writes a receipt, updates an anchor, rotates a real key, or performs any network operation.

## Threat model and regression

`tests/objective32g-witness-history.test.mjs` exercises normal three-receipt continuity and a dual-quorum rotation, same-policy continuation, omission, replay, reordering, duplicate receipts, re-signed forks, wrong external head/history/genesis pins, sequence gaps, forged signatures, substituted witness keys, missing/forged transition evidence, minority and duplicate quorums, policy overlap, stale timestamps, wrong epoch and forbidden production claims. Uses synthetic Ed25519 keys only. `npm test` also reruns all prior 2D/3D editor, GLB, geometry, order, storage and security regressions.

## Reproducibility

```sh
node --version
node --test tests/objective32g-witness-history.test.mjs
npm test
```

## Explicitly unfinished

Independent witness deployment, external monotonic pin publication, independently protected signing keys, trusted timestamps, immutable offsite retention, independent archival custody, production authentication, and atomic cross-resource recovery. This verifier returns `independentlyPublished:false`, `fullGenesisHistoryVerified:false`, `authorizesRemediation:false`, `authorizesCheckout:false`, `productionApproved:false`. No Shopify reads or writes; no staging edits; no real customer data; no manufacturing or checkout authority.

## Next objective

32H — offline bounded witness-history checkpoint portability and independent external-anchor import/export verification (strictly local files and fixtures), including crash-safe **read-only** verification of stale or conflicting checkpoint candidates. Do not implement hosted publication, make Shopify changes, or silently trust local pins.
