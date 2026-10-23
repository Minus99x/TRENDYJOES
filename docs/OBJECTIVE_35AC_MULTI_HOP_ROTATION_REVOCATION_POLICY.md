# Objective 35AC — Offline multi-hop observer rotation and revocation boundaries

**Read-only prototype; no hosted witness, customer identity, trusted time, Shopify mutation, or production authority.**

`src/preview-local-artwork-review-rotation-lineage.mjs` composes the existing 35AA signed receipts and 35AB dual-Ed25519 key transitions. It does **not** alter the existing receipt, journal, editor, 2D/3D preview, GLB import or calibration implementation.

## Contract

- `digestLocalReviewRevocationPolicy(policy)` hashes a canonical, strict, versioned policy. `revision` must be a positive safe integer; revoked key fingerprints and rotation digests must be unique, lexically sorted lowercase SHA-256 hex strings. The policy is **not** a trusted authority: it is supplied by the caller, with an expected digest pinned separately. No timestamp-based exceptions or automatic reauthorization.
- `exportLocalReviewRotationLineage` validates 1–16 consecutive rotations, each with independently verified old/new receipt signatures, both rotation signatures, one observer/root, a preserved complete journal prefix, strictly continuous predecessor receipt digests and key fingerprints, and no reused key ID/fingerprint or transition digest. Every key/rotation appearing in a supplied revocation list fails closed, including historical ones. The first receipt digest, first key fingerprint, root and policy digest must be supplied by the caller as anchors. Returns deterministic canonical UTF-8 JSON and its SHA-256 for external retention; it does not independently store or witness anything.
- `importLocalReviewRotationLineage` requires a separately retained bundle SHA-256, first receipt digest and first key fingerprint, **last receipt digest and last key fingerprint**, root pin and revocation-policy SHA-256. It rejects mismatched bytes, noncanonical JSON, duplicated fields, forged signatures, changed keys, history forks, rollback, replay, policy downgrade/substitution relative to the caller's external policy digest, and revoked keys or transitions. It never grants Shopify write authority.

## Local-only example

```js
const policy={schema:LOCAL_REVIEW_REVOCATION_SCHEMA,revision:1,
  revokedKeyFingerprints:[],revokedRotationDigests:[],authority:'NONE'};
const expectedPolicySha256=digestLocalReviewRevocationPolicy(policy);
const exported=await exportLocalReviewRotationLineage({
  hops:[{previousReceipt:r0,successorReceipt:r1,rotation:rot01},
        {previousReceipt:r1,successorReceipt:r2,rotation:rot12}],
  expectedRootPin,resolveObserverPublicKey,
  expectedInitialReceiptDigest:r0.receiptDigest,
  expectedInitialKeyFingerprint:initialKeyFingerprint,
  policy,expectedPolicySha256
});
// Retain exported.sha256, initial/final receipt digests, initial/final key
// fingerprints and expectedPolicySha256 in independently controlled storage.
const verified=await importLocalReviewRotationLineage({
  bytes:exported.bytes,expectedSha256:exported.sha256,
  expectedRootPin,resolveObserverPublicKey,
  expectedInitialReceiptDigest:r0.receiptDigest,
  expectedInitialKeyFingerprint:initialKeyFingerprint,
  expectedTerminalReceiptDigest:r2.receiptDigest,
  expectedTerminalKeyFingerprint:terminalKeyFingerprint,
  policy,expectedPolicySha256
});
```

## Explicit limits

External anchors, authenticated public-key registry, independent key custody, independent policy provenance and revocation freshness **must** be provided by a separately trusted system. A caller may pass all anchors from the same compromised source; this library cannot prove independence. A compromised old key cannot be safely rotated without an external recovery authority. This policy **conservatively rejects every lineage containing a currently revoked key**, including historical signatures: it does not implement historical-validity windows, trusted timestamps, key recovery, reinstatement or retroactive revocation proof. A caller-supplied policy digest does not prove monotonic revision or that the policy was externally retained. A forged but internally consistent history cannot be detected without separately trusted anchors. This is **not** a manufacturing, cart, checkout, order, hosted authentication or Shopify deployment contract.

Run `node --test tests/objective35ac-rotation-lineage-revocation.test.mjs` then the complete Node regression. No network, Shopify credentials or user data are used.
