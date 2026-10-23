# Objective 35AB — offline dual-key observer rotation and externally retained pin import

This opt-in **read-only local prototype** extends 35AA signed journal-head receipts. It does not change 35AA receipt format or the 35Z append-only journal.

`src/preview-local-artwork-review-observer-rotation.mjs` provides:

- `createLocalReviewObserverKeyRotation`: verify two 35AA signed receipts for the same observer, different Ed25519 key IDs and distinct public-key fingerprints; require the successor to begin a new key-specific receipt sequence at 1 and retain the entire prior signed journal history; sign one domain-separated transition with **both** old and new private keys. Check each signature against a **caller-trusted** resolver. A rotation at the same journal head is allowed; a shorter or forked history is not.
- `verifyLocalReviewObserverKeyRotation`: revalidate both receipts and both transition signatures, exact signed root/observer/key IDs, fingerprints and receipt digests. Fail closed for untrusted keys, tampering, fork, rollback and mismatched signing keys.
- `exportLocalReviewRotationPin`: produce deterministic canonical UTF-8 JSON bytes and SHA-256 digest for out-of-band retention. It writes **no file**, does not publish anything, and never exports private keys.
- `importLocalReviewRotationPin`: require the separately retained SHA-256 and separately retained prior receipt digest from the caller; check exact canonical JSON, root, all Ed25519 signatures and extension. This prevents an attacker changing the bundle without also changing the **external** anchors. The implementation cannot establish that the caller actually retained those anchors independently.

## Offline example

```js
const transition=await createLocalReviewObserverKeyRotation({
  previousReceipt,successorReceipt,oldSigningKey,newSigningKey,
  resolveObserverPublicKey,expectedRootPin
});
const bundle=await exportLocalReviewRotationPin({
  rotation:transition,previousReceipt,successorReceipt,
  resolveObserverPublicKey,expectedRootPin
});
// Operator stores bundle.bytes, bundle.sha256 and previousReceipt.receiptDigest
// separately, outside the journal, in independently controlled storage.
const verified=await importLocalReviewRotationPin({
  bytes:bundle.bytes,expectedSha256:bundle.sha256,
  expectedPreviousReceiptDigest:previousReceipt.receiptDigest,
  expectedRootPin,resolveObserverPublicKey
});
```

## Explicit limitations

Both private keys must be available to the operator at the transition. A lost or compromised old key cannot be safely rotated by this API without separate trusted recovery. Dual signatures do not prove independent key custody, trusted time, revocation, a hosted witness, offsite publication or independent retention. The caller's public-key resolver must be authenticated and enforce key-ID uniqueness, historical pinning and **revocation policy**; this module does not maintain a global revocation registry. If the prior receipt itself was never externally pinned, the import does not establish an independent origin. A compromised external digest store can substitute both bundle and anchors. Signed same-head transitions cannot prove that the journal did not fork elsewhere. Future multi-hop rotation requires externally anchored ordered transition history; this release validates **one** transition and does not silently accept a chain.

No hosted authentication, real customer data, manufacturing approval, product activation, checkout/order reconciliation, Shopify theme changes or production writes. All return values deny production and Shopify authority. The existing editor, 2D/3D model import and calibration, universal merchandise and mid-century branding are unchanged.

Run `node --test tests/objective35ab-observer-rotation-pins.test.mjs` and the full Node test suite. No network required.
