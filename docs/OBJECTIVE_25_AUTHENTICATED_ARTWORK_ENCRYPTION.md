# Objective 25 — Offline private artwork encryption at rest

**Scope:** Local Linux prototype only. No Shopify, hosted authentication, production key management, or physical manufacturing authorization.

## Opt-in configuration

`createOfflinePrivateRevisionRegistry({...existingOptions, encryption: {activeKeyId: 'key-2026-alpha', resolveKey(keyId) { return trustedKeyProvider(keyId); }}})`

`resolveKey` is a **synchronous** key-custody seam returning an independently protected 32-byte Buffer for the requested ID. The caller must retain old keys until all assets are rotated. Keys are not persisted in registry JSON. The existing HMAC `secret` is **separate** from encryption keys and should not be reused. A production key provider, host encryption and operator process are not implemented.

New private PNG artwork bytes use AES-256-GCM with independently random 96-bit nonces and 128-bit authentication tags. AAD binds the exact `storageKey`, `artworkId`, `layerId`, `shop`, `productGid`, `variantGid`, `ownerId`, `designId`, immutable revision, SHA-256, byte length, and encryption key ID. Only base64-encoded ciphertext, nonce, tag and key ID are persisted; the plaintext PNG base64 field is omitted. Decryption checks authenticated data, length, and SHA-256. HMAC state integrity and external anchor rollback detection remain mandatory.

## Compatibility and migration

- Existing instances **without** `encryption` retain the v0.24 plaintext format and 601-test compatibility. This is legacy/offline behavior, **not** encryption.
- With encryption enabled, a plaintext legacy registry fails closed with `REGISTRY_ENCRYPTION_REQUIRED`. There is no implicit plaintext read, append, or background migration.
- After a reviewed local backup/key-custody procedure, call `migratePlaintextArtwork({opId})` explicitly on an encryption-enabled instance. The operation acquires the Linux lock, validates the authenticated old snapshot and independent anchor, encrypts all existing assets, and atomically commits a new anchored registry sequence. It retains immutable revision records, revocations, and replay IDs. It cannot mix plaintext and encrypted assets.
- To rotate to a new key, open with the new `activeKeyId` and a resolver that can supply **all historical keys**, then call `rotateArtworkKey({opId})`. It atomically re-encrypts all assets with fresh nonces, preserves immutable revisions/revocations, and records the operation ID for replay prevention. Keep old keys until successful verified rotation. An already-current key rotation is refused.
- Failed anchor CAS, post-rename crashes and unavailable keys **fail closed**. Do not manually edit registry or trust-anchor bytes to recover. Use independently authorized Objective 24 recovery only when its strict predecessor and signed permit requirements can be met.
- Do not store encryption keys, HMAC secrets, or real customer artwork in this test fixture. Synthetic tests use ephemeral random keys.

## Reproduce

```bash
node --version
node --test tests/objective25-artwork-encryption.test.mjs
npm test
```

## Limitations

This is an offline authenticated-encryption contract, not a production encrypted storage service. Ciphertext metadata (identities, product/variant IDs, revisions, byte lengths, hashes, revocation records) remains visible. Legacy plaintext registry files, previous backups, crash remnants, memory and operating-system swap are not securely erased by migration. A malicious host with key access can read artwork. Independent durable trust anchors, protected key custody/rotation, distributed transactions, secure backups, hosted authentication, Shopify order/payment verification, and manufacturing calibration are future gates.
