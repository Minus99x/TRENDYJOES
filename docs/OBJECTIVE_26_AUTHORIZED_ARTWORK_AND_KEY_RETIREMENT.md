# Objective 26 — Authenticated offline artwork reads and key-retirement evidence

**Development fixture only. No Shopify writes, no hosted authentication, no production key destruction.**

## New server-only authenticated artwork read contract

Construct the existing encrypted registry with an additional **trusted server-injected** `verifyArtworkAccess` callback. The callback must independently validate an opaque session token against a trusted identity provider, including session revocation and expiry, and return exactly `{shop, ownerId, issuedAt, expiresAt}`. `issuedAt` and `expiresAt` are epoch milliseconds; authorization lifetime is limited to 15 minutes, and future/expired grants are rejected. The callback may be asynchronous. No token, verifier, or principal is persisted in the registry or returned with artwork bytes.

Call `readAuthenticatedArtwork({sessionToken,request})` with the exact request shape `{shop,productGid,variantGid,ownerId,designId,revision,storageKey,artworkId,layerId}`. All fields must match the immutable revision and asset; shop and owner must match the independently verified principal. Revoked or superseded revisions, revoked artwork, invalid tokens, malformed principals, stale sessions, missing encryption, tampered ciphertext and mismatched independent anchors fail closed. This method returns only verified PNG bytes. The registry is still a local fixture and does **not** authenticate tokens itself.

If `verifyArtworkAccess` is configured, the older owner-only `readPrivateArtwork` method is disabled with `REGISTRY_AUTH_REQUIRED`. When no verifier is configured, the older local prototype interface is retained for backward compatibility and is **not a safe public endpoint**. Production must never expose that compatibility interface or allow untrusted code to instantiate the registry with secrets/keys and no verifier. Other mutation methods still require trusted server-side enforcement before any real deployment; this objective does not supply end-to-end authorization for those operations.

### Example (synthetic integration seam, not a hosted service)

```js
const registry = createOfflinePrivateRevisionRegistry({
  directory, secret, readAnchor, compareAndSetAnchor,
  encryption: {activeKeyId, resolveKey},
  verifyArtworkAccess: async (opaqueSessionToken) => {
    // Server-only: validate token with a trusted identity provider.
    // Return a verified, bounded {shop, ownerId, issuedAt, expiresAt}.
    // Never trust principal data from the browser or request body.
    return trustedIdentityProvider.verify(opaqueSessionToken);
  }
});
const pngBytes = await registry.readAuthenticatedArtwork({sessionToken,request});
```

## Key-retirement inspection — deliberately conservative

`inspectArtworkKeyRetirement({keyId})` reads the authenticated, anchor-checked registry under the existing lock and returns `referencedAssets`, `legacyPlaintextAssets`, `activeKey`, `unusedInCurrentRegistry`, `backupsVerified:false`, `safeToDestroy:false`, and `productionApproved:false`. The reference count includes **all historical, superseded and revoked** assets, not just active designs. An unreferenced historical key is **not** certified safe for destruction: old backups, crash remnants, external replicas, and operator recovery requirements remain unverified. This operation never changes the registry, rotates or destroys keys, updates the anchor, or accesses Shopify. It refuses invalid key IDs, missing decryption keys, rollback, anchor outages and plaintext states under encryption.

Signed Objective 24 recovery remains the only supported local protocol for catching up an interrupted anchor after migration or rotation; ordinary reads and inspections cannot override anchor mismatch. Tests cover signed recovery, forged permits, encryption migration, rotation, revocation, superseded revisions, cross-product/variant/owner identity, and concurrency.

## Reproduce

```bash
node --version
node --test tests/objective26-access-retirement.test.mjs
npm test
```

## Remaining gates

Hosted identity verification, server-only custody of registry secrets, protected encryption keys, multi-host durable storage and trust anchors, backup discovery and retirement policy, authenticated authorization of **all mutation operations**, real Shopify cart/checkout/order verification, physical manufacturing approvals and calibration are not implemented. No customer data or real credentials were used in tests.
