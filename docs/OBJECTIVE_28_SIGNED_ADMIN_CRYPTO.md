# Objective 28 — Independently authenticated administrative artwork cryptography

**OFFLINE single-host integration contract only. No hosted authentication, production key management, checkout, physical manufacturing authorization or Shopify writes.**

## New protected interface

`createOfflinePrivateRevisionRegistry` optionally accepts `adminAuthorization: {registryId,publicKey,verifyOperator}` in addition to the existing `encryption` and independent anchor adapters. `publicKey` must be an Ed25519 public key. `verifyOperator(token,action)` is an independently protected operator identity/permission verifier; it must verify that the opaque token is authentic, current, not revoked, and permitted for the *exact action* (`migrate-plaintext` or `rotate-key`), returning **exactly** `{operatorId,issuedAt,expiresAt}`. It is an injected interface, not an implementation of authentication. Issuers must independently inspect the anchored registry and the complete historical encryption-key inventory before signing. No caller-provided principal or self-signed permit is trusted.

The two new server-only methods are:

- `migrateAuthenticatedArtwork({operatorToken,permit,request})`: encrypts an all-plaintext historical registry under the configured target key, atomically, without silently migrating mixed states.
- `rotateAuthenticatedArtworkKey({operatorToken,permit,request})`: re-encrypts **all** historical ciphertext, including revoked assets, using the configured target key. All historical keys must remain resolvable until migration is complete.

Both require configured `adminAuthorization` and `encryption`. A configured admin instance **blocks legacy unsigned** `rotateArtworkKey` and `migratePlaintextArtwork`, as does a configured customer-mutation instance. Unconfigured local development fixtures retain the earlier legacy APIs for compatibility; they must never be reachable by untrusted callers. A customer session alone never authorizes admin operations.

## Exact signed contract

The `request` object has exactly `{opId,expectedAnchor,targetKeyId,expectedAssetCount,sourceKeyIds}`. `expectedAnchor` is `{sequence,mac}` of the **independently verified prior anchor** (never `null`); `sourceKeyIds` is the sorted, unique list of every historical encrypted key ID, including revoked assets (empty for all-plaintext migration). `targetKeyId` must equal the configured active encryption key. `expectedAssetCount` binds the number of historical assets. The registry checks the full request against the current HMAC-authenticated state **under the single-host lock** and refuses stale anchors, unexpected keys, unexpected counts and mixed plaintext/ciphertext.

`computePrivateRegistryAdminDigest(action,request)` deterministically hashes `schema + NUL + JSON.stringify({action,opId,expectedAnchor,targetKeyId,expectedAssetCount,sourceKeyIds})`, with fields in exactly that order, where schema is `TJ-OFFLINE-PRIVATE-REGISTRY-ADMIN-1`. This is a request hashing helper, **not** authorization.

The permit is exactly `{schema,registryId,action,opId,operatorId,requestSha256,issuedAt,expiresAt,signature}`. Ed25519 signs UTF-8 `schema + NUL + JSON.stringify(payload)` where payload contains the first eight fields in exactly that order. `signature` is canonical base64url (64-byte Ed25519 signature). Permit and independently verified operator principal must both be valid at issuance check and **immediately before persistence (including after asynchronous pre-rename hooks)**. Validity is positive and no longer than 900,000 ms (15 minutes). The issuer must protect its private key and must never blindly sign client-provided hashes. Operator tokens, permit signatures and private keys are not persisted in registry state.

## Crash, replay, revocation and key-retirement semantics

- Existing Linux `flock`, HMAC-authenticated immutable revisions, atomic rename and independent anchor CAS are preserved. Signed admin operations consume persistent operation IDs in the same replay ledger as customer mutations.
- A crash before rename leaves the previous anchored state and permits retry with the still-valid original permit. A crash after rename fails closed until the **separate existing Ed25519 recovery permit** proves exactly one anchor step. Recovery never rewrites the registry, revocations, ciphertext or replay IDs.
- Rotation/migration preserves design revisions, artwork hashes, revocations and existing replay IDs; only encrypted bytes/key metadata and the new operation ID change. No key is retired or deleted. `inspectArtworkKeyRetirement` remains advisory and **always** reports `safeToDestroy:false` because off-host backups are not verified.
- The external anchor, signing keys, operator verifier and key resolver are synthetic in tests. This fixture does not establish production key custody, multi-host transactional safety, secure backup deletion, real customer identity, Shopify checkout/payment, GLB manufacturing approval or physical print quality.

## Reproduce

```bash
node --version
node --test tests/objective28-signed-admin-crypto.test.mjs
npm test
```

## Remaining gates

Trusted independent operator identity/role system; separate protected Ed25519 permit issuer and private signing-key custody; durable external anchor; encrypted backup lifecycle and secure deletion; multi-host transaction coordination; production auth policy forbidding unconfigured registry instances; real checkout/payment verification; approved print-zone/GLB profiles and physical calibration. **Shopify writes: NONE.**
