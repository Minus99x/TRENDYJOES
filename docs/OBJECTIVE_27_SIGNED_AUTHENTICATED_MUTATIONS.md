# Objective 27 — Signed, authenticated offline private-registry mutations

**Offline fixture, not a hosted customer identity service, production storage, checkout, or manufacturing approval. No Shopify writes.**

## Boundary

`createOfflinePrivateRevisionRegistry` now accepts the optional server-only `mutationAuthorization: {registryId, publicKey}` alongside **both** `verifyArtworkAccess` and encrypted artwork storage. The public key must be Ed25519. The verifier must independently validate and revoke opaque session credentials and return exactly `{shop,ownerId,issuedAt,expiresAt}`. The signed permit issuer must independently authorize the owner, action, exact immutable revision and artwork bytes before signing. Merely echoing client fields or blindly signing a client-supplied digest is not authentication or authorization.

When mutation authorization is configured, `commitRevision`, `revokeArtwork`, and `revokeRevision` (legacy unauthenticated APIs) reject with `REGISTRY_AUTH_REQUIRED`. Privileged operator `migratePlaintextArtwork` and `rotateArtworkKey` are likewise blocked on this user-facing instance; an independently protected offline operator instance is required for those administrative operations. Legacy methods remain available only in explicitly unconfigured local development instances for backward compatibility; **never expose them to untrusted clients**. `recoverInterruptedRegistry` remains separately Ed25519-signed under the existing operator recovery policy and never rewrites local ledger data.

## Public contract for a trusted server integration

- `commitAuthenticatedRevision({sessionToken, permit, request})`, where request has **exactly** `{record, artworks, expectedRevision, opId}`. `artworks` contains `{storageKey, artworkId, layerId, bytes}`; actual verified PNG bytes are SHA-256-bound to the permit. The record is the existing immutable design schema.
- `revokeAuthenticatedArtwork({sessionToken, permit, request})`, where request has exactly `{shop, productGid, variantGid, ownerId, designId, revision, storageKey, artworkId, layerId, opId}`. The persisted asset's full identity, artwork and layer must match.
- `revokeAuthenticatedRevision({sessionToken, permit, request})`, where request has exactly `{identity, opId}` and identity is `{shop, productGid, variantGid, ownerId, designId, revision}`. Only the current active revision can be revoked.
- `computePrivateRegistryMutationDigest(action,request)` returns a deterministic lowercase SHA-256 hash of the validated canonical request, including every PNG byte hash, length and storage/layer binding. Supported actions are `commit-revision`, `revoke-artwork`, `revoke-revision`. This is a **hashing utility**, never a grant or an identity verifier.

Each permit is exactly `{schema, registryId, action, opId, shop, ownerId, requestSha256, issuedAt, expiresAt, signature}`. `schema` is `TJ-OFFLINE-PRIVATE-REGISTRY-MUTATION-1`. The Ed25519 signature is canonical base64url over UTF-8 `schema + NUL + JSON.stringify(payload)` where `payload` is the permit without `signature`, **with properties ordered** `schema,registryId,action,opId,shop,ownerId,requestSha256,issuedAt,expiresAt`. Signer and verifier must use the same canonical format. The signed `registryId` binds the permit to one independent registry. Epoch-millisecond `issuedAt` and `expiresAt` must describe a strictly positive lifetime of at most 900,000 ms; future and expired permits are denied. A permit is valid only with an independently verified matching session owner/shop, matching request digest and matching operation ID. Operation IDs are recorded in the existing durable replay ledger. Both the session and permit must remain valid **immediately before persistence**, including after slow anchor reads.

No session token, signature, private signing key or verified principal is persisted in registry state. The trusted verifier is injected, not implemented here. Test keys are generated locally and are not production secrets. A signed permit does **not** confer checkout, pricing, manufacturing or shipping approval.

## Crash, replay and concurrency semantics

The existing single-host flock, atomic local rename, HMAC-authenticated state, and independent anchor CAS remain authoritative. A mutation verifies the session and permit under lock, loads the trusted current state, enforces revision/identity/revocation checks, then persists the operation ID with the mutation. Duplicate operation IDs are rejected after success or signed recovery. Concurrent conflicting revisions or revocations permit only one winner. A crash **before** rename allows a retry of the same still-valid signed request; a crash **after** rename blocks until independently signed recovery advances the anchor by exactly one provable step. Invalid or forged recovery permits cannot bypass the hold.

## Verification

```bash
node --version
node --test tests/objective27-authenticated-mutations.test.mjs
npm test
```

Tests use synthetic principals, generated Ed25519 keys, synthetic PNGs, in-memory independent anchor adapters and isolated temporary local files. They exercise tampering, wrong owner/shop/product/variant/revision/layer/bytes, expired sessions/permits, replay, concurrency, crashes, recovery and deliberate anchor delays. **No real Shopify, hosted authentication, production key vault, payment processor or printing hardware is involved.**

## Remaining production gates

Production identity provider, independently authorized and protected permit issuer, key rotation and custody, durable external anchors, distributed transaction semantics, complete authorization of operator/administrative APIs, secure backups and retention, real Shopify checkout/payment reconciliation, approved manufacturing profiles, GLB calibration and physical print proofs are still outstanding. This feature is **opt-in** to preserve the earlier offline fixture; production must forbid unconfigured registry construction and prohibit direct untrusted access to local registry secrets or files.
