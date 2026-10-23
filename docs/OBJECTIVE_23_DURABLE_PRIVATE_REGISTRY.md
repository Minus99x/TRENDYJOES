# Objective 23 — Offline durable private artwork and immutable revision registry

**Version 0.23 — offline prototype only. No hosted customer identity, no production private storage, no checkout, Shopify mutation, manufacturing approval, machine output or deployment.**

`src/offline-private-revision-registry.mjs` exports `createOfflinePrivateRevisionRegistry`. This is a deliberately bounded **Linux single-host** fixture with no new npm dependencies. The constructor requires a private local directory, an injected 32+-byte HMAC secret, and two *independently protected* trust-anchor callbacks (`readAnchor` and `compareAndSetAnchor`). The tests supply synthetic in-memory anchors and keys; they do not demonstrate a durable external trust service. The module never contacts Shopify or other services.

## Implemented contracts

- `commitRevision({record,artworks,expectedRevision,opId})`: atomically stores an exact `TJ-CURRENT-IMMUTABLE-DESIGN-1` record and all matching inspected PNG bytes, with strict owner/shop/product/variant/design/revision/composition binding. It enforces sequential CAS revisions, unique opaque storage keys, one asset per artwork layer, no missing or duplicate artwork, and a persistent anti-replay operation ID. A failed validation or stale CAS does not consume the operation ID. A successful result explicitly sets `productionApproved:false`.
- `loadCurrentRevision(identity)`: returns only the latest non-revoked exact identity/revision as a detached copy, or `null`. The returned shape is compatible with Objective 22's injected `loadCurrentRevision` seam. The caller MUST obtain identity from an independently authenticated server-side session; this module does not authenticate it.
- `readPrivateArtwork({storageKey,ownerId,designId,revision,artworkId})`: returns a detached copy of the inspected PNG bytes only when the revision is current, the key/identity matches, and neither asset nor revision has been revoked. Compatible with Objective 21/22's private-artwork read seam. The caller MUST enforce authenticated access independently. Storage keys are not bearer grants or public URLs.
- `revokeArtwork(...)` and `revokeRevision({identity,opId})`: atomic, durable, one-way revocation records. Replayed IDs and repeated revocations fail. Historical bytes/revisions remain stored as immutable evidence but become inaccessible through the read seam. Later revision numbers may advance; old storage keys cannot be reused.

## Durability and threat model

- A **single** JSON transaction contains revision snapshots, exact PNG bytes (base64-encoded), revocations, consumed operation IDs, sequence and HMAC. Base64 is **not encryption**; private artwork remains plaintext to a local disk reader with permission. Limit: 4 MiB total state, 512 KiB per asset, 100 revisions, 300 assets/revocations, 1,000 operation IDs. These bounds intentionally stop unbounded growth rather than pruning anti-replay evidence.
- Files use owner-only permissions, `O_NOFOLLOW`, inode/hardlink checks, and a stable Linux `flock` file held by an open descriptor. A temp file is fsynced and atomically renamed; the containing directory is fsynced. No stale PID lease stealing or lock-file unlinking is allowed. Shared filesystems, distributed hosts, backups, crash-consistent hardware, key rotation and real encrypted storage are **not** established.
- HMAC-SHA256 authenticates local state. An independently held `{sequence,mac}` anchor detects a restored valid older snapshot. Local writes occur **before** external anchor CAS. A crash *before* rename preserves the prior committed state and allows retry. A crash *after* rename but before anchor CAS **fails closed** on every subsequent operation. There is deliberately no automatic anchor catch-up or self-authorized recovery: an independently authorized recovery protocol is still required. An anchor outage/conflict also fails closed.
- This is an injected backend contract, not a secure API exposed to customers. Caller-supplied identity is **not trusted** until checked by a separately implemented hosted authentication/authorization boundary. Synthetic tests do not prove confidentiality from privileged local processes or protection against an attacker controlling both secret and anchor.

## Reproduce

```bash
node --version
node --test tests/objective23-private-registry.test.mjs
npm test
```

## Outstanding gates

Real authenticated tenant/owner identity, encrypted and access-controlled durable private storage, independently protected persistent anchor and signing keys, signed crash-recovery authorization, multi-host database transactions, secure backups/key rotation, expiry and retention policy, process approvals, physical manufacturing calibration, and actual Shopify checkout/payment/order verification remain outstanding. The integrated Objective 22 review continues to return evidence only, not permission to print or sell.

**Next Objective 24:** independently authorized recovery for interrupted private-registry anchor commits, with operator-signed recovery evidence, revocation integrity and adversarial rollback testing; no automatic self-repair.
