# Objective 32L — authenticated offline conflict-proof exchange

**Status: local prototype only.** No Shopify reads/writes, hosted identity, real witness deployment, real checkout, production authorization or independently published cryptographic pins.

## Scope

`src/offline-conflict-proof-exchange.mjs` adds an opt-in, two-party read-only receipt exchange and two-view reconciliation around Objective 32K's fully signed portable conflict proof. Both parties cryptographically bind to the same proof bytes and inventory pin. This is *not* a secure messaging service; callers transport the bytes independently and must separately authenticate the peer's Ed25519 public key and identity.

- `createOfflineConflictExchangeOffer` validates the entire 32K proof, signs an `OFFER` with the sender's Ed25519 private key and binds the proof SHA-256 digest, inventory digest, sender/receiver IDs, session, sender nonce, receiver challenge, monotonic sequence, previous exchange digest, issue and expiry.
- `acceptOfflineConflictExchangeOffer` independently validates the signed offer and full proof against the receiver's independently obtained expected pin, verifies the sender's public key, refuses same-key participants and countersigns an `ACK` bound to the exact offer digest.
- `verifyOfflineConflictExchange` re-verifies both signatures, proof and context; enforces nonces, identity, sequence, predecessor, issue/expiry windows, exact offer acknowledgement, independent keys, and caller-provided previously consumed exchange digests. It **does not persist** consumed digests or independently establish time.
- `encodeOfflineConflictExchangeTranscript` / `decodeOfflineConflictExchangeTranscript` enforce bounded canonical JSON transport, exact schemas and canonical base64url signatures; duplicate JSON fields, unexpected approval claims and malformed bytes are rejected.
- `offlineConflictExchangeTranscriptDigest` computes a domain-separated SHA-256 transcript pin. `reconcileOfflineConflictExchangeViews` demands two complete copies, ordered sender then receiver, with **separately obtained** exact transcript digests. It authenticates both views, rejects omissions, substitutions, role reorderings, and detects two different but individually valid signed exchange transcripts (equivocation).

## Required integration responsibilities

1. Independently distribute and authenticate each party's identity/public key, the full proof pin, transcript pins and peer challenge. A pin supplied by the same untrusted transcript is **not independent evidence**.
2. Generate unpredictable nonces and challenges from a trusted CSPRNG; the tests use deterministic synthetic tokens, which are **not production nonces**.
3. Use an external monotonic, atomic replay/sequence store and enforce a trusted clock. `seenExchangeDigests` is a **read-only fixture**; passing `[]` does not provide replay prevention. Historical forks outside the two presented views are not ruled out.
4. Protect signing keys; the code neither provisions keys nor verifies independent custody. The key check only requires distinct Ed25519 keys, not independently operated entities.
5. Never treat successful receipt verification as a manufacturing approval, payment, Shopify order, remediation authority, production identity proof or evidence of independent publication.

## Tests

`node --test tests/objective32l-conflict-exchange.test.mjs` exercises complete synthetic 32K proof signatures and 53 focused positive/negative cases. `npm test` exercises all prior Universal Studio regressions. No new runtime dependencies.

Known holds: independent witness deployment/publication, immutable offsite storage, protected signing keys, trusted timestamps, real hosted identity and replay store, distributed atomic recovery, approved physical profiles, artwork review, checkout and production.
