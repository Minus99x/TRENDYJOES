# Objective 32K — portable offline checkpoint conflict proofs

**Scope:** read-only, local-first TrendyJoes Universal Studio security test infrastructure. Not hosted authentication, independent witness publication, a Shopify integration, or production authorization.

`src/offline-portable-split-view-conflict-proof.mjs` provides two opt-in functions:

- `encodeOfflineSplitViewConflictProof({initialAnchor, observations})`: requires two complete, independently caller-pinned 32J ancestries with a verified sibling checkpoint fork. Verifies both entire paths and emits a bounded JSON byte bundle and an **unpublished local pin candidate**.
- `verifyOfflineSplitViewConflictProof({bytes, expectedPin})`: requires the exact **caller-supplied** root/left/right/conflict/inventory SHA-256 pin, rejects altered or omitted evidence, rehydrates only canonical Ed25519 public keys and binary evidence, re-verifies the full signed histories, and checks the authenticated fork summary. A manifest hash alone is insufficient.

Bundle schema `TJ-OFFLINE-SPLIT-VIEW-CONFLICT-PROOF-1` includes root anchor, both complete ancestry observations (receipt windows, checkpoint signatures, auditor keys and transitions), conflict summary and digest inventory. Pin schema `TJ-OFFLINE-SPLIT-VIEW-CONFLICT-PIN-1` covers all four constituent digests plus a domain-separated inventory digest. Ed25519 public keys are stored as DER/SPKI; binary evidence is base64url encoded. Private keys are never serialized. Object field order is preserved because earlier signed receipt digests bind exact JSON serialization order; byte encoding is checked on read, and duplicate JSON keys, noncanonical encodings, unknown type tags, excessive size/depth, accessor-bearing source objects, and unexpected approval flags fail closed.

**Important trust distinction:** `pinCandidate` generated alongside a bundle is **not** independently pinned or published. A caller must obtain and safeguard the expected pin through a separately trusted channel. Even with such a pin, this module verifies only the bounded historical evidence supplied; it cannot establish global uniqueness, independent custody, trusted time, or immutable offsite retention. A malicious party controlling both bundle and caller pin can re-anchor its own evidence. Re-pinning forged cryptographic signatures still fails signature validation.

**Adversarial coverage:** omission, branch swap, signature forgery, receipt substitution, conflict-summary alteration, malformed Ed25519 keys, malformed/noncanonical JSON, prototype pollution, stale/missing pin, overlarge bundle, cyclic/accessor evidence, and injected production claims.

Run `node --test tests/objective32k-portable-conflict-proof.test.mjs` and `npm test` on Node 22.16.0. Do not use the returned verification result for checkout, remediation, manufacturing approval or deployment.

**Future gates:** independent witness deployments, externally published monotonic pins, protected signing keys, trusted timestamps, offsite immutable retention, authenticated multi-party proof exchange and cross-resource atomic recovery.
