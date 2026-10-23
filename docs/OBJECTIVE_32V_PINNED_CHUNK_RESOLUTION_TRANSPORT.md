# Objective 32V — independently pinned offline chunk transport

**Scope:** Local read-only evidence exchange; **no Shopify API traffic, writes, hosted auth, production authority, or independent witness service**.

## Implemented

`src/offline-conflict-resolution-chunks.mjs` splits an existing 32U exact-byte evidence envelope into a bounded ordered sequence and a compact JSON manifest. It never reserializes or normalizes signed 32S evidence. Each chunk digest uses domain-separated SHA-256 over the session ID, numeric index, and original bytes. The manifest records the 32U byte digest, total byte length, fixed chunk size, exact chunk count, ordered chunk digests, and session ID; its own digest is domain-separated over its **exact bytes**.

The verifier requires independently obtained `expectedManifestDigest`, `expectedTransportDigest`, `expectedSessionId`, caller-maintained `previouslyAcceptedManifestDigests` (`Set`), and the complete independently pinned 32T observer roster, proof/inventory anchors, union digest, and verification time. It compares every received chunk **in order**, rejects omissions/duplicates/reordering, verifies exact expected chunk lengths, recomputes each chunk hash, checks the complete assembled 32U transport digest, and delegates to 32U/32T/32S for exact JSON and historical Ed25519 signature verification. The manifest cannot supply trust anchors. The read-only verifier does not alter replay history or disk state.

Limits: transport 1 MiB; manifest 16 KiB; chunks 512–65536 bytes; maximum 128 chunks; session IDs 16–96 ASCII URL-safe characters. JSON manifest parsing rejects duplicate keys and escaped aliases by enforcing exact compact reserialization, fixed keys/order and strict value types. All received byte buffers are copied before hashing.

## Threat model and boundaries

- An attacker who can change the chunks or manifest but not **independently supplied** pins cannot change accepted content. Cross-session chunk substitution, reordering, truncation, omission, malformed manifest, or forged historical signatures fail closed.
- A digest created and transmitted by the same attacker alongside manipulated content is **not** an independent trust anchor. Session IDs must be generated uniquely by a trustworthy caller; this module does not generate entropy.
- `previouslyAcceptedManifestDigests` is only a caller-supplied snapshot. A persistent replay store and **atomic** record-of-acceptance are not implemented. Supplying an empty Set on each call **does not** prevent replay. The verifier intentionally reports `durableReplayProtection:false` and never claims cross-process single-use guarantees.
- Session pins bind evidence to a caller-known session. They do not authenticate the human identity of the sender or prove independent publication.
- Reassembled signed 32S evidence remains in its original property order. This is **not** order-independent canonical JSON. Existing 32R receipts authenticate recovery attempts, not independently witnessed completion.
- Offline tests do not prove trusted timestamps, key custody, hosted Shopify authentication, manufacturing approval, checkout/order processing, immutable offsite evidence, or distributed atomic recovery.

## Reproduce

`node --test tests/objective32v-resolution-chunks.test.mjs` then `npm test` with Node v22.16.0. Tests use synthetic Ed25519 signers and local fixtures only. No external network, Shopify calls, secrets or customer data.
