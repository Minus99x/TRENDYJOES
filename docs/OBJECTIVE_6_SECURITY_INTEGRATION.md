# Objective 6 — offline security and integration contracts (v0.6)

**Status:** Implemented and locally tested October 14, 2026 (America/Phoenix). **Shopify production NOT authorized; Shopify changes: none.** All manufacturing templates remain draft snapshots. This package does not install or expose any Shopify app, does not transact, and does not include or use Admin credentials.

## Verified baseline and objective evidence

- Source baseline: `trendyjoes-universal-studio-v0.5-objective5.zip` in `/TrendyJoes Night Watch/`.
- Reproduced with Node.js v22.16.0 on the extracted archive: **56/56 pass**.
- This objective: **67/67 pass** (11 new tests), zero dependencies added, `node --test tests/*.test.mjs`.
- `test-results.txt` in the v0.6 archive records actual test-run stdout; checksum and archive contents are listed in `OBJECTIVE_6_RELEASE_EVIDENCE.txt`.
- Static code review and automated local tests only. Browser/device, pen testing, model authenticity, real machine profiles, external identity systems, payment/order reconciliation, and production deployment were **not** verified.

## Added architecture

### 1. Authenticated, signed, expiring local preview receipt

`src/preview-capabilities.mjs` implements a **local-only** `LocalPreviewCapabilityAuthority`. It invokes Objective 5's `prepareStagingBinding` *first*, which authenticates the owner capability via the store, verifies saved current revision, exact product and variant membership, print-zone and process constraints, and stored artwork integrity. Only a successful owner-authenticated preview binding may be sealed into a receipt.

The new receipt contains only exact design reference, revision, Shopify product GID, Shopify variant GID, composition SHA-256, random 192-bit nonce, issue timestamp, expiration timestamp, purpose and version. The receipt is HMAC-SHA-256 sealed under a fresh **per-process** 256-bit secret. Raw owner tokens and artwork access grants are excluded. The default TTL is five minutes; issuance rejects invalid TTLs and all receipts are limited to 15 minutes.

`consume` validates the HMAC in constant time, exact expected identity and nonce, expiry and clock skew, verifies ownership and current saved design again, checks digest equality, and burns the nonce once. `inFlight` locking prevents concurrent double-use in a single Node.js process. A wrong owner does not burn the receipt; a successful consume does. The replay ledger is **in memory only**; process restart invalidates receipts because the secret is process-local. It is NOT a production replay database or a cross-replica control. A future hosted backend must use session identities, durable atomic replay storage, access-controlled secrets/key rotation and rate limits.

Two *loopback-only* JSON endpoints were added to `src/local-server.mjs`:

- `POST /api/shopify/preview-capability`: same request body as `/api/shopify/preview-binding`, authenticated by the private bearer owner token. Returns a one-use, time-limited receipt, **not** a purchasable cart line.
- `POST /api/shopify/consume-preview-capability`: same exact identity and revision body plus `token`, requiring the private owner bearer token again. Returns a validated preview confirmation only.

Both endpoints leave checkout and production flags false and cart/order outputs null. A separate `/api/shopify/checkout` route does not exist.

### 2. Safe private artwork adapter and revalidation

`src/integration-security.mjs` exposes `localArtworkStorageInterface` with `upload`, `read`, `assertBound`, and `publicUrl` (always null). It accepts only an explicit store implementing the private-grant/integrity interface. `src/local-store.mjs` now checks checksums and image structure on authenticated download as well as on binding, rejecting previously modified bytes. No client-provided arbitrary storage paths or public URLs are issued.

**Not included:** cloud object-store credentials, private-bucket policies, signed URLs, image malware/content scanning, true decoder sanitization, backups, deletion/retention enforcement and access logging. This is a local interface contract, not a production storage service.

### 3. Strict cart/order metadata review contract

`reviewCommerceLine` checks the exact expected Shopify product/variant GID, design reference/revision, composition digest, numeric variant line ID, positive quantity and exclusive private metadata fields, using the Objective 5 HMAC metadata verifier. It refuses tampering, stale/mismatched identities and extra keys. **Even a fully matching line is NEVER accepted for checkout or production by this function.** It is a contract validator for future independent payment/order processing; no checkout/order issuance or mutation was implemented.

The Objective 5 legacy order-metadata HMAC lacks nonce/expiry and therefore is **not** an online checkout authorization. A future release must implement the final timed checkout/order cryptographic protocol with atomic replay protection, Shopify authentication and webhook/order reconciliation before production. The five-minute local preview receipt must NOT be sent to Shopify checkout or interpreted as authorization.

### 4. Manufacturing configuration and geometry safeguards

`reviewManufacturingGeometry` combines the existing manifest and composition validators, measured worksheet consistency, unique measured zones, explicit manufacturing route per surface and manifest family, positive plausible measured sizes, safe-inset checks, wrap circumference checks, model SHA-256 identity and rotated physical placement. Malformed/null worksheet/design inputs fail closed without creating machine output. The result is **review-only**, and always has `productionApproved:false`, `checkoutEnabled:false`, `machineOutput:null`. Passing a draft worksheet is not physical calibration or proof of machine compatibility.

### 5. Regression preservation

All seven original illustrative families plus six read-only Shopify manufacturing template mappings remain in place. The original editor, concept 3D viewing, GLB local inspection, worksheet, customer draft persistence, recovered designs and previous staging binding APIs were retained. 56 original regression tests remain green; 11 new tests include owner authentication, tampering, revision swap, replay, concurrent consumption, expiry/clock checks, artwork integrity, metadata mutation, measured geometry, malformed inputs and loopback HTTP integration.

## Security / deployment hold points

1. Replace local bearer owner tokens with a production customer/guest identity architecture, CSRF/session protection and abuse limits; do not confuse a receipt with an authenticated customer identity.
2. Design a production-capable, distributed atomic replay ledger; persistent secret rotation, issuer/audience restrictions and authenticated tenant scoping.
3. Authenticate the Shopify Admin app backend, refresh the entire live catalog with variant pagination, inventory, price/currency and configured manufacturing profiles; do not authorize from fixture GIDs alone.
4. Implement and audit timed order metadata/signatures, independent Shopify cart and order reconciliation, webhook verification and idempotent manufacturing job creation.
5. Build private object storage with malware and content checks, ownership access control, lifecycle deletion, checksum verification, backups and safe signed fetch mechanisms.
6. Acquire and validate actual supplier/product-specific geometry, real printable dimensions, UV calibration, device-specific processes and safe toolpaths with human approvals.
7. Run browser/device accessibility QA, integration security and penetration testing, staging-theme backup/revert and actual transaction tests only after explicit Captain authorization.

All examples, fixtures, cryptographic protocols, and data in this objective remain **development-only**. No plan upgrade, cost, production orders or live Shopify modifications were executed.
