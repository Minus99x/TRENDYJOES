# Objective 11 — Versioned, non-authorizing cart metadata and atomic nonce binding (v0.11)

## Trust boundary

**OFFLINE CONTRACT ONLY. No Shopify reads/writes, checkout, customer authentication, payment, order transition, fulfillment, or manufacturing authorization.** This release does not integrate into the live theme or the existing legacy order reconciliation. Existing v0.9 legacy `_TJ Binding HMAC` is still accepted by its *offline reconciliation fixture*, but **must never be treated as checkout authorization**; the new verifier rejects it as a v2 receipt.

`src/versioned-cart-metadata.mjs` exports `createOfflineVersionedMetadataAuthority({keys,activeKeyId,resolvePrincipal,lookupDesign,consumeNonce,clock,nonceSource,maxTtlMs})`. All three callbacks are server-only trust dependencies, NOT implementations of real Shopify authentication or storage:

- `resolvePrincipal({authContext})` MUST cryptographically authenticate and authorize a current customer or guest session. It must not accept client `verified:true`, spoofed subject/session IDs, or unverified tokens. Returned shape follows `TJ-TRUSTED-PRINCIPAL-1` with shop, subject, kind, sessionId, expiresAt, checkoutEnabled:false, productionReady:false. This module validates shape and time, **not the authenticity** of the callback.
- `lookupDesign({shop,reference})` MUST return a server-owned current design with exact shop, owner, revision, product, variant, composition digest and status. Issuance and verification both recheck it.
- `consumeNonce({nonceKey,receiptSha256,expiresAt,expectedDesign})` MUST atomically compare the **current design** and consume a one-use nonce. The local `createOfflineDurableLedger` adapter now does both under the same single-host filesystem lock, with revision CAS, persisted replay, and a backwards-compatible migration for v0.10 state files lacking a `nonces` array. A cross-process race accepts exactly one claim. A stale revision after lookup but before claim fails closed.

## Wire contract

The only properties issued are `_TJ Protocol: TJ-OFFLINE-CART-2` and `_TJ Cart Receipt: TJ2.<canonical-base64url-json>.<base64url-hmac>`. No bearer token, signing key, raw session ID, or raw owner/customer ID is put in line-item metadata. The JSON payload contains `version`, fixed `purpose`, `kid`, tenant/shop, HMAC-derived opaque owner and session tags, reference, immutable revision, product and variant GIDs, composition SHA-256, nonce, issuedAt and expiresAt. Tags are pseudonymous, **not encryption or guaranteed anonymization**. The signed payload may still be visible in Shopify metadata if ever integrated; privacy and platform size limits need separate review.

- HMAC-SHA256 with explicit domain separation; strict field whitelist, canonical JSON and canonical base64url. Reject malformed encodings, duplicate JSON keys, extra fields, wrong protocol, forged key IDs, swapped owner/session/shop/variant/product/revision, stale digest and altered signatures.
- Server-only keyring copies key bytes; `ACTIVE` signs/verifies, `VERIFY_ONLY` verifies for grace-period rotation, `REVOKED` never verifies. Key IDs and notBefore/verifyUntil windows are enforced; old keys may be removed. No automatic key distribution, HSM/KMS, production rotation service or revocation registry exists.
- Maximum receipt TTL 15 minutes; actual expiry is clipped to the authenticated principal's expiry and signing key's verification window. The verifier rejects future-issued or expired receipts and fails closed on unavailable auth, design lookup, nonce storage, or invalid callback results.
- Nonce collision and replay fail closed; the filesystem ledger stores a SHA-256 nonce key, SHA-256 receipt digest and expiry, prunes expired entries only under lock, and rejects capacity overflow. This is a local single-host demonstration, not a multi-host transactional database.
- All successful verification results have `checkoutEnabled:false`, `paymentVerified:false`, `productionApproved:false`, `fulfillmentAuthorized:false`. These are **integrity-only** receipts, not proof of a paid order or production approval.

## Reproduction

Run `node --test tests/objective11-versioned-metadata.test.mjs` and `npm test` with Node.js 22.16.0 (no npm dependencies). Adversarial tests cover owner/session/tenant swaps, signed-field tampering, key rotation and revocation, time boundaries, invalid canonical encodings, replay, concurrent cross-process claims, v0.10 state migration and stale-revision races. All tests use synthetic identity claims, synthetic keys, and offline scratch files.

## Known production gates

Real Shopify/customer/guest session verification, server key management and rotation, privacy/data retention review, transactional multi-host nonce/design database, actual Shopify cart property limits and checkout semantics, webhook/payment/order reconciliation, inventory/pricing authorization, approved physical GLBs and print zones, artwork scanning, manufacturing signoff, and browser/device QA. Existing v0.9 offline reconciliation remains separate; **no legacy-to-v2 checkout migration has been implemented**.

Next objective: isolated offline v2 cart-to-order lineage/reconciliation contract with authenticated synthetic checkout/session linkage, exact line-item property validation, and atomic order transitions; never equate HMAC integrity with payment or fulfillment.
