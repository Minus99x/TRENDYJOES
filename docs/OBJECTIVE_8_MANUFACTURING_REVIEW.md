# Night Watch Objective 8 — offline manufacturing evidence and GLB/print-zone review (v0.8)

**Status: local source and adversarial tests only. No verified real production dimensions, reviewed GLB, physical test prints, trusted reviewer service, real artwork integrity backend, saleable products, pricing, checkout or machine output. No Shopify requests or writes.**

## What changed

`src/manufacturing-review.mjs` implements `reviewManufacturingProfile(options)` as a **server-side offline review seam**, deliberately separate from the browser preview, the local design revision system, and any commerce operation. It uses the existing `reviewManufacturingGeometry`, `estimateLayerPhysicalPlacement`, and actual `inspectGlb` GLB parser, not a claimed model approval flag.

A complete, unapproved measurement worksheet must identify the exact manifest, physical blank SKU, operator, evidence document, nonfuture date, measured zone dimensions, bleed, safety inset, process and fixture. It must contain no unexpected fields or incomplete issues. For cylindrical wraps, measured circumference is mandatory. Zones must fit the blank, their combined bleed and safe inset must fit, and methods must be allowed on the exact product surface. Each design layer must fit within its measured print zone, including rotated bounds and any required bleed. **Artwork layers intentionally fail closed** until independent artwork byte/integrity/resolution evidence is available; browser-supplied pixel counts are not evidence.

For non-flat merchandise, the caller must supply **actual GLB bytes**. The existing strict GLB inspector rechecks the binary, SHA-256, surface bindings and UVs. All measured/used print surfaces must map to the selected model, printable UV triangles must have nonzero area, and the worksheet model hash must match the actual inspected bytes. Flat merchandise may be reviewed as a 2D physical worksheet without GLB; this does not confer production approval. Neither the GLB parser nor the prototype establishes real-world dimensions, model licensing, physical calibration or UV fidelity.

A deterministic `TJ-MANUFACTURING-SUBJECT-1` SHA-256 covers the tenant, Shopify product and variant GIDs, manifest geometry, surface method sets, blank SKU, measurement author/source/date, every measured zone, GLB checksum and mapped surface IDs. A future trusted registry must issue a `TJ-MANUFACTURING-REVIEW-1` record with exact subject hash, shop, product, variant, manifest, blank and model binding, reviewer, revision, review ID, issue/expiry timestamps and an external signature. Extra fields, stale records, future records, mismatches and periods over 90 days reject.

**Cryptographic trust is NOT implemented in this prototype.** The `verifyApproval(record,subject)` callback is an injected trust boundary. It must be implemented by a protected server, independently verifying cryptographic signature, authorized signer and role, exact signed payload, tenant, expiry, review revision, revocation and anti-rollback against durable records. The tests use a mock local HMAC verifier solely to demonstrate interface behavior; it is not a hosted identity provider, production signature service, or authorization to manufacture. An arbitrary callback returning true would be insecure and must not be wired to untrusted inputs.

The result exposes `reviewReady`/`evidenceVerified` for **offline structural review only**. It always returns `productionApproved:false`, `checkoutEnabled:false`, `machineOutput:null`, even if the injected verifier returns true. No code here promotes a draft worksheet or product to production. `profileSha256` is a change detector and subject binding, not authenticity proof.

## Reproduce

```bash
node --version
npm test
node --test tests/objective8-manufacturing-review.test.mjs
```

All tests are offline and use synthetic fixtures. They cover forged approval flags, extra metadata, wrong shop/product/variant/blank, plausible measurement tampering, unsupported process, absent or corrupted GLB, unmapped print surfaces, degenerate UVs, rotated unsafe placements, curved wrap circumference, bleed and date provenance, signature/revocation failure, expired review records, client-claimed artwork dimensions, flat 2D profiles and malformed inputs. No browser or device QA was performed.

## Remaining production holds

1. **Physical measurement provenance:** verified SKU/variant mapping, actual technician measurement evidence, calibrated geometry, print test results, reviewed materials, UV fidelity and tolerances; approval by an authorized human operator.
2. **Trusted signing:** production reviewer identity/authorization, cryptographic verification, secure key storage, revocation, tenant isolation, durable revision CAS, audit trail and anti-rollback. A locally injected verifier does not meet this requirement.
3. **Model security:** verified GLB licensing, geometry and UV fidelity, supplier provenance, production-safe rendering, real-world units, asset storage and CDN security.
4. **Artwork:** private authenticated storage, malware and image safety validation, verified pixel metadata, effective DPI per process, color management, print file generation and provenance.
5. **Commerce:** live authenticated Shopify catalog consistency, variant status/inventory, authoritative costs/prices, payment/order and webhook reconciliation, controlled checkout, staging/browser/device/accessibility/security testing. None are implemented or authorized.

**Next engineering objective:** offline cart-to-order reconciliation contracts with exact tenant/variant/design/revision/metadata binding, idempotent webhook replay handling and explicit payment/fulfillment non-claims. Do not enable Shopify writes.
