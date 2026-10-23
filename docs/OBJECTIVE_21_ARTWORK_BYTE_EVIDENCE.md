# Objective 21 — Offline artwork bytes, private-storage attestations, DPI and bleed

**Status:** v0.21, local prototype contract only. **No production, checkout, fulfillment, machine output or Shopify writes.** The existing editor, model import, and all previously verified contracts are unchanged. This is a **separate** artwork-evidence API, not a silent authorization upgrade to `reviewManufacturingProfile` or `reviewManufacturingGeometryProfile` (which continue to reject artwork as missing evidence).

## Implementation

`src/manufacturing-artwork-evidence.mjs` exports:

- `inspectVerifiedPng(bytes)`: bounded independent inspection of the **actual** PNG byte stream, not user-provided MIME/dimensions. Verifies signature, strict IHDR, CRC of **every** chunk, chunk ordering and bounds, a single consecutive IDAT stream, IEND and absence of trailing data, bounded zlib inflation and exact scanline length/filter values. It accepts **only** non-interlaced, 8-bit RGB or RGBA PNG with IHDR/IDAT/IEND chunks and <=8 MiB compressed, <=16M pixels and <=64 MiB inflated. JPEG, WebP, SVG, palette PNG, interlaced PNG, ancillary chunks and animations **fail closed**. This is not a pixel renderer, sanitizer, malware scanner, ICC/color-management check or proof of manufacturability.
- `computeArtworkDesignSha256(design)`: canonical, size- and depth-bounded JSON composition digest, stable under object-key reordering. Exact artwork placement and identity changes invalidate the prior attestation.
- `reviewManufacturingArtworkEvidence(...)`: inspects each artwork layer from a caller-injected **private** storage reader, recomputes SHA-256 and file size from retrieved bytes, validates a bounded exact-schema storage attestation for shop/product/variant/owner/design/revision/composition/manifest/blank/surface/process/layer/artwork and opaque private key, and requires a separately authenticated process policy for the exact tenant, blank, surface, process and variant. All records have explicit expiry; unknown fields and unsupported media are rejected. Caller-injected `verifyStorageAttestation` and `verifyProcessPolicy` must be protected server-side cryptographic, scoped, revocation-aware verifiers. A callback that returns true without verifying these facts is **not** trustworthy.

The trusted policy supplies `minDpi`, `minBleedMm`, `maxBleedMm`, maximum artwork bytes and allowed media types. **No universal production DPI or bleed defaults are invented.** The test-only DTF-TEXTILE fixture uses 200 DPI and 2–5 mm solely to exercise validation; those numbers have **not** been approved for real printing. Effective raster DPI is calculated from independently read source dimensions and measured placement, taking the lesser horizontal/vertical DPI. Rotated artwork must fit inside the measured printable zone with both bleed and safety inset. Multiple artwork layers are all-or-nothing; a single failure returns no approved artwork evidence.

Every response sets `productionApproved:false`, `checkoutEnabled:false`, `machineOutput:null`. A positive `artworkEvidenceReady` means only that these local checks passed with the supplied test trust seams.

## Reproduce

```sh
node --version
node --test tests/objective21-artwork-evidence.test.mjs
npm test
```

## Critical limitations and remaining gates

1. **No actual private cloud storage or authenticated user identity exists.** The reader and verifiers are injected interfaces; HMAC test keys and fake owners are synthetic. A real implementation must bind to a hosted authenticated principal and durable, tenant-isolated object store, protected signing keys, policy approvals, revocation and immutable object versions. Do not expose storage keys or accept caller-controlled storage URLs.
2. No complete pixel decode, sanitization, malware scanning, content moderation, color profile validation, alpha/transparent-edge coverage, print separations, physical material compatibility, or UV mapping distortion proof. Narrow PNG support is intentionally conservative; other formats require separately audited full decoders.
3. No independent approval of real manufacturing policies, physical measurements, actual fixtures, supplier GLBs or physical test prints. Current geometry/manufacturing APIs remain separate; **do not** infer that their checks have been combined or production-approved.
4. A composition SHA binds the submitted design bytes, but there is no protected, durable revision lookup in this API; production must compare against server-owned immutable revisions, not trust a client-supplied design object.
5. The injected callbacks and current worksheet can be supplied by local test code. They do not establish real-world trust, authorization or checkout eligibility. No Shopify API was called and no store state changed.

**Next objective:** compose authenticated artwork evidence with exact server-owned design revision and existing GLB/geometry reviews without bypassing the previous `ARTWORK_EVIDENCE_REQUIRED` fail-closed gate; include adversarial cross-gate tests and review of transparent-pixel/print coverage. Remain offline.
