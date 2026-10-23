# Objective 22 — Immutable revision + artwork + GLB manufacturing evidence (OFFLINE)

**Release v0.22. This is a local prototype review contract, not a production approval, physical print certification, live Shopify integration, checkout, sale, fulfillment or machine-output authorization.** All acceptance tests use synthetic customer identifiers, GLBs, PNGs, measurements and disposable HMAC signing keys. No network access, Shopify mutations or new dependencies are involved.

## Implemented integration

`src/manufacturing-integrated-review.mjs` exports `reviewIntegratedManufacturingEvidence(options)` and returns `integratedEvidenceReady` only when all required independent gates pass in one invocation:

1. The backend `loadCurrentRevision(identity)` callback must retrieve a **server-owned, current, immutable** design record. Its exact schema is `TJ-CURRENT-IMMUTABLE-DESIGN-1` with `shop`, `productGid`, `variantGid`, `manifestId`, `ownerId`, `designId`, `revision`, `designSha256`, `status:'CURRENT_IMMUTABLE'`, and `design`. The record is rejected if any identity field, canonical composition digest, schema, revision or status disagrees. Client-provided `design`, `verified`, `geometryEvidenceReady`, and `artworkEvidenceReady` flags are rejected, not consulted. The caller must derive `ownerId` from independently authenticated server identity, **not** a browser-controlled string; this package does not implement hosted authentication or the registry.
2. The existing Objective 8 manufacturing profile, Objective 20 inspected GLB geometry/UV calibration, and Objective 21 independently inspected private PNG bytes/attestations/process policies must all pass. The old `ARTWORK_EVIDENCE_REQUIRED` hold remains when the caller omits the new **raw** `artworkEvidenceInput` trust bundle. A Boolean evidence flag never bypasses it. New base and geometry opt-in arguments do not by themselves guarantee a current server-owned revision; use the integrated entrypoint for that additional binding.
3. The integrated subject binds exact tenant, owner, design ID, immutable revision and canonical composition SHA-256, manufacturing profile SHA-256, geometry profile SHA-256, actual GLB digest, independently inspected artwork IDs/digests/effective DPI, signed storage-attestation record digest, and signed process-policy record digest. A distinct exact `TJ-INTEGRATED-MANUFACTURING-REVIEW-1` record must bind the subject SHA-256, tenant, product/variant, owner/design/revision, reviewer and a maximum seven-day validity. `verifyIntegratedApproval(record,subject)` is a **trusted backend callback** responsible for cryptographic signature validation, authorization, role/revision and revocation checks. No real service or protected key management is provided.
4. The registry is reread after asynchronous verification to detect a revision changed during review. Inputs are cloned/frozen before awaiting trust callbacks, including a private copy of the GLB bytes. This closes several local time-of-check/time-of-use mutation opportunities, but the final registry reread is **not atomic** with subsequent real-world activity and does not replace a production transactional lock or a production authorization decision.
5. Every result, including passing evidence, explicitly has `productionApproved:false`, `checkoutEnabled:false`, and `machineOutput:null`. There is no Shopify cart/order write, no pricing logic, no checkout authority and no manufacturing output.

## Trust boundaries and residual risk

- Every verifier (`verifyApproval`, `verifyModelApproval`, `verifyStorageAttestation`, `verifyProcessPolicy`, `verifyIntegratedApproval`) and the `loadCurrentRevision`/`readPrivateArtwork` callbacks must be supplied by an independently protected, authenticated backend. Passing test stubs or caller-selected callbacks cannot establish a trusted production service. Callbacks are deliberately injected only for offline contract tests.
- Manifest and measured worksheet must originate from trusted backend catalogs/technicians; signed review contracts validate their identities and exact measurement/model binding but **do not** independently measure physical goods.
- There is no protected registry, hosted session identity, trusted process-policy signer, real private artwork store, durable revocation store, physical model approval, print color proof, full raster decoder, or actual Shopify payment/order verification.
- The Objective 21 PNG parser is a deliberately narrow subset; JPEG, WebP, SVG, advanced PNG and production raster rendering remain unsupported. Geometry UV coverage is conservative and not a proof of printable physical fidelity.
- Two passes of private artwork inspection verify the same signed digest but do not establish production asset durability. Cross-host transactionality, locking and final production authorization remain future gates.

## Regression evidence

```bash
node --version
node --test tests/objective22-integrated-manufacturing.test.mjs
npm test
```

The Objective 22 suite includes passing synthetic integration, legacy hold preservation, forged flags, absent/stale/corrupt/superseded immutable revisions, registry failure or change during review, cross-gate artwork/policy/geometry/GLB substitution, signed policy and attestation changes, integrated signature expiry/revocation, low real DPI, no model bytes, and asynchronous caller-buffer mutation. This is **offline evidence only**.

**Next Objective 23:** strengthen private storage and immutable revision registry persistence contracts, including transactional anti-replay and revocation semantics, while preserving non-authorizing offline boundaries.
