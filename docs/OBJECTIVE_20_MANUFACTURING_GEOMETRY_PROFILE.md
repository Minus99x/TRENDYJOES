# Objective 20 — GLB physical geometry, print-zone coverage, and independent review contract

**Release v0.20 — offline-only engineering contract. NOT an approved physical product, print-ready file, saleable listing, verified Shopify checkout, or production authorization.** All tests use synthetic blank measurements, synthetic GLB meshes, disposable signing keys and injected verifier callbacks. No real product dimensions, calibration, customer data, pricing or production permissions have been supplied or inferred.

## New boundary

`src/manufacturing-geometry-profile.mjs` exports `reviewManufacturingGeometryProfile(options)` and `uvRectangleCovered(bounds,triangles)`. The new review composes the existing Objective 8 `reviewManufacturingProfile` with an **additional independent model-calibration approval**. If the existing manufacturing review fails, no model review is attempted. This is a new optional integration contract; it does not silently upgrade old Objective 8 callers into production workflows.

An exact `TJ-GLB-GEOMETRY-CALIBRATION-1` profile must bind the store, Shopify product and variant GIDs, manifest, blank SKU, inspected GLB SHA-256, an explicitly measured model-unit-to-millimeter factor, a three-axis physical bounding box, maximum permitted discrepancy (0–2 mm), technician, nonfuture date, evidence reference, and unapproved draft status. The GLB inspector's transformed scene bounds are multiplied by the supplied unit factor; the predicted physical bounds must match the measured bounds within the *smaller* of the declared tolerance and 2% of the measurement (minimum 0.01 mm). No automatic meter or preview-camera scale is treated as real calibration. Measurements and approval records are supplied externally, not created from a model preview.

The selected worksheet's print zones must fit the model's physical envelope. For cylinders, a planar mesh cannot masquerade as a three-dimensional wrap: X/Z radial extents, vertical extent, circumference and height must be plausible. For flat surfaces, the two largest physical extents bound the print rectangle. Other product families use explicit X/Y planar extents. These are deliberately conservative coarse checks, **not** accurate seam/curvature, garment fit, fabric distortion, printhead collision or CNC toolpath checks.

For every design layer, the conservative axis-aligned rectangle containing the rotated layer must be fully covered by the union of its selected surface's GLB UV triangles. The validator subtracts printable UV triangles from the rectangle and rejects uncovered regions, including narrow gaps missed by point sampling. It rejects malformed/degenerate UVs and degenerate printable 3D triangles; each surface has a 4,096-triangle review limit to bound offline CPU work. This check is geometric UV coverage only, not UV-to-physical-distance fidelity, distortion, self-intersection, color accuracy, safe DPI, or licensed asset approval.

A separate `TJ-GLB-GEOMETRY-REVIEW-1` record binds the exact SHA-256 geometry-review subject (which itself binds the existing manufacturing profile hash), tenant, product/variant, blank, manifest, model digest, reviewer identity, revision and a maximum 30-day issue/expiry window. `verifyModelApproval(record,subject)` must be implemented by an independently trusted, server-side signature, authorization, revocation and revision-verification service. The prototype **does not implement that service**; a test-only HMAC callback is not a production signature authority. A callback returning true is not evidence of physical safety.

The result may expose `geometryEvidenceReady:true` only for structurally passing *synthetic offline evidence*. In **every** code path, `productionApproved:false`, `checkoutEnabled:false` and `machineOutput:null`. Existing studio 2D/3D editor, GLB import and calibration features are preserved. No Shopify read/write, no staging write, no new dependencies.

## Test coverage and reproduction

```bash
node --version
node --test tests/objective20-geometry-profile.test.mjs
npm test
```

The new adversarial tests cover independently approved synthetic GLBs, tamper/expiry/revocation/verifier failure, shop/product/variant/blank substitution, model checksum and scale changes, mismatched physical bounds and method, future measurement sources, unapproved records, unexpected fields, missing/corrupt/surface-swapped GLBs, geometric degeneracy, UV gaps, a narrow UV seam, rotated layers, cylinder shape mismatch, and flat/accessory routes. All tests are synthetic and offline.

## Production gates not satisfied

Independent durable asset registry and reviewer authorization; actual SKU-to-variant measurements and proof prints; protected key storage and revocation; physical units/axes/orientation verification; full mesh/manifold/winding/UV distortion analysis; manufacturing process tolerances and fixtures; image-byte inspection and DPI; genuine Shopify cart/order/payment/webhook integration; production-grade storage; browser/device accessibility tests. This module must not be wired to real checkout or manufacturing until those gates are independently satisfied and the Captain authorizes deployment.

**Next:** Objective 21 — independently verified raster/vector artwork evidence and process-specific effective DPI/bleed checks, with private storage and adversarial content metadata tests, still offline.
