# Objective 3 — product-specific conceptual 3D meshes (v0.3)

## Delivery status

**Implemented locally:** a dependency-free, rotatable conceptual mesh viewer, distinct geometries for the seven current illustrative manifests, normalized parametric UV surface patches, perspective camera controls, 2D editor fallback, and draft artwork projections. The existing v0.2 private local design-storage HTTP API remains unchanged.

**NOT implemented or implied:** photogrammetry/supplier garment assets; commercial 3D GLB/glTF model import; photorealistic material simulation; product size/drape simulation; true calibrated UV unwrapping; DPI/physical placement accuracy; print-ready design export; production pricing; Shopify cart/order integration; public customer storage; customer authentication.

No new third-party dependency, external CDN call, subscription, Shopify app, theme mutation, or product publication was introduced.

## Architecture

- `src/geometry3d.mjs`: pure mesh and conceptual surface mapping. Returns triangles with 3D coordinates and materials. `createConceptMesh()` deliberately returns `null` for unknown product shapes instead of lying about support. `buildConceptSurfacePatch()` interpolates design UV coordinates to a product-specific parametric surface. `project3D()` supports deterministic orbit math and is unit-tested.
- `src/viewer3d.mjs`: local browser CPU canvas renderer and small raster texture sampler. Curved surfaces are tessellated for approximate image projection. It never sends data to Shopify and is only a visual draft aid.
- `demo/studio.mjs`: toggles 3D concept / 2D placement, rotate, front/back, zoom, mobile pointer controls. The original editable composition and local draft-save API are preserved.
- `src/catalog.mjs`: unchanged broad declarative product configuration system with the seven *examples*, not a global category restriction.

## Shapes delivered

| Manifest | Type | Procedural concept | Draft UV surfaces |
| --- | --- | --- | --- |
| Crew T-shirt | Short-sleeve, crew neck | Extruded garment polygon | Front, back, left sleeve |
| V-neck T-shirt | Short-sleeve V-neck | Distinct neckline shape | Front, back |
| Long-sleeve shirt | Long-sleeved crew | Extended sleeve shapes | Front, back, left sleeve |
| Pullover hoodie | Hood, torso and pocket | Separate hood and pocket geometry | Front, back |
| Tumbler | Tapered cylindrical vessel | Segmented frustum, caps | Continuous conceptual wrap with rear seam |
| Backpack | Raised pack, pocket and straps | Multi-part extruded mesh | Front panel |
| Rug | Low-profile rectangular mat | Thin slab | Top face |

This is a starting model sample library. Actual products require their own meshes, selectable variants and production-approved surfaces, independent of this list. Unknown geometry must use a truthful 2D fallback instead of a misleading substitute.

## Coordinate convention / known limitations

- +X points right, +Y up, +Z toward the product's front.
- `u` and `v` are **normalized conceptual preview coordinates**, never millimeters, not known printable extents.
- For apparel, draft UV coverage is a rectangular projection over an approximate torso or sleeve plane; no seams, folds, fabric stretch or neck clipping are modeled. Draft UV may not match the physical garment. Not proof-quality.
- Tumbler wraps over a tapered cylinder. The seam lies on the back of the vessel (`u=0/1`). Real blanks require measured circumference, taper and fixture tolerances.
- Backpack front panel is an approximate plane; strap geometries have no verified fabric bending or printable-area constraints.
- Rug top is planar, with no pile texture and no exact dimensions.
- CPU canvas triangle rasterization is intended for low-poly exploration, not high-fidelity real-time commercial use. Angle-dependent occlusion, lighting and textile materials need a future industrial-strength renderer and verified 3D assets.
- The editor's original 2D view remains the authoritative *draft* composition interface; neither view is a manufacturing approval.

## Before release: required engineering gates

1. Create a versioned asset contract for real supplier-provided or accurately modeled GLB/glTF files (rights provenance, topology, compatible licenses, variants and physical dimensions).
2. Create each product's physical printable zones and calibrated UV artwork masks, including actual curved-boundary intersections and occlusion.
3. Validate mapping through printed test pieces, image quality and dimensional measurements; define accepted color/profile/press/cure outputs per manufacturing route.
4. Implement user-owned durable artwork storage with Shopify customer identity or safe anonymous authorization, deletion and retention policies, malware/media sanitization, audit logs and access controls.
5. Implement server-verified variant, pricing and production configuration checks before any cart line metadata is written.
6. Test full Shopify staging cart, checkout and production order workflow; only deploy with the Captain's authorization.

## Verification evidence

- `npm test`: **31 of 31 passed** (21 original plus 10 v0.3 geometry/UI-contract tests).
- Node local HTTP service health check returned `200`, confirms `checkoutEnabled:false`.
- Desktop (1440×900) and mobile (390×844) browser UI smoke tests: concept canvas produced raster output, orbit/front-back/product switching worked, 2D editor toggled correctly after a fixed SVG visibility bug, a design layer was added, and simulated save/review controls worked with no browser script exceptions. Screenshots included separately.
- Browser test restriction: Chromium blocked **all direct URL navigations**, including intercepted test URLs. For UI testing, local HTML/CSS and the ESM modules were injected in-memory; the browser save endpoint was **mocked**. Browser-to-real-HTTP persistence remains unverified and must not be reported as passed end to end. The real local HTTP/persistence/security behaviors were tested separately by Node.
