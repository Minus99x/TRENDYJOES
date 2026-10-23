# TrendyJoes Universal Studio v0.4 — Verified-source 3D asset intake and calibration draft contract

**Scope: a real GLB mesh reader and a physical measurement WORKSHEET, not verified manufacturing assets or live Shopify fulfillment.** This document defines the boundary between a local preview and future commercial deployment.

## GLB preview pipeline

- `src/model-assets.mjs` imports a product-specific **GLB 2.0** file from the user’s local browser, not an external website or Shopify CDN. It computes a SHA-256 checksum and validates the scene graph, indices, embedded buffer ranges, scene transforms, triangles, UV coordinates and named surface bindings.
- A printable surface must be identified on a glTF node (`node.extras.tjSurfaceId`) or on a primitive (`mesh.primitives[].extras.tjSurfaceId`), matching the selected product’s `surfaces[].id`, such as `front`, `back`, `wrap`, `top`, or `front-panel`.
- Each printable surface requires a `TEXCOORD_0` glTF UV set in the 0..1 coordinate range. UI design positions are normalized inside each selected **surface**, never the entire model. UV mappings on 3D geometry are modeled product-by-product; cylinder wraps cannot be substituted for garment geometry.
- Supported preview subset: standard embedded single-buffer GLB 2.0, float32 `POSITION` VEC3 and optionally float32 `TEXCOORD_0` VEC2, unsigned-short/unsigned-int indices, static TRIANGLES, scene node `matrix` or TRS. Nodes with extensions, external references, skins, morph targets, compression and embedded/external textures **fail closed**, rather than claiming support.
- A GLB can be inspected up to 16 MiB, 140k vertices and 45k triangles. The CPU-only renderer is intentionally restricted and not a WebGL/photorealistic pipeline. Unknown/no GLB, invalid geometry or model removal restores the existing procedural 3D **concept**, and the 2D editor remains available. An imported model is **never persisted to the local draft server** and needs re-import on reopening.
- Imported bounds are reported in glTF coordinate units (commonly meters), then normalized *for camera preview*. Do not treat the preview scaling as a guarantee of physical sizing or print dimensions. The importer records `asset.status='IMPORTED_UNVERIFIED'` and `approval='UNVERIFIED_LOCAL_PREVIEW_ONLY'` irrespective of success.
- File extensions and SHA-256 alone **do not** establish ownership, manufacturer identity, copyright license, authenticity, realistic material color, UV accuracy, shape fidelity, production approval, or suitability for untrusted public uploads.

## Physical measurements: external evidence required

`src/calibration.mjs` creates an exportable **draft only**. Each measured surface records actual blank SKU, print width/height (mm), blank width/height (mm), known manufacturing process code, equipment/fixture reference, author/date, source evidence and optional model SHA-256 linkage. Curved products may additionally record a measured circumference; modelled seam behavior and taper need their own on-press samples.

Example input (illustrative *fields*, **not production measurements**):

```js
const result=createCalibrationWorksheet(manifest,[{
 surfaceId:'front',widthMm:MEASURED_MM,heightMm:MEASURED_MM,
 blankWidthMm:MEASURED_MM,blankHeightMm:MEASURED_MM,
 processCode:'DTF-TEXTILE',fixtureReference:'actual tested fixture',
 safetyInsetMm:MEASURED_INSET_MM,bleedMm:MEASURED_BLEED_MM
}],{
 blankSku:'real manufacturer SKU',measuredBy:'bench operator',
 sourceDocument:'controlled physical inspection record',measuredAt:'YYYY-MM-DD',
 modelSha256:'64-character SHA-256 from reviewed GLB'
});
```

When all fields are structurally valid, the worksheet remains `status='DRAFT_REQUIRES_PHYSICAL_VERIFICATION'`, `manufacturingApproved=false` and `checkoutEnabled=false`. This module never promotes an item to a saleable variant or changes existing Shopify shop data. `estimateLayerPhysicalPlacement` computes position/print size and optional effective DPI from actual measured zone dimensions, respecting rotated layer bounds and safe insets. A useful DPI value is **not** an automatic accept decision: source quality, substrate, artwork color profile, underbase/pretreatment, finishing, bleed, tolerances and minimum DPI must be validated per actual process and blank.

## Future Shopify staging bridge — not yet implemented

1. **Asset registry:** authenticated backend stores a licensed, source-reviewed model with product and variant IDs, content SHA-256, asset version, coordinates/unit conventions, all declared surface IDs and per-surface UV mapping. Require explicit review status before allowing it to replace the concept preview on public listings.
2. **Calibration registry:** preserve physically measured print areas for each blank/size/color/material/fixture/process combination. Require proof prints, wash/adhesion/fit tests where applicable and accountable reviewer sign-off. Model asset version, measurement worksheet revision and approved SKU must match.
3. **Design persistence:** use authenticated customer or short-lived draft ownership, private malware-checked art storage, signed retrieval, expiry/revocation and production-export generation. Existing v0.2 local service is explicitly unsuitable for public hosting.
4. **Authoritative price:** use current approved Shopify variant plus actual measured/costed customization options on the backend. Shopify line item properties carry an **opaque** design reference; they do not set a trusted selling price.
5. **Cart/order:** verify add-to-cart, cart mutation, checkout, order data and fulfillment reproduction end to end on a controlled non-production environment before enabling checkout. Preserve the trial, unpublished staging theme and $0 draft manufacturing templates until separately authorized.
6. **Deployment:** snapshot and review staging changes; inspect theme block mounting and conflicts; deploy only to the unpublished staging theme with an actual rollback procedure. No Shopify theme was changed as part of v0.4.

## QA and limitations

Automated Node tests validate GLB parsing and reject malformed headers, invalid external references, unrecognized print-surface bindings, out-of-range UVs and bad indices. Independent browser smoke tests were run with static bundled modules because direct Chromium navigation to local HTTP destinations was blocked by the environment; **browser SHA-256 was replaced with a test-only digest in that harness**. The real GLB importer uses native WebCrypto SHA-256, validated in Node tests. Do not equate these browser checks to natural deployed full-stack tests.

To use customer-submitted 3D assets, add deeper security review and a 3D renderer with correct material/lighting pipelines, robust resource isolation, accessibility, triangulation issues, high-resolution previews and extensive device/browser testing; do not promote the constrained CPU viewer unchanged into production.
