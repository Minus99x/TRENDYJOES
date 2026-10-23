# Universal Custom Design & 3D Product Studio — architecture and controls

## Baseline (verified 13 October 2026)

- Connected Shopify shop: `gucgmp-bc.myshopify.com`, trial, password-protected.
- Live theme: Horizon (`MAIN`), untouched.
- Staging theme: `TrendyJoes - Mid-Century Studio - STAGING` (`UNPUBLISHED`).
- Staging theme `config/settings_data.json` defines current palette: oxblood `#7A2A30`, slate `#52697A`, parchment `#F3E9D7`, ink `#231F20`. A separate broader complementary palette remains to be designed and verified.
- Existing section `sections/tj-studio-landing.liquid` is **a marketing landing**, not a customer design editor or 3D renderer. Keep it intact.
- Staging `templates/product.custom-print.json` is assigned to one draft (`Custom UV DTF Decal`) and references working Liquid blocks for custom-property text and an `<input type="file" name="properties[Artwork File]">` upload. **Ajax cart handling, storage, security, file presence and checkout behavior are not yet validated.**
- 14 Shopify products are drafts; 6 are manufacturing product templates, 8 are digital products.
- Existing Shopify metaobject definitions: production job (0 records), production SOP (6 records), manufacturing cost profile (6 records). All SOP processes pre-commissioning; costs `PENDING_INPUTS`.
- Installed apps observed: Shopify ChatGPT MCP and Digital Products. No verified customization app.

## Design goals

**Universal architecture, product-specific geometry.** An item definition is NOT a generic T-shirt template. `src/catalog.mjs` contains independent concept examples for crew-neck, V-neck, long sleeve, hoodie, tumbler, backpack, and rug; not a restricted supported catalog. All have preview zones but NO calibration, supplied 3D assets, supplier inventory, confirmed methods, prices, or Shopify variant IDs.

### Core model

`ProductManifest`: identity, category, `geometry.kind/subtype`, external 3D model asset, UV map per surface, preview shape, independent surfaces, candidate/approved manufacturing methods, calibration and product/variant references. Expand to shoes, jerseys, skirts, hats, rugs, irregular vessels, etc. **Never declare a production-safe area from a 2D illustration.**

`DesignComposition`: version, product identity, surface-specific ordered layers, text/artwork source IDs, normalized transforms, rotation, color, and future typography details. Store artwork in access-controlled object storage with consent, retention policy and antivirus/file parsing protections. Never trust direct client uploads as final print masters.

`ProductionDefinition`: process-specific printable dimensions, materials, machine limits, artwork format, cut/bleed rules, machine profile, quality checks and approval status. Backend production gate requires actual verified data and trained operators.

`3DAdapter`: renderer to accept product-specific meshes with verified UV maps and print-surface transforms. 3D support is **not implemented** in this package. A model presence check plus geometry tests must precede enabling a 3D toggle. Do not distort or stretch a single mesh to impersonate all apparel.

`PriceEngine`: price determined server-side from approved manufacturing cost profile, variant, quantity, surface count, per-process surcharges, taxes/shipping separately. Draft manufacturing cost profiles have no prices. **Do not let browser-supplied totals set checkout prices.**

`ShopifyBridge`: use real product+variant IDs fetched from Shopify. Persist an immutable customer design with a server-issued opaque reference, attach only the reference as a line-item property (and approved customization choices). Orders must link to approved artwork, proof state, process, and version. Test render/form integration, cart Ajax, order mapping, fulfillment and refund transitions before declaring ready. Shopify cart item properties are **metadata, not a file store or a pricing authority**.

### Gates

1. Preview: manifest structural validation + design placements within the relevant preview surface.
2. Production preflight: verified dimensions/materials/process route, validated artwork DPI/bleed/format, calibrated layout, legal permission and approved proof if required.
3. Commerce: authoritative server-side cost and matching Shopify variant/price plus persisted design reference, inventory, variant availability and order routing.
4. Rollout: staging theme tests (desktop/mobile/a11y), customer paths, no cross-project page changes, no paid apps, no changes to live theme before explicit authorization.

## Objective delivery in this package

- Product family-independent manifest and composition validation.
- Rotation-aware collision checks in normalized zones.
- DPI helper returning *unknown* when actual dimensions are unavailable.
- Separately reported preview / production gates.
- Locked-down Shopify cart serializer that rejects unapproved concepts and requires verified variants, authoritative prices and server-issued references.
- An accessible-ish local 2D editing prototype with product selection, surfaces, text, local image previews, per-layer transformations, drag placement, and JSON draft export.
- Automated tests using built-in Node.js test runner. No outside packages or billing.

## Objective v0.2 (completed locally)

- Implemented localhost-only testing API with preliminary PNG/JPEG/WebP signature and pixel checks; limit 5 MiB.
- Opaque artwork references + private grants, preview draft references + private owner tokens.
- Local immutable revisions and optimistic `expectedRevision` conflict checks.
- Draft recovery receipt reopens artwork and design, including after editor refresh, when using the same local server and saved data directory.
- Added explicit preview-only and checkout-disabled output flags and tests for private reads, invalid uploads, and saved revisions.
- Desktop/mobile UI smoke-tested via mocked browser fetch while independent real HTTP API tests were conducted via Node fetch. The browser's direct localhost route was blocked in this environment, so a true browser-to-server full-path test is **not** claimed.
- Neither live nor staging Shopify theme was edited, and no Shopify prices, checkout, or 3D assets were activated.

## Next implementation objectives

1. Verify actual product-specific manufacturing envelopes, blank materials and models for each supported SKU. Do not hardcode inferred real-world dimensions.
2. Implement design save API with secure object store, signed short-lived artwork access, malware/file-type checks, immutable revisions, and production file processing.
3. Obtain or build correctly licensed product-specific 3D geometry plus UV maps, then implement Three.js/Babylon.js/webgl adapter with fallback and mobile performance budget.
4. Map approved manifests to real draft Shopify products, move price calculation server-side and link genuine order/cart metadata. Keep unpublished until full test cycle.
5. Polish studio UX consistent with verified mid-century identity and broader brand colors; test accessibility and actual screen sizes.

## Separation and safety

- No OmegaVault, Golden Rule, or Seller Studio code was copied or edited.
- Local prototype only: Shopify, Github, its paid plan, and its production orders were NOT changed.
- The backpack and rug examples intentionally have no nominated manufacturing method until equipment/media compatibility is verified. The illustrative apparel and drinkware method candidates are also unapproved.
- All invented catalog example IDs begin with `concept-` and cannot be sold by default.


## v0.3 update (Oct 13/14, 2026): 3D conceptual model adapter
See `3D_CONCEPT_MODELS.md` for verified changes and release gates. The adapter has unique procedural geometries and per-product draft UV mappings for 7 examples; it is not measured supplier 3D imagery, not calibrated artwork placement, and cannot be represented as production readiness.
