# Objective 34A — Main/Night offline customer-flow integration

**Scope:** TrendyJoes Universal Custom Design & 3D Product Studio, offline local prototype only. This release does not modify Shopify, staging, production, products, inventory, customer data, checkout or payments.

## Independently verified source parents

- Night Watch v0.30.70 Objective 33Q: `trendyjoes-universal-studio-v0.30.70-objective33q.zip`, SHA-256 `2771c700f825e9f1574c9b4e3aaebd2e038dc7f2766213d6ace06e3368aa0926`; 3,344/3,344 pristine tests pass on Node v22.16.0. This is the actual editable parent.
- Main Engineering v0.32 Objective 32: `trendyjoes-universal-studio-v0.32-objective32-main.zip`, SHA-256 `e4d5333fabd22648c5bb08806289b9be52f8061605bd3140ebc8a83173dbd083`, CRC PASS. This is the **read-only integration reference**, not a replacement for Night Watch's later security history. Its customer options and preview-only cart-readiness modules were selectively ported.

## Actual integration delivered

1. **Customer-facing offline concept choices.** Seven existing 2D/3D concept product families retain their shapes, artwork layers, GLB import/calibration and universal-merchandise coverage. Explicit swatches and concept sizes appear in the editor and review summary; color affects the conceptual 2D silhouette and the 3D procedural preview, not verified physical materials.
2. **Staging-snapshot concept choices.** Five mapped, still-DRAFT manufacturing templates receive *illustrative-only* color options and apparel-only sizes through a server-controlled manifest adapter. This never maps to a supplier blank SKU, inventory or a live Shopify variant. Unmapped products remain catalog-only.
3. **Authenticated local revisions.** Saved local drafts persist the selected concept color/size; only their local owner capability can read/revise. Old clients that omit the option field when revising preserve the last selected options. Invalid/extra choices and forged approvals fail closed.
4. **Revision and option-sensitive binding.** Server-side preview-binding composition SHA-256 includes the normalized saved color/size, exact design reference, revision, product/variant identities and saved layers. Stale revisions or tampered saved choices reject; one-use local preview tokens do not survive a changed revision. Client-supplied color/price/approval/registry fields cannot override server state.
5. **Actual local cart-readiness interaction.** The local demo now shows a non-purchasing readiness check for a saved draft and actual *offline snapshot* product/variant identity. It enumerates hosted customer auth, live catalog, approved price, manufacturing, private artwork and checkout/order blockers. It returns no cart line, cart mutation, order, payment URL or production permit. The editor prevents stale on-screen option/layer changes from being represented as current saved proof.
6. **Cross-branch test reconciliation.** Imported Main Objective 31 and 32 executable tests into Night Watch's larger suite; added eight new cross-branch HTTP/security tests for exact saved options, local owner access, option-only revisions, stale preview tokens, client-injected approvals, tampered saved choices, and disabled cart/checkout routes.

## Explicit limitations

The loopback prototype is not a Shopify theme extension or hosted app; no native Shopify theme preview was tested. Color swatches are design illustrations, not approved inventory, dye/print proofs or actual saleable variants. Local owner tokens are not authenticated Shopify customers; saved files are not production private artwork storage. No manufacturing approval, current catalog/pricing, cart/checkout/order or public deployment. A local Chromium attempt was blocked by browser administrator policy; HTTP tests and JavaScript syntax checks are separate evidence, not substitutes for full visual/device acceptance.

## Main Engineering handoff contract

Main Engineering should inspect `src/preview-product-options.mjs`, `src/preview-editor-state.mjs`, `src/customer-cart-readiness.mjs`, the updated `src/shopify-intents.mjs`, and `demo/studio.mjs`. It may compare them with its own v0.32 sources, but must NOT overwrite Night Watch's extensive offline security modules. Integrate this customer flow behind the **unpublished** staging preview only after independent conflict review, theme compilation, browser/keyboard/mobile acceptance, and explicit staging write authority. The Shopify public Horizon theme and selling functions remain out of scope.

**Next objective:** customer-journey integration acceptance: reconcile the staging homepage CTA to a working preview-only Studio entry, validate one saved custom-design journey in a real Shopify staging browser, then close remaining accessibility and native theme rendering gaps. Night Watch itself stays offline-only and can deliver an integration adapter without Shopify writes.
