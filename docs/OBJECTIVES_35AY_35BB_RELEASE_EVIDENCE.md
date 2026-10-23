# TrendyJoes Unified Engineering — Objectives 35AY through 35BB

**Version:** 0.30.150. **Authority:** OFFLINE SOURCE ONLY. This release is not installed in Shopify, not an approved manufacturing model, and not a cart or sales enablement.

## Implemented engineering

- **35AY — untrusted GLB preview receipt validation:** Reject missing, forged or inconsistent mesh identity, SHA, bounds, triangle geometry, UV coordinates, surfaces and unauthorized fields before accepting an imported model preview. Validated against an actual embedded GLB inspected by `src/model-assets.mjs`, plus adversarial fabricated receipts.
- **35AZ — private-evidence export ABA race hardening:** A monotonic local-editor revision invalidates an outstanding digest even if intervening edits are later reversed to exactly the original text and layers. It does not confer account, order or pricing authority.
- **35BA — redacted GLB provenance in design evidence:** An explicitly downloaded local private concept report now includes an allowlisted, validated GLB digest, triangle count, byte count and mapped/missing surfaces, or a visible `null` when no model is imported. Raw geometry, artwork files, GLB bytes, tokens, private customer text, pricing/checkout claims and manufacturing approvals are omitted.
- **35BB — secure-origin SHA fail-closed boundary:** Missing browser WebCrypto yields the precise `GLB_SECURE_CONTEXT_REQUIRED` or `CONCEPT_EVIDENCE_SECURE_CONTEXT_REQUIRED` refusal, never a fabricated hash or automatic network fallback. Fixed the historical 35R model-listener test harness to validate the current lifecycle and actual strict receipt.

## Verification executed in this working session

- Focused Node `model-assets.test` + 35AU through 35BB: **78/78 PASS**, zero failures.
- Additional manufacturing, surface-calibration and restored historical 35R tests: **113/113 PASS**, zero failures.
- Offline Chromium DOM: 35AS **19/19**, 35AT **82/82**, 35AX **13/13**, 35BA **15/15**, 35BB **9/9**. **138/138 observed checks passed.** No observed page JavaScript exceptions or external HTTP requests in the newest browser suites.
- Offline preview asset integrity: **38/38 SHA-256 checks PASS** following regeneration for the updated local source.
- The Chromium `about:blank` environment has no native WebCrypto. The 35BA positive UI/download browser test uses an explicitly injected *test-only* digest stub, not a true secure-origin crypto proof. Real SHA-256 was separately exercised with Node; the 35BB negative Chromium suite ran **without any digest stub** to confirm safe denial.
- No claim of complete historical Node regression: earlier handoffs documented three staging-currentness failures against intentionally frozen candidate assets. Those tests are not proof that the protected candidate should be overwritten.

## Protected source and release boundaries

The static staging candidate and separate Main57A reconciliation candidate are frozen. Preserve 13 candidate assets + their manifests in each tree, and compare exact SHA-256 and byte sizes against v0.30.146. The ongoing Main57A reconciliation has four unresolved divergent candidate assets; a full current byte-pinned hosted Shopify readback is not included in this offline release. No changes were made to either protected candidate tree.

No Shopify theme write (including staging), Horizon modification, deployment, real checkout/orders/customers, subscription, spending, automation change, external secret handling or GitHub push. Development commits are **local only** and must not be presented as remotely published commits.

**Next objective 35BC:** obtain the independently verified read-only 13-asset hosted snapshot with SHA-256 pins, then propose a manual conflict-preserving three-way reconciliation. Separately pursue GLB calibration using actual supplier dimensions and physical print-zone samples when available. Keep commerce off until hosted auth, payment and manufacturing review gates are independently approved.
