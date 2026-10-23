# Objective 35AT — Offline calibration lifecycle and cross-category 2D editor

Parent: v0.30.141 Objective35AS, SHA-256 `829292ac56899092be90188a77a5b01698b0ae5e3393512f9e0e5d402ad7d3d0`.

## Product changes

- A previously validated, unapproved physical measurement worksheet can no longer be exported after the operator changes any input, the selected product, surface, color/size, or imported model. A context fingerprint is checked again on export, not only on UI events.
- Product and surface changes clear previous physical measurements and require fresh evidence. Local draft reopening, tab recovery, and Start Over clear the worksheet. Model changes invalidate the prior worksheet. No print calibration is asserted by synthetic tests.
- Cross-category browser regression exercises all eight concept products, surface isolation, 2D keyboard positioning and focus, including apparel, drinkware, accessories, home and sneaker 2D fallback.
- Legacy Objective35AP/AQ browser expectations now reflect the intentionally surface-scoped layer picker introduced in 35AS: each surface lists its own layers, while the global count includes all surfaces.
- The protected unpublished 13-file staging and 13-file Main reconciliation candidates are not rebuilt or modified.

## Verification scope

- Focused Node corpus: **471 PASS / 3 FAIL**. The three failing historical 34I, 34J, 35AQ assertions require the frozen protected staging candidate to equal newer source; this would contradict preservation. These are genuine existing test failures, not tool failures.
- Offline Chromium: 35AR **35/35**, 35AS **19/19**, 35AO **16/16**, 35AP **14/14**, 35AQ **20/20**, 35AT **82/82** pass. All use in-memory offline test modules, no external HTTP, and do not establish hosted acceptance.
- Offline client asset inventory: **27/27** SHA checks pass; static-only asset inventory: **13/13** SHA checks pass.
- The backpack, rug, and sneaker manifest surfaces currently have no allowable production methods, so synthetic calibration worksheet validation correctly reports `PROCESS` instead of implying manufacturing support. Hosted Shopify, supplier dimensions, actual physical calibration, pricing, and cart remain blocked.

No Shopify, hosted theme, payments, customer/order records, secrets, or automation settings were modified. No GitHub commit or deployment is claimed.
