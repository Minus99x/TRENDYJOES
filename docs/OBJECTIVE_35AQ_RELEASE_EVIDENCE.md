# Objective 35AQ — Explicit target positioning + staging provenance repair

Offline source checkpoint `v0.30.139`, derived strictly from verified Night 35AP (`v0.30.138`). No Shopify writes or hosted reads.

## Functional work

The local 2D editor now offers an accessible, explicitly selected target placement strategy for duplicating a layer across concept design surfaces: preserve relative normalized coordinates (backward-compatible default), or center the copy in the target surface. Both paths preserve the original layer and its source surface; target geometry is validated, no clipping, resizing, physical calibration or manufacturing authorization is implied. No owner token, authorization or private grant is copied. Existing keyboard focus restoration, saved binding invalidation and disabled checkout remain.

A second, independent integration defect was fixed: `buildStagingStaticBundle` previously hard-coded source version `0.30.137`, causing generated metadata and nine existing staging regression assertions to disagree with the evolving package version. It now validates and reads the actual offline `package.json` version, rejecting malformed metadata. The **13 protected staged source assets are byte-for-byte unchanged**. Only the offline staging candidate *metadata manifest* records `0.30.139`; no hosted staging or published theme was accessed.

## Executed verification

- Bounded integrated Node suite: **1,140 / 1,140 PASS** across core, geometry, 34-series, 35-series, and new 35AQ tests. See external `OBJECTIVE_35AQ_NODE.tap`.
- New explicit-center Chromium offline in-memory UI: **20 / 20 PASS**; parent 35AP offline browser regression: **14 / 14 PASS**. No page errors or external HTTP. Neither is hosted Shopify acceptance.
- Preview asset graph: **27** assets integrity check PASS. Static source graph **13** assets PASS. Staging offline candidate **13** source files plus manifest integrity PASS.
- Adversarial tests include malformed placement modes, unsafe authority duplication, rotation overflow, and malformed staging package versions.
- This is a bounded suite, not a claim that the entire historical Node corpus or the five previously timed-out cryptographic/provenance suites passed.

## Reconciliation boundaries

Main57A manual conflicts are **not resolved**. Parent 35AP separately documented five static-candidate vs Main57A differences and four Main-reconciliation-candidate vs Main57A differences across the 13 protected files; the 13+13 offline JS/CSS/Liquid candidate assets remain byte-identical here. The current metadata fix is *not* a merge or authorization to publish. A fresh authenticated read-only capture of the actual 13 hosted unpublished staging assets with source identities and SHA pins remains necessary before any proposed write; the Captain alone authorizes such writes.

No real shoes, supplier GLB dimensions, UV/print-zone calibration, physical production approvals, real orders, pricing, checkout, credentials, published Horizon or other projects were changed. Next: add bounded footwear/merchandise concept previews while retaining 2D fallback and explicit surface positioning, then secure hosted reconciliation evidence separately.
