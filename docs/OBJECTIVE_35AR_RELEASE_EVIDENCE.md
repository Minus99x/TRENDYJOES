# Objective 35AR — Footwear concept 2D fallback and static-editor visibility

Version: **0.30.140**. Scope: offline source only. This is not a Shopify release, hosted acceptance, physical print calibration, GLB supplier model, inventory proof, or production approval.

## Verified source lineage

- Input archive: `trendyjoes-universal-studio-v0.30.139-objective35aq.zip`, SHA-256 `b500fd6c1389fab47885323d183eaf2fb915aa149f7091f481e5eb7ccf0ddd9b`.
- Input archive verified independently: 553/553 member SHA-256 digests match `OBJECTIVE_35AQ_BUILD_MANIFEST.json`; ZIP CRC valid.
- Independent Main57A archive: SHA-256 `e2cd0eed6e535970f102f5372a25de214bc5b08a1592537319b9a8916f9bee80`; 258/258 member SHA-256 digests and CRC valid.
- Read-only Main57A/Night comparison on 13 protected assets: four Main-vs-reconciliation differences and five Main-vs-static-candidate differences. No independently captured hosted source; no automatic merge.

## Functional engineering

1. Added `concept-sneaker` as the eighth merchandise concept, with **three distinct 2D surfaces**: outer side, inner side and tongue. Each has an explicit normalized design rectangle and a fixed, product-specific SVG silhouette. No inferred print dimensions, 3D mesh or manufacturer process.
2. Both offline editors show a working 2D concept and disable their 3D control for unsupported procedural footwear. The local editor may enable an inspected **unverified** GLB if the user supplies one; no supplier geometry is asserted.
3. Corrected a real Chromium accessibility defect: the static editor had set `SVGElement.hidden=false`, which left the SVG `hidden` attribute in place. It now adds/removes the actual attribute so 2D is visible and can be reviewed.
4. The static state contract now rejects forged 3D state for a product without procedural 3D. Cross-surface copies remain immutable and production-blocked.
5. Added an inert eighth concept entry to the **offline** navigation snippet, preserving its default disabled staging gate. No hosted or Shopify write.

## Tests and known gates

- Bounded functional Node suite: **889/889 pass** across 54 files.
- Separate Ed25519 retention/key-rotation Node regression: **39/39 pass**.
- Server/model/cart boundary Node regressions: **62/62 pass**.
- Offline Chromium: **35/35 new 35AR** + **20/20 35AQ** + **14/14 35AP** + **16/16 35AO** = **85/85 pass**. No observed page errors or external HTTP in these harnesses. No hosted-browser claim.
- New source and static browser SHA-256 inventories: **27/27** and **13/13**, respectively.
- Protected 13-file static staging candidate and separate 13-file Main candidate remain byte-pinned; new source would change three generated static candidate files. The source does **not** regenerate or overwrite them.
- Six legacy staging-currentness assertions remain **red by design**: 34I (1), 34J (1), 35AQ version (1), 35E (1), 35F (2). Their old assumption that the protected staging candidate equals current source is no longer valid until authorized manual reconciliation. Remaining **81/87** tests in that gated group pass. Do not misreport those six as passing or silently update protected assets.
- Full historical Node corpus not completed: earlier attempted full run reached 2,990 passing checks with no observed failure before its 100-second timeout; it is **not** a full-suite pass.

## Explicit blockers and next objective

Main57A's four unresolved protected/Night-only changes remain manual. Actual hosted 13-file unpublished staging export, authenticated source pins and approval to write have not been provided. The newer footwear work adds local-source-versus-protected staging drift on three assets; these must be reviewed in the eventual three-way merge, not automatically applied. Supplier-specific sneaker GLB, measured print zones, real color/material proof, authenticated cart/order boundaries and hosted accessibility acceptance are not complete.

Next safe objective **35AS**: improve 2D shoe artwork/lettering positioning accessibility, adversarial focus/keyboard regression coverage and per-surface draft review, without changing protected staging candidates. A separate authorized read-only hosted export remains a prerequisite to Main57 reconciliation.
