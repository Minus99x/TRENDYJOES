# Objective 35AP — cross-surface concept duplication and fail-closed consolidation

This is an offline development checkpoint, not a hosted Shopify installation.

## Functional implementation

`src/preview-surface-copy.mjs`: source and destination surfaces must be different
valid surface identifiers; selected source must exist; new ID must be unique and
safe; source composition and target composition must both validate. Rejection
returns the same original layer-array reference. Success copies only explicit
renderable geometry and text/artwork reference fields, never owner tokens or
private grants. Original stays intact. `demo/studio.mjs` uses the reducer, selects
the new surface, restores keyboard focus and invalidates any saved draft binding.

The original 3D viewer, imports, preview geometry and manufacturing preflight
are preserved. This operation is concept coordinates only; no physical blank
approval, price, authenticated purchase, or order is created. Preview-only
checkout remains disabled.

## Unified source reconciliation

`scripts/check-unified-reconciliation.py` accepts externally pinned Main57A ZIP
and, optionally, a complete **independently preserved** 13-file hosted-source
capture. It independently hashes the offline Night static candidate and offline
Night main-reconciliation candidate and reports every deviation. No mutation or
automated three-way merge occurs. It exits 3 while source is incomplete or
conflicts remain, 2 for corrupt/unavailable source. Do not treat historical
Main57A hosted readback receipts as current source. Main57A integration is
by verified reference and independent read-only checker, not by copying its
protected staging files over Night or over published Horizon.

Main57A archived checkpoint: `e2cd0eed6e535970f102f5372a25de214bc5b08a1592537319b9a8916f9bee80`.
Night35AO source parent: `f599440ea443627e7ba97686268128e42df3d8681b74ac43227c6d742fef4863`.

**Known offline divergences at this checkpoint:** five static candidate differences
versus Main57A, four main-reconciliation candidate differences. These are not
hosted-state measurements, and none are approved to overwrite. The additional
static CSS divergence shows why comparing both candidate directories matters.

## Gates

Before hosted integration: exact 13-file read-only hosted capture, pinned
SHA-256s, explicit manual conflict resolution preserving staging accessibility
fixes and Night 3D/security changes, repeat tests, authorized staging write,
hosted browser acceptance, physical-device and manufacturing validation.

## Actual evidence

Node bounded group verification: 4571/4571 PASS across all completed groups; five old authority/provenance source files were not fully verified due two execution timeouts. Chromium: 14/14 Objective35AP and 16/16 Objective35AO PASS, browser import-map offline, no external HTTP. SHA-protected staging candidate JS/CSS/Liquid files: 26/26 identical across the verified parent. Full Node corpus is not claimed.
