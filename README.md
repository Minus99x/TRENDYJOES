## Current offline engineering checkpoint — v0.30.156 / Objectives 35BC–35BH + 35BI/35BJ

Read-only, offline Universal Studio work: strict GLB-v2 header and triangle/UV validity, bounded mapped-UV diagnostics, actual-measurement draft guards, context-bound redacted design review, and current-state accessible UV reporting. User-initiated downloadable review is locally generated and never authorizes checkout, production, price, product variants or server authentication. Source staging candidates remain protected and unchanged; no Shopify writes or hosting acceptance.

## Current offline engineering checkpoint — v0.30.150 / Objectives 35AY–35BB

This checkpoint hardens strict geometry/UV validation before accepting an imported GLB preview receipt, prevents edit-and-revert (ABA) races in explicitly requested redacted design-evidence exports, and includes an allowlisted model SHA/print-zone summary in private offline evidence without raw triangle buffers or checkout authority. Missing secure-origin WebCrypto now fails with typed errors; Chromium insecure-origin failure behavior was tested honestly. The existing protected unpublished staging assets remain frozen; no hosted Shopify source reconciliation, manufacturing approval, physical calibration or authenticated cart integration is asserted.

## Bulk engineering checkpoint 35AU–35AX (v0.30.146, offline only)

This release adds guarded local GLB import lifecycle, validated preview-only model receipts, byte-bounded model reading, sampled UV diagnostics (not manufacturing proof), accessible 2D fallback and surface narration, plus explicit private redacted design evidence exports with SHA-256 and stale snapshot refusal. Checkout, hosted authentication, manufacturing approval, prices, orders and production remain unavailable. The 13+13 protected staging candidate assets are not modified. No Shopify writes. Local Git history supplements the authoritative versioned ZIP; no GitHub repository or remote commit is claimed.

## Night Watch Objective 35AN (v0.30.136; offline)

Added independently pinned dual-signed Ed25519 retention signer cutover with cross-key receipt-chain continuity and adversarial tests. No external custody, signer revocation, hosted identity, production authorization, or Shopify writes. See `docs/OBJECTIVE_35AN_RETENTION_SIGNER_CUTOVER.md`.

## Night Watch Objective 35AM (v0.30.135; offline)

Added portable domain-separated Ed25519 retention receipts, independently pinned append-only genesis/extension windows, signed pruning certificates, expiry/replay/tamper/fork rejection, and adversarial tests. It is not an external retention service or a substitute for 35AL issuer-provenance verification. No independent custody, trusted clock, hosted identity, production authorization or Shopify writes. See `docs/OBJECTIVE_35AM_PORTABLE_RETENTION_RECEIPTS.md`.

## Night Watch Objective 35AL (v0.30.134; offline)

Added independently retained historical issuer-signed epoch continuity verification with signed cross-epoch fork, replay, rollback and pruned-history rejection. Caller-protected historical keys, SHA pins and trusted time are prerequisites; there is no hosted consensus or production authority. See `docs/OBJECTIVE_35AL_RETAINED_EPOCH_CONTINUITY.md`.

## Night Watch Objective 35AK (v0.30.133; offline)

Added a portable issuer-signed epoch-chain provenance verifier that pairs each 35AJ hash-linked record with its 35AH signed transition and both historical witness rosters. It requires independent Ed25519 issuer key fingerprints, genesis/current head, roster/policy/audience pins, and a caller-supplied trusted clock. Historical cutovers are checked at their actual signed cutover times; the latest roster must remain valid at verification time. Optional observer-view verification refuses to adjudicate a view unless its entire signed transition provenance verifies. No Shopify writes, no hosted authentication, independent key custody, consensus, or production authority. See `docs/OBJECTIVE_35AK_ISSUER_TRANSITION_PROVENANCE.md`.

## Night Watch Objective 35AJ (v0.30.132; offline)

Added independently pinned, canonical portable epoch-chain evidence and offline Ed25519 observer receipts, including multi-observer fork/prefix adjudication, stale retained-head rejection, strict challenges/expiry, and adversarial tests. Hash-link verification is **not** independent 35AH transition-signature provenance, hosted witnessing, trusted custody, global consensus, replay consumption, or production authority. See `docs/OBJECTIVE_35AJ_MULTI_OBSERVER_EPOCH_EVIDENCE.md`. No Shopify writes or deployment.

## Night Watch Objective 35AI (v0.30.131; offline)

Added independently pinned, append-only, single-host witness epoch-head CAS registry. Signed Objective 35AH roster transitions are verified before durable epoch record creation; external genesis and current-head pins are mandatory, and interrupted writes fail closed. See `docs/OBJECTIVE_35AI_PINNED_EPOCH_HEAD.md`. No Shopify writes, hosted authentication, external custody, or production authorization.

## Night Watch Objective 35AH (v0.30.130; offline)

Signed Ed25519 roster-epoch transitions and independently pinned issuer challenge tickets, with cutover/expiry/replay rejection and 35AG durable ledger integration. See `docs/OBJECTIVE_35AH_SIGNED_WITNESS_EPOCH_CHALLENGES.md`. No external issuer, production authority, or Shopify writes.

## Night Watch Objective 35AC — anchored multi-hop observer rotation and revocation boundaries (v0.30.125)

Added a separate offline read-only lineage verifier for 1–16 signed 35AB key transitions,
strict key/receipt continuity, replay/cycle/fork rejection and externally pinned
revocation policy. No external witness, trusted key custody, trusted time, hosted
authentication or Shopify write authority. See
`docs/OBJECTIVE_35AC_MULTI_HOP_ROTATION_REVOCATION_POLICY.md` and
`tests/objective35ac-rotation-lineage-revocation.test.mjs`. No theme or store writes.

## Night Watch Objective 35AB — dual-key observer rotation and external pin import (v0.30.124)

Adds read-only dual-Ed25519-signed observer key transitions, fail-closed journal-history extension, and canonical export/import of rotation pins requiring independently supplied SHA-256 and prior receipt anchors. External custody is **not** established by code. See `docs/OBJECTIVE_35AB_DUAL_KEY_ROTATION_EXTERNAL_PIN_IMPORT.md`. No Shopify writes, hosted identity, or production authority.

## Night Watch Objective 35AA — observer-signed portable journal-head receipts (v0.30.123)

Objective 35AA adds offline read-only Ed25519 observer receipts, externally pinned rollback/split-view reconciliation, and adversarial tests. See `docs/OBJECTIVE_35AA_PORTABLE_OBSERVER_SIGNED_HEAD_RECEIPTS.md`. No Shopify writes, production authority, trusted time or hosted witness.

## Night Watch Objective 35Z — crash-safe signed artwork review journal (v0.30.122)

Added an opt-in Linux-local, externally pinned append-only journal for 35Y signed read-only review evidence, with cross-process flock serialization, fsynced pending/hardlink commits, durable challenge/ticket/evidence replay rejection, historical Ed25519 verification, and fail-closed real SIGKILL crash tests. **No automatic repair, quarantine/deletion, independent witness, hosted auth, manufacturing or Shopify authority.** See `docs/OBJECTIVE_35Z_DURABLE_SIGNED_ARTWORK_REVIEW_JOURNAL.md`.

## Night Watch Objective 35Y — signed operator-readable review evidence (v0.30.121)

Added caller-trusted Ed25519 review evidence bound to the 35W ticket, 35X image-content pin, and a fresh reviewer challenge. Strict size/expiry and signature checks, adversarial cross-session replay and cross-process tamper tests, and an operator-readable **read-only** report. No deletion/quarantine authority, no Shopify writes, and no hosted identity. See `docs/OBJECTIVE_35Y_SIGNED_ARTWORK_REVIEW_EVIDENCE.md`.

## Night Watch Objective 35X — content-bound read-only artwork pins (v0.30.120)

Artwork image bytes and metadata now contribute SHA-256 content digests to the local retention reference pin; mismatched image/metadata digests fail closed, and previously issued signed review tickets become stale after content substitution. Includes cross-process tamper tests; no delete/quarantine authorization and no Shopify writes. See `docs/OBJECTIVE_35X_ARTWORK_CONTENT_PINS.md`.

## Night Watch Objective 35W — signed read-only quarantine review (v0.30.119)

Added a caller-keyed, expiring, root-bound review ticket with a SHA-256 snapshot reference pin and adversarial freshness checks. Verification rescans all local saved revisions and artwork under the cooperative lease. **Neither API can move, quarantine, or delete artwork; review is not authorization.** See `docs/OBJECTIVE_35W_QUARANTINE_REVIEW.md`. No Shopify reads/writes.

## Night Watch Objective 35V — cooperative local artwork lease (v0.30.118)

Added fail-closed local cross-process exclusion for cooperating artwork writes, design saves, revisions and read-only retention scans. Stale locks are not auto-reclaimed, and no artwork is quarantined or deleted. See `docs/OBJECTIVE_35V_COOPERATIVE_ARTWORK_LEASE.md`. Offline prototype only; no Shopify writes.

## Night Watch Objective 35U — read-only artwork reference inventory (v0.30.117)

Added conservative offline two-pass reference inventory across **all saved design revisions**, distinguishing apparently unreferenced complete local artwork from still-referenced, missing, incomplete, and pending artwork. This **never deletes** anything and explicitly does not authorize cleanup. See `docs/OBJECTIVE_35U_REFERENCE_AWARE_ARTWORK_RETENTION.md`. No Shopify writes or deployment.

## Objective 34F — customer-flow HTTP acceptance and staging integration adapter

The offline loopback customer journey now has executable HTTP acceptance tests across concept selection, editor modules, private local draft creation, owner-only access, revision conflicts, preview summary and blocked checkout. A **default-disabled**, merge-ready Shopify staging Liquid snippet/CSS and strict route contract are provided under `integrations/shopify/`; they are NOT installed or hosted. Main Engineering must independently install and verify a preview editor page before enabling any links. See `docs/OBJECTIVE_34F_STAGING_INTEGRATION_ADAPTER.md`.

## Objective 34E — customer preview-only design review

From `/demo/start.html`, select a concept, customize in `/demo/`, and click **Review my design · preview only** to see a validated, privacy-conscious, explicitly non-purchasing summary. Review invalidates on changes; no Shopify checkout, price, order, or manufacturing authorization. See `docs/OBJECTIVE_34E_CUSTOMER_PREVIEW_SUMMARY.md`.

## Objective 34C — late draft catalog and unsaved-work protection

The offline editor now guards delayed local catalog snapshots against overriding a user's unsaved design or manual product choice, and asks for confirmation before an explicit product switch discards work. See `docs/OBJECTIVE_34C_DELAYED_CATALOG_GUARD.md`. No Shopify integration or hosted checkout is implied.

**Night Watch integration Objective 34A / v0.30.71:** Merged Main Engineering v0.32 concept color/format UI and Objective 31 preview-only cart readiness into the Night Watch v0.30.70 offline foundation. Local owner-only draft persistence, option-sensitive preview binding, unsaved-change gating and explicit checkout blockers now work together; source provenance and release gates in `docs/OBJECTIVE_34A_MAIN_NIGHT_STUDIO_INTEGRATION.md`. NO Shopify writes, hosted identity, price or production approval.

**Night Watch Objective 33J / v0.30.63:** Offline single-Linux-host, append-only, independently pinned cross-observer 33I adjudication transcript inventory. Re-verifies two independent Ed25519 observers and 33H reviewer quorums on admission and history reads; rejects replay, rollback, forged/omitted evidence and uncertain SIGKILL commits. Requires caller-retained external head; no automatic lock/pending repair, trusted time, global witness, hosted authentication, Shopify writes or production authority. See `docs/OBJECTIVE_33J_DURABLE_CROSS_OBSERVER_ADJUDICATION_INVENTORY.md`.

**Night Watch Objective 33I / v0.30.62:** Offline, portable, independently pinned Ed25519 observer-signed read-only pending-adjudication transcripts. Re-verifies the 33H two-group reviewer decision, exact pending/predecessor/observed-head bindings, strict UTF-8/JSON, bounded caller-supplied expiry and cross-observer consistency. No independent disk witness, persistent replay ledger, trusted time, repair, Shopify writes or production authority. See `docs/OBJECTIVE_33I_PORTABLE_SIGNED_PENDING_ADJUDICATION_TRANSCRIPT.md`.

**Night Watch Objective 33G / v0.30.60:** Opt-in, single-Linux-host crash-safe signed-equivocation envelope acceptance registry. Full 33F nested-signature verification inside cross-process lock; independently pinned monotonic head and predecessor, durable replay/nonce rejection, fsync/hardlink append, uncertain-crash fail-closed, adversarial competing-process and SIGKILL tests. No independent publication, trusted clock, automatic repair, Shopify writes or production authorization. See `docs/OBJECTIVE_33G_DURABLE_EQUIVOCATION_ACCEPTANCE_REGISTRY.md`.

**Night Watch Objective 33F / v0.30.59:** Offline, read-only portable Ed25519-signed authority equivocation-evidence envelopes with independently pinned exact-byte digests, canonical UTF-8/JSON, signed-history re-verification, bounded typed binary/public-key transport, and adversarial substitution/omission/replay tests. No hosted service, persistent replay ledger, trusted time, publication, Shopify writes or production authorization. See `docs/OBJECTIVE_33F_PORTABLE_EQUIVOCATION_EVIDENCE_ENVELOPE.md`.

## Night Watch Objective 33A (v0.30.54) — offline multi-claim evidence inventory

Added a bounded read-only multi-claim inventory and cross-observer reconciliation of independently pinned Objective 32Z claim histories. It re-verifies every signed transcript, rejects same-slot forks, omitted claims, unequal concurrent checkpoints, and conflicting observer histories. The journal namespace and pins remain caller-supplied; this is **not** an external witness, proof of global completeness, repair permission, or production readiness. See `docs/OBJECTIVE_33A_MULTI_CLAIM_INVENTORY.md`. **No Shopify writes or deployment.**

## Night Watch Objective 32T (v0.30.47) — pinned cross-observer resolution evidence reconciliation

Added an opt-in, offline **read-only** verifier for 32S resolution-attempt proofs across independently pinned observer inventories. It re-verifies Ed25519-signed history, detects missing proofs, observer omissions, conflicting fully signed actions, re-pinned forged signatures, and complete-union rollback. It requires separately obtained exact observer-roster, per-observer inventory, per-proof and union pins. **No independent publication, hosted identity, completed recovery, production authorization, Shopify writes or deployment.** See `docs/OBJECTIVE_32T_RESOLUTION_EVIDENCE_RECONCILIATION.md`.

## Night Watch Objective 32M (v0.30.40) — durable offline conflict-exchange replay journal

Added opt-in Linux single-host cross-process flock serialization and fsync/hardlink durable exchange claims. Signed 32L transcripts are fully reverified inside the lock; independently supplied head pins, monotonic sequence, predecessor, expiry and replay protections fail closed. Simulated power loss leaves uncertain pending records blocked, with no automatic recovery. **No independent anchor publication, trusted time, hosted identity, Shopify writes, checkout, production deployment or distributed transaction guarantees.** See `docs/OBJECTIVE_32M_DURABLE_EXCHANGE_REPLAY_JOURNAL.md`.

## Objective 32K (v0.30.38): portable offline conflict-proof bundles

Added opt-in, read-only portable conflict proof encoding/verification with complete signed history, separately supplied inventory pins, Ed25519 key rehydration, omission/substitution checks and 31 adversarial regression tests. See `docs/OBJECTIVE_32K_PORTABLE_CONFLICT_PROOFS.md`. No Shopify writes, hosted auth, manufacturing authorization, production deployment, or external witness publication.

## Night Watch Objective 32F — portable signed replay audit and witness receipt (offline)

`src/offline-portable-replay-audit-bundle.mjs` exports portable, bounded audit evidence with a complete per-item inventory, strict independent digest pins and 32E historical signature re-verification. It verifies a separate Ed25519 witness quorum receipt binding the exact bundle/checkpoint/history, independently pinned receipt predecessor/sequence and non-reused witness keys. **No witness publication, trusted timestamp, independent deployment, recovery, remediation, Shopify access or production authorization.** See `docs/OBJECTIVE_32F_PORTABLE_AUDIT_BUNDLE_WITNESS.md`.

## Night Watch Objective 32E — independently pinned signed replay-head audit (offline)

`src/offline-supervisor-replay-checkpoint.mjs` verifies majority-quorum Ed25519 auditor-signed replay-head checkpoints against **separately supplied** exact checkpoint, prior-checkpoint and policy pins. It reconstructs the entire replay chain from signed 32C decisions and 32D commit records, checks every historical signature and replay/nonce binding, and rejects rollback, forks, tampering, missing history and expired-at-observation decisions. No external pin publisher, trusted timestamp authority, private-key custody, network or Shopify integration is supplied. Historical observation times are attested by auditors, **not independently timestamped**. A locally computed pin is never proof of offsite publication. See `docs/OBJECTIVE_32E_SIGNED_REPLAY_HEAD_AUDIT.md`.

## Night Watch Objective 32A — externally pinned multi-archive completeness (offline)

A read-only inventory verifier binds every authenticated signed receipt to a
complete canonical manifest and exact forensic archive bytes across shared or
legacy per-archive directories. It fails closed on missing/orphan/pending
archives, rollback, forged pins, tamper and unsafe filesystem objects, with
three-epoch signed-witness integration tests. No automatic repair or atomic
cross-resource recovery. See `docs/OBJECTIVE_32A_PINNED_MULTI_ARCHIVE_INVENTORY.md`.

## Night Watch Objective 31D — opt-in durable offline anchor adapter

`src/offline-durable-anchor-adapter.mjs` provides a Linux-only, append-only
file-backed CAS anchor adapter with cross-process cooperative locking, fsync,
fail-closed pending/crash handling, signed exact-byte recovery and optional
independent-head pinning. Authenticated registry and audit-journal integration
is exercised offline. This is **not** an offsite witness, host-compromise
protection, production authentication or Shopify checkout. See
`docs/OBJECTIVE_31D_DURABLE_ANCHOR_ADAPTER.md` for guarantees and limits.

## Night Watch Objective 31A — opt-in independently anchored audit observations (offline)

Objective 31A adds `src/offline-anchored-audit-journal.mjs`: an append-only per-event, independently anchored cryptographic record of signed-authorized registry audit snapshots with consecutive-sequence enforcement, tamper/gap detection and separate signed interrupted-append recovery. Existing v0.30 registries are not migrated destructively; initial bootstrap explicitly **does not prove earlier history**. See [`docs/OBJECTIVE_31A_ANCHORED_AUDIT_JOURNAL.md`](docs/OBJECTIVE_31A_ANCHORED_AUDIT_JOURNAL.md).

**The journal is opt-in and not wired automatically to every registry write; uninterrupted mutation-to-audit coverage is not yet guaranteed.** No live Shopify writes, deployment, customer identity service, trusted offsite anchor or production backup service.

## Night Watch Objective 30 — cross-process coordination and audit continuity (offline)

The encrypted private registry now rejects detected lock/directory pathname swaps
before durable writes, isolates lock ownership across concurrent asynchronous calls,
and tests real external-process contention for signed backup restoration. A new
operator-signed `exportAuthenticatedAudit` interface returns independently anchored
**current-state commitments** to revisions, encrypted artwork, revocations and
operation IDs, without disclosing the raw records. It is **not** a complete
append-only audit log, offsite backup, hosted authentication, or production
assurance. See `docs/OBJECTIVE_30_CROSS_PROCESS_AUDIT.md`. No Shopify writes.

## Night Watch Objective 29 — signed encrypted-registry backup/restore (offline)

The private registry adds action-specific Ed25519-signed operator backup export and
**no-clobber, exact-current-anchor** restoration of missing encrypted registry
files. Backups contain ciphertext, authenticated state bytes, historical key-ID
inventory and revocations; restore requires all historical keys and HMAC secret,
consumes a durable operation ID and cannot roll back a newer anchored state.
Interrupted restoration requires separate signed anchor recovery. Backups are
in-memory only and require independently protected offsite storage/key custody;
this is **not** production disaster recovery or Shopify authorization. See
`docs/OBJECTIVE_29_SIGNED_BACKUP_RESTORE.md`. No Shopify writes.

## Night Watch v0.27 — signed authenticated private-registry mutations (offline only)

The optional encrypted private-registry server contract now requires an independently verified session **and** an Ed25519-signed, exact-request permit for immutable revision commits and artwork/revision revocations. It binds owner/shop, product, variant, design, revision, operation ID, and inspected PNG byte hashes; enforces 15-minute validity and durable replay protection; blocks legacy unauthenticated mutation methods on a configured instance; and preserves signed crash recovery. These are synthetic offline tests, **not** hosted authentication or manufacturing/checkout authorization. See `docs/OBJECTIVE_27_SIGNED_AUTHENTICATED_MUTATIONS.md`. No Shopify writes.

## Night Watch v0.20 — independent GLB geometry evidence gate (offline only)

`src/manufacturing-geometry-profile.mjs` adds strict physical model-unit scaling, measured model envelope vs. printable zones, complete conservative UV artwork coverage, and separately signed/revocable GLB calibration review **interfaces**. It composes the existing Objective 8 manufacturing review; it never grants manufacturing or checkout. See `docs/OBJECTIVE_20_MANUFACTURING_GEOMETRY_PROFILE.md`. Synthetic tests only; no real-world measurements or trusted production signing service.

## v0.19 — independently signed offline recovery (Objective 19)

Optional Ed25519 public-key verified, operator-authorized, one-step anchor catch-up for the Objective 18 crash window. Never automatically repairs mismatches; cannot roll back the ledger or anchor. Requires independent operator evidence, external trusted anchor and offline-held signing private key. Test fixtures are synthetic and **not** production-ready. See `docs/OBJECTIVE_19_SIGNED_RECOVERY_PROTOCOL.md`. No Shopify writes.

# TrendyJoesDIYandMore — Universal Custom Design Studio (foundation v0.16)

**Local-only design prototype; NOT Shopify-deployed or production-ready.** The product manifests and printable zones are conceptual. A GLB importer and physical measurement worksheet now exist, but no independently verified manufacturer models, machine-calibrated print zones, manufacturing approval, cost-approved prices, Shopify cart integration or public artwork backend exist yet.

### v0.13 — Atomic offline receipt-to-lineage observation (Night Watch Objective 13)

The new **opt-in offline atomic adapter** verifies a v2 receipt without consuming it, then persists its one-use nonce and the synthetic observed order/event in a **single local ledger transaction**. It rejects owner/session, revision, variant, HMAC, replay and cross-protocol claim conflicts, and is regression-tested with injected pre-/post-rename failures and concurrent processes. The older compatibility adapter is still non-atomic and must not be used for the new atomic guarantee. This is **not hosted authentication, Shopify checkout proof, payment verification or manufacturing authorization**. See `docs/OBJECTIVE_13_ATOMIC_OFFLINE_LINEAGE.md`.

## Run on your own computer

Requires Node.js **20+**. No additional packages or subscriptions are required.

```bash
npm test
npm run serve
```

Open http://127.0.0.1:8000/demo/ in a modern browser on the same computer. `npm run serve` deliberately binds only to 127.0.0.1. It is **not reachable from another device**, and it must never be exposed directly to the public Internet. If port 8000 is occupied, use `PORT=8100 npm run serve` (PowerShell: `$env:PORT='8100'; npm run serve`).

### Rotatable 3D views and GLB intake (v0.4)

The local demo has two views: **Rotatable 3D concept** and **2D design editor**. In 3D, drag to rotate the product, use Front/Back and zoom controls, or inspect the shape-specific projected draft design. Return to the 2D editor to move, resize or rotate actual design layers. The 3D meshes are explicitly **conceptual, low-poly, and uncalibrated**; they are not supplier GLB files, photorealistic previews or physical print proofs. Tumbler wraps are mapped onto a curved frustum; different apparel neck/sleeve/hood constructions have separate conceptual meshes. Unknown geometries intentionally fall back to 2D.

Read `docs/3D_CONCEPT_MODELS.md` for exact scope, UV constraints, independent verification and remaining deployment gates.

**Introduced in v0.4:** Import a local GLB 2.0 file into the preview, with strict mesh/index/UV/surface-binding checks and native SHA-256 asset identity. Import is local/browser-only, supports a constrained static GLB subset and never implies that a garment, material, or print area is authentic or approved. In **Physical print-area measurement worksheet**, enter real blank dimensions, print-zone dimensions, operator/date, evidence and fixture details; validate and download a draft worksheet. No measurements are pre-filled and no manufacturing approval is issued. See `docs/GLB_ASSET_AND_CALIBRATION_CONTRACT.md` for the full contract and known unsupported GLB features.


### Local project persistence

You can upload PNG/JPEG/WebP artwork (maximum 5 MB per file), move/rotate/re-size it within conceptual preview zones, save the design to a private *local development directory*, and download a **private recovery receipt**. Opening the recovery receipt in the editor restores its saved artwork and design layers from the same local development server, provided those files still exist. Each save creates a new immutable revision; older versions remain on disk.

**Handle the recovery receipt like a password.** It contains design-owner and artwork-access tokens. Do not upload or share it with customers, teammates, or third-party services. It is not a production authorization and cannot add a product to Shopify checkout. The local data directory `.tj-local-data/` is deliberately excluded from this distributable archive. Back it up separately only if you wish to retain local drafts.

This service implements rudimentary capability tokens for local prototyping; it does **not** authenticate Shopify customers, provide cloud encryption/key management, malware scanning, moderation, retention/deletion automation, order routing, or signed CDN URLs. Those must be designed and independently tested before public release. Artwork header/magic inspection is only a preliminary rejection gate, not safe file sanitization. Do not use it with untrusted internet traffic.

### v0.5: Shopify staging integration bridge (read-only snapshot)

The code now normalizes real Shopify product and variant IDs from a *read-only Admin snapshot*, maps five draft manufacturing templates to safe conceptual studio manifests, and keeps ready-to-ship decor catalog-only. The editor can optionally display those draft configurations, save a private revision, and verify a non-purchasable design-to-variant binding. Missing variants, unrecognized product/production identities, invalid print zones, stale revisions and damaged artwork fail closed. No live Shopify store changes or cart/checkout operations occur.

Load the included development fixture with `TJ_STAGING_FIXTURE=fixtures/shopify-draft-manufacturing-2026-10-14.json` before `npm run serve` (PowerShell: `$env:TJ_STAGING_FIXTURE='fixtures/shopify-draft-manufacturing-2026-10-14.json'; npm run serve`). Leave it unset to keep the original concept-only demo. See `docs/OBJECTIVE_5_SHOPIFY_BRIDGE.md` for exact features, account/authentication limitations, security hold points, line-item metadata semantics and required future deployment steps.

### New v0.6: Night Watch Objective 6 — security and integration contracts (offline)

The loopback development API now exercises a five-minute, HMAC-bound **preview-only** receipt. Only the design owner can issue and consume it, and it is consumed once per server process. Owner, revision, product, variant and composition bindings are checked again on consumption. Private artwork reads verify saved checksums; strict cart/order metadata and geometry/measurement review contracts reject mismatches without enabling checkout. The new API routes are `/api/shopify/preview-capability` and `/api/shopify/consume-preview-capability`. **No real Shopify customer authentication or approved purchase flow exists.** The test suite now includes 67 tests (56 preexisting + 11 new). Read `docs/OBJECTIVE_6_SECURITY_INTEGRATION.md` before adopting any code into a hosted backend.

## Contents

- `src/shopify-bridge.mjs` / `src/shopify-intents.mjs` — staging Shopify registry, safe manifest adaptation, authenticated preview-only design bindings and future signed order metadata contract.
- `src/preview-capabilities.mjs` / `src/integration-security.mjs` — local one-use expiring preview receipts, artwork adapter and strict metadata/manufacturing contract review; never checkout authorization.
- `fixtures/` — read-only manufacturing SKU snapshot captured 2026-10-14, not an authoritative sales source.
- `src/catalog.mjs` — seven *illustrative* product geometries: crew T-shirt, V-neck, long sleeve, hoodie, tumbler, backpack, rug. These are examples, never a limit on the business catalog.
- `src/model-assets.mjs` — validated static GLB scene/mesh/UV intake, local SHA-256 and CPU preview adapter; never production approval.
- `src/calibration.mjs` — physical measurement worksheet validation and DPI / placement calculations; always unapproved.
- `src/manufacturing-review.mjs` — offline server-side profile provenance, exact variant/model/zone bindings, GLB UV and bleed checks, and injected reviewer trust seam; never production approval.
- `src/geometry3d.mjs` — distinctive procedural low-poly meshes, normalized conceptual UV patches, and perspective math for seven example shape families.
- `src/viewer3d.mjs` — local-only CPU canvas 3D display with orientation, zoom and draft artwork overlays; never print-proof accurate.
- `src/core.mjs` — manifest and composition validation, rotated preview bounds, calibrated-dimension DPI helper and production/commerce gates.
- `src/image-inspection.mjs` — checks accepted image headers, declared type and dimensions; **not** a full image decoder, scanner or production acceptance pipeline.
- `src/local-store.mjs` — local storage, random grants, verified composition, private design revisions.
- `src/local-server.mjs` — loopback-only HTTP API and static demo server, never a Shopify storefront backend.
- `demo/` — mobile and desktop 2D editing experience and private local draft recovery.
- `tests/` — core/HTTP/security smoke tests using Node's test runner.
- `docs/ARCHITECTURE.md` — handoff baseline and production milestones.
- `docs/GLB_ASSET_AND_CALIBRATION_CONTRACT.md` — GLB importer contract, physical measurement inputs and controlled Shopify staging roadmap.
- `docs/3D_CONCEPT_MODELS.md` — exact v0.3 implementation, model limitations, verification and upcoming milestones.
- `docs/LOCAL_API.md` — HTTP interface and known security limitations.
- `docs/OBJECTIVE_5_SHOPIFY_BRIDGE.md` — local staging integration evidence and rollout hold points.
- `docs/OBJECTIVE_6_SECURITY_INTEGRATION.md` — offline security contracts, results and unaddressed production hold points.
- `docs/SHOPIFY_STAGING_INTEGRATION.md` — verified Shopify staging baseline and controlled integration plan.

**Shopify is unchanged by this package.** No app was installed, no product or price was published, no live or staging theme was modified, and no plan upgrade was made.


## Objective 7 — offline catalog and identity boundaries (v0.7)

See `docs/OBJECTIVE_7_CATALOG_IDENTITY.md`. The new catalog assembler validates fully
paginated read-only product/variant captures, identity uniqueness, query-scope counts,
freshness and pure anti-rollback transitions. The injected trusted-principal interface
requires an external cryptographic verifier; no Shopify authentication is bundled.
The optional local capture integration exposes read-only evidence and never checkout.
Run `npm test` on Node 22+ to reproduce all 83 offline regression tests.


## Objective 8 — offline manufacturing profile evidence and GLB print-zone gates (v0.8)

See `docs/OBJECTIVE_8_MANUFACTURING_REVIEW.md`. An independent server-side review contract now binds exact shop/product/variant/blank/measurement evidence and inspected GLB bytes to a deterministic SHA-256 review subject. It rejects unmeasured or unmapped zones, degenerate printable UVs, unsafe rotation/bleed, forged review fields, expired/revoked evidence and untrusted artwork dimensions. A cryptographic reviewer/verifier must be provided by a future protected backend; test-only mock signatures do not provide production trust. All results explicitly disable production, checkout and machine output. Run `npm test` on Node 22+ to reproduce offline regression tests. No Shopify writes.

## Objective 9 — offline authenticated order/webhook reconciliation (v0.9)

`src/order-reconciliation.mjs` adds a fail-closed Shopify-style raw-body HMAC verification seam and synthetic `orders/create` reconciliation against a trusted current design lookup, exact product/variant/customer identities, signed metadata and an injected atomic replay ledger. The adversarial tests include forged events, duplicate JSON keys, tenant/owner/variant swaps, stale revisions, altered metadata, replay conflicts, concurrent idempotency and ledger outages. **No actual Shopify webhook, checkout, payment or production authorization is implemented.** See `docs/OBJECTIVE_9_ORDER_RECONCILIATION.md` for trust boundaries and integration holds.


## Objective 10 — offline durable replay and revision CAS (v0.10)

`src/offline-durable-ledger.mjs` adds a single-host, local-only filesystem fixture with atomic event/order/design-revision claims, cross-process serialization, persisted design revision compare-and-swap, crash-fault injection and fail-closed stale lock/corruption behavior. `reconcileOfflineOrder` passes validated matched-line bindings into the injected claim transaction. No Shopify writes, checkout, hosted authentication, payment or manufacturing authorization. See `docs/OBJECTIVE_10_DURABLE_LEDGER.md` for security limitations and reproducible tests.

### v0.11: Night Watch Objective 11 — offline versioned cart metadata (NO CHECKOUT)

`src/versioned-cart-metadata.mjs` provides a non-authorizing HMAC-SHA256 v2 receipt that binds tenant, pseudonymous owner/session tags, immutable design revision, exact product/variant, digest, nonce and expiry. It supports key rotation/revocation and rejects tamper, replay, stale revisions and invalid identity callbacks. `src/offline-durable-ledger.mjs` now atomically consumes nonces with current design-revision CAS on a **single host**, migrating prior v0.10 local state. The existing v0.9 legacy order reconciliation is not upgraded to v2 and cannot authorize checkout. No real Shopify customer login, checkout, payment, or production workflow exists. See `docs/OBJECTIVE_11_VERSIONED_CART_METADATA.md`.

## Objective 12 — offline synthetic cart-to-order lineage (v0.12)

The new `src/offline-order-lineage.mjs` and `src/offline-durable-ledger.mjs`
implement a **test-only** authenticated checkout/session identity seam and
atomic observed-order/cancellation transitions with strict event replay, design
revision, owner, product, variant, checkout and line binding. A v2 receipt's
nonce remains one-use and cannot authorize payment, production or fulfillment.
The synthetic HMAC event format is **not** a Shopify webhook. There is a
**known two-transaction crash gap** between nonce consumption and lineage commit,
so this is not a production exactly-once solution. See
`docs/OBJECTIVE_12_OFFLINE_ORDER_LINEAGE.md` for exact boundaries and holds.

No live or staging Shopify writes, no deployments and no new dependencies.


## Objective 14 — opt-in Linux kernel lock crash recovery (offline)

The local ledger now supports `createOfflineDurableLedger({directory, lockMode: 'kernel'})` on Linux with `/usr/bin/flock`. This uses a persistent `.atomic-lock` file and kernel advisory locking; SIGKILL releases the lock without unsafe age-based theft. It is deliberately incompatible with a pre-existing legacy `.atomic-lock` directory, and the old `mkdir` mode remains the default. See `docs/OBJECTIVE_14_KERNEL_LOCK_CRASH_RECOVERY.md` for safety constraints, tests, and remaining production gates. **No Shopify writes, checkout, payment, or manufacturing authorization.**


## Objective 15 — atomic offline multi-line order lineage

The synthetic-only `src/offline-multiline-order.mjs` supports HMAC-authenticated
2–25 line events with exact tenant, owner, checkout/session, product, variant,
design revision, and digest binding. `src/offline-durable-ledger.mjs` atomically
commits **all** prepared cart receipt nonces, design claims, order lines, and event
under one local filesystem lock. Legacy single-line APIs remain supported;
cross-protocol order/event/design collisions fail closed.

See `docs/OBJECTIVE_15_ATOMIC_MULTILINE_ORDER.md` for security boundaries,
synthetic fixtures, migration, test commands, and remaining production gates.
**No Shopify reads or writes, checkout, payment, manufacturing, or deployment.**


### v0.16 — Offline multi-order cancellation history and reconciliation (Night Watch Objective 16)

The local-only durable ledger now validates a **complete append-ordered synthetic
multi-line history**: exactly one observed event per order, no orphan events or
cancellations preceding observation, and `OBSERVED`/`CANCELLED` state must match
the stored cancellation evidence. A read-only, deeply immutable
`getMultiLineageHistory` snapshot supports offline review; a maximum of 32 events
per order limits cancellation-event flooding. Fault-injected cancellation tests
cover pre-rename rollback, post-rename lost acknowledgments, concurrent writers,
and persistent claim retention. This is not tamper-proof storage, real Shopify
order proof, payment confirmation, or production authorization. See
`docs/OBJECTIVE_16_MULTILINE_HISTORY.md`.

### v0.17 — Lossless synthetic multi-order history compaction (Night Watch Objective 17)

`compactMultiLineageHistory` atomically stores the full UUID/digest replay
history of a CANCELLED multi-line order as compact tuples without deleting any
replay tombstones, design/variant/owner claims, receipt nonces, or order records.
Historical lookups, subsequent cancellations, event conflicts, and cross-protocol
replay protection consult the compact archive. The existing 32-events-per-order,
5,000 combined events and 2 MiB ledger limits remain. This is **not** a
garbage-collection, production retention, hosted-auth, checkout, or fulfillment
mechanism. See `docs/OBJECTIVE_17_LOSSLESS_HISTORY_COMPACTION.md`. No Shopify
reads/writes, deployment or new dependencies.

## Objective 18 — optional authenticated offline ledger (v0.18)

`createOfflineDurableLedger({audit:{keys,activeKeyId,readAnchor,compareAndSetAnchor}})`
adds opt-in HMAC-SHA256 snapshot commitments linked by previous MAC and
compared against an independently trusted external monotonic anchor contract.
It rejects tampered data, rollback/restore mismatches, missing keys, unsafe
legacy adoption, and unaudited downgrades. A two-resource crash between local
rename and anchor CAS deliberately **blocks** reads/writes until independently
verified operator recovery; there is no production-grade atomic coordination.
See `docs/OBJECTIVE_18_AUTHENTICATED_OFFLINE_LEDGER.md`. Existing offline
editor/GLB/catalog features and unaudited fixture behavior are unchanged.
**No hosted auth, production anchor, checkout, payment or Shopify writes.**


## Objective 21 — offline private artwork-byte and process evidence (v0.21)

`src/manufacturing-artwork-evidence.mjs` introduces a **separate, non-authorizing**
PNG-byte verification and private-storage attestation contract, with exact owner,
revision, design composition, product, variant, blank, surface, process and
artwork binding. It rejects altered/missing bytes, forged or stale attestations,
low effective raster DPI and unsafe bleed/rotation using independently supplied
process policy values. Only a deliberately narrow, structurally verified PNG
subset is accepted; JPEG/WebP and other formats await full trusted decoders.
This does **not** override older manufacturing review's artwork hold, provide
hosted identity/storage or approve printing, checkout or deployment. See
`docs/OBJECTIVE_21_ARTWORK_BYTE_EVIDENCE.md`. No Shopify writes.


## Objective 22 — integrated immutable revision and manufacturing evidence (v0.22)

`reviewIntegratedManufacturingEvidence` combines backend-sourced CURRENT immutable
design revisions, independent artwork byte/policy attestations, measured
manufacturing profiles, GLB UV/physical calibration, and an additional signed
integrated review subject. Existing manufacturing/geometry entrypoints retain
their artwork hold unless **raw** independently checked private-byte evidence
is supplied; caller `verified` flags never bypass it. The integrated wrapper
rejects caller-supplied design, checks the registry twice, clones untrusted
records and model bytes, and binds policy/attestation/model/design revisions
together. **All successful evidence remains non-authorizing**: no production,
checkout, machine output, hosted auth or Shopify writes. See
`docs/OBJECTIVE_22_INTEGRATED_MANUFACTURING_EVIDENCE.md`.

## Objective 23 — Offline private artwork and immutable revision registry

`src/offline-private-revision-registry.mjs` adds a single-host, Linux-only, HMAC-authenticated, externally anchored, revocation-aware local fixture. Atomic CAS revision + private PNG byte commits, persistent operation replay rejection, revocation and crash fail-closed tests are in `tests/objective23-private-registry.test.mjs`. See `docs/OBJECTIVE_23_DURABLE_PRIVATE_REGISTRY.md` for limitations. This is **not** hosted authentication, encrypted production storage, manufacturing authorization or Shopify integration. No store writes.


## Objective 24: independently signed offline registry recovery

See `docs/OBJECTIVE_24_SIGNED_REGISTRY_RECOVERY.md`. Optional Ed25519-verified operator permits permit exact one-step external anchor catch-up after interrupted v0.24 private-registry writes, preserving immutable revisions, revocations and replay records. Normal reads remain fail-closed. Legacy v0.23 interrupted writes cannot be automatically repaired. This is an offline Linux single-host fixture, not production recovery or Shopify integration.

## Objective 25 — optional authenticated artwork encryption (offline)

Private revision registry now supports opt-in AES-256-GCM artwork ciphertext with identity/revision-bound associated data, explicit plaintext migration, and replay-protected key rotation. Existing unconfigured offline plaintext behavior remains for backwards compatibility. No production key provider, hosted storage, checkout integration, or Shopify write is implied. See `docs/OBJECTIVE_25_AUTHENTICATED_ARTWORK_ENCRYPTION.md`.


## Night Watch Objective 26 (offline)

The encrypted private-artwork registry now exposes an opt-in, trusted-verifier-backed `readAuthenticatedArtwork` seam that binds owner, shop, product, variant, design, revision, artwork and layer before releasing PNG bytes. Configuring this seam disables the weaker legacy owner-only artwork read. Read-only `inspectArtworkKeyRetirement` counts historical/revoked ciphertext references without ever certifying old keys safe to destroy. See `docs/OBJECTIVE_26_AUTHORIZED_ARTWORK_AND_KEY_RETIREMENT.md`. **This is not hosted authentication, checkout integration, key custody, or production authorization.**

## Objective 28 — signed offline administrative artwork cryptography

The optional `adminAuthorization` contract adds independently verified, Ed25519-signed operator permits for encryption-key rotation and legacy plaintext migration. The exact signed request binds the current anchored state, full historical key inventory, asset count, target key and durable operation ID; failures are fail-closed. See `docs/OBJECTIVE_28_SIGNED_ADMIN_CRYPTO.md`. The synthetic verifier/keys/anchor are **not production authorization**. No Shopify writes, deployment or manufacturing approvals.


### Objective 31B — Opt-in audited registry coordination (v0.30.2)

The offline `createOfflineAuditedRegistryCoordinator` integration wraps signed-authenticated private-registry mutations and independent Objective 31A audit journal appends under a single-host cooperative lock. It fails closed when either independently anchored head is missing, stale, or inconsistent, and supports independently signed exact-one-step crash reconciliation and legacy bootstrap (explicitly unproven earlier history). It is **not** a distributed transaction or a production audit guarantee; direct registry callers can bypass it. See `docs/OBJECTIVE_31B_AUDITED_REGISTRY_COORDINATION.md`. No Shopify writes or deployments.

## Night Watch v0.30.3 / Objective 31C — trusted offline audited service

The opt-in `src/offline-audited-registry-service.mjs` now constructs the authenticated private registry and independent audit journal behind a frozen, allowlisted service API. Only authenticated registry mutations are routed through Objective 31B's coordinator; authenticated artwork reads and operator-signed backup exports are guarded by before/after audit-anchor continuity checks. `tests/objective31c-trusted-service.test.mjs` includes real child-process crash, synthetic external anchor rollback and independent signed recovery fixtures. See `docs/OBJECTIVE_31C_TRUSTED_OFFLINE_SERVICE.md`. **No production readiness or Shopify writes.** This Night Watch branch remains separate from Main Engineering's v0.32 UI branch.

## Night Watch v0.30.5 / Objective 31E — independent offline witness and recovery permit ledger

Opt-in Ed25519-signed **challenge-bound** independent witness receipts and strict-majority verification now detect stale local anchor heads relative to separately held witness state. An append-only, fsync-backed local authorization ledger reserves a signed recovery permit ID **before** attempting pending-anchor recovery and refuses replays across process restarts. A witnessed recovery guard composes these with the existing Objective 31D anchor adapter. All services are **offline synthetic contracts**: no deployed witness, protected production key custody, offsite/WORM retention, global rollback protection, Shopify modifications, or production recovery authority. The local permit ledger requires an independently retained pin to detect valid-prefix rollback. See `docs/OBJECTIVE_31E_WITNESS_AND_RECOVERY_LEDGER.md`. Main Engineering's separate v0.32 UX branch is untouched.


### Objective 31F — offline witnessed recovery-ledger reconciliation (v0.30.6)

An opt-in `src/offline-recovery-reconciliation.mjs` guard now verifies independent Ed25519 witness quorums for **both** the durable anchor and the recovery-ledger head, re-reads both resources to detect races, and uses the ledger’s new locked `reserve(expectedHead)` precondition. Ambiguous recovery outcomes and any prior burned reservation require forensic review; no automatic retries or second recovery are allowed. This is an **offline security contract only**: no hosted witnesses, production keys, global anti-rollback, atomic multi-resource transaction, real customer authentication, Shopify changes, or deployment. See `docs/OBJECTIVE_31F_LEDGER_WITNESS_RECONCILIATION.md` and `tests/objective31f-ledger-witness-reconciliation.test.mjs`.

## Objective 31G — offline independently reviewed recovery

The optional Objective 31G forensic-review quorum validates independently signed, challenge-bound outcomes for **every** burned recovery reservation before allowing a **new** recovery permit. It never retries a burned permit or automatically clears review-required state. See `docs/OBJECTIVE_31G_FORENSIC_ADJUDICATION.md`. This is an offline integration contract, not production authorization; independent reviewer deployment, durable proof retention, offsite monotonic anchoring and atomic cross-resource recovery remain unimplemented. No Shopify modifications.


### Night Watch Objective 31H (offline only)

Version 0.30.8 adds an opt-in durable forensic-review evidence journal with independent signed head verification and fail-closed recovery-guard integration. See `docs/OBJECTIVE_31H_FORENSIC_JOURNAL.md`. This is a local Linux-only security contract, not production authorization or Shopify integration.

## Objective 31I-A — offline historical forensic reviewer epochs

The optional `reviewerEpochs` contract retains verification of old signed forensic evidence after reviewer key rotation. `verifyOfflineForensicEvidenceBundle` checks a portable evidence chain against an **independently pinned** head and epoch policy. This is not a deployed reviewer, witness-publication, production-authentication, or offsite evidence-retention service. See `docs/OBJECTIVE_31I_HISTORICAL_REVIEWER_EPOCHS.md`.


## Objective 31I-B — offline signed witness-head publication (v0.30.10)

An opt-in, strict-majority Ed25519 signed forensic-head publication chain and durable Linux-only retention store provide portable verification of independently pinned publication heads. Reviewer-policy transitions require the **old** reviewer quorum plus witness signatures; the composite verifier binds the publication to the exact forensic evidence and reviewer epochs. Real child-process crash and cross-process lock tests are included. **No deployed independent witness, offsite retention, trusted time, protected production keys, Shopify writes, or production authorization.** See `docs/OBJECTIVE_31I_B_WITNESS_HEAD_PUBLICATION.md`.

## Objective 31J — offline certified reviewer rotations and publication outbox (v0.30.11)

An opt-in strict verifier requires outgoing-quorum-signed reviewer-policy transition certificates plus incoming-key proof of possession. A separate durable single-host witness-publication outbox stages signed publications and records majority-witness acknowledgements; cross-store crash windows fail closed pending forensic review. The v0.30.10 APIs remain backward compatible. **No independent hosted witness, trusted time, offsite retention, protected production keys, atomic distributed commit, Shopify writes or production authorization.** See `docs/OBJECTIVE_31J_TRANSITION_OUTBOX.md`.


## Night Watch Objective 31Z (offline, QA only)

`src/offline-archive-receipt-coordinator.mjs` implements a separately pinned, fail-closed archive/receipt staging and supervised reconciliation boundary. It verifies Ed25519-signed export receipts and authentic acquisition archives, fsyncs durable local evidence, refuses orphaned or ambiguous states, and delegates actual signed receipt commits to the existing registry (including multi-epoch witness-policy histories). This does **not** provide atomic distributed transactions, Shopify writes, production authentication, manufacturing approval, or hosted checkout. See `docs/OBJECTIVE_31Z_CROSS_RESOURCE_ARCHIVE_RECEIPT_COORDINATION.md`.


## Night Watch Objective 32B (v0.30.29; offline QA only)

Added an opt-in, externally pinned, read-only multi-directory orphan/uncertain-state classifier (`src/offline-pinned-orphan-classifier.mjs`). It authenticates signed receipt history and witness-policy pins through the existing registry, verifies signed archive bytes, classifies untrusted pending/quarantine/orphan evidence without promoting it to authenticated status, and returns a frozen supervisory evidence report with an unkeyed digest. No remediation, Shopify access, checkout, manufacturing authorization or deployment. See `docs/OBJECTIVE_32B_EXTERNALLY_PINNED_ORPHAN_CLASSIFICATION.md`.


## Night Watch Objective 32C (offline supervisory review verifier)

Version v0.30.30 adds fail-closed, Ed25519-quorum verification of externally pinned Objective 32B orphan reports, including exact anomaly evidence binding, independently pinned reviewer policies, expiry and externally anchored replay-snapshot membership checks. This is read-only cryptographic verification, **not** durable replay consumption or authorization. See `docs/OBJECTIVE_32C_AUTHENTICATED_SUPERVISORY_REVIEW.md`. No Shopify writes, live authentication, production readiness, remediation or checkout.

### Objective 32D — offline durable supervisor replay commitment

`src/offline-supervisor-replay-commit.mjs` adds Linux-local, fail-closed, immutable one-successor-per-head replay consumption for signed 32C supervisory reviews. Requires separately pinned replay genesis/head, trusted clock and reviewer policy; uses fsync + atomic hardlink CAS and explicitly supervised post-crash staging finalization. Does not authorize remediation, manufacturing, checkout, Shopify writes or deployment. See `docs/OBJECTIVE_32D_DURABLE_SUPERVISOR_REPLAY_COMMIT.md`.

## Night Watch Objective 32G (v0.30.34; offline QA only)

Added `src/offline-portable-replay-witness-history.mjs` to authenticate a bounded consecutive window of independently pinned 32F signed witness receipts, with no omissions, forks, rollback or gaps. Policy rotation requires **outgoing and incoming** Ed25519 majorities and an independently pinned transition digest; incoming keys must be disjoint. This is read-only cryptographic verification, not independently deployed witness publication or proof of trusted time. See `docs/OBJECTIVE_32G_WITNESS_HISTORY_CONTINUITY.md`. No Shopify writes, production keys, checkout, remediation or deployment.

## Night Watch Objective 32H (v0.30.35; offline QA only)

Added `src/offline-portable-witness-history-checkpoint.mjs` for strict portable JSON, Ed25519-majority signed witness-history checkpoints and independently supplied anchor comparisons. Exact anchored checkpoints and successor windows are verified against complete 32G/32F evidence; stale, forked, gapped, tampered or forged candidates fail closed. A locally supplied anchor is **not** independently published proof; the module never writes or authorizes downstream operations. See `docs/OBJECTIVE_32H_PORTABLE_WITNESS_HISTORY_CHECKPOINT.md`. No Shopify reads/writes, deployment, production auth, checkout, or manufacturing authorization.


## Objective 32I — offline signed checkpoint ancestry (v0.30.36)

Opt-in `src/offline-witness-checkpoint-ancestry.mjs` verifies multiple contiguous signed witness-history checkpoints with full underlying witness evidence, externally supplied start/end anchor pins, and dual-majority Ed25519 auditor rotation contracts. See `docs/OBJECTIVE_32I_SIGNED_CHECKPOINT_ANCESTRY.md`. **Local-only; no independent publication, production, remediation or checkout authorization.**


## Objective 32J — offline signed checkpoint split-view comparison (v0.30.37)

`src/offline-witness-checkpoint-split-view.mjs` verifies **both** supplied 32I ancestries against a shared root and separately supplied terminal pins before identifying authenticated sibling checkpoint forks. It reports same-policy Ed25519 quorum signer intersection, or conflicting dual-majority policy-rotation outgoing signer intersection when provable, without claiming independent publication, globally unique history, checkout or production readiness. See `docs/OBJECTIVE_32J_PINNED_SPLIT_VIEW_DETECTION.md`. No Shopify reads/writes or deployment.


## Objective 32L — offline conflict-proof exchange

Opt-in two-party Ed25519-signed proof exchange receipts, canonical transport, independent proof/transcript pins, and read-only two-view equivocation reconciliation. See `docs/OBJECTIVE_32L_OFFLINE_CONFLICT_EXCHANGE.md`. No hosted identity, independent publication, persistent replay state, Shopify checkout or production authority.

## Objective 32N — offline signed pending recovery

Opt-in, fail-closed majority-Ed25519 adjudication of uncertain Objective 32M journal commits. Requires independently pinned reviewer keys, exact pending evidence and externally trusted head pins; no automatic recovery, hosted identity, Shopify mutation or production authorization. See `docs/OBJECTIVE_32N_SIGNED_PENDING_ADJUDICATION.md`.


### Objective 32O — opt-in durable recovery attempt receipts (offline only)

`createOfflineConflictExchangeJournal()` now exposes `recoveryReceiptGenesisHead`
and `inspectRecoveryReceipts({expectedReceiptHead})`. Supply an independently
retained `{count,headDigest}` as `expectedReceiptHead` when calling
`adjudicatePending` to opt into the receipt ledger. Under the same Linux
cross-process journal lock, a signed recovery decision is independently
reverified, its nonce and pending byte digest are checked against the entire
append-only receipt inventory, and an authenticated, hash-chained **attempt**
receipt is fsynced before the pending file is unlinked. Once the inventory
exists, unreceipted adjudication is rejected. A crash after the receipt is
written but before unlink is intentionally fail-closed: that nonce and pending
byte digest cannot be retried, and a human must independently investigate.
Receipt heads are **caller-pinned**, not published by this prototype.
The ledger proves neither completion nor cross-resource atomicity. It does
not grant hosted identity, Shopify operations, production, or checkout.
See `docs/OBJECTIVE_32O_DURABLE_RECOVERY_ATTEMPT_RECEIPTS.md`.

## Objective 32P — offline recovery reviewer-policy epoch continuity (v0.30.43)

A read-only Ed25519 dual-majority reviewer-rotation history verifier binds independently pinned 32O recovery-attempt receipt segments to an authenticated policy-transition chain. The journal exposes `inspectRecoveryPolicyEpochHistory` to compare the verified terminal receipt pin against its local inventory. This **does not rotate active journal authorization**, independently publish pins, authorize recovery or enable hosted Shopify operations. See `docs/OBJECTIVE_32P_RECOVERY_POLICY_EPOCH_CONTINUITY.md`.

## Objective 32Q (v0.30.44) — offline opt-in reviewer cutover

The Linux-local exchange journal now supports a one-time, externally pinned, dual-majority authenticated recovery-reviewer policy cutover. Pending or uncertain commits fail closed; after activation, adjudication requires the independently retained cutover digest and active reviewer roster. See `docs/OBJECTIVE_32Q_DURABLE_REVIEWER_CUTOVER.md`. This is NOT hosted authentication, production readiness, or Shopify integration.

## Objective 32R (offline interrupted reviewer cutover adjudication)

Opt-in dual-majority Ed25519-signed abort/finalize adjudication for interrupted local reviewer-policy cutovers, exact independently pinned marker and receipt evidence, durable one-shot resolution receipts, and fail-closed crash/replay handling. See `docs/OBJECTIVE_32R_INTERRUPTED_CUTOVER_ADJUDICATION.md`. Not hosted auth, external witness publication, independent monotonicity, Shopify integration, or production authorization.

### Objective 32S (offline cutover-resolution proof audit)

Portable, independently pinned 32R resolution-attempt proof verification and fail-closed read-only local inspection of interrupted cutovers. `src/offline-conflict-cutover-resolution-proof.mjs`, `tests/objective32s-resolution-proof.test.mjs`, `docs/OBJECTIVE_32S_RESOLUTION_HISTORY_VERIFICATION.md`. A signed resolution receipt proves an authorized **attempt**, not successful completion; a locally completed marker does not establish independent offsite publication. No Shopify writes, hosted auth, manufacturing authorization, checkout or production deployment.

## Objective 32U — offline byte-pinned resolution-evidence transport (v0.30.48)

`src/offline-conflict-resolution-transport.mjs` provides bounded exact-byte JSON evidence export/import, independently supplied domain-separated SHA-256 byte pins, duplicate-key and malformed-stream rejection, and revalidation of 32T observer/union pins and signed 32S histories. No trust anchors are embedded in transport. JSON property order of signed proof bodies is preserved; this is **not** an order-independent canonical JSON format. See `docs/OBJECTIVE_32U_CANONICAL_RESOLUTION_TRANSPORT.md`. Local only; no Shopify access, hosted authentication, independent publication, checkout or production authorization.


## Objective 32V — offline session-bound chunk evidence transport (v0.30.49)

`src/offline-conflict-resolution-chunks.mjs` provides bounded chunk manifests and read-only ordered reassembly with independently supplied manifest/transport/session pins, caller-supplied replay-history checks and complete downstream 32U/32T/32S Ed25519 evidence verification. Omission, reordering, duplicate chunks, mixed sessions and altered bytes fail closed. **No durable replay store, independently published anchors, hosted authentication, Shopify writes, checkout or production authority.** See `docs/OBJECTIVE_32V_PINNED_CHUNK_RESOLUTION_TRANSPORT.md`.

## Objective 32W — offline crash-conscious signed manifest acceptance journal (v0.30.50)

`src/offline-conflict-resolution-manifest-journal.mjs` adds a single-Linux-host, `flock`-serialized, hash-chained acceptance journal for fully verified Objective 32V signed evidence chunks. It persists manifest, session and transport replay claims with externally pinned head continuity, fsynced pending/link/commit stages, and fail-closed uncertain-crash handling. See `docs/OBJECTIVE_32W_DURABLE_MANIFEST_ACCEPTANCE_JOURNAL.md`. This is **not** a remote witness, distributed atomic transaction, hosted authentication, Shopify checkout, manufacturing approval, or production deployment.


## Night Watch Objective 32X (v0.30.51, offline)

`src/offline-conflict-manifest-claim-adjudication.mjs` and the 32W journal `adjudicateInterruptedClaimReadOnly` method authenticate dual-quorum, independently pinned, state-specific read-only inspection of interrupted claims. No repair, auto-retry, Shopify writes, hosted identity, or deployment. See `docs/OBJECTIVE_32X_READ_ONLY_MANIFEST_CLAIM_ADJUDICATION.md`.

## Night Watch Objective 32Y (v0.30.52, offline)

`createOfflineConflictManifestJournal().exportInterruptedClaimTranscriptReadOnly()` emits bounded canonical bytes for the 32X dual-quorum local inspection; `verifyOfflineConflictManifestClaimTranscript()` re-verifies independently supplied snapshot/byte/decision/roster/head pins and signed Ed25519 authorization. Duplicate keys, reordered fields, truncation, malformed UTF-8, tampering and forged production/repair flags fail closed. See `docs/OBJECTIVE_32Y_CANONICAL_INSPECTION_TRANSCRIPT.md`. **No independent witness, repair, checkout, Shopify writes, or deployment.**


### Objective 32Z — read-only signed transcript continuity (offline)

`src/offline-conflict-manifest-claim-continuity.mjs` verifies bounded, independently pinned append-only continuity across multiple 32Y authenticated inspection transcripts. It rejects forks, missing checkpoints, rollback, duplicate signed decisions and nonmonotonic caller-supplied observations. This is **not** a trusted timestamp, external anchor, repair authority, hosted authentication, or production evidence. See `docs/OBJECTIVE_32Z_PINNED_TRANSCRIPT_CONTINUITY.md`.

## Night Watch Objective 33B — signed namespace and observer roster (v0.30.55, offline)

`src/offline-conflict-signed-namespace-roster.mjs` adds a read-only Ed25519 majority-authority **and unanimous observer** signature contract binding an independently pinned namespace, journal scope, epoch, complete observer roster, 33A inventory pins, and reconciliation digest. It rejects forged, omitted, reordered or substituted members and re-verifies the full 33A/32Z/32Y evidence chain. Full-roster membership/nonmembership is **only scoped to the supplied signed roster**. See `docs/OBJECTIVE_33B_SIGNED_NAMESPACE_OBSERVER_ROSTER.md`. No independent anchor publication, globally complete observer discovery, trusted clock, hosted identity, Shopify writes, checkout, repair, or production authority.

## Night Watch Objective 33C — independently pinned authority-policy rotation (v0.30.56, offline)

`src/offline-conflict-authority-policy-rotation.mjs` verifies a signed adjacent-epoch transition between two independently pinned 33B namespace/authority commitments. Both predecessor and successor authority majorities must authorize the same domain-separated transition; all underlying signed observer/inventory/transcript evidence is reverified. Missing external transition/previous-head pins, forged signatures, rollback, skipped epochs, substitution and expiry fail closed. See `docs/OBJECTIVE_33C_PINNED_AUTHORITY_POLICY_ROTATION.md`. Caller-supplied time and externally held anchors are not trusted timestamps, global fork prevention or hosted authorization. No Shopify writes, checkout, repair, production or deployment.


## Night Watch Objective 33D — pinned multi-transition authority history (v0.30.57, offline)

`src/offline-conflict-authority-history.mjs` verifies 2–8 consecutive dual-quorum 33C rotations with strictly linked epochs, previous transition digests, policy and commitment pins and a domain-separated, independently retained terminal chain head. Every link re-verifies complete signed 33B/33A/32Z/32Y evidence. Tests include real three-link signed histories, omissions, signed forks, rollback, expiry, malicious inputs and forged signatures. See `docs/OBJECTIVE_33D_PINNED_AUTHORITY_HISTORY.md`. No global fork prevention, independently published anchors, protected keys, trusted time, Shopify writes, hosted auth, checkout, repair, production or deployment.

## Night Watch Objective 33E — signed cross-observer authority-history reconciliation (v0.30.58, offline)

`src/offline-conflict-authority-observer-reconciliation.mjs` authenticates two independently pinned Ed25519 observer attestations over complete 33D authority histories, distinguishing agreement, authenticated prefix extension, and conflicting signed authority transitions. Fork evidence includes portable snapshots of both signed transitions and observer attestations. Signed re-pinning, missing anchors, forged signatures, omission and scope substitution fail closed against independently retained pins. See `docs/OBJECTIVE_33E_SIGNED_OBSERVER_AUTHORITY_RECONCILIATION.md`. **No independent anchor publication, global fork prevention, protected signing keys, trusted time, Shopify writes, hosted authentication, checkout, repair or production authority.**


## Objective 33H (v0.30.61) — signed pending-acceptance adjudication (offline only)

`adjudicatePendingReadOnly` verifies independently pinned pending bytes and a two-reviewer-group Ed25519 inspection decision under the 33G cross-process lock. It distinguishes pending-only from hardlinked pending-linked interrupted commits without modifying acceptance records, clearing pending markers, or granting recovery/production authority. See `docs/OBJECTIVE_33H_SIGNED_PENDING_ACCEPTANCE_ADJUDICATION.md`.

## Night Watch Objective 33K — independently pinned signed inventory-head receipts (v0.30.64, offline)

`src/offline-conflict-adjudication-inventory-head-receipts.mjs` verifies 2–8 externally pinned, Ed25519-signed 33J inventory-head assertions with canonical bounded receipts, exact host roster and unique keys, expiry, caller-supplied replay sets, and scope/head/digest pins. It distinguishes matching claims, same-height signed divergence and unequal-height unresolved progress without inventing remote filesystem, global fork or ancestry proof. See `docs/OBJECTIVE_33K_SIGNED_CROSS_HOST_INVENTORY_HEAD_RECEIPTS.md`. **Read-only local prototype; no trusted timestamps, external publication, protected keys, actual cross-host networking, Shopify writes, hosted authentication, checkout, recovery or production authority.**

## Night Watch Objective 33L — signed predecessor assertions for unequal inventory heads (v0.30.65, offline)

`src/offline-conflict-adjudication-inventory-ancestry.mjs` verifies two independently pinned 33K signed host receipts and up to 32 contiguous Ed25519-signed predecessor **claims** from the higher host. Each adjacent link is externally pinned and binds namespace, scope, host identities, 33J claimed record digest, head counts, expiry and nonce; omissions, forged signatures, tampering, stale observations and noncanonical bytes fail closed. A missing or too-large chain stays explicitly unresolved, and count differences never imply ancestry. See `docs/OBJECTIVE_33L_SIGNED_INVENTORY_PREDECESSOR_ASSERTIONS.md`. **This does not independently verify 33J record contents or remote disk ancestry. No hosted auth, independent time/anchors, Shopify writes, checkout, recovery, production or deployment.**

## Night Watch Objective 33M — pinned record-byte ancestry evidence (v0.30.66, offline)

`src/offline-conflict-adjudication-inventory-record-evidence.mjs` revalidates independently pinned signed 33K head receipts and a bounded suffix of actual canonical 33J record **bytes**, including the nested signed 33I observer transcripts and 33H reviewer approvals. Adversarial tests reject omitted/reordered/forked records, substituted pins, tampered reviewer/observer signatures, replay and malformed bytes. It verifies only **supplied** record evidence: not remote disk state, earlier prefix, global history, independent anchor publication, hosted authentication, checkout or production. See `docs/OBJECTIVE_33M_PINNED_INVENTORY_RECORD_EVIDENCE.md`. **No Shopify writes or deployments.**

### Objective 33N — independently pinned, read-only filesystem acquisition receipts

Optional Linux-local, read-only acquisition of actual 33J inventory record bytes through directory-FD-anchored `O_NOFOLLOW` file opens, external directory/record/head pins, and signed Ed25519 witness receipts. Detects unsafe filesystem entries and observable TOCTOU races. **Does not prove remote disk state, historical-prefix validity, trusted time, independently witnessed publication, durable replay prevention, embedded reviewer/observer signatures, or production authority.** Use the separate Objective 33M verifier for nested signed evidence. See `docs/OBJECTIVE_33N_FILESYSTEM_ACQUISITION.md`.

### Objective 33O — independently pinned, durable multi-session acquisition receipts

Offline Linux-local append-only acceptance registry for independently pinned 33N signed acquisition receipts, with historical signature re-verification, contiguous inventory-head binding, durable nonce/digest replay prevention, crash-uncertainty blocking, and cross-process admission serialization. **Not** remote disk proof, trusted time, multi-host consensus, hosted authentication, production or Shopify checkout authorization. See `docs/OBJECTIVE_33O_ACQUISITION_RECEIPT_REGISTRY.md`.

### Objective 33P — independently signed acquisition registry head assertions (v0.30.69)

`src/offline-conflict-acquisition-head-publications.mjs` verifies 2–8 independently pinned Ed25519-signed publisher claims for the Objective 33O acquisition registry head and inventory head, with namespace/host/registry/directory bindings, nonce/digest replay rejection, expiry, rollback floor, and explicit split-view/unequal-height classification. These are **signed assertions**, not verified remote disk state, actual external publication, independently trusted time, proven ancestry, hosted auth, recovery, checkout, Shopify writes or production authorization. See `docs/OBJECTIVE_33P_SIGNED_ACQUISITION_HEAD_PUBLICATIONS.md`.

### Objective 33Q — independently pinned 33O registry record-byte verification (v0.30.70)

`src/offline-conflict-acquisition-registry-record-evidence.mjs` verifies a complete, bounded 33O acquisition-registry history **from its independently derived genesis** against two or more independently pinned 33P Ed25519 publisher claims. It checks canonical actual record bytes, externally pinned per-record byte digests, contiguous predecessor hashes, embedded signed 33N acquisition receipts, durable-history nonce/digest uniqueness, final registry and inventory heads. An optional Linux-local, read-only directory-descriptor acquisition detects symlinks, hardlinks, unsafe modes, omitted files, uncertain pending commits and observable file/directory substitutions. **It does not prove remote disk state, independently witnessed publication, protected keys, trusted time, multi-host consensus, hosted auth, recovery, checkout, Shopify transactions or production readiness.** See `docs/OBJECTIVE_33Q_PINNED_ACQUISITION_REGISTRY_RECORD_EVIDENCE.md`.


### Objective 34B — Guided offline Design Works entry
Run `npm run serve`, then open `/demo/start.html` on the local loopback service. Seven real concept cards navigate to `/demo/?product=<allowlisted-manifest>`; the existing 2D/3D editor preselects the exact requested concept and preserves the saved-draft/cart-readiness preview. Invalid, duplicated, unknown, or credential-bearing query parameters are rejected and visibly fall back to a safe default. This is **not** a hosted Shopify staging entry, checkout or customer-auth integration.

### Objective 34D: opt-in tab recovery

The offline editor now offers explicit 30-minute, text-only sessionStorage recovery with customer-controlled Restore and Forget. It is off by default, never caches bearer grants, artwork, GLBs or measurements, and does not provide hosted customer storage. See `docs/OBJECTIVE_34D_OPT_IN_TAB_RECOVERY.md`.

### Objective 34G — browser-executable local acceptance and safe asset inventory (v0.30.77)

The real editor has an **explicit loopback-only** DOM acceptance harness at
`http://127.0.0.1:8000/demo/?tj_acceptance=1` after `npm run serve`.
It exercises product selection, 2D/3D mode, synthetic lettering, privacy-safe
review, invalidation, and disabled checkout. This is not automatically run by
Node and is not proof of Shopify staging or browser acceptance until actually
executed in a browser. The deterministic SHA256 asset inventory at
`integrations/shopify/preview-asset-manifest.json` can be checked with
`npm run preview:assets:check`. **It is NOT a hosted/deployable editor bundle**:
private drafts/artwork require the loopback Node API and must not be published
as a customer service. See `docs/OBJECTIVE_34G_BROWSER_ACCEPTANCE_AND_ASSET_INVENTORY.md`.

## Objective 34H: static-only Design Works concept preview (v0.30.78)

A new **ephemeral, browser-only** concept customization candidate is available at
`/demo/static-preview.html?product=concept-rug` while running `npm run serve`, or
from any static origin that retains the source's relative module paths.
It provides all seven concept products, text-only 2D/3D previews, validated
layer transforms, and an explicitly non-purchasing design review. It deliberately
has **no private save, artwork/model upload, tab recovery, hosted auth, inventory,
pricing, cart, order or checkout**. Refresh discards the design. The previous
local-server-dependent Studio remains intact, including its private drafts,
GLB inspection and calibration worksheets. The new candidate is not Shopify-
installed and not a hosted customer backend. See
`docs/OBJECTIVE_34H_STATIC_CLIENT_PREVIEW.md` and run
`npm run preview:static:assets:check` for its 13-file exact dependency inventory.

## Objective 34I — offline Shopify staging candidate (not installed)

Run `npm run preview:staging:build` to generate a flat, CSS/DOM-scoped, import-rewritten, preview-only Liquid section and browser asset bundle. Run `npm run preview:staging:check` for byte-for-byte integrity verification. See `docs/OBJECTIVE_34I_STAGING_STATIC_BUNDLE.md`. No Shopify writes or production acceptance.

### Objective 35K — opt-in multi-design local review (v0.30.107)

The loopback-only editor now supports selecting 2–25 individually saved local designs across products for an accessible, non-purchasing review. Each saved revision is rechecked against its private local owner capability and offline product/variant snapshot through the existing local readiness API. No owner token is rendered in the review UI or stored in browser session storage. See `docs/objective35k-multidesign-customer-review.md` and `tests/objective35k-multidesign-customer-review.test.mjs`. This is not a hosted cart, order, customer identity or manufacturing authorization; no Shopify writes or deployment occurred.

### Objective 35L — explicit interrupted multi-design review recovery (v0.30.108)

The offline loopback editor now exports a **non-private, 30-minute review checklist** for interrupted multi-design comparisons. The checklist contains only saved references, immutable revisions, product/variant bindings, labels and selection flags. It does **not** contain owner tokens, artwork grants, session capabilities, checkout metadata, orders or prices. Importing a checklist is non-authorizing and restores **no** designs automatically. The user must reopen each corresponding PRIVATE local recovery receipt separately. For every resumed line, the local API verifies exact owner/revision/product/variant readiness twice and rejects stale revisions, wrong-owner grants, digest drift, catalog substitutions, expiry, tampering and concurrent checklist changes. All commerce and manufacturing actions remain disabled. No browser or Shopify acceptance is claimed; see `docs/objective35l-interrupted-review-recovery.md`.

### Objective 35M — explicit multi-receipt confirmation and progress (v0.30.109)

A reopened PRIVATE local saved-design receipt no longer silently joins an imported
multi-design review checklist. The editor now requires an explicit **Confirm reopened
private receipt** action, provides per-checklist progress and cancellation controls,
and restores keyboard focus to the confirmation or status control. An ephemeral
controller holds owner grants only in memory and never serializes them into the
checklist or public status. It refuses replay, stale revision, product/variant
substitution, wrong-owner capabilities, digest drift, concurrent confirmation,
and cancellation/clear races. Asynchronous receipt loading and checklist import
also reject superseded actions, and partial artwork object URLs are revoked on
failure. Synthetic loopback tests are not hosted authentication or real checkout.
No Shopify reads/writes or deployments. See
`docs/objective35m-receipt-confirmation.md` and
`tests/objective35m-multidesign-recovery-confirmation.test.mjs`.


### Objective 35AD — signed revocation-policy checkpoint continuity (v0.30.126)

An offline read-only Ed25519 checkpoint verifier binds the 35AC revocation
policy to a caller-retained registry head, requires contiguous revisions and
cumulative revocations, and rejects rollback, tamper, identity substitution
and observed head changes. No external registry, independent key custody or
production authority is bundled. See
`docs/OBJECTIVE_35AD_RETAINED_POLICY_CHECKPOINTS.md`.

### Objective 35AE — offline policy-head CAS and signed split-view evidence (v0.30.127)

Adds an opt-in single-host, crash-fail-closed retained-head CAS adapter and
verified one-revision signed-policy advancement. Separately detects two
signer-valid competing policy checkpoints from one externally pinned head.
No independent custody, hosted registry, global fork prevention, production
approval or Shopify authority is established. See
`docs/OBJECTIVE_35AE_OFFLINE_POLICY_HEAD_CAS.md`.


## Night Watch Objective 35AF (v0.30.128; offline)

Added independently pinned Ed25519 witness acknowledgement and portable policy-fork evidence verification contracts with bounded expiry, audience/challenge binding, mandatory atomic replay-store interface, and adversarial cross-observer tests. See `docs/OBJECTIVE_35AF_PINNED_WITNESS_ACKNOWLEDGEMENTS.md`. All witnesses and stores in tests are synthetic; no hosted custody, external registry, Shopify writes, staging installation or production authority.

## Night Watch Objective 35AG (v0.30.129; offline)

Adds an externally SHA-256-pinned, canonical witness roster and an opt-in,
private-directory, single-host durable witness challenge ledger. Ed25519
acknowledgements are verified through the existing 35AF signature/expiry
contract; the ledger atomically consumes each witness/challenge/audience/registry
combination, including differently signed receipts with the same challenge.
Explicit initialization, fsync, restrictive permissions, retained receipt pins,
and cross-process/crash adversarial tests are included. Local storage is NOT
cross-host replay consensus or independently retained rollback protection.
See `docs/OBJECTIVE_35AG_PINNED_ROSTER_CHALLENGE_LEDGER.md`.

### Night Watch Objective 35AL — retained epoch continuity (offline)

`src/preview-local-artwork-review-retained-epoch-continuity.mjs` verifies independently retained, issuer-signed epoch snapshots against caller-provided historical SHA-256, issuer, identity and observation-time pins. It rejects pruning, rollback, replay and conflicting signed epoch histories. It **does not** supply independent custody, a trusted clock, hosted authentication, production authorization, Shopify checkout or cross-host consensus. See `docs/OBJECTIVE_35AL_RETAINED_EPOCH_CONTINUITY.md`.


### Objective 35AO (v0.30.137) — Accessible concept positioning

The local editor now supports keyboard and button nudging for selected text/artwork layers on the current 2D design surface, with rotated print-zone boundary checks. Arrow keys move 1% and Shift+arrows 5%. No manufacturing approval or hosted Shopify interaction is implied. See `docs/OBJECTIVE_35AO_ACCESSIBLE_POSITIONING.md`. Main57A's four protected/Night-only staging differences remain unresolved.


### Objective 35AP — unified offline source and cross-surface copy

Source checkpoint v0.30.138. The local-only editor supports copying a selected
artwork/text layer between distinct conceptual surfaces while retaining the
original layer and excluding all private ownership or authorization fields from
the copy. The read-only `scripts/check-unified-reconciliation.py` requires a
separately pinned Main57A archive and refuses automatic changes for mismatched
Main/Night/hosted source. Main57A and Night35AO archives are preserved intact.

The 13-file unpublished staging candidates are frozen, NOT merged, NOT installed
or published. No verified production manufacturing zone, Shopify checkout or
customer identity authorization has been established by this change.

## Objective 35AQ — explicit target placement (offline only)

The local editor's “Duplicate to another surface” control offers “Keep relative placement” or “Center element in target zone.” The original artwork/text layer is preserved, and both options validate the target preview rectangle without inferring manufacturing dimensions or permission to order. Offline staging metadata now derives its version from the package rather than a stale constant; the protected 13-file staging asset candidates are preserved unchanged. See `docs/OBJECTIVE_35AQ_RELEASE_EVIDENCE.md`. No hosted Shopify work was performed.


### Objective 35AR — offline footwear concept fallback (v0.30.140)

The local editor and the separate static, ephemeral editor now offer a low-top sneaker
concept with three explicitly mapped 2D design views: outer side, inner side, and
tongue. Neither editor fabricates a procedural 3D sneaker; the 3D control is disabled
for this concept unless a locally inspected, still-unverified GLB is loaded into
the local editor. A Chromium regression also fixed the static editor's SVG `hidden`
attribute handling, which previously left 2D canvases invisible in Chromium.

These are **visual-only** rectangles, not printable supplier measurements or
production-ready UV maps. No shoe print process, inventory, size, pricing,
checkout, hosted theme change or manufacturing approval is implied. The existing
13-file static staging candidate and separate 13-file Main reconciliation candidate
are intentionally preserved byte-for-byte at their earlier pins; generated source
now differs, so manual Main/Night/hosted reconciliation remains mandatory before
any separately authorized staging change.

### Objective 35AS — surface-specific 2D editing (offline only)
The interactive local editor now lists only the layers on the active design surface; switching surfaces preserves the other layers without offering invisible elements for selection. A polite live status and dynamically named keyboard-focusable SVG announce the current surface, visible element count and selected element. These are conceptual positions, not approved footwear manufacturing coordinates. Shopify and protected staging bundles remain unchanged.

### Objective 35AT — offline worksheet and cross-category editor safety

A validated physical-measurement worksheet is scoped to the selected product, design surface, concept color/size, imported model fingerprint and the exact measurement fields. Editing any of those inputs invalidates export until revalidation. Changing products or surfaces also clears prior measurements, preventing accidental reuse across blanks. The 2D layer picker and keyboard movement are exercised across apparel, drinkware, accessories and home products in an offline Chromium harness. No manufacturing approval, cart or Shopify write is introduced.

### Offline release 0.30.172: security and manufacturing-boundary corrections

The 35BK–35BZ engineering batch adds 16 independently tested fail-closed
corrections to physical calibration review, GLB surface identity and authority,
UV reports/sampling, local physical placement estimation, and redacted concept
exports. These are local-only concept utilities. They do **not** confer
supplier calibration, production approval, authenticated cart/order readiness,
or permission to modify Shopify themes. The frozen staging candidates remain
unaltered while their known mismatches await separately verified read-only
hosted-source acquisition and manual reconciliation.
