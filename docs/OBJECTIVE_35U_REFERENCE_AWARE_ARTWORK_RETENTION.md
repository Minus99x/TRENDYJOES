# Objective 35U — Reference-aware local artwork inventory (offline only)

**Version v0.30.117.** No Shopify access, deletion, remote storage, or deployment.

`inspectLocalArtworkRetention(root)` in `src/preview-local-artwork-retention.mjs` is a deliberately **read-only** inventory over the local `designs/` and `artworks/` directories. It scans **every** immutable revision, not only the latest. An artwork referenced by any historical revision is still retained as referenced, even if the latest draft no longer uses it. A complete pair that is absent from all scanned references is described as *apparently unreferenced*, **not safe to delete**. Pair completeness here means structurally matched metadata/extension/byte length, **not** cryptographically validated image contents.

Example (offline operator inspection only):

```js
import {inspectLocalArtworkRetention} from './src/preview-local-artwork-retention.mjs';
const inventory = await inspectLocalArtworkRetention('/absolute/path/to/local-data');
console.log(inventory.unreferencedCompleteArtworkIds); // INFORMATIONAL ONLY
console.log(inventory.safeToAutoDelete); // always false
```

The scan rejects unknown filesystem entries, symlinks, special files, malformed owner hash records, malformed design revisions, missing revision numbers, forged artwork IDs, mismatched metadata, unbounded directories, and detected file changes. It reads each file with before/after stat checks and performs two full snapshots. Pending publication metadata and incomplete artwork pairs are surfaced without mutation. Errors fail closed; they are not evidence of zero references.

**Explicitly not guaranteed:** Cross-process writer exclusion, a durable lock/lease, atomic directory snapshots, race-free deletion, image SHA verification, authenticated operator reclamation, retention periods, crash recovery, storage quotas, user deletion rights, production audit trails, or hosted identity. A writer can begin immediately after the scan. **Never use this inventory alone to authorize deletion.** Future cleanup requires an exclusive cross-process reclamation protocol, verified identity/ownership, stable reference pins and crash-safe quarantine with rollback evidence. No automatic cleanup was added in this objective.

Adversarial tests include historical revision references, dangling and incomplete pairs, pending stages, corruption, forged IDs, symlinks, unknown entries, bounded scans, two classes of concurrent mutation, and integration with the real `LocalDesignStore` fixture. No customer credentials appear in inventory output.
