# Objective 35X — Content-bound local artwork review inventory

**Offline prototype only. No Shopify reads or writes. No file deletion or quarantine.**

`inspectLocalArtworkRetention()` now hashes actual artwork image bytes under the cooperative local lease, using a bounded 5 MiB default (the current local upload maximum), and compares the digest with the paired metadata's declared SHA-256. It also binds the full metadata file's byte digest into the snapshot. The existing two-pass `referencePin` consequently changes when image content or metadata changes, even when file length is unchanged. Any mismatched image digest fails closed with `LOCAL_RETENTION_ARTWORK_DIGEST_MISMATCH`. The previous Objective 35W signed, read-only review ticket automatically inherits this stronger content pin and cannot verify against changed bytes. All stored revision references, including historical revisions, remain inventoried.

Reproducible focused checks: `node --test tests/objective35u-artwork-retention.test.mjs tests/objective35v-cross-process-artwork-lease.test.mjs tests/objective35w-quarantine-intent.test.mjs tests/objective35x-artwork-content-pin.test.mjs`.

Adversarial coverage includes same-length tampering of referenced and unreferenced image files, metadata-only digest forgery, coordinated image+metadata replacement, pre-read byte limits, mutation during a read, and actual child-process modifications after ticket issuance. Read-only flags remain false for deletion and quarantine. The earlier Objective 35U synthetic test fixture now uses an actual matching SHA-256 digest rather than a placeholder.

## Limits / security boundary

This is a local, read-only integrity signal, **not** a tamper-proof or append-only evidence registry, hosted authentication, immutable content storage, a production writer fence, a trusted clock, or human authorization. An uncooperative writer can change files after a successful scan. A writer with access to both image and metadata can create a new self-consistent pair; old review tickets will be stale, but new reviews still require independent human evaluation. The caller-controlled HMAC key is not a production identity. Image bytes are read into memory under a strict maximum; large or malformed files fail closed. No customer data, secrets, checkout, Shopify staging, or live theme was accessed. Never interpret `safeToAutoDelete:false` as permission to mutate files.
