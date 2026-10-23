# TrendyJoes Design Works — Offline Objective 35BC–35BJ

Version: 0.30.156. OFFLINE ENGINEERING CHECKPOINT ONLY. Zero Shopify writes and zero task configuration changes. Local Git history is NOT GitHub.

### Engineering outcomes

- **35BC GLB header gate:** validates glTF-v2 magic/version, file length and JSON/BIN chunk framing before passing to the full inspector. A valid header is not a valid/safe model by itself.
- **35BD geometry integrity:** zero-area 3D and UV triangles fail closed before imported geometry is treated as a preview.
- **35BE sampled UV diagnostics:** rejects malformed model surface inventories, invalid mapped UV tuples, and maps exceeding safe interactive complexity. Coverage is SAMPLE-ONLY, never physical UV approval.
- **35BF measured worksheet integrity:** rejects missing traceability, wrong product/surface/model, unsafe bleed/inset, fictitious manufacturing route and forged draft fields.
- **35BG private review packet:** computes cryptographic design fingerprint and redacted model/UV/measurement readiness summary; no text, artwork payload, technician, fixture or blank SKU disclosed. All claims non-authorizing.
- **35BH accessible editor:** updates UV coverage from *current* design layers after render; export measured draft is gated by current inspection and worksheet review.
- **35BI user-triggered preview review:** downloads local redacted quality review with revision + worksheet fingerprint race rejection and clearly announced unresolved readiness warnings.
- **35BJ insecure-browser regression:** positive offline review/download test uses a clearly disclosed test-only digest stub; separate negative Chromium test without WebCrypto rejects new and old private downloads. Real SHA-256 evaluated separately by Node.

### Verification scopes

- Broad relevant Node test selection (42 files): **357 PASS, 1 FAIL**. The sole failure is pre-existing 35AQ staging-candidate-version assertion comparing intentionally frozen protected staging assets to the new offline code; **not fixed by altering staging**. This is not a full-suite pass.
- Offline Chromium browser runs: 35AO 16, 35AP 14, 35AQ 20, 35AR 35, 35AS 19, 35AT 82, 35AX 13, 35BA 15, 35BB **11**, 35BI 27 = **252/252 PASS**, zero observed page exceptions / HTTP requests.
- Main offline preview manifest: 40/40 SHA checks pass. Protected static preview manifest: 13/13 SHA checks pass.
- No genuine secure-origin browser digest proof (the test-only positive Chromium stub is explicitly noted). Real digest tested in Node. No physical calibration/supplier GLB, authenticated cart, published Horizon or hosted Shopify acceptance.

### Reconciliation boundary

Four unresolved Main57A differences across thirteen unpublished staging assets; no complete live read-only, byte-preserved Shopify staging export was acquired in this batch. Both frozen staging candidate trees are unchanged. No protected JavaScript/CSS/Liquid/3D asset substitution. Continue with a separately pinned and auditable read-only hosted-source acquisition and manual reconciliation proposal; ask before any Shopify writes.
