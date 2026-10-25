# TrendyJoes — Approved Storefront Autonomous Engineering Queue

This is the standing backlog for GitHub-native unattended engineering on `dev/approved-storefront-preview-20261024`. It is a **source engineering queue**, not permission to change the approved Shopify theme or publish anything.

## Engineering contract

- Inspect latest source, tests and commits first; choose the highest-priority *uncompleted* item, or advance to the next independent item if blocked.
- Make one cohesive, measurable code change with positive and adversarial regression coverage. Never commit a no-op, status-only edit, cosmetic churn or a fabricated completion receipt.
- Reuse established patterns and standards (MDN/WAI-ARIA, WCAG, Canvas/HTML APIs and permissively licensed references) when appropriate; examine license, maintenance, security and fit before copying or adapting source. Do not import unaudited packages to avoid doing the integration work.
- Allowed production paths: `website-preview/app.js`, `website-preview/index.html`, `website-preview/styles.css`. Allowed tests: `website-preview/verify_preview.py`, `website-preview/verify_20261024_advance.py`. The worker must not modify this queue.
- Preserve the approved oxblood/slate/cream editorial hero, gentleman artwork URLs, six collections, designated Home/Collections/Studio/About/Contact pages and all working editor controls.
- Keep the customer-order boundary explicit. Do not invent or enable pricing, SKUs, checkout, accounts, stock, manufacturing files, payments, uploads to Shopify, live orders or publication. Never change `integrations/shopify/**`, `main`, the unpublished staging theme, secrets, release files, deployment files or workflows.
- Candidate patches are validated in a separate GitHub Actions job. Only tested, substantive source changes and their tests can be committed to dev.
- Browser preview's external Shopify CDN artwork may be unreachable in CI; never claim the real hosted artwork has been visually verified if not observed.

## Priority objectives (implement incrementally; inspect actual coverage before editing)

### 1. Route navigation and mobile accessibility
- Verify keyboard/screen-reader focus after Home/Collections/Studio/About/Contact navigation.
- Preserve appropriate aria-current, mobile expanded state and Escape behavior where supported.
- Validate deep-link reload and back/forward navigation without losing unsaved Studio design state.
- Add desktop + 375 px mobile regression tests for a real identified gap.

### 2. Design surface reliability
- Preserve artwork and text across Front/Back/Side, product switches, save/load, JSON export/import, undo/redo.
- Find an untested reproducible edge case (e.g., blank change and undo, repeated import, complex Unicode text) and fix the cause.
- Add positive and malicious/invalid input coverage; fail closed on bad data without overwriting existing artwork.

### 3. Layer-editor practical usability
- Improve touch/keyboard movement or selection of overlapping layers and announce the result accessibly.
- Protect performance with larger valid artwork without silently losing data.
- Validate 375 px and desktop browser behavior, plus preservation after history undo/redo.

### 4. Portable design review clarity
- Ensure exported JSON/brief includes correct product/surface/layer information after real editing.
- Detect and report unsupported manufacturing claims or file tampering.
- Distinguish illustrative PNG exports from calibrated/production-ready print files.

### 5. Launch-readiness UI guardrails (offline preview only)
- Confirm unavailable purchase actions cannot be misrepresented as real orders.
- Validate copy/preview and Contact inquiry remain browser-local and don't send customer data.
- Make failure/success messages accessible; use actual tests rather than simply changing words.

## Acceptance gate

- Change at least one production path and at least one permitted browser regression test file.
- Run all existing asset integrity and bounded security tests.
- Run both Chromium browser acceptance scripts; reject if any fail.
- Reject any mutation beyond allowed files. Reject no-op patches, secrets and permission changes.
- Commits must contain exact GitHub Actions run URL, SHA and result receipts.
- A scheduled trigger is evidence of an invocation, **not evidence of implementation**. Report no-change, failure, CI success and actual commits distinctly.
