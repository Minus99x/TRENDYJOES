# Objective 34B — Guided offline customer-entry integration

The local Design Works entry at `/demo/start.html` presents seven existing concept manifests as actionable cards. Each routes to the actual 2D/3D editor through an exact, allowlisted `product` query. The editor displays the selection, allows saving owner-protected local revisions and a non-purchasing cart-readiness summary, and retains all model import/calibration functionality.

The deep-link resolver refuses unknown, duplicate, oversized, malformed and credential-bearing query strings. It never carries owner tokens, Shopify variant identities, design references, revisions, or checkout claims through a URL. The same entry path can be exercised in an offline loopback HTTP smoke test.

**Main Engineering handoff:** Review these source assets and adapt the Design Works homepage into a hosted preview only after a real authenticated hosting environment and theme browser acceptance exist. A Shopify storefront must **not** link customers to a loopback-only URL. The local entry is not a deployed Shopify page. No Shopify writes, products, checkout, or orders.

Reproduce: `node --test tests/objective34b-guided-entry.test.mjs`; `npm test`; `npm run serve`; visit `/demo/start.html`.
