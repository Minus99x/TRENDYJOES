# Local-only development API (v0.2)

This is an architectural test harness, **not a cloud API**. Run `npm run serve`. The server binds `127.0.0.1` by default, uses Node built-ins, rejects non-loopback bind hosts, restricts static file paths and records files under `.tj-local-data/` with restrictive file permissions.

| Endpoint | Purpose | Input | Output |
|---|---|---|---|
| `GET /api/health` | Return local preview health | — | Scope and `checkoutEnabled: false` |
| `POST /api/artworks` | Upload prototype raster | Raw PNG, JPEG, WebP; matching content type; up to 5 MiB | Random artwork ID plus **secret artwork grant** |
| `GET /api/artworks/{artworkId}` | Read private raster | `Authorization: Bearer {artworkGrant}` | Artwork bytes, served as attachment |
| `POST /api/designs` | Save first immutable revision | JSON `{productManifestId,layers,artworkGrants}` | Opaque reference and **secret ownerToken** |
| `GET /api/designs/{reference}` | Retrieve latest revision | `Authorization: Bearer {ownerToken}` | Saved preview-only design |
| `GET /api/designs/{reference}/revisions/{n}` | Retrieve old revision | Owner bearer token | Immutable version |
| `POST /api/designs/{reference}/revisions` | Create a new revision | Owner bearer; JSON including `{expectedRevision,productManifestId,layers,artworkGrants}` | Next revision number or HTTP 409 conflict |

Never put access tokens in Shopify line-item properties, URL query parameters, analytics events, client logs or public issue trackers. Only the opaque reference may eventually be associated with a Shopify cart, after server-side identity, fulfillment, approval and price verification.

## Controls tested

Image content type and first-header/dimension consistency; image byte ceiling; version conflict; private artwork reads; private design reads; composition bounds; local-only server configuration; publicly inaccessible storage path; preview-only and checkout-off response flags; no plain-text token in persisted design JSON.

## Deliberately missing (hard blockers for production)

Shopify customer authentication and identity linking; per-customer object authorization; Shopify app proxy and session security; secure object storage with at-rest encryption; virus/malware scan and safe image rewriting; PDF and vector preflight in a sandbox; upload rate limiting and quotas; deletion/retention privacy policy; abuse monitoring; production artwork processing; verified DPI and bleed; real geometry/UV maps; independent pricing approval and order linkage; end-to-end order/checkout testing; public hosting and penetration testing. **Do not port this local server into production without redesigning these controls.**

Browser QA used a mock service because the graphical browser's local-network route was blocked in the test environment. The actual server HTTP endpoints were tested independently via Node fetch.
