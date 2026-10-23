# Verified Shopify staging baseline and safe integration sequence

Inspection conducted against the connected TrendyJoes store on 13 October 2026, using read-only Shopify Admin operations.

## Store inventory and theme facts

- Store `gucgmp-bc.myshopify.com` was on a **trial** and password-protected.
- Live `Horizon` theme role `MAIN`, ID `gid://shopify/OnlineStoreTheme/155090223239`.
- `TrendyJoes - Mid-Century Studio - STAGING` theme role `UNPUBLISHED`, ID `gid://shopify/OnlineStoreTheme/155831271559`.
- Staging theme's `config/settings_data.json` currently uses oxblood `#7A2A30`, slate `#52697A`, parchment `#F3E9D7`, ink `#231F20`. These are the **verified existing anchors**, not a prohibition on additional mid-century workshop/craft colors.
- `sections/tj-studio-landing.liquid` is a branded marketing landing section, **not** an editor or functional 3D renderer.
- `templates/product.custom-print.json` is a customized product template with built-in custom-property controls, required artwork permission checkbox and a `tj-artwork-upload` file input with name `properties[Artwork File]`. Submission/upload behavior is **not** verified.
- The `custom-print` template is currently assigned only to the *draft* UV DTF decal product. Remaining custom production templates do not have it assigned.
- All 14 products are drafts, including 6 manufacturing draft templates and 8 digital-product drafts.
- Production SOP metaobject definition has six instances; all processes are **PRE-COMMISSIONING**. Manufacturing cost profiles exist for six methods but have no approved prices and are `PENDING_INPUTS`. Production job definition exists but contains no jobs.
- Installed apps observed: Shopify ChatGPT MCP connector and Digital Products. No verified live customer-customization app.

## Integration plan (not yet executed)

1. **Identity and hosting:** develop a Shopify-authenticated app backend or approved third-party backend for customer-specific design ownership. Add signed short-lived preview assets, rate limiting and storage security. Local v0.2 server must not be exposed.
2. **Product and process registry:** map verified Shopify product and variant GIDs to approved product-specific manifests, UV maps and real printing dimensions; don't map concept IDs to saleable inventory by default.
3. **3D:** license/create physical product-specific GLB/glTF assets with per-product UV surfaces. Verify geometry-specific rendering (crew vs V-neck vs long sleeve vs hoodie) and provide accessible 2D fallbacks; no generic mesh masquerading as distinct garments.
4. **Commerce:** persist immutable design/version under authenticated ownership; assign server-issued opaque design references to actual Shopify line-item properties; verify storage and file access through cart, checkout, order and production job creation.
5. **Pricing:** calculate server-side using **approved** machine, material and labor costs and Shopify variant rules. Cart line item properties are not a price setter. Never activate existing $0 draft production templates as purchasable.
6. **Staging rollout:** edit ONLY the existing unpublished staging theme after app is testable, with a recorded backup and rollback plan. Leave MAIN Horizon, existing draft catalog, and trial untouched; browser, mobile, a11y, load and end-to-end prelaunch tests before permission to launch.

## Hold points

No live theme modification, pricing activation, production declaration, payment processing, app purchase, trial upgrade or customer data collection has been authorized or performed by this objective.
