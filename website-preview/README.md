# TrendyJoes Design Works — Approved-Style Functional Preview

Created: October 24, 2026. This is NEW code for a bundled, inspectable and browser-interactive private site preview, **not** the Shopify published storefront and **not** the previous generic workbench HTML.

## Open
- Easiest: open `TrendyJoes_Approved_Interactive_Preview.html` in a capable browser, with internet enabled. It has all CSS and JavaScript embedded in one file.
- Alternatively, serve `index.html`, `styles.css`, and `app.js` together from any static local web server, e.g. `python -m http.server 8080` (the command runs locally, not an internet deployment).

## Content and behavior
- Approved original **brand identity and landing structure**: cinematic editorial two-column hero, approved copy and imagery references, six product collections, Custom Design Studio explanation, bespoke/bold/built-to-last, and philosophy.
- Five actual navigable preview sections: Home, Collections, Studio, About, Contact.
- Studio: six product concepts, selectable surface, four blank colors, local text layers, optional PNG/JPEG/WebP artwork, drag/touch placement, text size/color, layer duplication/removal, undo/redo, local review, device-local draft saving, JSON and PNG export.
- Contact: prepare and copy project brief; does not send or store information on a server.
- Mobile navigation, accessible labels, and browser-only logic.

## Original artwork and offline behavior
The approved hero and six collection images are referenced by their actual Shopify Files CDN paths, taken from `sections/tj-design-works-home.liquid` in the unpublished theme `TrendyJoes - Mid-Century Studio - STAGING` (Shopify theme ID 155831271559). No reference screenshot was cropped or used in the new HTML code. The files are **not duplicated** in the ZIP. When the CDN is accessible, the customer's browser displays those original Shopify assets. When disconnected or blocked, honest CSS fallback images are shown. The included automated Chromium screenshots show these fallbacks because this execution container cannot reach Shopify's CDN. Those screenshots are NOT evidence that hosted imagery loaded.

## Critical limitations
- This is a local functional **preview**, not published, deployed, password-unlocked, or connected to the store's live products.
- No actual SKUs, inventory, pricing, cart, checkout, payments, printing authorization, or manufacture-ready templates.
- Shape and placement are conceptual only; exported PNG is not a calibrated print file. Product silhouettes are illustrations.
- Site preview code is separate from Shopify-hosted Liquid. The Shopify staging theme itself has not been changed by building this preview.
- Browser device draft saving depends on local storage availability. No backend storage.
- No additional subscriptions, external services, or spending.

## Validation
Run `python verify_preview.py` with the installed Chromium + Playwright. This mounts the self-contained page as `about:blank` due this environment's local-file navigation restriction and exercises desktop and mobile interactions. Real hosted Shopify theme acceptance remains unverified.

## To make the approved site actually sell
- Integrate customer-facing features into the protected staging theme after resolving four known Main57A source discrepancies; retain live Horizon untouched until final authorization.
- Verify supplier blanks, product dimensions, applicable printing methods, inventory, prices and physical output.
- Test Shopify products, cart, orders, checkout, and mobile storefront end-to-end in staging before promotion.
- Do not publish or disable password protection without explicit approval.

## Development continuation — October 24, 2026, Batch 2

This batch fixes a **verified data-loss-in-navigation defect** in the private preview: switching Front / Back / Side or product concepts previously cleared the editor. This private preview now retains drafts for every product+surface, and undo/redo preserves those transitions. It does not modify Shopify staging files.

Additional tested editor functions:
- Portable concept JSON v2 exports the current canvas and all designed product/surface canvases; secure local JSON import (including v1 migration) restores multiple surfaces.
- Strict draft validation rejects malformed artwork, oversized files, duplicate IDs, invalid canvas keys and forged `manufacturingApproved`, `priceApproved`, or `checkoutEnabled` claims.
- Browser-local project brief export identifies each personalized surface but is **not** a printer's production file or order.
- Selected-layer rotation, image scaling and keyboard arrow movement (Shift + arrows for larger movement) improve the actual Studio controls.
- Current review displays the number of designed surfaces. Review must be rerun after any editor change.

### Regression evidence

- `verify_preview.py`: previously supported browser operations checked again against the **new standalone bundle**, PASS.
- `verify_20261024_advance.py`: 30 new Chromium acceptance checks, PASS. Includes cross-product/multi-surface editing, undo/redo, JSON export and reimport, backward-compatible import, injection of a false manufacturing approval flag, local save/load, PNG artwork handling, mobile menu and no horizontal overflow, zero page JavaScript errors.
- `advance-test-results.json`: exact machine-readable outcomes.
- `advance-studio-mobile.png`: current mobile concept Studio screenshot showing actual controls and preview, not an old mockup.
- CDN imagery was not verified to load in the offline Chromium execution environment; source HTML references the original approved Shopify asset URLs.

### Business-critical remaining blockers

This is not a production-ready Shopify implementation. Product details, real supplier print templates, calibration, variant availability, inventory, pricing, checkout, order transmission, customer upload retention, hosted site/browser tests, and Shopify staging integration remain unverified or unavailable. No paid services, Shopify theme edits, publication, or order flows were performed by Batch 2. The published Horizon theme remains untouched.
