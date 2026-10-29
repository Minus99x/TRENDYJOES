# TrendyJoes — O1 Omni full-stack premium manufacturing engineering charter
Date: 2026-10-29 (Arizona)
Project: Minus99x/TRENDYJOES
Engineering branch: dev/approved-storefront-preview-20261024
STATUS: Planning and product specifications ONLY. No live purchase, machine qualification, or Shopify publication is authorized.

## Confirmed owner operating context
Owner reports purchasing the full xTool O1 Omni companion package via preorder, including OR1 rotary, RF1 roll feeder, LM1 laminator, associated accessories, and the WonderPress (already possessed). User reports the other equipment and previously discussed modules are coming. Verify the actual O1 printhead edition and delivered contents against order/packing list, and account for all WonderPress Heat Press, Craft Oven and 3D Form modules individually during setup. Do not treat accessories as a printhead upgrade. The UV + DT fabric edition enables UV direct, UV DTF, DTG and textile DTF, but not dual-UV-only fluorescent ink. Dual-UV edition provides fluorescent specialty modes but not fabric DTF/DTG.

User's current residence: family of four in a single combined sleeping/living/food-preparation room. Production workspace is not established; Phoenix temperatures and dust are relevant. Main goals: digital/storefront readiness BEFORE printer arrival and differentiated products that are not commodity $2 transfers.

## Primary xTool references
- O1 editions, materials, films, add-ons: https://support.xtool.com/article/3666
- O1 FAQ and supported effects: https://support.xtool.com/article/3701
- O1 manual, exhaust interface, power and maintenance: https://support.xtool.com/academy/lesson/3084?courseId=336
- O1 safety and environmental limits: https://support.xtool.com/article/3478
- Lenticular real-LPI interlacing and tilt content: https://support.xtool.com/article/3802
- WonderPress modules and limitations: https://support.xtool.com/article/3206
- WonderPress curing and forming safety: https://support.xtool.com/article/3617
- Air filter service: https://support.xtool.com/article/3556

## Capability-to-product matrix (concept until machine qualification)
1. UV direct rigid: acrylic premium signs, wood signs, ceramic tiles, metal tags, art panels, magnets, coasters. Track material-specific primer and adhesion; avoid food-contact areas.
2. UV DTF: transparent and white-backed decals, maker transfers, tumbler wraps, branded product labels. Requires correctly paired A/B media and LM1.
3. Textile DTF: sheet sales and ready-to-apply artwork for Whatnot makers; UV+DT head, correct film, powder, curing and heat press required. DTF powder is a separate process exposure.
4. DTG: shirts, tote bags and selected cotton apparel; UV+DT head, garment tray, pre-treatment, qualifying blanks.
5. Lenticular: photo flip (2–5 frames), tilt animation (5–12 frames), 3D viewpoint effect (8–20 views), creator collectibles. Generate frame packs, calibrated lens-pitch metadata and operator instructions. xTool Studio performs final interlacing; measure LPI for every lens batch. This is NOT raised ink.
6. Raised UV texture: tactile prints, lettering, 3D-effect logos, textured plaques; nominal up to 7 mm in supported cases, depending on material and process. This is NOT an FDM structural part.
7. Gold/silver/holographic specialty foil: decals, monograms, presentation packaging. Qualify LM1 and film workflow.
8. OR1 cylindrical direct print: tumblers, bottles, mugs, ornament exteriors. Track diameter, handle clearance, surface chemistry and coating.
9. RF1 roll production: labels, stickers, clear film, vinyl, long repeated patterns and maker runs; roll media profiles are distinct.
10. WonderPress Heat Press: DTF apparel, canvas and accessories; final transfer application.
11. WonderPress Craft Oven: DTF cure, heat bending and other allowed craft material processes; account for fumes and ventilation.
12. WonderPress 3D Form: vacuum-formed package inserts/shells and compatible 3D sublimation. A SUBLIMATION PRINT SOURCE is separately required for full-color sublimation; O1 is not inherently a sublimation printer.
13. In-house FDM + UV hybrid: original 3D printed products, calibrated UV embellishment and printed/formed packaging. Test surface adhesion.
14. Small-business identity bundles: QR signage, business tags, foil labels, event souvenirs, branded drinkware.
15. Digital-only products: editable SVGs, print-resolution transparent PNGs, and original STLs with copyright/license metadata; zero dependency on having the physical O1 operating.

## Twelve prioritized premium product packets
Produce one complete source design, variant schema, marketing preview, process checklist, and cost-input sheet for each:
- TJ-P01: original two-frame lenticular flip card
- TJ-P02: 3D-depth lenticular collectible card
- TJ-P03: raised-texture personalized acrylic desk sign
- TJ-P04: textured custom business logo plaque
- TJ-P05: direct printed personalized rotary tumbler
- TJ-P06: UV DTF full-wrap maker bundle
- TJ-P07: gold/silver foil luxury brand labels
- TJ-P08: holographic monogram accessory set
- TJ-P09: small-business QR-counter display kit
- TJ-P10: garment DTF front-icon/back-art streetwear set
- TJ-P11: original FDM decoration with UV art insert
- TJ-P12: custom vacuum-formed packaging tray and branded backing

Each packet requires: artwork rights, printhead and accessory dependencies, applicable substrates, media and primer, artwork format, white/varnish layer policy, cut/bleed/safe area, dimensions, fixture and orientation, safety warnings, theoretical vs measured cost, proof and test results, digital delivery or physical fulfillment flag. Start as CONCEPT with pricing and shipping turned off, not an unsupported promise.

## Website architecture instructions
- Preserve approved TrendyJoes oxblood/slate/cream identity and assets, existing gallery and mobile editor. Protect approved hero.
- Introduce premium collections by effect: Motion/Flip, Raised & Tactile, Foil & Holographic, Drinkware, DTF & Maker Transfers, Premium Business Branding, Hybrid 3D, Digital Art/STL.
- Build a machine-capability registry keyed by head model + actual available accessories + qualified substrate profiles. An unknown head or missing accessory must disable its physical production option, while allowing inquiry/preview.
- For lenticular: collect 2–20 source images by documented mode, aspect ratio, view order, intended material; provide browser tilt simulation labeled CONCEPT ONLY and a structured xTool Studio handoff with measured LPI left pending until material arrives.
- For raised UV: offer relief-style preview with thickness/finish clearly CONCEPT ONLY, not a calibrated production proof.
- Distinguish digital download, customer proof request, and physical order; never mark a conceptual render as a manufacture-ready file.
- Keep existing read-only Shopify bridge and manufacturing authorization gates. Shopify live checkout and manufacturing approval require separate verification.
- Build job packets with immutable artwork hashes, product variant IDs, equipment profile, customer approvals, operator material checklist, QA photos, and actual measured costs.
- xTool official software remains the printing path; do not invent direct RIP/printhead API integration.

## Deliverable priorities and tests
P0: verify current exact GitHub branch HEAD and all existing staging/preview components. Finish digital catalog with actual attached file bytes, rights, user-ready downloadable products, tested mobile workflow, price inputs and Shopify trial upgrade blockers. Do not activate live sales without authorization.
P1: add real capability registry and unit tests for dual UV vs UV+DT rules, missing modules, material requirements, no accidental approval and versioned data schema.
P2: implement user-facing specialty collections plus 12 product concept template packets, with accessible responsive tests and source artwork files that can actually be downloaded.
P3: implement design intake, lenticular frame sequencing and preview, tactile design layered previews, and manufacturing handoff JSON and human-readable prep sheet. Test edge cases and malformed inputs.
P4: after delivery and a suitable facility, measure fixtures, ink adhesion, lenticular LPI, printer output, throughput, materials, equipment constraints, physical durability, packaging, and margins. Then mark specific SKUs physically qualified.

## Facility gate — no bedroom production assumption
O1 has integrated HEPA/carbon filtration and a rear exhaust port; compatible external window ducting can be part of a dedicated indoor facility, but not a guarantee of safe air. Opening covers or servicing ink may release material not captured by exhaust. Craft Oven DTF powder curing and thermal plastic processing require their own exposure controls. Children's sleeping/food space is not an appropriate unverified production room. Identify owner-approved, secure, conditioned and independently exhausted workspace (a properly modified garage or offsite workspace), suitable airflow/make-up air, outdoor discharge position, equipment load/clearance, 120V circuits, security and maintenance access. Avoid dependence on unconditioned Phoenix garage or frequently moving an ink-filled O1. Keep printer power for auto-maintenance when commissioned. If workshop is not established, finish digital commerce and preproduction specs without starting ink priming.

## Engineering reporting contract
This is a durable shared repo handoff for TrendyJoes Main Engineering and any successor chat. It changes no autonomous worker permissions or launch approvals. Avoid repeated no-op audits: implement source and tests and give exact run/commit evidence. Distinguish PREVIEW, VERIFIED DIGITAL SELLING, SHOPIFY LIVE, and PHYSICALLY QUALIFIED. Do not claim a product line works merely because its conceptual preview works.
