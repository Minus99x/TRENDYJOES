# Print-test release: 48 streetwear looks

October 29, 2026 (America/Phoenix).

## Delivered

The owner archive TrendyJoes_Masculine_Streetwear_Studio_48_Looks_COMPLETE.zip was materialized and inspected. Source SHA256: 3a50736d08d5df72275e52a1d6dde6ed198a23a63cd8d954bb688249579ddcaa.

192 PNG files across 48 looks passed exact dimension, RGBA transparency, nonempty artwork, 300-PPI metadata, byte size and release SHA256 verification. Each look has DTF front/back and UV-DTF hardgoods/spot artwork. A new pack preserves these exact bytes and adds a canonical manifest and 192-row physical test queue. Editable SVG masters remain in the original archive. The older MANIFEST.json referenced pre-packaging directory names; the new manifest references actual packaged paths.

Nominal canvas sizes at 300 PPI: front/spot 3x3 inches; back 12x15 inches; hardgoods 4x5 inches. Transparent margins mean visible artwork is smaller; the manifest records actual visible bounds separately. These are file measurements, not printer compatibility or garment placement approval.

## Reproduce

python3 scripts/prepare_transfer_release.py ORIGINAL.zip OUTPUT.zip --report report.json
python3 -m unittest discover -s tests -p test_transfer_release.py -v

Requirements: Pillow (existing CI dependency). No source artwork mutation, Shopify write or printer-specific settings.

## Current live-store evidence

Shopify connector verified gucgmp-bc.myshopify.com on trial. Complete product query returned 29 products, all DRAFT. The 12 launch-01 artwork product records remain drafts with $0 prices; this does not establish attached file fulfillment. No plan change, publication or product activation performed.

## Fastest launch sequence

1. Select a small initial range from this verified batch rather than waiting for hundreds more designs.
2. Confirm rights and choose exact blanks/materials, sizes, packaging and unit costs; keep selling prices explicit and approved.
3. On equipment arrival, use manufacturer instructions for the exact hardware/media and run recorded physical tests. No invented curing, white-ink, varnish or heat settings.
4. Finish staging asset hosting and draft-product mapping, then verify actual file delivery and customer ordering end to end.
5. Obtain owner approval for the Shopify plan, product activation and theme publication only when those steps are ready.

The universal customizer and additional catalog expansion can continue without being prerequisites for a small fixed-design launch. Current deliverable is a print-test preparation pack, not production certification or a live storefront.
