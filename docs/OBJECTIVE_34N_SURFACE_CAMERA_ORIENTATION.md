# Objective 34N — Surface-aware 3D camera (offline only)

## Reproduced defect
The previous static preview kept the 3D camera yaw when a customer selected another printable surface. Selecting a garment's back after designing its front left the model facing forward; the existing `surfaceFacingCamera` deliberately hides back-side artwork when viewed from the front. As a result, the new back-side text could appear to be missing until the customer manually rotated the model. Switching to a new product also inherited the prior camera orientation.

## Repair
- Added pure `conceptCameraForSurface(manifest,surfaceId,{zoom})` in `src/viewer3d.mjs`, with validated surface IDs and zoom. Garment back faces rear; sleeve uses front-quarter angle; other surfaces use normal front concept orientation. This remains **visual only**, not calibrated geometry.
- The static editor reorients on product, surface, and design reset; retains bounded zoom on surface changes; resets zoom on product/design reset; cancels active drag before reorientation.
- The 3D Reset camera control now returns to the selected surface, not always to the front. Existing 2D/3D functionality, GLB import/calibration, other product categories and all layer content remain intact.
- Added adversarial and regression tests covering every conceptual product surface, stale IDs, malformed zoom, immutable inputs, multi-surface artwork retention, browser module and generated staging candidate.

## Limits
Static preview is ephemeral and non-purchasing. No customer auth, durable storage, manufacturing geometry proof, real Shopify integration, prices or checkout. No browser-interactive acceptance is claimed without an actual browser run. No Shopify writes authorized.
