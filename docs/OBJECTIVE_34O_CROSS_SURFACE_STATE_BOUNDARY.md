# Objective 34O — Fail-closed stale selection boundary (offline)

Reproduction on verified v0.30.84: start a crew tee, add a front layer, switch to back, then supply a stale reconstructed state with the front layer ID selected. `ROTATE_LAYER`, `SCALE_LAYER` and `REMOVE_LAYER` all accepted that hidden layer and modified/deleted front artwork. Ordinary UI transitions cleared the ID, but the state update contract itself did not enforce the invariant.

The v0.30.85 contract now resolves the selected layer by an unambiguous ID and checks that its `surfaceId` equals the active surface before any rotate, scale or remove operation. Missing and duplicate IDs reject; legitimate null-selection remove remains a no-op. A customer may still select and edit a layer after navigating back to its actual surface. Rejections are atomic: source state remains unchanged.

This is defense in depth for the ephemeral local concept preview, not a server-side ownership/authentication claim. The existing complete Studio and manufacturing controls remain untouched. The generated static staging candidate is still NOT installed, hosted or approved for commerce.
