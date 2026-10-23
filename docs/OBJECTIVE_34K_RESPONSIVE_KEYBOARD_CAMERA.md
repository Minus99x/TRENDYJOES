# Objective 34K — Offline static preview 3D keyboard/touch/resize acceptance

The static Design Works preview now exposes keyboard focus on the 3D concept canvas, arrow-key rotation, plus/minus zoom, Home reset, explicit mobile zoom buttons, and a visible instruction. Pointer capture is limited to the primary pointer and cleared on cancellation or capture loss. Camera pitch and zoom are bounded and non-finite deltas are rejected. A ResizeObserver (or window-resize fallback) redraws the backing canvas on responsive layout changes.

This does **not** approve geometry, production dimensions, Shopify theme compatibility, customer authentication, storage, pricing, carts, or checkout. The full Studio and GLB/calibration path remain untouched.

Reproduce offline from the archive root:

```sh
node --test tests/objective34k-responsive-camera.test.mjs
npm run preview:static:assets:check
npm run preview:staging:check
npm test
```

The Node tests exercise the pure camera math, negative inputs, source wiring, generated staging candidate and HTTP fixture. They are **not** a substitute for interactive keyboard, touch, screen reader or responsive browser acceptance. Main Engineering should verify at 390/768/1440px and confirm actual Shopify Liquid/CDN behavior before staging use. No Shopify writes are authorized.
