# Objective 34R — typed-but-unadded wording discard protection

Offline, ephemeral customer concept editor only. Prior UI considered only committed lettering layers when asking before product changes or clear design. A customer could type private wording, then change product or clear design without a warning; the textarea retained that wording, contrary to the clear/discard intent. This is a privacy and customer-experience defect, not a hosted security vulnerability.

The client-only `staticPreviewHasPendingWork` returns a boolean for any layers or any typed characters (including whitespace); malformed input fails closed to a warning. Product changes and Clear design now require explicit confirmation for typed-only drafts, restore the previous product on cancellation, and clear textarea, error state, and helper after successful discard. A failed change does not erase wording. Successful Add wording clears the composer as before. Textarea autocomplete is disabled as a best-effort hint, not a guarantee against browser session restoration.

No browser storage, customer data transmission, commerce or Shopify operations were added. No claims of native browser, hosted authentication or storefront acceptance. Main Engineering must reconcile this offline patch with its customized Objective 35 unpublished staging source; do not overwrite the staged theme.
