# Objective 35W — Read-only quarantine review tickets

Offline prototype only. `createLocalArtworkQuarantineIntent` inventories all saved design revisions under the cooperative filesystem lease and returns an operator-reviewable candidate list with a SHA-256 snapshot pin. A caller-supplied 32–128-byte HMAC key binds the ticket to the exact root, pin, sorted candidates, nonce and expiration. The key is never stored here. `verifyLocalArtworkQuarantineIntent` authenticates the ticket, checks expiry and rescans the entire inventory before returning a **read-only** verification result.

The snapshot pin includes revision contents and observed artwork filesystem metadata, but it is **not** a filesystem transaction, durable pin, writer fence, production authorization, quarantine grant, or protection against an uncooperative writer after verification. The clock is caller-provided (no trusted time source), and a malicious caller controlling the key or clock can create misleading review tickets. Tickets may be replayed within their short TTL for *read-only* verification; no replay-consuming store exists. Both APIs categorically refuse mutation. Any missing/incomplete referenced artwork, incomplete pair, pending stage, unsafe entry, stale snapshot, changed root, invalid signature or expired ticket fails closed. A crash-left lease remains an operator-only investigation gate. The system never moves, deletes, or quarantines a byte.

Example (local fixture only):

```js
const key = randomBytes(32); // ephemeral, caller-held
const ticket = await createLocalArtworkQuarantineIntent(root, {reviewKey:key});
const check = await verifyLocalArtworkQuarantineIntent(root,ticket,{reviewKey:key});
// check.safeToAutoDelete === false; check.safeToQuarantine === false
```

No Shopify reads/writes, hosted auth, checkout, orders, customer data or manufacturing approval.
