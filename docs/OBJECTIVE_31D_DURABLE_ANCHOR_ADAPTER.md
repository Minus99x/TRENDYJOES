# Objective 31D — Offline durable independent anchor adapter

**Scope:** opt-in, Linux-only, single-host filesystem adapter for the private registry and anchored audit journal. It is **not** a trusted offsite witness, hardware-backed monotonic counter, production database, hosted auth, Shopify integration, or production anti-rollback mechanism.

## Contract and threat boundary

`createOfflineDurableAnchorAdapter({directory,registryId,anchorType,recovery,lockTimeoutMs,injectFault})` in `src/offline-durable-anchor-adapter.mjs` accepts `anchorType: 'registry' | 'journal'` and an independently controlled Ed25519 **public** recovery key. Use distinct anchor directories outside the registry and journal data directories. It returns a frozen object:

- `read()` — returns current locally verified head or `null`. Fails closed when a prepared record remains or history is damaged.
- `readPinned(expectedHead)` — same check, additionally refuses a head that differs from an **independently retained** exact expected value. Without that independent pin, a fully rolled-back but valid local prefix cannot be distinguished from an earlier legitimate state.
- `compareAndSet(expected,next)` — strict one-step anchor CAS; returns `false` on a stale expected head. A new event is prepared with exclusive creation, file and directory sync, then atomically renamed and directory-synced under a cooperative cross-process `flock`. It re-verifies the committed head. A crash or uncertain outcome must be checked by reading the head, not retried blindly.
- `inspect()` — verified current head, event count, local chain digest, `productionApproved:false`.
- `recoverInterruptedCommit({authorization})` — requires an independent Ed25519 signature on exact registry ID, anchor type, action, authorization ID, issued/expiry times, expected and target heads, SHA-256 of pending bytes and reason. A valid complete pending event may be committed; a torn proposal may be **aborted** with `targetAnchor:null`. Both operations fail closed on state mismatch, invalid signature or expiration. An abort does **not** prove that a separate registry or journal state was rolled back.

The journal/registry coordinator's existing signed recovery rules still apply independently. Recovery at the anchor adapter layer **does not** authorize bypassing their consistency checks or skipping audit observations. A pending record stops ordinary reads, mutations and signed backups until authorized recovery.

## Integration

The adapter methods match existing injected `readAnchor` / `compareAndSetAnchor` and `readJournalAnchor` / `compareAndSetJournalAnchor` interfaces. Pass the **same function object** for registry reads through registry, journal and coordinator options; likewise the same journal reader through journal and coordinator. `tests/objective31c-trusted-service.test.mjs` exercises a real authenticated revision commit, protected artwork read, authenticated revocation, both durable anchor histories, and denial after a journal anchor rollback.

## Explicit limitations

- The directory and all its event files are on one local host. The hash chain detects alteration **relative to a trusted digest/head** but cannot detect complete rollback of both data and anchors by an attacker controlling the host. A trusted offsite/WORM witness, key custody, backup retention, and host-level access control are not implemented.
- Locking is cooperative and Linux-specific; same-user or root-level adversaries can bypass filesystem protections. Multi-host CAS/linearizability is not provided. Atomic rename and fsync depend on filesystem semantics; do not assume distributed filesystem durability.
- The registry and journal anchors are **not atomically committed together**. After a crash between them, existing signed one-step coordinator reconciliation remains mandatory.
- A signed `abort-pending` approval can be replayed against the exact same bytes and unchanged head if an actor with direct filesystem write access recreates the pending record; this adapter does not maintain an independently anchored global recovery-authorization replay ledger. Do not treat its permits as production-grade single-use credentials.
- It cannot infer missing audit history or validate production identity, manufacturing measurements, Shopify cart/checkout, payment, or real orders.

## Reproduction

```sh
node --test tests/objective31d-durable-anchor.test.mjs
node --test tests/objective31c-trusted-service.test.mjs
npm test
```

Tests use ephemeral signing keys, synthetic registry data and disposable directories. They cover real separate-process crash, two competing processes, pending/torn recovery, tamper, hardlink/symlink, wrong key/signature, stale pin, missing events and authenticated service integration. No Shopify writes or external network traffic.
