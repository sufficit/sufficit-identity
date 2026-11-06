# Activity — Session notification-channel transitions

Date: 2026-11-06. Scope: bounded F4.2/F4.3 verification in the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Verified behavior

Added two integration regressions to `SessionValidityCacheIntegrationTests`:

1. Warm cache, then connected-to-disconnected publisher transition and stamp
   rotation: the validator reads the authoritative store and rejects the ticket.
2. Two independent node caches, stamp rotation delivered only to one node, then
   reconnection of the isolated node. The notified node rejects immediately;
   the isolated node may accept at second 29 of the original 30-second window,
   including repeated cache hits, but rejects at second 30. No sleep or host
   clock change is needed; only the cache clock is advanced.

The real validator and test user store execute in both cases. No runtime change
was required. Reconnection alone has no missed-message replay guarantee; this
bounded stale acceptance is documented rather than described as immediate
revocation. The window belongs to stamp validation, distinct from ticket-cache TTL.

## Evidence and limits

- Release build with `--no-restore -warnaserror`; focused stamp-validator,
  validity-cache and ticket-cache-race suite: 22 passed.
- Full Release suite: 2140 passed, 12 skipped, zero failures (2152 total,
  TRX counters). Final Markdown coverage: 8 passed.
- Publisher connectivity is simulated, not a real NATS partition/reconnect.
  Real automatic HA election/discovery, packet-loss behavior, Galera failover
  and quantitative production clock-skew evidence remain open.
- Updated [session architecture](../architecture/ARCHITECTURE-SESSION-VALIDITY.md).

## Execution checkpoints

1. Implementation and focused verification complete.
2. Full regression and documentation validation complete.
3. Delivery record and diff review complete; commit/push verification is reported
   with the delivery result. Six unrelated package-lock changes are excluded.

No production deployment or runtime behavior change is claimed.
