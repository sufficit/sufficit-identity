# Activity — Isolated session notification connection

Date: 2026-11-06. F4 bounded verification in the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Change and scenario

Added an owned loopback TCP relay that closes existing sockets and refuses new
connections while cut. Restore resumes forwarding. Cancellation/disposal closes
the listener and connections and joins the forwarding tasks; no host firewall
or production route is modified.

The opt-in regression creates three real user-security NATS bridges. Only the
second uses the relay. After that connection is cut, the first publishes a
security-stamp invalidation and the third receives it while both stay connected.
The isolated cache remains warm, but its disconnected validator reads the user
store and rejects the revoked ticket. After restoring the relay, the missed
notification is not replayed: the old ticket may be accepted within the original
window, but is rejected at its deadline. A new invalidation is then delivered to
the recovered node and rejects another revoked ticket.

Uses real TCP/NATS transport, real stamp validator/test user store, independent
caches and a controlled cache clock. Waits follow connection and invalidation
events, with hang guards. No sleeps or production mutation.

## Verification

- Release build (`--no-restore -warnaserror`) and ordinary stamp-cache/synchronization
  tests: 9 passed; both opt-in broker tests skipped without environment settings.
- Dedicated local NATS run: 2 passed, zero skips, including the earlier whole-broker
  restart case and the new isolated-node case. Container removed afterward.
- Same pinned image and fixed-port setup as the
  [broker recovery activity](202611061809-session-nats-recovery.md).
  Filter: `FullyQualifiedName~Real_notifications_resume_after_broker_outage|FullyQualifiedName~Isolated_node_misses_invalidation`.
- Full Release suite: 2140 passed, 14 skipped, zero failures (2154 total).
  Both broker cases are skipped in this ordinary run and were executed separately.
  Final Markdown coverage: 8 passed.

## Limits and checkpoints

This models an explicitly severed TCP connection and refusal to reconnect. It
is not silent packet dropping, one-way loss, clustered NATS election, Redis HA,
Galera failover or a production clock-skew measurement. F4 remains open for those
remaining scenarios. Runtime code and configuration are unchanged.

1. Implementation and dedicated broker regressions completed.
2. Full regression/documentation validation complete.
3. Delivery record and diff review complete; commit/push verification is reported
   with the delivery result. Six parallel lockfiles are excluded.

No deployment is claimed.
