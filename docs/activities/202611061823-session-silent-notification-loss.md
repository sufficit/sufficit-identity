# Activity — Silent one-way notification loss

Date: 2026-11-06. Bounded F4 verification from the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Scenario and result

Extended the owned loopback relay to discard broker-to-client bytes without
closing TCP. A signal confirms the revoked user's identifier was actually seen
in the discarded bytes, including identifiers split across reads. The other
direction remains forwarded. A bounded suffix is retained only for matching the
fictional test identifier; no traffic is logged.

The new real-NATS regression uses the existing three-node scenario. Unaffected
peers remain connected and receive the revocation, while the affected bridge
still reports Connected and misses it. Inside the original cache window the old
stamp may be trusted; at its original 30-second boundary the real validator reads
the authoritative test user store and rejects the revoked ticket. The clock is
controlled, so this verifies the window independently of heartbeat timing.

Recovery explicitly replaces the damaged TCP stream before restoring forwarding:
discarded bytes may include only part of a protocol frame, so resuming the same
stream cannot safely be assumed to restore framing. New notifications then arrive
and invalidate the recovered node. The other two broker regressions still pass.

## Evidence

- Release build with `--no-restore -warnaserror`, ordinary stamp-cache and test
  synchronization contracts: 9 passed, three broker cases skipped without opt-in.
- Dedicated pinned local NATS run: 3 passed, zero skips. Container removed afterward.
  Image/setup from [broker recovery](202611061809-session-nats-recovery.md).
  Filter: `FullyQualifiedName~Real_notifications_resume_after_broker_outage|FullyQualifiedName~Isolated_node_misses_invalidation|FullyQualifiedName~Silently_dropped_notification`.
- Full Release suite: 2140 passed, 15 skipped, zero failures (2155 total).
  The three opt-in broker cases were executed separately above.
  Final Markdown coverage: 8 passed.

## Limits and checkpoints

This is byte discard by a terminating TCP relay, not IP packet loss/retransmission
or a measurement of when production heartbeats detect a blackhole. It proves the
cache bound while connectivity appears healthy. Automatic HA election/discovery,
Galera failover and production host/provider clock bounds remain open. Runtime
code and production configuration are unchanged.

1. Implementation and three dedicated broker cases completed.
2. Full regression/documentation checks complete.
3. Delivery record and diff review complete; commit/push verification is reported
   with the delivery result. Six parallel lockfiles are excluded.

No deployment is claimed.
