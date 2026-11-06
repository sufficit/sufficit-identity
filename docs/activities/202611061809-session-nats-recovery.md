# Activity — Real session notification broker recovery

Date: 2026-11-06. Bounded F4 verification from the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Scenario

Added an opt-in integration test using two real `UserSecurityNatsBridge`
instances, independent stamp caches, the real validator and test user store.
A dedicated loopback-only NATS container is stopped and restarted by the test.

Verified initial remote invalidation, disconnected publisher refusal, authoritative
stamp rejection during outage, reconnect with a missed notification bounded by
the original 30-second cache window, and new invalidation delivery after recovery.
The cache clock is controlled; transport readiness and invalidation use events,
not sleeps. Connection waits have an overall 45-second hang guard.

No runtime change or production broker access occurred. This proves real local
broker restart/reconnection, not a network partition, clustered NATS election,
Redis HA, Galera failover or production clock-skew bounds.

## Reproduction and evidence

Use a dedicated container named `identity-proxy-sync-tests-*`, NATS authentication
`identity-test-token`, and an explicitly fixed loopback host port mapped to 4222.
Set `IDENTITY_TEST_NATS_CONTAINER` and `IDENTITY_TEST_NATS_URL` for the test process.
Run only `FullyQualifiedName~Real_notifications_resume_after_broker_outage` when
using that container: other broker fault-injection tests must not share it concurrently.
Remove the owned container afterward, including on failure.

- Image: `nats:2.10-alpine`, pinned during execution to
  `sha256:b83efabe3e7def1e0a4a31ec6e078999bb17c80363f881df35edc70fcb6bb927`.
- Initial preparation used an ephemeral Docker host port. Restart reassigned that
  port; clients retained the previous endpoint, so the run was stopped by explicit
  test-host PID. Its container was removed by cleanup. This was a fixture failure.
- Corrected preparation kept the host port fixed. The real-broker test passed
  (1 executed, no skip), and its owned container was removed.
- Release build with `--no-restore -warnaserror`, ordinary validity-cache and
  synchronization contracts: 9 passed; broker case skipped without opt-in settings.
- Full Release suite: 2140 passed, 13 skipped, zero failures (2153 total).
  The new opt-in broker case is among the skips here and was executed separately
  above. Final Markdown coverage: 8 passed.

## Execution checkpoints

1. Implementation and dedicated real-broker verification complete.
2. Full regression and documentation validation complete.
3. Delivery record and diff review complete; commit/push verification is reported
   with the delivery result. Six unrelated package-lock modifications are excluded.

This is test coverage and documentation only; no deployment is claimed.
