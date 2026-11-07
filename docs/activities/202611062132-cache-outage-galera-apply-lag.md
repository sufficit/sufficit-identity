# Activity — Cache outage combined with Galera apply lag

Date: 2026-11-06, 21:32 America/Sao_Paulo. Extends the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md) and
[owned Galera session integration](202611061948-identity-galera-session-reads.md).

## Change and observations

Extended the existing delayed-apply integration scenario with a separate ticket
store using the real causal repository/interceptor and an IDistributedCache
implementation that throws IOException. The cache failure is injected; Galera,
EF and the ticket-store fallback path are real.

With the remote revocation applied on the writer but deliberately blocked on the
reader, an unprotected reader still sees the old session. The store with the
unavailable cache falls back to the protected repository and propagates MySQL
1205 rather than returning the revoked ticket. Exactly one cache read was
attempted and no cache Set was attempted.

After releasing the owned reader's apply lock, the same store returns null for
the revoked session while its cache remains unavailable. Its second read failure
falls back to the recovered database, with no attempted cache write. Existing
assertions also verify that renewal cannot recreate the revoked row and that an
already cached stale ticket remains a separate cache-lifetime limitation.

No production implementation needed correction. The test makes the combined
failure behavior executable rather than inferring it from separate cache and
Galera tests.

## Validation

- Warnings-as-errors build and session/cache/cancellation/synchronization checks:
  **21 passed**.
- `python3 scripts/check-galera-causal-reads.py --identity-tests`: **2 passed**,
  covering the extended combined scenario and all four pooled-open combinations.
- MariaDB 10.4.34 / Galera 26.4.18(ra96793fc), three disposable local nodes.
- Owned containers and network were removed; absence checked after execution.
- All eight Markdown coverage checks and `git diff --check` passed.

All three checkpoints are complete and archived here.

No production mutation, schema change, deployment or GLOBAL SQL change outside
the owned fixture occurred. This is not Redis transport/failover coverage,
production latency evidence or an authenticated HTTP test. F4's remaining
combined infrastructure and production gates remain open. The six parallel
lockfile edits are preserved and excluded.
