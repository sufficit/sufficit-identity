# Activity — Opt-in Galera causal-read policy

Date: 2026-11-06. Implements the barrier proven by the
[Identity Galera integration](202611061948-identity-galera-session-reads.md),
continuing the [runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Change

Added `Database.RequireGaleraCausalReads` (default false) and a production EF
connection interceptor. HTTP-host contexts and maintenance-only pruning contexts
register it when opted in. Setup preserves existing sync-wait bits and adds the
READ bit, rejects sessions with wsrep disabled or dirty reads enabled, bounds its
command timeout and propagates provider exceptions/cancellation. It never changes
global settings. The [permanent contract](../architecture/ARCHITECTURE-SESSION-VALIDITY.md#optional-galera-causal-reads)
contains configuration, scope, activation/rollback and cache limitations.

The owned Galera integration now uses this product interceptor and also verifies
synchronous opening produces value 15 from inherited 14. The stale client remains
unprotected intentionally to retain the control case. This test does not require
or activate the option on any production host.

## Validation

Seven policy tests and four synchronization checks passed with warnings as errors.
They cover sync/async rejection and error propagation, cancellation during setup,
pre-canceled calls without command creation, disposal and the compatibility default.
The first build detected conflicting names in fake-command test members; those
were renamed before tests ran. Product behavior was not changed by that correction.

Owned Galera integration: **1 passed**, using MariaDB 10.4.34 and Galera
26.4.18 with the product interceptor (sync and async paths). Full Release suite:
**2,147 passed, 18 opt-in tests skipped**. EF-based health checks/watchdog share
the configured context and are subject to setup when the option is enabled.

All eight Markdown checks and whitespace validation passed. Owned Galera
containers/networks were removed. The three implementation, validation and
delivery-documentation checkpoints are complete; code and evidence are shipped
together on main.

## Remaining delivery boundary

This implements an opt-in capability, not an activated production mitigation.
Production session configuration, rollout observation, weighted failover and full
HTTP/cache combinations remain pending. Cached stale tickets are not retroactively
invalidated by a database barrier. Keep the six parallel lockfile edits excluded.
No production connection, configuration, schema or deployment was changed.
