# Activity — Production Galera membership and readiness inventory

Date: 2026-11-06, observations around 22:14 UTC. Read-only evidence for the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md), extending the
[configured database topology](202611061855-production-provider-topology.md).

## Direct SQL observations

Queried only hostname, version, SQL UTC time, read-only mode and allowlisted
wsrep status fields over SSH using the existing local database authentication.
No application records, credentials or complete configuration files were emitted.

| Node | SQL UTC observation | Version | State | Component | Connected / ready | Members | Read only |
|---|---|---|---|---|---|---|---|
| eveo-data | 22:14:17.367543 | 10.4.34-MariaDB | Synced | Primary | ON / ON | 4 | 0 |
| castrum-data | 22:14:24.750471 | 10.4.34-MariaDB | Synced | Primary | ON / ON | 4 | 0 |
| apoint-data | 22:14:24.700852 | 10.4.34-MariaDB | Synced | Primary | ON / ON | 4 | 0 |

All three report cluster state UUID `222eeeda-4c8a-11ed-a545-22686e94f700` and
zero local send/receive queue at collection. Flow-control paused fractions were
0.00109576, 0.00109542 and 0.00109553 respectively; the accounting intervals were
not measured, so these are not incident-window percentages or latency guarantees.
SQL timestamps are observations, not measured offsets against a trusted clock.
The requests were not simultaneous and do not establish a sustained skew budget.

Additional eveo-data fields:

- provider version `26.4.18(ra96793fc)`, wsrep enabled;
- cluster weight **6**;
- global `wsrep_sync_wait=14`, `wsrep_OSU_method=TOI`;
- incoming endpoints `172.16.3.102:3306`, `172.16.1.102:3306`,
  `172.16.2.102:3306`, `100.64.0.38:3306`.

## Fourth node and access limit

SSH to google-data succeeded. Its `tailscale0` interface has `100.64.0.38`,
matching the fourth incoming endpoint announced by eveo-data. This correlates the
fourth member with google-data; it is not a direct SQL readiness check there.

The default local MySQL root login returned `ERROR 1698 (28000): Access denied`.
A fallback using the conventional maintenance defaults file could not run because
`/etc/mysql/debian.cnf` does not exist on that host. No credentials were guessed,
changed or extracted. Its SQL version, readiness, causal-read settings and clock
remain unverified. Existing authentication on the other three hosts was sufficient
for their status queries.

## Consequences for the pending rehearsal

The local session outage tests use MariaDB 10.11, while the three verified live
nodes use 10.4.34. Those local results prove their documented test scope, not
production Galera compatibility or cross-node failover behavior.

A representative follow-up must pin the database/provider versions and inventory
per-node voting weights and effective connection-level causal-read settings.
Do not infer a four-equal-voter quorum from four members when the observed total
weight is six. The global sync-wait value on one node is not proof of every
application session's value. HAProxy selected-backend health, actual failover and
cross-node visibility of acknowledged revocations remain to be exercised.
No production service was stopped, restarted or reconfigured.

## Validation and delivery

The three direct SQL observations succeeded. Fourth-node SQL access remains a
concrete limitation, recorded above instead of being reported as healthy.
All eight Markdown coverage tests passed; whitespace validation passed. The
three observation/reconciliation/documentation checkpoints are complete, with
the Google SQL limitation retained. Activity and plan are delivered together on
main, excluding the six unrelated package lockfile edits. This observation
requires no deployment.
