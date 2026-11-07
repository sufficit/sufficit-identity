# Runbook — Runtime HA validation and observation acceptance

Owner: [runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).
Evidence rules: [production evidence](RUNBOOK-PRODUCTION-EVIDENCE.md).
This procedure preserves the distinction between passing owned fixtures and
production fault evidence. It does not authorize unbounded shared-service faults.

## Execution record to fill before a production fault

| Required field | Why it is needed |
|---|---|
| Selected environment, release, affected provider and node | Shared Redis/Galera serve more than the Identity process |
| Maintenance window and reachable operator | Restore service promptly if the first fault does not recover |
| Affected consumers and permitted impact | Identity readiness alone cannot validate other consumers |
| Maximum failed requests, latency and recovery interval | Defines abort criteria before injecting the fault |
| Observation duration and representative synthetic workload | A series of idle health checks is not a workload/SLO measurement |
| Maximum accepted inter-host/provider skew | Daemon snapshots alone cannot decide whether a budget is met |
| Current topology, backup/restore record and rollback owner | A local cluster rehearsal does not prove production recovery |

The current session supplied publication authorization, but no numerical
production fault/latency/skew acceptance thresholds or affected-consumer envelope.
Record those inputs rather than inventing a pass criterion after observing results.

## Preflight

1. Run `helpers/verify-production-cluster.sh` with the recorded deployed revision
   and expected certificate/JWKS pins. Confirm shared-cache and causal-read options
   in every running process without emitting credentials.
2. Query all six Redis endpoints: cluster_state ok, all 16384 slots healthy,
   replicas connected and offsets/lag acceptable under the recorded threshold.
   Retain the exact primary/replica map; do not assume it stayed unchanged.
3. Query all Galera candidates: Primary, Synced, ready ON, expected membership
   and voting weight. Verify each route's health checks and duplicated backups.
4. Confirm the operator can restore the selected service and health-check it.
   Abort if unrelated degradation, replication lag or concurrent maintenance exists.
5. Start synthetic workload and aggregate telemetry before the first change.
   Avoid real customer credentials, payloads or sessions in the evidence.

## One fault at a time

- Redis: select one primary whose replica and majority are verified. Exercise
  automatic election/discovery and record the new slot owner, acknowledged state,
  revocation visibility and original TTL. A commanded graceful promotion alone
  does not prove failure detection or automatic election.
- Database route: remove only the selected candidate by the approved procedure,
  leaving a verified Primary component. Observe actual selected fallback,
  causal-read enforcement and acknowledged revocation visibility. A separate
  direct SQL connection is not application pool failover evidence.
- Do not compound site/database/cache faults until each individual case has passed
  and its recovery is verified. Do not bootstrap a minority, ignore quorum or
  change GLOBAL dirty-read/causal settings as an emergency workaround.
- On an abort condition, restore the exact affected service/routing state and
  verify every consumer in the execution record, not only Identity health.

## Completion

Keep before/during/after timing, error counts, election/member state and sanitized
workload outcomes. Verify service configuration, memberships, health and original
TTL bounds after recovery. Close the relevant F4 gate only when its specified
workload and thresholds pass. If no fault ran, record observation only.
