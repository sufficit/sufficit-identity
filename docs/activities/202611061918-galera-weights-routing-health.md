# Activity — Galera weights, causal-read setting and live routing

Date: 2026-11-06, approximately 22:17–22:18 UTC. Read-only continuation of the
[Galera inventory](202611061915-production-galera-inventory.md) under the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Voting and provider observations

All three queried nodes remained Synced, ready, in a Primary component of four
members and total weight six. Allowlisted provider options were parsed on the
remote host; no full provider configuration or credentials were emitted.

| Node | pc.weight | Global wsrep_sync_wait | pc.recovery |
|---|---|---|---|
| eveo-data | 2 | 14 | false |
| castrum-data | 1 | 14 | false |
| apoint-data | 1 | 14 | false |

All three reported `pc.ignore_quorum=false`, `pc.ignore_sb=false`,
`evs.suspect_timeout=PT20S`, `evs.inactive_timeout=PT40S`,
`pc.wait_prim_timeout=PT30S`, `wsrep_on=ON` and `wsrep_OSU_method=TOI`.
These are observed settings, not measured failure-detection or recovery durations.
The residual weight is two (6 minus 2 minus 1 minus 1); attributing that to Google
is an inference from this four-member snapshot, not a direct Google SQL query.
Google SQL access remains unresolved as recorded in the previous activity.

## Causal SELECT gap to investigate

The official [MariaDB wsrep_sync_wait reference](https://mariadb.com/docs/galera-cluster/reference/galera-cluster-system-variables#wsrep_sync_wait)
assigns READ/SELECT to bit 1. Value 14 includes write operations and SHOW, but
excludes that bit. Therefore the observed global value alone does not establish
a causal barrier for an ordinary SELECT on another node after an acknowledged
revocation. It must not be described as proof of causal reads.

A source search of the Identity C# and JSON files found no explicit wsrep/causal
session configuration. The production connection interceptor records telemetry;
this search does not prove the effective settings of already-open application
sessions, initialization performed outside this repository, or client-library
behavior. No stale production read or session resurrection was reproduced.

Priority for the next representative rehearsal is to verify the effective
application-session value and cross-node revocation visibility with the observed
setting. Compare a SELECT barrier in disposable infrastructure before choosing a
product/session-specific policy. Do not change shared global database settings
based solely on this observation; other applications use the same cluster.

## Live HAProxy observation

Issued only `show stat` to `/run/haproxy/admin.sock` on each proxy and retained
status fields. The following rows concern the `MySQL` listener, not LogData.

| Proxy | Local primary connections (scur) | Four ordinary targets | Duplicate local backup |
|---|---|---|---|
| eveo-proxy | 41 | UP, L7OK, code 200 | UP, L7OK, code 200 |
| castrum-proxy | 7 | UP, L7OK, code 200 | no check |
| apoint-proxy | 8 | UP, L7OK, code 200 | no check |

All current connections in these listener snapshots were assigned to the local
ordinary target; other targets and backup had zero. These counters aggregate
all listener users and cannot identify Identity's particular connections.
The Google target was UP according to each proxy's configured health check;
that is distinct from directly observing its SQL wsrep state or authenticating
as the application. The semantics of the HTTP health-check endpoint were not
inspected in this checkpoint. A `no check` backup must not be counted as a
health-verified target merely because the overall backend is UP.

## Representative failover matrix remaining

- Cross-node SELECT after an acknowledged revocation, with warm and cold caches,
  observed session settings and a deliberately delayed apply path locally.
- Loss of a weight-two member and loss of a weight-one member, separately;
  actual Primary/non-Primary observations, not an assumed equal-voter model.
- Partition/combined losses and subsequent recovery, using the recorded provider
  options, while verifying no removed session row or ticket is recreated.
- HAProxy selection and reconnection when ordinary checks fail, including the
  duplicate local backup behavior and the two entries without a check.
- Direct Google SQL version/readiness/weight and actual Identity session settings
  remain missing inputs for claims about full production equivalence.

No production fault injection, SQL mutation, configuration edit, restart or deploy
was performed. This narrows F4; it does not close failover or consistency gates.

## Validation and delivery

All eight Markdown coverage tests passed; whitespace validation passed. The
three inventory/reconciliation/documentation checkpoints are complete. Activity
and owning plan are delivered together on main; the six existing lockfile edits
are excluded. The matrix above remains pending work, not completed testing.
