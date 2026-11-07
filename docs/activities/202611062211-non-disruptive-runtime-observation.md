# Non-disruptive runtime observation

Owner: [runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

The owner could not specify production fault tolerances. This follow-up uses
no intentional interruption and does not establish acceptance thresholds.
No restart, configuration change, fault injection or customer credentials were used.

## Method and results

Executed `helpers/verify-production-cluster.sh e1aeb17488af8b82af3fd270853a51c88cb94b15`
12 times sequentially, with five seconds between rounds, using the existing
production host/SSH environment. All 36 node checks reported active services,
Healthy health/readiness, the expected deployed revision and consistent certificate
and JWKS hashes. All 12 commands exited zero.

| Round | Start (UTC) | Whole round duration (seconds) | Exit |
|---|---|---|---|
| 1 | 2026-11-07T01:09:50.003543+00:00 | 1.978 | 0 |
| 2 | 2026-11-07T01:09:56.981388+00:00 | 1.785 | 0 |
| 3 | 2026-11-07T01:10:03.766859+00:00 | 1.701 | 0 |
| 4 | 2026-11-07T01:10:10.468076+00:00 | 1.837 | 0 |
| 5 | 2026-11-07T01:10:17.305101+00:00 | 1.758 | 0 |
| 6 | 2026-11-07T01:10:24.063302+00:00 | 1.702 | 0 |
| 7 | 2026-11-07T01:10:30.765788+00:00 | 1.72 | 0 |
| 8 | 2026-11-07T01:10:37.485944+00:00 | 1.703 | 0 |
| 9 | 2026-11-07T01:10:44.188857+00:00 | 1.727 | 0 |
| 10 | 2026-11-07T01:10:50.916019+00:00 | 1.853 | 0 |
| 11 | 2026-11-07T01:10:57.769181+00:00 | 1.748 | 0 |
| 12 | 2026-11-07T01:11:04.517595+00:00 | 1.749 | 0 |

Durations include SSH and all checks across three nodes; they are not HTTP
request latency measurements. Local raw output: `/tmp/identity-observation-followup.jsonl`
(ephemeral); the durable table above records each sample.

## Limits and remaining work

This short sample does not demonstrate login throughput, production failover,
revocation timing during faults, continuous availability between samples, clock
skew, or an SLO. F4.2/F4.3 remain open for their existing operational gates.
The next meaningful operational step is to define a maintenance window and the
affected-consumer recovery envelope, then execute the existing HA runbook.
Repeating this health sample alone cannot satisfy those gates.

## Delivery validation

Documentation-only change. The Release `MarkdownCoverageTests` filter passed
all 8 tests using `--no-build --no-restore`; Git whitespace validation passed. No additional application deployment is required.
