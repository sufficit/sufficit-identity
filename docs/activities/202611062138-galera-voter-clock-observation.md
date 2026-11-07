# Activity — Fourth Galera voter, clock and activation observation

Date: 2026-11-06, 21:37–21:38 America/Sao_Paulo (2026-11-07 00:37 UTC).
Extends the [runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md),
[weighted local rehearsal](202611062107-local-weighted-galera-quorum.md) and
[causal-read activation](202611062102-galera-causal-read-activation.md).

## Direct voter inventory

An ephemeral diagnostic on eveo-apps reused existing service authentication in
memory. It queried only connection/server variables and allowlisted status;
no customer rows or secret values were emitted. From wsrep_provider_options it
returned only pc.weight, not the complete option string. No SET commands ran.

| Destination | SQL hostname | pc.weight | State / component | Members / weight |
|---|---|---|---|---|
| Configured route | eveo-data | 2 | Synced / Primary | 4 / 6 |
| eveo-data | eveo-data | 2 | Synced / Primary | 4 / 6 |
| castrum-data | castrum-data | 1 | Synced / Primary | 4 / 6 |
| apoint-data | apoint-data | 1 | Synced / Primary | 4 / 6 |
| google-data | google-voip | 2 | Synced / Primary | 4 / 6 |

All were ready ON, MariaDB 10.4.34. Provider versions remained
26.4.18(ra96793fc) on the first three and 26.4.18(ra96793f) on Google.
This resolves the previously inferred fourth weight: the local 2/1/1/2 model
now has a direct production weight inventory behind it. Historical records
correctly retain the uncertainty that existed when those tests were run.

Fresh raw diagnostic connections inherited sync-wait 14 and dirty reads ON.
That is expected: they do not pass through the deployed EF interceptor, and
activation deliberately did not change GLOBAL defaults. It is not evidence that
the application's session-local policy was disabled. These diagnostic connections
were disposed and their remote temporary directory was removed and checked absent.

## Fourth host clock

SSH destination google-data reports hostname google-voip, matching SQL. The older
timedatectl does not support the initially requested show/property syntax;
`timedatectl status` succeeded and reports NTP enabled and synchronized.
Chrony tracking and sources succeeded:

- Selected source: metadata.google.internal (169.254.169.254), reach 377.
- Local stratum 3, source stratum 2, leap status Normal.
- Reference time 00:24:35 UTC; observation approximately 00:37:30 UTC.
- System time 0.000000252 seconds fast of NTP time.
- Last offset -0.000000435 seconds; RMS offset 0.000012354 seconds.
- Root delay 0.000102822 seconds; root dispersion 0.000857325 seconds.
- Reported update interval 1030.8 seconds.

These are daemon-reported values, not independent absolute accuracy measurements.
The snapshot does not establish a sustained inter-provider clock-skew budget.

## Post-activation application check

All three application nodes remain on e1aeb174 with active services, Healthy
health/readiness and unchanged certificate/JWKS hashes. Each running process
still contains RequireGaleraCausalReads=true. NRestarts=0 on every node, with
reported start times 20:59:06 (Eveo), 20:59:29 (Castrum), 20:59:48 (Apoint).
The observation is about 38 minutes after activation. It does not establish
continuous request success between health samples; request/error telemetry,
load and authenticated journeys were not collected here.

No service restart, configuration mutation, application data access, fault
injection or GLOBAL/session-variable change occurred. Production HA, actual
Redis replica placement, combined failures and sustained observation remain open.
All temporary diagnostic artifacts were removed. Six parallel lockfiles remain
outside this documentation change.

All three observation/reconciliation/delivery checkpoints are complete.
All eight Markdown coverage checks and `git diff --check` passed.
