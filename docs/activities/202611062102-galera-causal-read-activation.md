# Activity — Gradual production activation of Galera causal reads

Date: 2026-11-06, approximately 20:58–21:02 America/Sao_Paulo.
Extends the [runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md) and
[release publication](202611062045-production-publication.md).

## Compatibility and activation

Before changing configuration, a temporary diagnostic reconstructed the service
configuration and reused its database secret in memory on each application host.
It tested the configured HAProxy route and each of the four known SQL candidates
from Eveo, Castrum and Apoint: **15/15 compatible sessions**. All returned sync-wait
15 and session dirty reads 0 after preparation; GLOBAL dirty reads remained 1.
The configured routes selected the respective local data node. The option was
absent/default false on all three hosts before activation. Diagnostic directories
were removed; their absence was independently verified.

With the shared cluster deployment lease held on Eveo, enabled
`Sufficit__Identity__Database__RequireGaleraCausalReads=true` in
`/etc/sufficit/identity/hardening.env`, one host at a time: Eveo, Castrum, Apoint.
Each update was an atomic replacement preserving ownership and permissions.
The machine-specific configuration was checked for a conflicting override.

Each host restarted through the installed `activate-release.sh --current` helper.
Before proceeding, checked the actual service process environment and four
successful readiness samples separated by five seconds. All services reported
active/running and NRestarts=0. The exact original environment was preserved as
`/etc/sufficit/identity/hardening.env.before-causal-20261106` on each host.
A final comparison confirmed the sole configuration delta was the added switch,
with unchanged ownership/permissions. No application binary or schema changed.

## Final evidence

`verify-production-cluster.sh` confirmed all three hosts at revision
`e1aeb17488af8b82af3fd270853a51c88cb94b15`, health/readiness Healthy.
Certificate and JWKS hashes remained identical to the publication record.

Three additional direct readiness samples per host returned HTTP 200:

| Host | Observed elapsed range |
|---|---|
| Eveo | 3.832–4.322 ms |
| Castrum | 2.579–15.572 ms |
| Apoint | 2.813–3.283 ms |

Public health, readiness, discovery and login endpoints returned HTTP 200
(118–157 ms in four single requests). These are brief endpoint measurements,
not isolated SQL timings, percentiles, a load test or an availability guarantee.
Transient 502 responses occurred during service restarts.

Source registration, enabled process configuration and successful EF-based health
checks support activation of the deployed interceptor. No debugger or SQL session
inspection was attached to the live service pool, and no authenticated user journey
or revocation race was induced in production. The fifteen SQL probes were separate
fresh diagnostic connections, not those application pool connections.

## Rollback and remaining gates

Restore the host's exact backup to `hardening.env`, preserving ownership/mode,
then run the installed helper with
`IDENTITY_HEALTH_HOST=identity.sufficit.com.br` and `--current`; verify readiness
before proceeding to another node. The rollout script restored the current host
on a failed activation/check and would restore already changed hosts on failure.
No rollback was needed or exercised. Keep the backup until the observation period
is accepted; review later configuration edits before restoring the entire file.

Only application SESSION behavior changed; no GLOBAL SQL setting, customer data,
certificate, credentials or schema was modified. Existing stale cache hits bypass
the database barrier and retain their documented bounds. Weighted Galera failover,
partitions, sustained latency/error observation and the remaining F4 fault/clock
gates stay open. The six unrelated workspace lockfile edits were preserved.

All three activation checkpoints are complete. The eight Markdown coverage tests
and `git diff --check` passed. This was an operational configuration change;
product code and its previously validated tests were unchanged.
