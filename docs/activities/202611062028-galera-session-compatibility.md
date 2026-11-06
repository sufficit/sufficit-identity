# Activity — Galera application-session compatibility gate

Date: 2026-11-06, live observations at 23:25 and 23:27 UTC. Extends the
[causal-read policy](202611062018-galera-causal-read-policy.md) under the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Actual incompatibility and correction

A temporary diagnostic used the service's existing database credentials on
eveo-apps, reconstructing the selected production/machine configuration and
secret override in memory on that host. Credentials never left the host and
were not included in command arguments or output. It opened fresh, unpooled
connections to the configured route and each of the four known SQL candidates.
No application rows were queried or changed.

All five diagnostic connections inherited `wsrep_sync_wait=14`, `wsrep_on=1`
and `wsrep_dirty_reads=1`. The previous policy's compatibility result was false
even after setting sync-wait to 15. This would reject connection preparation if
activated, so publication/activation was not attempted.

The opt-in interceptor now first executes `SET SESSION wsrep_dirty_reads=OFF`,
then adds the READ bit and verifies its required session conditions. It still
never changes GLOBAL variables. This follows the documented requirement that
[dirty reads bypass wsrep_sync_wait](https://mariadb.com/docs/galera-cluster/reference/galera-cluster-system-variables#wsrep_sync_wait).
The owned integration launcher now supplies the observed dirty-read default;
the test verifies inherited value 1, protected-session value 0 and unchanged
global value 1, in addition to its delayed-apply/revocation assertions.

## Successful revised preparation

At 23:27 UTC the temporary diagnostic executed the revised preparation on new
connections. Every result was compatible, with sync-wait 15, session dirty reads
0, global dirty reads 1, wsrep ON, Synced, ready ON and Primary component size 4.

| Destination from eveo-apps | SQL-reported host | MariaDB | Provider |
|---|---|---|---|
| Configured HAProxy route | eveo-data | 10.4.34 | 26.4.18(ra96793fc) |
| eveo-data.sufficit.com.br | eveo-data | 10.4.34 | 26.4.18(ra96793fc) |
| castrum-data.sufficit.com.br | castrum-data | 10.4.34 | 26.4.18(ra96793fc) |
| apoint-data.sufficit.com.br | apoint-data | 10.4.34 | 26.4.18(ra96793fc) |
| google-data.sufficit.com.br | google-voip | 10.4.34 | 26.4.18(ra96793f) |

Google's endpoint reports SQL hostname `google-voip`; the table preserves that
observation rather than renaming it. Earlier local root authentication there
failed, but application credentials succeeded in this probe. The readiness and
version evidence for that endpoint is now direct SQL evidence. Per-node Google
voting weight and time synchronization were not collected here.

## Validation and operational boundary

- Owned Galera integration with dirty reads initially ON: **1 passed**.
- Policy and synchronization checks: **11 passed**, warnings-as-errors build.
- Full Release suite: **2,147 passed, 18 opt-in tests skipped**.
- Revised session preparation: five diagnostic connections succeeded; initial
  preparation returned incompatible on all five, providing the failure evidence.
- Temporary diagnostic artifacts were removed from eveo-apps and absence verified.

The live probe exercised the exact SQL preparation, not a deployed EF interceptor.
It observed fresh sessions from Eveo, not already-open Identity pool connections
or routing from all application sites. Existing pools were never modified. Only
diagnostic SESSION settings changed, and those connections were disposed. No
GLOBAL change, schema/application data mutation, service restart or deployment
occurred. The option still defaults off, and production activation remains pending.

The application release also contains earlier changes not yet published; the
normal sequential deployment and readiness checks still apply. Cache entries
created before activation retain their documented lifetime and invalidation
limits. This gate does not establish weighted failover or an uptime guarantee.

All eight Markdown checks and whitespace validation passed. Owned local Galera
containers/networks were removed. All four compatibility/correction/verification/
documentation checkpoints are complete and delivered together on main. The six
parallel lockfile edits are excluded.
