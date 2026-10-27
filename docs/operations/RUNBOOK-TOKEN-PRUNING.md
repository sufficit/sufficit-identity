# Token maintenance

Server is the only executable; the STS provides the pruning operation. The
`--prune-tokens` command composes the database and OpenIddict only — no HTTP, no
provisioning, no migrations, no other workers. Retention: 30 days. Eligibility
matches OpenIddict 7.7.2: age alone never removes a valid, unexpired token on a
valid authorization. Inactive tokens without expiry remain protected too.

Each transaction removes at most 100 tokens and their newly orphaned, eligible
authorizations. Existing orphaned authorizations are handled first in batches
of 100. The last child and its eligible parent always commit together; separate
commits can be applied out of order by a parallel replication applier even when
the writer issues them sequentially. Each phase is capped at 10,000 batches per
sweep. A failure rolls back the current batch; earlier batches stay committed,
and repeating the command is safe. A concurrent change that violates a foreign
key or concurrency check fails the batch, with the success file left unchanged.
Keep foreign key checks enabled. External scheduling requires one owner; the
integrated mode below coordinates replicas through the database.

## Integrated scheduling and Management

The normal Identity executable hosts `OpenIddictPruningWorker`; no second release
directory or maintenance daemon is needed. The worker checks the shared schedule
every 30 seconds when `TokenPruning:RunInWebHost=true`. The migration seeds a
**disabled** policy (30 retention days, 360-minute interval), so installing the
release does not overlap an existing timer. The database is authoritative for
retention/interval/enabled state in this mode; file `RetentionDays` is CLI-only.

In Management → Settings → Token maintenance (`/management/settings/token-maintenance`):

- Read the policy, pending request and latest 30 executions with
  `identity.maintenance.read`.
- Save enabled state, retention (1–3650 days) and interval (5–10080 minutes), or
  request a run, with `identity.maintenance.manage`. Existing MFA and object access
  policies apply. Grant these capabilities through the normal operator mapping.
- Save/request operations are audited atomically with the configuration change.
  A stale revision requires a reload. HTTP only records a request: deletion runs
  in the worker, with a default 30-minute deadline.

The same service is exposed under the configured Management API prefix at
`api/maintenance/tokens` (GET/PUT) and `api/maintenance/tokens/runs` (POST; 202).
PUT accepts `revision`, `enabled`, `retentionDays`, `intervalMinutes`; POST accepts
`revision`. Repeated pending requests coalesce. A request made during a sweep is
preserved for a subsequent sweep. Configuration changes take effect on the next
sweep; disabling also prevents subsequent batches of an active sweep.

### Coordination and recovery

`tokenmaintenance` is the singleton schedule/lease. `tokenmaintenanceruns` stores
run status and counts, without token contents or subjects. A claim commits before
work starts. Each bounded deletion transaction checks the run id, enabled state
and two-minute lease, renews it and updates the same revision row. This write is
in the transaction containing the deletes: local locking and Galera certification
can reject stale ownership rather than allowing an old owner to keep committing.
No server-local advisory lock is used. MariaDB supplies UTC for lease comparisons;
cluster clocks should be synchronized.

Counts commit with each batch, so interrupted runs retain confirmed progress.
An expired run is marked `interrupted` on takeover. Completion schedules from its
finish time; failures retry after five minutes. A successor cannot be overwritten
by the previous worker's completion. The command-line pruner in this release
refuses to run while database-managed maintenance is enabled, and also checks
that condition inside every batch. **Older binaries do not have this protection.**

The UI exposes recent history; the database keeps the full run-level history.
Monitor last successful finish and pending/expired runs externally; the old
file-based watchdog does not monitor this mode. For example, alert when an enabled
policy has no success beyond its interval plus the execution deadline and polling
allowance. A disabled policy is an intentional pause, not a success.

### Transition from the external timer

1. Apply [109-add-token-maintenance.sql](../migration/sql/109-add-token-maintenance.sql)
   after the preceding migrations, or apply the equivalent EF migration. It adds
   two tables and a disabled singleton; it does not change protocol rows.
2. Install the normal Identity release on every participating instance, initially
   keeping `RunInWebHost=false` and the database policy disabled.
3. Disable the old pruning and watchdog timers/CronJobs and wait for their current
   invocation to finish. Verify there are no old maintenance binaries running.
   Remove any override pointing to a separately pinned maintenance release.
4. Set `RunInWebHost=true` and restart the normal Identity instances sequentially.
   Enable the database policy through Management, request one run and verify its
   finish, counts and cluster health. Install monitoring for the database history.

Rollback: disable the policy, disable workers and wait for active batches to stop
before restoring a single external scheduler. Leave the additive tables intact.
Keep the replication-applier mitigation until separately validated; this feature
does not change database replication settings.

Tests cover SQLite, isolated MariaDB 10.4.34 and two Galera writers. The Galera
rehearsal runs 20 contested claims plus lease-expiry takeover and stale-owner
rejection (`IDENTITY_TEST_GALERA_CONNECTIONS`, pipe-separated connection strings).
This exercises replicated coordination, not a network-partition/load campaign.
No production cutover is implied by this document.

## Legacy external scheduling

node-c is the single owner of the schedule for the multimaster replicated
database. Install `helpers/sufficit-identity-pruning-api.conf` as
`/etc/systemd/system/sufficit-identity.service.d/token-pruning.conf` on **every**
server and restart each API one at a time. Only then enable, on node-c, the four
`helpers/sufficit-identity-pruning{,-watchdog}.{service,timer}` units. Do not
enable those timers on node-a/node-b. Do not use GET_LOCK as a lock between
replicas: that lock belongs to the MariaDB instance, not to the replicated set.

The schedule runs at 00/06/12/18 UTC, with up to five minutes of spread and
recovery after a restart. systemd does not overlap the same unit. Cooperative
deadline of 30 min, external limit of 35 min and 30 s to shut down. The command
also holds a file lock in the state directory; that is not a distributed lock
across machines.

`/var/lib/sufficit-identity-maintenance/token-pruning.json` records the UTC
timestamp and the counts **only after both stages succeed**, including zero
deletions. The write uses atomic replacement; failures keep the last success.
The watchdog runs hourly, with no database connection and no access to its
secrets. A missing, corrupt or older-than-14 h file emits `TokenPruningOverdue`
at Warning level and exits with code 1, leaving the unit failed. The next healthy
run returns 0. Maximum delay until the alert is roughly 15 h.

```sh
systemctl start sufficit-identity-pruning.service
systemctl start sufficit-identity-pruning-watchdog.service
journalctl -u sufficit-identity-pruning -u sufficit-identity-pruning-watchdog
systemctl list-timers 'sufficit-identity-pruning*'
```

Local logs do not detect node-c going down entirely: host availability needs
external monitoring. To move the schedule, disable the old timers, wait for or
stop the running execution, copy the state, and only then enable the new owner.
Do not re-enable the API worker during that handover.

## Kubernetes

Use the same Server image with the `--prune-tokens` / `--check-token-pruning`
arguments. The `helpers/kubernetes/token-pruning.yaml` example has one pruning
CronJob and one checking CronJob. There is **one owner per data set**, even with
several clusters. Disable the node-c timers before enabling the CronJob and keep
`Sufficit__Identity__TokenPruning__RunInWebHost=false` on every API Deployment.

The image and the Secret/PVC names are environment parameters; the example starts
suspended. The PVC must persist between Jobs and allow access from both CronJobs
(RWX or a compatible provisioner). The file is only the operational record, not
global coordination. `concurrencyPolicy: Forbid` applies per CronJob and does not
provide exactly-once execution; the operation stays idempotent. It is also
possible to alert externally on the CronJob's `lastSuccessfulTime`, which covers
an executor failure. Do not create a second schedule for the same database.

Reference: [Kubernetes CronJobs](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/).
