# Centralized token pruning

Server is the only executable; the STS provides the pruning operation. The
`--prune-tokens` command composes the database and OpenIddict only — no HTTP, no
provisioning, no migrations, no other workers. Valid tokens stay protected by
OpenIddict's own rules. Retention: 30 days. Tokens are handled before orphaned
authorizations; a failure can leave partial work, and repeating it is safe.

## Current production

Castrum is the single owner of the schedule for the multimaster replicated
database. Install `helpers/sufficit-identity-pruning-api.conf` as
`/etc/systemd/system/sufficit-identity.service.d/token-pruning.conf` on **every**
server and restart each API one at a time. Only then enable, on Castrum, the four
`helpers/sufficit-identity-pruning{,-watchdog}.{service,timer}` units. Do not
enable those timers on Eveo/Apoint. Do not use GET_LOCK as a lock between
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

Local logs do not detect Castrum going down entirely: host availability needs
external monitoring. To move the schedule, disable the old timers, wait for or
stop the running execution, copy the state, and only then enable the new owner.
Do not re-enable the API worker during that handover.

## Kubernetes

Use the same Server image with the `--prune-tokens` / `--check-token-pruning`
arguments. The `helpers/kubernetes/token-pruning.yaml` example has one pruning
CronJob and one checking CronJob. There is **one owner per data set**, even with
several clusters. Disable the Castrum timers before enabling the CronJob and keep
`Sufficit__Identity__TokenPruning__RunInWebHost=false` on every API Deployment.

The image and the Secret/PVC names are environment parameters; the example starts
suspended. The PVC must persist between Jobs and allow access from both CronJobs
(RWX or a compatible provisioner). The file is only the operational record, not
global coordination. `concurrencyPolicy: Forbid` applies per CronJob and does not
provide exactly-once execution; the operation stays idempotent. It is also
possible to alert externally on the CronJob's `lastSuccessfulTime`, which covers
an executor failure. Do not create a second schedule for the same database.

Reference: [Kubernetes CronJobs](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/).
