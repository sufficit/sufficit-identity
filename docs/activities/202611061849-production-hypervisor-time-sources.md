# Activity — Production hypervisor time sources

Date: 2026-11-06. Read-only continuation of the
[application clock observation](202611061844-production-application-clock-observation.md)
under the [runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Current placement and synchronization

Queries at approximately 21:49:40 UTC used verified SSH and bounded read-only
commands: `hostname`, UTC `date`, `pct list`, `timedatectl show`, `chronyc tracking`
and `chronyc -n sources`. All completed successfully. No daemon restart,
configuration modification, clock adjustment or workload migration occurred.

Current placement was verified rather than inferred from historical VMIDs:

| Application container | Current VMID | Proxmox host |
|---|---:|---|
| eveo-apps.sufficit.com.br | 2101 | eveo-cloud |
| castrum-apps.sufficit.com.br | 3101 | castrum-cloud |
| apoint-apps.sufficit.com.br | 1101 | apoint-cloud |

All three hypervisors reported `NTP=yes`, `NTPSynchronized=yes`, chrony leap
status Normal, and a selected source (`^*`) with reach register `377`.
The following values are daemon-reported observations, not independent UTC
accuracy measurements:

| Host | Stratum | System time relative to NTP | Last offset | RMS offset | Root delay | Root dispersion |
|---|---:|---:|---:|---:|---:|---:|
| eveo-cloud | 2 | 0.022163 ms slow | -0.033212 ms | 0.118776 ms | 40.824383 ms | 0.929767 ms |
| castrum-cloud | 3 | 0.098459 ms fast | +0.332274 ms | 0.305615 ms | 8.641211 ms | 0.699561 ms |
| apoint-cloud | 2 | 0.179899 ms fast | +0.248068 ms | 0.115216 ms | 1.770012 ms | 0.324121 ms |

Selected sources and reference times:

- eveo-cloud: `2001:129c:7002:2::146`, source stratum 1; reference 21:36:21 UTC;
  reported update interval 2053.3 seconds.
- castrum-cloud: `a.ntp.br` / `200.160.0.8`, source stratum 2; reference
  21:44:55 UTC; update interval 517.7 seconds.
- apoint-cloud: `gps.nu.ntp.br` / `200.160.7.193`, source stratum 1; reference
  21:46:58 UTC; update interval 1029.9 seconds.

## Interpretation and remaining gates

These observations resolve the previously unverified current placement and
hypervisor time-source status for the three application LXCs. They are consistent
with the containers reporting a synchronized kernel despite inactive local time
daemons. They do not establish sub-millisecond absolute accuracy: root delay and
dispersion remain material, and there was no independent reference instrument.

Still identify the actual database/cache providers used by the deployment and
verify their time-source relationship, define an accepted skew budget and observe
it over time and failover. HA election, production network behavior and Galera
failover remain open. Do not turn this snapshot into a sustained synchronization
or session-revocation SLA claim.

## Validation and delivery

1. Current placement and source diagnostics collected successfully on all hosts.
2. Results reconciled with the earlier LXC observation; limitations retained.
3. Markdown coverage: 8 passed; diff whitespace check clean. Commit/push
   verification is reported with the delivery result. Six unrelated lockfiles
   are excluded. No release or deployment is claimed.
