# Activity — Production application clock observation

Date: 2026-11-06. Read-only F4 evidence from the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Collection

Queried the three previously recorded Identity application hosts over verified
SSH. No clock, daemon, application, firewall or configuration was modified.
Three UTC samples per host used `date -u +%s.%N`. The observer recorded realtime
before/after each SSH process and monotonic elapsed time. Sampling began at
2026-11-06 21:44:05.710 UTC and ended around 21:44:07.201 UTC.

The first diagnostic attempt timed out on a synchronization-status command;
that attempt's samples were not used. A second collection saved independent
per-host results and bounded each remote diagnostic command with `timeout 4`.

## Observations

All three reported `systemd-detect-virt=lxc`, `NTPSynchronized=yes`, `NTP=no` and
`Timezone=America/Sao_Paulo`. `chrony.service` and `chronyd.service` were not found;
`systemd-timesyncd.service` was loaded but inactive. `timesync-status` timed out
(exit 124) on each node. A synchronized kernel flag in these containers is not
proof of a functioning local NTP daemon or of the physical host's time source.

For a remote timestamp R observed between local timestamps B and A, the
conservative remote-minus-observer offset interval is [R-A, R-B]. The table uses
the shortest round-trip sample on each host, rounded outward to whole milliseconds.
It includes SSH setup/transport/scheduling uncertainty; it does not assume symmetric
network delays or estimate true UTC accuracy.

| Application host | Selected round trip | Offset interval relative to observer |
|---|---:|---:|
| eveo-apps.sufficit.com.br | 376.527 ms | [-7, +371] ms |
| castrum-apps.sufficit.com.br | 493.841 ms | [-11, +484] ms |
| apoint-apps.sufficit.com.br | 319.880 ms | [-7, +314] ms |

All intervals include zero. They do not establish sub-millisecond alignment.
Observer realtime elapsed and monotonic elapsed differed by at most 3.14
microseconds in these samples; this is a sanity check, not a drift guarantee.

The observer itself reported NTP enabled/synchronized with chrony, stratum 3,
normal leap status, last offset -0.000019564 seconds, RMS offset 0.000205249
seconds and system time 0.000319231 seconds slow of NTP. Root delay was
0.168823794 seconds and root dispersion 0.003552761 seconds. These are daemon
reports from the snapshot, not an independent measurement of absolute accuracy.

## Remaining evidence

Identify and query the actual physical time-source owners for these LXC nodes;
observe database/cache provider clocks; define an accepted skew budget and verify
it over time, including failover. This snapshot does not satisfy those gates or
prove production revocation timing under skew. Earlier controlled-clock tests
remain separate functional evidence. HA election and partition scenarios remain
open; no production fault injection was performed.

## Validation and delivery

- Nine remote UTC samples returned successfully; host virtualization and service
  state queries succeeded. Synchronization status command timeout is recorded above.
- Documentation-only change; Markdown coverage: 8 passed; diff whitespace check clean.
- Collection, interval analysis and delivery record complete. Commit/push
  verification is reported with the delivery result; six unrelated package-lock
  modifications are excluded.

No release or deployment is claimed.
