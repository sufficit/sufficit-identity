# Activity — Redis replica placement

Read-only observation on 2026-11-06 around 21:48 America/Sao_Paulo, under the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

Using the service secret in memory on Eveo, queried CLUSTER NODES, CLUSTER INFO
and INFO replication on every discovered endpoint. The client-side AllowAdmin
switch was needed for INFO; no server permissions or configuration changed.
No keys, customer records or credentials were printed. Temporary probe files
were removed by the remote cleanup trap.

| Primary | Slots | Replica | Link |
|---|---|---|---|
| apoint-apps 172.19.1.113:6379 | 0–5460 | eveo-apps 172.19.2.101:6380 | up |
| eveo-apps 172.19.2.101:6379 | 5461–10922 | castrum-apps 172.19.3.101:6380 | up |
| castrum-apps 172.19.3.101:6379 | 10923–16383 | apoint-apps 172.19.1.113:6380 | up |

Every endpoint reported cluster_state ok, with six connected nodes, three
primaries and one replica each. Replica mappings were checked against INFO's
master_host/master_port and CLUSTER NODES parent IDs. Replicas share the already
inventoried application hosts and their hypervisor clock dependencies.

This closes current replica-placement inventory. It does not prove acknowledged
write durability, election under site loss, network partition recovery, or a
continuous clock/error budget. No production fault was injected.
