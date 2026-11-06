# Activity — Production database/cache topology

Date: 2026-11-06. Read-only F4 evidence from the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Application configuration evidence

Inspected the active service PID/cwd, the selected production and machine JSON
files, and the process's relevant secret overrides on each application node.
Only allowlisted endpoint fields and nonsecret options left the host. No complete
connection string, password, token or secret file was printed or copied locally.

All three active release directories report revision
`56d046306578c95be8cfa8b022dd78e3dd7ea2ce`, `ClusteredBehindTrustedProxy`, shared
cache required, and the `DefaultConnection` database key. The three machine
files are respectively `appsettings.eveo-apps.json`, `appsettings.castrum-apps.json`
and `appsettings.apoint-apps.json`, layered over `appsettings.Production.json`.

| Application | Database endpoint | Database |
|---|---|---|
| eveo-apps | eveo-proxy-local:26493 | identity |
| castrum-apps | castrum-proxy-local:26493 | identity |
| apoint-apps | apoint-proxy-local:26493 | identity |

All configure the same Redis seed list: `172.19.1.113:6379`,
`172.19.2.101:6379`, `172.19.3.101:6379`. This is configuration evidence,
not a trace of every application connection or a guarantee of effective options
under arbitrary additional command-line overrides.

## Redis runtime evidence

Matched those addresses to the live application nodes and queried only
`INFO replication` and `CLUSTER INFO` via local authenticated read-only clients.
Credentials stayed in the remote process environment. All three redis-server
services are active and reported:

- role master, one connected replica per queried primary;
- cluster_state ok;
- 16384 slots assigned and healthy, zero failed slots;
- six known nodes, cluster size three.

| Primary address | Host |
|---|---|
| 172.19.1.113:6379 | apoint-apps |
| 172.19.2.101:6379 | eveo-apps |
| 172.19.3.101:6379 | castrum-apps |

Thus the automatic cache-HA rehearsal must cover Redis Cluster slot discovery
and replica election; a Sentinel-only test would not match this deployment.
The primary processes share the already observed application LXC hosts. Replica
placement and their clock dependencies are not established by these fields.

## Database routing evidence

Read the current HAProxy configuration on all three proxy hosts, emitting only
listener names, bind endpoints and backend server names/addresses. The MySQL
listener binds 26493. Each has its local data node, the other two data sites,
`google-data.sufficit.com.br:3306`, and a repeated local backup entry. The eveo
configuration uses `castrum-data-vpn` for its Castrum target; the others use the
public names for remote targets.

This identifies configured routing candidates, not current backend health,
selected connections, Galera quorum or SQL server time. The fourth configured
site must be included or explicitly excluded with current evidence in a database
failover/clock inventory; three application hosts alone are insufficient.

## Validation, remaining scope and delivery

No production configuration, session or key was changed. Successful live Redis
reads narrow the required F4 topology, but do not prove automatic failover,
partition recovery, replication durability or a sustained clock budget.
Database selected-backend health/time and Redis replica placement remain open.

1. Application metadata and live Redis/configured database topology collected.
2. Reconciled with earlier clock evidence; Redis Cluster HA identified as the next
   matching cache rehearsal, while Galera and provider-clock gates remain pending.
3. Markdown coverage: 8 passed; diff whitespace check clean. Commit/push
   verification is reported with the delivery result; six unrelated lockfiles excluded.

No deployment is claimed.
