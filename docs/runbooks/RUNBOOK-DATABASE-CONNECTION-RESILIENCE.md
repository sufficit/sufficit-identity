# Database connection resilience and monitoring

This runbook covers the failure mode in which the Identity process remains
alive but every request waits for a database connection. The runtime combines
bounded provider settings, in-process telemetry, readiness checks and a
watchdog that delegates recovery to the process supervisor.

## Effective safeguards

`Sufficit:Identity:Database:ConnectionPool` is applied to the MySQL/MariaDB
connection string before Pomelo configures `AppDbContext`:

| Setting | Default | Purpose |
| --- | ---: | --- |
| `MaximumSize` | 50 | Caps open connections per process/replica |
| `MinimumSize` | 0 | Avoids retaining unused connections |
| `ConnectionTimeoutSeconds` | 15 | Bounds connection and pool acquisition wait |
| `CommandTimeoutSeconds` | 30 | Bounds database command execution |
| `ConnectionLifetimeSeconds` | 180 | Recycles long-lived physical connections |
| `ConnectionIdleTimeoutSeconds` | 180 | Releases idle capacity |
| `ResetOnCheckout` | `true` | Resets session state before reuse |
| `ApplicationName` | `Sufficit.Identity` | Gives the pool a non-secret metrics label |

`MaximumSize` is a per-process limit. Before increasing it, keep this budget
true for the database server:

```text
(Identity replicas × MaximumSize)
+ other applications' maximum pools
+ administration/maintenance connections
+ safety margin
<= database max_connections
```

The versioned systemd unit uses `Restart=on-failure`, a 10-second restart
delay, a 15-second graceful stop window and `KillMode=mixed`. It permits up to
10 starts in 5 minutes, preventing a permanent restart storm.

## Watchdog behavior

`Sufficit:Identity:Database:Watchdog` defaults to:

- wait 60 seconds after startup;
- probe `AppDbContext` every 30 seconds;
- cancel each probe after 10 seconds;
- after three consecutive failures, set exit code `1` and stop the host;
- let systemd or the container orchestrator recreate the process and pools.

A successful probe resets the consecutive-failure counter. A transient outage
therefore affects readiness but does not immediately restart the process.

`GET /health` remains liveness-only. `GET /health/ready` includes the database.
Do not use readiness failures alone as a container restart trigger; the
watchdog owns the sustained-degradation decision and avoids a thundering herd.

## Management access and surfaces

The operator needs capability `identity.database.read`.

- Embedded UI: `/management/database`
- Management API: `GET /api/database/connections`

Both call the same `IDatabaseMonitoringService`; the UI does not access EF Core
or the provider directly. The response and UI never include connection
strings, credentials, SQL text or parameters.

The screen is event-driven. Connection, command, pool and watchdog changes are
published through the in-process telemetry stream; the embedded Blazor Server
UI sends the resulting render diffs over its existing SignalR connection
(WebSocket when available, with the framework transport fallback). Event bursts
are coalesced into a 100 ms window, so the database execution path never waits
for a UI consumer and no periodic telemetry query runs while the state is idle.
The operator can pause live rendering, request a manual snapshot and resume
without losing the current view. An interrupted internal stream reconnects with
bounded exponential backoff from 1 to 15 seconds.

The screen shows:

- provider pool usage, idle connections, maximum size, pending requests and
  pool-acquisition timeouts;
- watchdog state, last probe and latency;
- currently leased EF Core connections;
- provider physical/session ID when the driver exposes one;
- commands observed for that physical connection and for the current lease;
- active command count, last command time and duration.

Pool pressure is informational below 75%, warning at 75%, and critical at 90%.
Any pending request is critical. Any pool-acquisition timeout keeps the pool in
warning state for the lifetime of that process so the incident remains visible.

## Interpretation and limitations

- “Conexões locadas agora” means logical connections currently checked out by
  EF Core. A lease that opens and returns entirely inside the 100 ms event
  coalescing window may not persist as an individual row; aggregate command
  counters still advance to the latest observed value.
- Idle physical connections are available as aggregate provider metrics, not
  as an individually enumerable cross-provider list. This is an ADO.NET/provider
  boundary, not missing UI data.
- Per-connection command counts cover commands observed through the configured
  EF Core interceptors after process startup. Raw provider calls created outside
  that `AppDbContext` are not attributed to a connection row.
- A physical ID is optional. MySqlConnector exposes the server thread ID;
  providers without a safe public ID fall back to the runtime logical ID.
- Pool detail depends on the provider publishing OpenTelemetry database pool
  instruments. The generic connection list remains available without them.
- Every replica has its own in-process snapshot. In a multi-replica deployment,
  inspect each instance or export the aggregate metrics to the monitoring stack.

MySqlConnector's pool instruments and tags are documented in
[MySqlConnector metrics](https://mysqlconnector.net/diagnostics/metrics/).

## Production rollout

1. Calculate the connection budget across all replicas and other applications.
2. Keep the defaults or set explicit environment overrides in
   `/etc/sufficit/identity/hardening.env`.
3. Deploy through staging and controlled release activation.
4. Grant `identity.database.read` only to operators who need runtime telemetry.
5. Verify `/health`, `/health/ready` and `/management/database`.
6. Confirm pool name `Sufficit.Identity`, a finite maximum and zero pending
   requests/timeouts under ordinary load.
7. In a non-production environment, block database access long enough for three
   probes and confirm: `degraded` → process exit `1` → supervisor restart →
   `healthy` after database recovery.

Alert on sustained pool usage at 75% and 90%, any pending request, increases in
pool timeouts, failed commands or a watchdog transition to `degraded` or
`restarting`.

## Recovery and rollback

If the watchdog reacts incorrectly, set
`Sufficit__Identity__Database__Watchdog__Enabled=false` and restart the service;
pool bounds, timeouts, readiness and monitoring remain active. Do not raise the
pool maximum as an incident shortcut until server capacity and connection leaks
have been checked. Restore the watchdog after correcting the probe or database
dependency.
