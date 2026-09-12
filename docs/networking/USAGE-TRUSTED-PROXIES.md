# Trusted proxies

The `/management/settings/trusted-proxies` page and the `GET/PUT /api/trusted-proxies` API use the same administrative service. Reading requires `identity.trusted-proxies.read`; writing requires `identity.trusted-proxies.manage` plus the Management MFA policy. The HTTP prefix follows the module configuration.

## Merging and application

`Sufficit:Identity:TrustedProxies` remains the file baseline. The database holds additional networks, normalized and de-duplicated, in the singleton row of `trustedproxyconfiguration`. Removing a network from the database never removes an identical entry from the file. The page shows both sources.

`Sufficit:Identity:ForwardLimit` defaults to 2. The optional database value takes precedence; the "Use the appsettings hop limit" option removes that override. Accepted limits are 1 to 10. IPv4/IPv6 addresses and CIDR networks are accepted; universal `/0` networks, DNS names and scoped addresses are rejected. CIDRs with host bits set are normalized to the base network.

The host loads the snapshot before accepting traffic, after migrations. An initial failure prevents startup. The worker queries only the revision every 30 seconds by default, with ±10% jitter; the full content is read only at startup or when the revision changed. A confirmation without a change renews freshness and keeps the same snapshot instance.

The administrative write and the refresh share coordination: after the commit, the confirmed data is applied directly in memory, without another SELECT. A reload started before the write cannot overwrite it. The notification is sent only after the commit. Files are loaded when the process starts and require a restart when changed.

The middleware captures an immutable options instance per snapshot version. It does not modify lists used by concurrent requests and does not query the database while forwarding. Every hop must be trusted, and processing stops at the first untrusted intermediary.

## Audit and concurrency

The configuration and the audit event are written in the same SaveChanges/transaction. The `beforejson`/`afterjson` fields contain only the networks and the limit configured in the database, visible under "View change" in the audit log. Actor, date, capability and correlation follow the existing contract. The revision sent by the page prevents overwriting a concurrent change; on conflict, reload before saving.

## Publication

Apply `20260910131719_AddTrustedProxyConfiguration` once to the database before swapping binaries. Alternatively, the SQL script `docs/migration/sql/097-add-trusted-proxies.sql` applies the same delta once; do not run both without checking the history. The canonical empty schema was updated as well. The migration creates the initial row and adds optional fields to the audit table, preserving existing data.

In the chain client → proxy → Nginx → Identity, the header must reach Identity as `CLIENT_IP, PROXY_IP`. The edge proxy must replace forwarded headers supplied by untrusted clients; merely trusting the proxy IP does not authenticate a header it copied without validating. Do not raise the hop count without verifying that behavior. The application test covers the limit and the stop at untrusted peers; it neither modifies nor replaces the external proxy configuration.

## NATS synchronization and recovery

Implemented according to the [runtime snapshot architecture](../architecture/ARCHITECTURE-RUNTIME-SNAPSHOTS.md). NATS is optional and disabled by default. Its unavailability does not prevent saving the configuration; the API reports `NotificationPending` when the last local commit could not send the notice. That field is not confirmation that other nodes applied the change. `NotificationsConnected` reports the transport connection.

Every instance subscribes without a queue group. The notice carries the envelope version, event/process identifier, domain, scope, revision and timestamp; it never carries trusted networks. The subscription defaults to `sufficit.<lower-case environment>.identity.trusted-proxies.changed.v1` (for example, `sufficit.production.identity.trusted-proxies.changed.v1`). All nodes must reach the same NATS domain and subject, with restricted credentials and permissions. The connection accepts a `nats://` or `tls://` URL; use TLS as the network and operational policy require.

On connect or reconnect, the subscription is confirmed before a database check is requested. The bridge keeps retrying even when the initial connection fails. Notices are coalesced in a queue of capacity 1, so a burst cannot build an unbounded queue. There is a 100 ms debounce before the query triggered by a notice. A notice received during an update is kept for the next check.

If the announced revision does not appear yet, additional attempts run after roughly 1, 2, 4, 8, 15 and 30 seconds, with ±10% jitter. After that window, periodic reconciliation continues. GUIDs are opaque: late notices do not order snapshots, and an old revision that was already superseded cannot block the process indefinitely. The applied content and revision are always the ones returned together by the local database.

Convergence is eventual and depends on replication: a recent read from a replica does not prove it has seen every commit from other servers. There is no outbox and no per-node application acknowledgement. A crash between commit and publication, or a lost notice, is recovered on connection or reconciliation. External SQL that changes the configuration must also change `revision`; keeping the revision prevents the change from being detected.

## Host options

Under `Sufficit:Identity:ProxySynchronization`:

| Option | Default | Behavior |
| --- | --- | --- |
| `ReconcileSeconds` | 30 | Scalar check interval, 1 to 3600 seconds, with ±10% jitter. |
| `MaxStaleSeconds` | 120 | Maximum time without a successful database confirmation; must be at least twice the interval and at most 86400. |
| `RefreshTimeoutSeconds` | 10 | Timeout for each worker attempt, between 1 and 60 seconds. |
| `StaleSnapshotMode` | `FileBaseline` | What forwarding does once `MaxStaleSeconds` passes; see [Freshness and diagnostics](#freshness-and-diagnostics). |
| `Nats:Enabled` | false | Enables notices; does not change the database's authority. |
| `Nats:Url` | nats://127.0.0.1:4222 | Endpoint; configure the real address reachable by the nodes. |
| `Nats:Token` | absent | Optional credential; supply it through the service's protected environment. |
| `Nats:Subject` | derived from the environment | Optional override, without wildcards. |

Example variable names for the protected environment: `Sufficit__Identity__ProxySynchronization__Nats__Enabled`, `Sufficit__Identity__ProxySynchronization__Nats__Url` and `Sufficit__Identity__ProxySynchronization__Nats__Token`. Do not version credential values. No secret is required for reconciliation without a broker.

To adopt 300 seconds, also declare a compatible tolerance (at least 600 seconds) and assess the trust-removal delay. The default stays at 30 seconds so that window is not widened automatically. This interval is not an absolute propagation guarantee: it includes replication, jitter and the duration of attempts.

## Freshness and diagnostics

Failures keep the last valid snapshot. Once `MaxStaleSeconds` passes without a successful database confirmation, the database-managed list is no longer trusted, and `StaleSnapshotMode` decides what happens next:

| Mode | Forwarding while stale | Readiness (`trusted-proxy-snapshot`) |
| --- | --- | --- |
| `FileBaseline` (default) | Trusts only `Sufficit:Identity:TrustedProxies` from configuration. Database additions are ignored until the database confirms the list again. Traffic keeps flowing. | Degraded (HTTP 200) |
| `Reject` | Refuses traffic with `503`. Liveness (`/health`) is still answered. | Unhealthy (HTTP 503) |

Neither mode disables validation or trusts arbitrary sources. The default trusts fewer peers, never more: a proxy an operator just removed from the database is not trusted while the database is unreachable. It also keeps replicas that share one database from all refusing traffic, and all failing readiness, at the same moment — which is how a two-minute database outage used to take every node offline, liveness included.

Plan for one consequence: while degraded, requests that arrive through a proxy listed only in the database lose the forwarded client address and scheme. List the production edge proxies in the file baseline so a database outage does not strip that information.

The worker keeps retrying, and the next confirmation restores the full list automatically. State transitions are logged once each — Warning when degrading to the file baseline, Error when refusing traffic, Information on recovery — rather than on every request.

The administrative API includes `LastConfirmedAtUtc`, `Generation`, `IsFresh`, `NotificationsEnabled`, `NotificationsConnected` and `NotificationPending`. `Generation` identifies local swaps; it is not an ordered global version. On `TrustedProxySnapshotStore`, `State` reports the forwarding state (`Fresh`, `StaleFileBaseline`, `StaleRejected`) and `Diagnostics` exposes scalar/content read counters, last change and consecutive failures for inspection and tests. Logs record connection, disconnection, failures, exhausted recovery and reloads; a successful check is Debug. Broker URL and token are never logged.

## Local tests with a dedicated broker

`TrustedProxySynchronizationTests` covers scalar SQL, commit without re-reading, rollback, concurrency, freshness, invalid input and recovery, as well as degradation to the file baseline, refusal with liveness still answered in `Reject` mode, and readiness status per mode. `TrustedProxyNatsIntegrationTests` uses three independent stores, an authenticated broker, an initial failure, delayed replica visibility and reconnection after a lost notice.

The NATS test is opt-in: provide `IDENTITY_TEST_NATS_URL` and `IDENTITY_TEST_NATS_CONTAINER`, whose name must start with `identity-proxy-sync-tests-`. The broker is exclusively for tests, with token `identity-test-token`; the test stops and starts that container. Map a FIXED local port, because random ports can change on restart. Never point these variables at production. Without them, the test is reported as skipped.

This implementation requires no migration beyond the existing trusted proxy table. Enabling NATS and publishing this version to production are separate operational steps.
