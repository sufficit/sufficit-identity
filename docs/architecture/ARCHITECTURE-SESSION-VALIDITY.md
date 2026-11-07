# Session validity: from polling to notification

Every cookie-authenticated request verifies that the session is still valid by
reading the user's security stamp. That is one primary-key lookup, but it
happens on every request of every signed-in user, and it is how a revocation
takes effect: `SecurityStampValidatorOptions.ValidationInterval` is zero, so
nothing is cached.

`ISessionValidityCache` (`src/core/Sessions/`) lets a request skip that read
while two things hold at once:

- the ticket records a verification (`.identity.verified_at`) newer than the
  last known invalidation of that user, and
- the entry is younger than `UserSessions:ValidityCacheSeconds`.

## Why it is off by default

The cache is only consulted while `IUserSecurityChangePublisher` reports a
**connected** channel. A node that cannot hear about a revocation performed on
another node keeps reading the stamp, because the database is the only thing
all three nodes share. With `ValidityCacheSeconds` at its default of `0` the
server behaves exactly as it always has.

The window is the blast radius of a lost notification: for at most that many
seconds, one node may still accept a session another node revoked. Pick it
deliberately — seconds, not minutes.

## What invalidates

- `OpenIddictIdentityUserSessionRevoker.RevokeAsync` — every path that revokes
  a subject's sessions (password change, administrative revocation, credential
  mutation) drops the local entry and publishes to the other nodes.
- `UserSecurityNatsBridge` (`src/server/`) — applies what the other nodes
  publish. Same shape as `TrustedProxyNatsBridge`: best-effort notification
  beside an authoritative database, with the subject and payload validated
  before use. A hostile message can only ever cause **one more** stamp read,
  never one less.

## What is not covered

A mutation that rotates the user row without going through the revoker — a
lockout or a claim edit — is seen at the next principal refresh
(`PrincipalRefreshIntervalSeconds`) or when the window expires, not
immediately. That is the deliberate trade, and it is why the window is short
and the feature opt-in.

## Configuration

```jsonc
"UserSessions": {
  "ValidityCacheSeconds": 15,          // 0 disables; clamped to 0..300
  "Nats": {
    "Enabled": true,
    "Url": "nats://127.0.0.1:4222",
    "Token": "…",                      // from the secret store, not here
    "Subject": null                    // defaults per environment name
  }
}
```

Covered by `SessionValidityCacheTests` (the rules of the cache) and
`SessionValidityCacheIntegrationTests` (the validator: no channel means no
skipping, an invalidation brings the read back at once).

## Ticket-store request cancellation

`OidcUserSessionTicketStore` implements the token and HttpContext overloads of
`ITicketStore`. Explicit tokens reach database context creation, EF operations
and distributed-cache calls. Context overloads link the supplied token with
`RequestAborted`; legacy overloads use the current accessor's request token when
available. Outside a request, legacy callers retain non-cancelable behavior.

Cache operations link cancellation with their own bounded timeout. Cache timeout
may fall back to the authoritative database; caller cancellation propagates as
`OperationCanceledException` instead of starting a fallback read. Cancellation is
not rollback: a completed database mutation remains committed if a subsequent
cache operation is canceled. Invalidation may therefore remain pending until the
existing cache TTL; this change does not make database/cache updates atomic.

`SessionTicketCancellationTests` exercises all four operations via the interface,
explicit/context cancellation, cache-read cancellation without fallback, and
cancellation during cache writes/removal after a real SQLite commit.

## Browser-session persistence boundary

`IOidcUserSessionRepository` is the internal STS contract for durable session
operations; `OidcUserSessionRepository` uses a short-lived factory-created EF
context per call. Its singleton registration never captures a scoped context.
The repository reads detached session snapshots, upserts protected bytes, deletes
rows, touches activity, lists subject metadata and returns the IDs needed for
cache invalidation after subject deletion. All operations accept cancellation.

`OidcUserSessionTicketStore` owns serialization/Data Protection, request metadata,
expiry checks, the activity interval and distributed-cache policy. It no longer
queries EF directly. Its protector purpose and cache-key format are unchanged.

A touch attaches the previously read snapshot and changes only activity; it does
not overwrite a concurrently renewed protected ticket or insert a removed row.
Renewal uses one conditional update matching session ID and subject, without an
insert fallback. If revocation already deleted the row, renewal cannot recreate
it and the ticket store does not cache the rejected renewal. Creation/device
metadata remains unchanged. Fresh sign-in retains its separate upsert path.

Database mutation and cache writes are still not atomic: a renewal accepted
before revocation can write its cache entry after invalidation. The
bulk deletion now restricts its target to the selected internal row IDs (see
below). Cross-store atomicity remains outside this contract.

## Ticket-cache publication deadline

Each sign-in, renewal and cache-miss database read fixes an absolute cache
deadline before accessing persistence. Publication uses that deadline, capped
by the ticket expiry, rather than a new relative TTL at write time. Cache hits
do not extend it. A slow operation skips publication if the deadline has
already elapsed; a write delayed inside the cache provider still carries the
original absolute deadline.

This bounds a late publication after revocation to the original cache window
when the provider honors absolute expiration and replica clocks agree. It
does not guarantee immediate revocation: a stale entry inside that window
and an already running request may still return the ticket. Database/cache
operations are not atomic. Real-provider failover and clock-skew evidence
remain part of F4.2/F4.3.

Database session expiry compares UTC DateTime values explicitly; an
unspecified DateTime kind from persistence must not invoke local timezone
conversion. Ticket/cache serialization, protector purpose and keys are unchanged.
During rolling updates, older writers still use relative expiration until all
instances have been replaced and their previous entries have expired.

See the [delayed-publication activity](../activities/202611061303-session-cache-publication-deadline.md)
for deterministic two-store regression coverage and its limits.

## Bulk revocation snapshot

Subject-session revocation selects internal row IDs together with cache session
keys, then deletes only those rows while retaining the subject and exclusion
predicates. A concurrent insertion is outside that snapshot. A row deleted and
recreated with the same session key has a new internal ID and is not deleted by
the earlier operation.

Every row deleted by this operation therefore has a selected invalidation key.
Concurrent deletion can make the removed count smaller than the selected key
count; invalidating the full selected key set remains safe. For a recreated
key this can evict a fresh cache entry, which the new durable row can repopulate.
An empty snapshot returns zero without a later broad delete.

This operation revokes a snapshot of browser-session records, not future
sign-ins. Credential revocation still relies on the higher-level security-stamp
rotation. Cache invalidation can fail or race with late publication; the
publication-deadline contract above still applies. See the
[bulk snapshot activity](../activities/202611061318-bulk-session-revocation-snapshot.md).

## Disposable Redis integration rehearsal

`SessionTicketRedisIntegrationTests` is opt-in via
`SUFFICIT_TEST_REDIS_EXECUTABLE`, an absolute path to a runnable local Redis
server binary. It starts its own loopback-only process with automatic persistence disabled,
uses independent Redis cache clients and real SQLite persistence, stops only
that owned process, and restarts it to verify post-revocation recovery.
Temporary server directories and processes are disposed even after failures.
Without the variable the test is explicitly skipped.

Example:

```sh
SUFFICIT_TEST_REDIS_EXECUTABLE=/path/to/redis-server dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore -p:SufficitUseLocalSui=false --filter FullyQualifiedName~SessionTicketRedisIntegrationTests
```

The test verifies shared cache publication, database fallback during a real
cache outage, durable renewal/revocation, rejection after a clean cache restart
and fresh sign-in after recovery. A second scenario explicitly saves an RDB
snapshot before outage, verifies the identical protected ticket is restored
after revocation, and checks rejection at the original cache deadline despite
repeated reads. This demonstrates the remaining stale-access window rather
than promising immediate revocation. It is not a Sentinel/Cluster failover,
clock-skew or MariaDB outage rehearsal.
See the [dated results](../activities/202611061339-session-redis-outage-rehearsal.md).

The [persisted-cache activity](../activities/202611061343-persisted-session-cache-recovery.md)
records the RDB restoration test. The local fixture retains only its own
temporary snapshot between restarts and removes it on disposal.

## Disposable MariaDB outage rehearsal

`SessionTicketMariaDbOutageTests` uses an owned Docker container from
`mariadb:10.11`, publishing only on loopback with a stable port across restart.
It never takes an external connection string. Opt in with:

```sh
SUFFICIT_TEST_MARIADB_DOCKER=1 dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore -p:SufficitUseLocalSui=false --filter FullyQualifiedName~SessionTicketMariaDbOutageTests
```

The fixture creates the current EF schema, disables connection pooling/retries
to isolate connection failures, then stops/restarts only its own container.
A warm ticket cache can still return a ticket while the database is unavailable.
A cold read fails; create/renew/revoke errors propagate without reporting a
successful mutation. Failed creation does not publish a cache ticket, and a
failed revocation does not delete its cache entry as though the durable delete
had committed. On recovery the original row remains and can be revoked.

The test also exercises conditional renewal and selected-row bulk deletion on
the real MariaDB provider. Memory cache isolates the database failure; Redis
rehearsals remain separate. It does not prove combined outage, Galera failover,
retry-policy or production HTTP behavior. It explicitly skips without opt-in,
and removes its container and anonymous volumes on disposal. See the
[dated results](../activities/202611061349-session-mariadb-outage.md).

## Combined database and cache outage

The opt-in combined theory in `SessionTicketMariaDbOutageTests` requires both
`SUFFICIT_TEST_MARIADB_DOCKER=1` and `SUFFICIT_TEST_REDIS_EXECUTABLE`.
It reuses only owned disposable infrastructure and exercises both recovery
orders. While both stores are down, read/create/renew/revoke fail with the
database connection error; no successful revocation is reported.

If MariaDB recovers first, reads fall back to it and revocation commits while
Redis remains offline. If Redis recovers first with an empty cache, reads still
fail until MariaDB returns. A failed revocation leaves its durable row intact;
the caller must retry after recovery. No uncommitted sign-in appears in storage
or cache. The scenarios then verify successful revocation after recovery.

Those two combined recovery-order cases restart Redis empty. They are not
distributed HA, clock-skew or production HTTP tests. [Execution evidence](../activities/202611061355-combined-session-outage.md).

A further combined case restores a pre-revocation RDB snapshot while MariaDB is
unavailable, after confirming that durable revocation committed. The restored
ticket is accepted only within its original cache deadline. Failed renewal and
repeated reads do not extend that deadline; after expiry reads surface database
unavailability. When MariaDB returns, renewal cannot recreate the revoked row,
and a fresh sign-in works. This records bounded stale acceptance, not immediate
revocation across snapshot restoration.
[Restored-cache/database-outage evidence](../activities/202611061910-restored-cache-database-outage.md).

## Replica clock offsets

Ticket expiration is evaluated against each reader's TimeProvider, both on cache
hits and database fallback. A fast reader can reject a ticket early and delete
its durable row during lazy expiry. A slow reader can accept an expired ticket
from persistence until its own UTC clock reaches that ticket's absolute expiry.
The stored expiry is not extended; this is a disagreement about the current time.

That differs from revocation after database deletion: once the shared provider
expires the cache entry, a reader clock offset cannot recreate the missing row.
The controlled-cache tests verify these separate cases with independent reader
and cache clocks, without sleeps or changing host clocks.

Those tests do not emulate the production Redis provider's conversion between
absolute deadlines, local wall time and Redis TTL. They therefore do not prove
writer/provider clock independence or a production skew bound. Reliable host
time remains necessary; an arbitrary clock-skew tolerance would also change the
session-expiry policy and is not introduced here.
[Clock-offset evidence](../activities/202611061432-session-replica-clock-offsets.md).

## Acknowledged Redis replica promotion

An additional opt-in local Redis case starts a primary and replica, waits for
the replica's synchronization event, writes a ticket and verifies replication.
After revoking the durable row and cache entry, it sends a barrier SET followed
by WAIT on the same dedicated primary connection. A reply of one acknowledged
replica proves that the replication stream includes the preceding deletion.

The test then stops the owned primary, explicitly promotes the replica with
REPLICAOF NO ONE and connects a fresh client to that endpoint. Neither retrieval
nor late renewal restores the revoked session; a fresh sign-in can write/read
the promoted cache. Both processes and temporary directories are disposed.

This verifies acknowledged data preservation through explicit promotion, not
automatic Sentinel/Cluster election, client endpoint discovery, split-brain,
unacknowledged-write loss or Galera failover.
[Promotion evidence](../activities/202611061437-session-redis-replica-promotion.md).

## Replica that misses invalidation

The paired promotion scenario deliberately detaches a synchronized replica
before revocation, using REPLICAOF NO ONE. The original primary then deletes the
durable row and its own cache entry, while the detached replica retains the exact
protected ticket bytes. After primary loss a fresh client targets that replica.

Inside the original TTL the old ticket may still be returned. Renewal consults
the absent durable row and cannot recreate it or replace the cached bytes.
After the original deadline, the ticket is rejected; a new sign-in still works.
The real-Redis expiry wait is explicitly justified in the synchronization guard.

This deterministic detachment models a missing invalidation, not automatic
election, packet-loss injection or a partition-healing protocol. Production
revocation is still best effort within the configured cache window.
[Execution evidence](../activities/202611061440-session-replica-missed-invalidation.md).

## Notification-channel transitions

A warm per-user security-stamp cache does not bypass verification while the
notification publisher reports disconnected. A stamp rotated on another node is
then rejected by an authoritative user-store read, even inside the cache window.

Reconnection does not prove that missed notifications have been replayed. A node
that received no requests while disconnected can still trust its old stamp
verification inside the original window after reconnecting. Cache hits do not
refresh that deadline: at the original window boundary it reads the user row and
rejects the old stamp. Another node that received the invalidation rejects it
without waiting for that boundary.

Tests use independent in-memory stamp caches, the real validator/user store and
a controlled cache clock. Publisher state is simulated; this is not evidence of
NATS delivery, packet-loss recovery, Redis failover or production clock bounds.
[Transition evidence](../activities/202611061745-session-notification-transitions.md).

## Real NATS broker recovery

The opt-in `SessionValidityCacheIntegrationTests.Nats.cs` case exercises two real
user-security bridges against a dedicated local NATS container. It observes
remote invalidation before outage, stamp-store fallback while disconnected,
reconnection with a missed notification bounded by the original cache window,
and delivery of a new invalidation after recovery. Publisher acceptance alone
is not treated as proof of remote application: the test waits for cache invalidation.

Use a fixed loopback host port across container restarts. This local broker
restart does not establish partition behavior or clustered broker failover.
[Real broker evidence and invocation requirements](../activities/202611061809-session-nats-recovery.md).

## Isolated notification connection

A three-bridge local NATS regression now cuts only one node's TCP relay while
the other two remain connected. The unaffected receiver applies the invalidation;
the isolated node bypasses its warm cache while disconnected. Once restored,
missed invalidation remains bounded by the original cache deadline, and new
notifications arrive again. The relay closes sockets and refuses new connections;
it does not emulate silent packet loss or one-way network partitions.
[Isolated-connection evidence](../activities/202611061818-session-isolated-notification-path.md).

## Silent notification loss while Connected

A local relay can discard the broker-to-client bytes of a revocation while the
bridge still reports Connected. The new opt-in scenario confirms those bytes
were discarded, verifies unaffected peer delivery and proves that cached stamp
acceptance still ends at the original revalidation deadline. Recovery uses fresh
sockets before testing new notification delivery, because partial byte loss can
break NATS framing. This models silent notification loss, not kernel packet
retransmission or production heartbeat timings.
[Silent-loss evidence](../activities/202611061823-session-silent-notification-loss.md).

## Optional Galera causal reads

`Sufficit:Identity:Database:RequireGaleraCausalReads` defaults to `false` for
compatibility with standalone/non-Galera deployments. Enabling it registers the
production connection interceptor on the HTTP host's shared AppDbContext factory
and the maintenance-only token-pruning context. It disables `wsrep_dirty_reads` only in that application session and adds bit 1
to its existing `wsrep_sync_wait`, preserving the other bits. Dirty reads would
otherwise bypass the causal check. Both
synchronous and asynchronous opens run setup, including pooled logical opens.
It requires session wsrep enabled and dirty reads disabled; setup errors and
cancellation propagate rather than allowing an unchecked query. Setup has a
10-second command timeout. Subsequent query waits retain the database/provider
and command timeout settings; this option does not promise a recovery deadline.

Example configuration for a verified Galera deployment:

```json
{
  "Sufficit": {
    "Identity": {
      "Database": { "RequireGaleraCausalReads": true }
    }
  }
}
```

This changes only application sessions, never GLOBAL variables. It is not
applied to raw SQL connections outside those EF registrations. EF-based health
checks and the database watchdog using the shared context also run setup.
Activation must verify selected-node compatibility and read latency, then observe
connection/setup failures and readiness. A rollback to `false` restores inherited
session behavior on new application connections and also restores its stale-read
risk. Restart/recreate the application scope when changing this startup option.

The barrier protects database reads; a cache hit bypasses it. Existing stale
cache entries, notifications, TTL bounds and race handling remain separate.
No production activation is implied by merging the option. The
[compatibility gate](../activities/202611062028-galera-session-compatibility.md)
verified this session-local preparation on all four live SQL candidates from
Eveo using the application credentials; existing service pools were not modified.
[Implementation and validation](../activities/202611062018-galera-causal-read-policy.md).

The [2026-11-06 gradual activation](../activities/202611062102-galera-causal-read-activation.md)
records enabling the option on all three production application hosts, after
compatibility checks from each site and sequential restart/readiness gates.
It does not establish behavior under a production partition or failover.

### Owned weighted-quorum rehearsal

Run `python3 scripts/check-galera-causal-reads.py --weighted-quorum` to create
four disposable Galera nodes with explicit voting weights 2/1/1/2. No database
endpoint parameter or published SQL port is used in this mode. The launcher
pauses only containers it created, and removes containers/volumes/network on exit.

The rehearsal first loses weight 2 from a weight-6 component and checks that the
remaining primary component can revoke a row. It then loses another weight-2
node from the accepted weight-4 component: the remaining half must become
non-primary. Protected reads must fail with a non-primary rejection or causal
wait timeout, while dirty reads demonstrate the legacy availability behavior.
After resuming the nodes, every member must converge with the revoked row absent.
A resumed process can expose a stale membership snapshot before causal reads
recover. The fixture therefore polls only recognized availability errors for up
to 60 seconds per node and records them; a successful stale answer fails
immediately. This is a test convergence gate, not an application retry policy.

This is a SQL/provider rehearsal with paused processes, not HTTP/ticket-cache
integration, a bidirectional network partition or production HAProxy routing.
The explicit fourth weight is a model parameter, not a verified production
Google-node setting. It does not replace the outstanding production HA gates.
