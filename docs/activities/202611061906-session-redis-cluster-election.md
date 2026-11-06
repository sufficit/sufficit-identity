# Activity — Local Redis Cluster automatic election

Date: 2026-11-06. F4 evidence for the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md), following the
[production topology observation](202611061855-production-provider-topology.md).

## Scope and method

The opt-in `SessionTicketRedisIntegrationTests.Cluster.cs` scenario owns six
loopback Redis processes: three slot-owning primaries and one replica each.
Client and cluster-bus ports are temporary, with explicit bus ports in CLUSTER
MEET. Replication/election readiness follows server log events, not fixed sleeps.
The test stops only the primary process it created, then awaits automatic
election and the existing StackExchange.Redis client's topology events. It does
not promote a replica manually, recreate the client or call ConfigureAsync.
The client's default periodic topology check remains unchanged; discovery has a
90-second test guard. This guard is not a production recovery-time guarantee.

The real distributed-cache adapter, ticket store and repository use a disposable
SQLite database. Three sessions share a Redis hash tag. A separate SET followed
by WAIT 1 on the owning primary acknowledges the replication stream after the
revoked ticket's deletion. After primary loss and election the test verifies:

- the existing client routes the revoked key to the promoted replica;
- its cache entry and durable row remain absent, including after attempted renewal;
- an unrevoked session remains cached and retrievable;
- a new session can be stored, cached and retrieved after recovery.

The 180-second cache lifetime exceeds the discovery guard so preservation checks
cannot pass merely because the revoked key expired during discovery.

## Validation

The final opt-in Cluster scenario passed in 63.9 seconds (including setup and
cleanup), with Redis 7.4.12 from `SUFFICIT_TEST_REDIS_EXECUTABLE`.
The four existing opt-in real Redis scenarios passed. The ordinary Release suite
passed 2,140 tests with 16 opt-in tests skipped. Compilation used warnings as
errors. All eight Markdown coverage checks and four synchronization-contract
checks passed. `git diff --check` passed; no owned Redis process remained.

Initial fixture runs exposed three harness issues: omitted dynamic bus port in
MEET prevented cluster formation; a 45-second discovery guard was shorter than
the normal client topology refresh; a 60-second cache lifetime expired the control
session during discovery. These were corrected without changing product code or
forcing client reconfiguration. Timeouts were test cancellation guards, not user
cancellations, and the owned Redis processes were cleaned up.

## Remaining limits

This covers one acknowledged revocation and primary loss in a disposable local
Redis 7.4.12 cluster. It does not establish production failover timing, behavior
under unacknowledged deletion, multi-primary loss, kernel packet loss, host clock
skew, Galera failover or simultaneous database failure. Earlier local tests cover
some stale-replica/TTL paths separately; they do not substitute for those combined
or production gates. No production configuration, data or deployment changed.

All implementation and validation checkpoints completed. This activity is
delivered with its test and plan update in the same main-branch commit; the six
pre-existing package lockfile changes are excluded. No runtime deploy is involved.
