# Activity — Persisted Redis session recovery

Date: 2026-11-06. Further F4.2/F4.3 evidence in the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Scenario and result

Extended the opt-in local Redis rehearsal with an explicit synchronous SAVE
before outage. The test confirms the RDB file exists, kills only its owned
Redis process, revokes the session in SQLite while Redis is unavailable, and
restarts the same server directory.

The restored cache bytes must exactly match the saved protected ticket, so an
empty cache or an unrelated replacement cannot satisfy the test. A fresh
ticket-store instance can read that stale ticket while the database row is
absent. Repeated cache reads must not extend its original 15-second lifetime;
the test requires rejection at the original publication deadline with 250 ms
of scheduling allowance. It then verifies that a late renewal does not
recreate the cache entry and a fresh sign-in still succeeds.

This behavior already meets the bounded-cache contract. No production code,
schema or configuration change was required. The test explicitly demonstrates
that cache persistence can restore a revoked ticket inside the remaining TTL;
it does not assert immediate revocation.

## Validation

Redis **7.4.12**, using the disposable executable extracted in the
[earlier rehearsal](202611061339-session-redis-outage-rehearsal.md).
Standalone empty/persisted recovery tests: **2 passed, zero warnings**.

Combined command:
`SUFFICIT_TEST_REDIS_EXECUTABLE=/tmp/identity-redis-rehearsal/redis-server
rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore
-p:SufficitUseLocalSui=false --filter
'FullyQualifiedName~SessionTicketRedisIntegrationTests|FullyQualifiedName~SessionTicketCacheRaceTests|FullyQualifiedName~OidcUserSessionRepositoryTests|FullyQualifiedName~SessionTicketCancellationTests|FullyQualifiedName~ServerSideSessionsTests|FullyQualifiedName~InteractiveSignInServiceTests|FullyQualifiedName~SessionValidity'
--nologo --verbosity quiet`.

Combined result: **53 passed, zero warnings**, including both real Redis cases.

MarkdownCoverageTests: **8 passed, zero warnings**. `git diff --check`: clean.
All three execution checkpoints completed; test snapshot directories removed.

## Limits and delivery

This is an RDB restart with SQLite persistence and independent Redis clients,
not Sentinel/Cluster promotion, clock skew, MariaDB outage or a production
cluster. Those remain pending. Snapshot and server processes are owned and
cleaned by the test. Without the explicit executable variable both integration
cases are skipped, not silently counted as passed.
See the [architecture](../architecture/ARCHITECTURE-SESSION-VALIDITY.md).
No deployment or production session changes.
Delivery commit title: `Verify revoked-session expiry after Redis snapshot recovery`.
