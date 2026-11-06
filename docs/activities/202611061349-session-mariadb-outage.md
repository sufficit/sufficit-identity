# Activity — MariaDB session outage and recovery

Date: 2026-11-06. Partial F4.2/F4.3 evidence in the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Delivered rehearsal

Added an opt-in test that creates an owned MariaDB Docker container, current EF
schema and a loopback-only stable published port. No external connection string,
production database or existing container is accepted. The test stops/restarts
only its uniquely named container and removes it with its anonymous volumes.
Connection pooling is disabled and no retry policy is configured.

Before outage the test verifies conditional renewal and selected-row bulk delete
on the real provider. During outage it checks warm-cache retrieval, failures for
create/renew/revoke and cold reads, absence of an uncommitted creation in cache,
and preservation of the cache after a failed durable revoke. After restart,
the original row persists, the uncommitted session is absent, and a new revoke
succeeds in both stores.

The initial assertion expected a bare MySqlException; Pomelo wraps transient
errors in InvalidOperationException. The assertion now checks the connector
root cause. This was test-contract adjustment, not a production-code failure.

## Environment and validation

Local image: `mariadb:10.11`, image label version **10.11.19**, ID
`sha256:d769e37960821dfdcf096954f6e7ac89f747e116c1bba98e48edd265dfc7deae`.
Cache for this slice is DistributedMemoryCache; the Redis tests run separately.

Standalone:
`SUFFICIT_TEST_MARIADB_DOCKER=1 rtk dotnet test
src/tests/Sufficit.Identity.Tests.csproj --no-restore
-p:SufficitUseLocalSui=false --filter FullyQualifiedName~SessionTicketMariaDbOutageTests
--nologo --verbosity quiet`: **1 passed, zero warnings**.

Combined session command uses both `SUFFICIT_TEST_MARIADB_DOCKER=1` and
`SUFFICIT_TEST_REDIS_EXECUTABLE=/tmp/identity-redis-rehearsal/redis-server`,
`--no-build --no-restore` and filter:
`FullyQualifiedName~SessionTicketMariaDbOutageTests|FullyQualifiedName~SessionTicketRedisIntegrationTests|FullyQualifiedName~SessionTicketCacheRaceTests|FullyQualifiedName~OidcUserSessionRepositoryTests|FullyQualifiedName~SessionTicketCancellationTests|FullyQualifiedName~ServerSideSessionsTests|FullyQualifiedName~InteractiveSignInServiceTests|FullyQualifiedName~SessionValidity`.

Combined result: **54 passed, zero warnings**, including MariaDB and both Redis cases.

MarkdownCoverageTests: **8 passed, zero warnings**. `git diff --check`: clean.
All three execution checkpoints completed; no rehearsal containers remain.

## Limits and delivery

No product-code change was needed. This covers a single-node database outage,
not combined Redis/database failure, Galera failover, migration rollback or
production retry policies/HTTP behavior. Those remain distinct work.
See the [architecture](../architecture/ARCHITECTURE-SESSION-VALIDITY.md).
No deployment, production sessions or external databases were changed.
Delivery commit title: `Exercise session persistence through MariaDB outage and recovery`.
