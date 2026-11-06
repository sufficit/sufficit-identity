# Activity — Real Redis outage and session recovery

Date: 2026-11-06. Partial F4.2/F4.3 coverage in the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Delivered rehearsal

Added an opt-in integration test using a disposable, loopback-bound Redis
process with persistence disabled, two independent Redis-backed ticket stores
and a third fresh client after restart. Persistence uses a real SQLite database.
The test owns and terminates only its child process and cleans its temporary
directory. Without SUFFICIT_TEST_REDIS_EXECUTABLE it is explicitly skipped.

Assertions verify a cache key through the actual second Redis client before
outage, so database fallback cannot hide a bad cache setup. After stopping Redis,
reads fall back to storage, renewal commits, and revocation removes the durable
row despite unavailable invalidation. After restart, a fresh client verifies
cache health, rejects the revoked session, and accepts a fresh sign-in.
Late renewal cannot republish the removed session.

## Execution

The first local executable was incompatible: its ELF interpreter required
/lib/ld-musl-x86_64.so.1, absent on this host. No product failure was inferred.
Extracted the glibc binary from the already available redis:7 image into
/tmp/identity-redis-rehearsal/redis-server; the temporary extraction container
was removed. The runnable server reports **Redis 7.4.12**. No installed service
was changed or production endpoint contacted.

Command:
`SUFFICIT_TEST_REDIS_EXECUTABLE=/tmp/identity-redis-rehearsal/redis-server
rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-build --no-restore
--filter 'FullyQualifiedName~SessionTicketRedisIntegrationTests|FullyQualifiedName~SessionTicketCacheRaceTests|FullyQualifiedName~OidcUserSessionRepositoryTests|FullyQualifiedName~SessionTicketCancellationTests|FullyQualifiedName~ServerSideSessionsTests|FullyQualifiedName~InteractiveSignInServiceTests|FullyQualifiedName~SessionValidity'
--nologo --verbosity quiet`.

Result: **52 passed, zero warnings**, including the real Redis rehearsal.
The test assembly was built with `-p:SufficitUseLocalSui=false`.
Standalone Redis rehearsal also passed.

MarkdownCoverageTests: **8 passed, zero warnings**. `git diff --check`: clean.
All three execution checkpoints completed. Disposable test directories were
removed; only the extracted reusable binary remains under /tmp.

## Limits and delivery

This validates a standalone Redis outage and empty-cache restart, not HA
failover, persisted stale cache, original-client reconnection timing, clock skew
or MariaDB outage. Those remain pending. No production deployment was performed.
The [architecture](../architecture/ARCHITECTURE-SESSION-VALIDITY.md) documents
the opt-in invocation and scope.
Delivery commit title: `Exercise session fallback and revocation through real Redis outage`.
