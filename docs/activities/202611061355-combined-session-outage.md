# Activity — Combined MariaDB and Redis session outage

Date: 2026-11-06. Continuation after the authorized
[production publication](202611061353-production-session-publication.md).
Partial F4.2/F4.3 coverage in the [runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Delivered

Added two opt-in integration cases sharing the existing owned MariaDB and Redis
fixtures. Redis helper visibility is internal to the test assembly so the same
lifecycle and cleanup are reused, without production-code changes.

Both services stop after a durable/cached sign-in. Read/create/renew/revoke must
fail with the database connection cause; a failed revoke cannot be reported as
committed. The scenarios cover:

- Database first: durable reads succeed through cache fallback, revoke commits
  while Redis is still unavailable, and recovery does not restore the removed row.
- Redis first: the new healthy empty cache cannot authenticate without the
  offline database. After MariaDB returns, the original row remains because the
  earlier revoke failed; a new revoke then succeeds.

Both check absence of the uncommitted sign-in in persistence/cache. Infrastructure
is restricted to an owned loopback Redis child and owned MariaDB Docker container.

## Validation

Standalone combined theory: **2 passed, zero warnings** against local MariaDB
10.11.19 and Redis 7.4.12.

Combined suite invocation:
`SUFFICIT_TEST_MARIADB_DOCKER=1
SUFFICIT_TEST_REDIS_EXECUTABLE=/tmp/identity-redis-rehearsal/redis-server
rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-build --no-restore
--filter 'FullyQualifiedName~SessionTicketMariaDbOutageTests|FullyQualifiedName~SessionTicketRedisIntegrationTests|FullyQualifiedName~SessionTicketCacheRaceTests|FullyQualifiedName~OidcUserSessionRepositoryTests|FullyQualifiedName~SessionTicketCancellationTests|FullyQualifiedName~ServerSideSessionsTests|FullyQualifiedName~InteractiveSignInServiceTests|FullyQualifiedName~SessionValidity'
--nologo --verbosity quiet`.

The assembly was restored/built in package mode with SufficitUseLocalSui=false
after production packaging, which used local SUI as required by DEPLOY.md.

Combined result: **56 passed, zero warnings**, including both recovery orders.

MarkdownCoverageTests: **8 passed, zero warnings**. `git diff --check`: clean.
All four deployment/evaluation/continuation checkpoints completed. Test containers
and Redis snapshot directories were removed.

## Limits and delivery

No product-code change was required. Combined scenarios restart Redis empty;
persisted stale-cache coverage is a separate test. HA promotion, clock skew,
retry configuration and authenticated production flows remain distinct.
No additional deployment is needed for these test/docs-only changes.
[Architecture contract](../architecture/ARCHITECTURE-SESSION-VALIDITY.md).
Delivery commit title: `Record production rollout and combined session outage recovery`.
