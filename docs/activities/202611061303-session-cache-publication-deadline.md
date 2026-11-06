# Activity — Bound delayed ticket-cache publication

Date: 2026-11-06. Partial F4.2/F4.3 evidence; the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md) remains open.

## Delivered

Sign-in, renewal and cache-miss reads capture an absolute publication deadline
before persistence. Cache writes use this deadline capped by ticket expiry.
A delayed publication cannot start a fresh relative lifetime. Publication is
skipped if the deadline has already elapsed before calling the cache.
Serialization, cache keys and database schema remain compatible.

The expiry regression also exposed an implicit local timezone conversion when
comparing the database UTC DateTime against DateTimeOffset. The comparison now
uses UTC explicitly. The lifecycle comment now describes conditional renewal.

## Evidence

Two ticket-store instances use real SQLite persistence, shared Data Protection
and a controlled shared cache. Task gates order database completion, revocation,
clock advancement and delayed cache publication without timing sleeps.

Before correction: **5 failed, 1 passed**: four delayed renewal/read cases
(2 and 6 seconds of delay with a 5-second window) plus database ticket expiry
on this non-UTC host. Failed invalidation was already bounded and passed.

After correction:
`rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore
-p:SufficitUseLocalSui=false --filter
'FullyQualifiedName~SessionTicketCacheRaceTests|FullyQualifiedName~OidcUserSessionRepositoryTests|FullyQualifiedName~SessionTicketCancellationTests|FullyQualifiedName~ServerSideSessionsTests|FullyQualifiedName~InteractiveSignInServiceTests|FullyQualifiedName~SessionValidity'
--nologo --verbosity quiet`: **48 passed, zero warnings**.

Coverage includes stale access inside the original window, rejection at its
deadline, expiry before a late write, failed invalidation without extension on
hits, ticket expiration, renewal ownership, login and cancellation.

MarkdownCoverageTests: **8 passed, zero warnings**. `git diff --check`: clean.
All three execution checkpoints completed.

## Limits and delivery

This is bounded staleness, not atomic revocation. In-flight requests can finish,
and stale cache entries inside the original window may be returned. Provider
absolute-expiration enforcement and synchronized clocks are required; these
tests do not simulate Redis/network failover or a production cluster.
Older writers retain relative TTL behavior during a rolling update. See the
[architecture contract](../architecture/ARCHITECTURE-SESSION-VALIDITY.md).

No deployment, schema migration or production identity mutation performed.
Delivery commit title: `Bound delayed session cache publication by absolute deadline`.
