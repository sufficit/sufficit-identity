# Activity — Reject session renewal after revocation

Date: 2026-11-06. Bounded F4.2 correction; remaining work stays in the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Change and evidence

The ticket store previously renewed via upsert. A real SQLite/cache regression
created a ticket, revoked it, and renewed the retained ticket. Before the fix,
the test failed because a new database row appeared.

Renewal now performs a single conditional SQL update matching session ID and
subject. Missing rows are never inserted; mismatched subjects cannot take over
the session. The cache is written only after an accepted renewal. Creation and
device metadata are retained, cancellation propagates, and fresh sign-in keeps
its existing separate persistence path. No schema migration is needed.

## Validation

Command: `rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore
-p:SufficitUseLocalSui=false --filter
'FullyQualifiedName~OidcUserSessionRepositoryTests|FullyQualifiedName~SessionTicketCancellationTests|FullyQualifiedName~ServerSideSessionsTests|FullyQualifiedName~InteractiveSignInServiceTests|FullyQualifiedName~SessionValidity'
--nologo --verbosity quiet`.

Result: **42 passed, zero warnings**. This includes the formerly failing
revocation regression, ownership rejection, renewal metadata preservation,
interactive sign-in, cancellation and cache validity coverage.

MarkdownCoverageTests: **8 passed, zero warnings**. `git diff --check`: clean.
All three execution checkpoints completed.

## Limits and delivery

An accepted database renewal followed by revocation and then a late cache write
remains a separate race. Bulk-revocation ID selection and combined outage
coverage also remain open. See the
[session architecture](../architecture/ARCHITECTURE-SESSION-VALIDITY.md).
No production deployment or session mutation was performed.
Delivery commit title: `Prevent late renewal from recreating revoked sessions`.
