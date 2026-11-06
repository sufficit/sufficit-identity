# Activity — Session ticket cancellation propagation

Date: 2026-11-06. Delivered the cancellation portion of F4.1; repository
extraction and combined outage/staleness scenarios remain in the runtime plan.

## Changes

Implemented all ITicketStore cancellation/context overloads. Legacy overloads
forward the accessor's RequestAborted when available; context overloads link both
request abort and the explicit token. Propagated cancellation to context creation,
EF queries/writes/deletes and cache reads/writes/removal. Cache-operation deadlines
remain independent: caller cancellation is not swallowed as a cache timeout and
does not initiate database fallback. Updated adjacent comments to describe the
actual cache/activity/failure behavior.

The [session architecture](../architecture/ARCHITECTURE-SESSION-VALIDITY.md)
records the contract and post-commit limit. Cancellation does not undo a database
mutation already committed, and does not make cache invalidation atomic.

## Validation

- Nine initial regressions failed before the change: four explicit-token paths,
  four request-abort paths, and cache-read cancellation without database fallback.
- Added three real SQLite cases for cancellation during cache mutation after
  store/renew/remove commits; the persisted database outcome remains intact.
- `rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore
  -p:SufficitUseLocalSui=false --filter
  'FullyQualifiedName~SessionTicketCancellationTests|FullyQualifiedName~ServerSideSessionsTests|FullyQualifiedName~SessionValidityCacheIntegrationTests'
  --nologo --verbosity quiet`: **20 passed, zero warnings**. Existing timeout
  fallback and interactive-session behavior remain covered.
- `MarkdownCoverageTests`: **8 passed, zero warnings**. `git diff --check`: clean.
- All three cancellation execution checkpoints completed.

Delivery commit title: `Propagate cancellation through session ticket storage`.
No production deployment, schema change or session revocation was performed.
