# Activity — Bulk session revocation snapshot

Date: 2026-11-06. Partial F4.2 evidence; the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md) retains outage/failover work.

## Problem and contract

Bulk revocation previously selected cache keys, then independently deleted all
matching subject rows. A concurrent insertion could be deleted without its key
being invalidated. Deletion/recreation with the same session key could also
remove a newer row.

The repository now selects internal IDs and session keys together and restricts
the single delete to those IDs, retaining subject and exclusion predicates.
New sign-ins after selection are outside the revocation snapshot. An empty
snapshot returns zero. Concurrent deletions can reduce the affected count;
all selected cache keys are still invalidated safely.

This does not revoke future sign-ins or replace higher-level credential
security-stamp rotation. It does not make database/cache changes atomic.
No schema, ticket serialization or cache-key changes are required. The
[architecture](../architecture/ARCHITECTURE-SESSION-VALIDITY.md) records the contract.

## Validation

A database command interceptor injects a committed insertion, deletion or
same-key replacement immediately before the bulk DELETE, after selection.
It uses the real SQLite repository and resets before nested commands.

Before correction: **2 failed, 1 passed**. Insertion deleted two rows instead of
the selected one; replacement deleted the newer row instead of zero rows.
After correction all three scenarios pass, alongside subject isolation and
the excluded-session test.

Command: `rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore
-p:SufficitUseLocalSui=false --filter
'FullyQualifiedName~SessionTicketCacheRaceTests|FullyQualifiedName~OidcUserSessionRepositoryTests|FullyQualifiedName~SessionTicketCancellationTests|FullyQualifiedName~ServerSideSessionsTests|FullyQualifiedName~InteractiveSignInServiceTests|FullyQualifiedName~SessionValidity'
--nologo --verbosity quiet`: **51 passed, zero warnings**.

MarkdownCoverageTests: **8 passed, zero warnings**. `git diff --check`: clean.
All three execution checkpoints completed.

## Delivery and limitations

SQLite regressions exercise deterministic interleavings, not MariaDB contention
or a live cache cluster. Production outage/failover evidence remains pending.
No deployment or production session changes were made.
Delivery commit title: `Restrict bulk session revocation to selected rows`.
