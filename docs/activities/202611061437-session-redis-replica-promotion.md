# Activity — Acknowledged Redis replica promotion

Date: 2026-11-06. Partial F4.2/F4.3 evidence in the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Delivered

The owned local Redis fixture can now start a replica and await the replication
completion log event, without sleep-based synchronization. A bounded command
helper supports fixed fixture commands with simple/integer replies.

The test stores a ticket with real SQLite persistence and real Redis caching,
then confirms replication with a SET/WAIT barrier on one connection. Following
revocation, another barrier returns one acknowledged replica. Since the barrier
write follows the completed deletion in the primary stream, that offset includes
the cache invalidation. This avoids incorrectly issuing WAIT on a fresh client
without an associated preceding write.

After killing only the owned primary, the test explicitly promotes the replica,
connects a fresh cache client, verifies the revoked entry stays absent and cannot
be renewed, then verifies a fresh sign-in. Replica startup and promotion are
local test operations only.

## Build prerequisite

The initial build failed on the pre-existing TimeInText.razor line combining
implicit range expressions and a component tag. Explicit Razor expression
parentheses resolve parsing without changing the displayed text or markup.
No visual redesign was made. The subsequent build completed without warnings.

## Validation

Standalone promotion case with Redis 7.4.12: **1 passed, zero warnings**.

Combined invocation enables both SUFFICIT_TEST_REDIS_EXECUTABLE and
SUFFICIT_TEST_MARIADB_DOCKER, then runs
`rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-build --no-restore
--filter 'FullyQualifiedName~SessionTicket|FullyQualifiedName~TestSynchronizationContractTests|FullyQualifiedName~OidcUserSessionRepositoryTests|FullyQualifiedName~ServerSideSessionsTests|FullyQualifiedName~InteractiveSignInServiceTests|FullyQualifiedName~SessionValidity'
--nologo --verbosity quiet`.
Assembly built with `-p:SufficitUseLocalSui=false`.

Combined result: **66 passed, zero warnings**, including the real Redis and
MariaDB rehearsals, controlled clock cases and synchronization contracts.

MarkdownCoverageTests: **8 passed, zero warnings**. `git diff --check`: clean.
All three execution checkpoints completed; owned Redis directories removed.

## Limits and delivery

This is manual promotion after acknowledged replication, not automatic
Sentinel/Cluster election, client discovery, split-brain, unacknowledged writes
or Galera failover. Those remain separate pending evidence.
[Architecture contract](../architecture/ARCHITECTURE-SESSION-VALIDITY.md).
No production failover or deployment was performed.
Delivery commit title: `Verify session revocation across acknowledged Redis promotion`.
