# Real migration SQL failure and recovery

Date: 2026-11-06 (America/Sao_Paulo).
Parent: [runtime architecture plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md), F5.2.
Durable guidance: [database migration assets](../migration/README.md#failure-recovery-under-the-dedicated-migrator).

## Implementation and observations

`MariaDbMigrationRecoveryTests` starts an owned disposable MariaDB 10.11 container,
applies the canonical EF migrations through the penultimate migration, then
creates a fixture table conflicting with the second table in `AddTokenMaintenance`.
The real host wrapper and real EF migrator execute SQL; no migration service is mocked.

- The SQL error is MariaDB 1050 (table exists), and the host connection is closed.
- Previously applied history stays unchanged and the final migration remains pending.
- The first table created by the failed migration remains empty: DDL was partially applied.
- Blind retry fails with 1050 and still does not advance history.
- Explicitly removing the two fixture-owned empty tables permits a fresh context
  to finish the migration. History matches every canonical migration, the seed
  row exists, and another host-wrapper invocation preserves history and the row.

No production code or schema was modified. Cleanup is deliberately limited to
the disposable fixture and is not a generic recovery algorithm.

## Validation

`SUFFICIT_TEST_MARIADB_DOCKER=1 rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj
--no-restore -p:SufficitUseLocalSui=false
--filter 'FullyQualifiedName~MariaDbMigrationRecoveryTests|FullyQualifiedName~MigrationAdvisoryLockTests|FullyQualifiedName~SchemaProvisioningGuardTests|FullyQualifiedName~TestSynchronizationContractTests'
--nologo --verbosity quiet` — **15 passed**.

## Remaining scope

Concurrent complete migrator startup, repair with production-like data and
rollback to an old binary remain open. This rehearsal does not establish Galera
behavior or automatic SQL rollback. No production access or deployment occurred.

## Delivery

MarkdownCoverageTests: **8 passed**. `git diff --check`: clean.
This record accompanies the main-branch implementation commit. Commit/push does
not imply deployment.
