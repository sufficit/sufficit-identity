# Concurrent canonical migrations

Date: 2026-11-06 (America/Sao_Paulo).
Parent: [runtime architecture plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md), F5.2.

## Implementation

`MariaDbConcurrentMigrationTests` creates an owned disposable MariaDB 10.11
container. Independent AppDbContexts/connections invoke the real host advisory-lock
wrapper and the real EF migrator against the same initially empty database.
A command interceptor pauses the owner's first model DDL while it holds the lock;
the competitor invocation starts before that gate is released. No readiness sleeps
or elapsed-time assertions are used. Timeouts bound failed test execution.

Both invocations complete and close their connections. The owner executes model
DDL, while the competitor executes none (history-table bootstrap is excluded from
that count). Both contexts observe every canonical migration in order, there are
no pending migrations, and the expected token-maintenance seed row exists once.

The interceptor observes/gates commands; it does not replace the migrator or SQL
execution. No production code, database, configuration or deployment was changed.

## Validation

`SUFFICIT_TEST_MARIADB_DOCKER=1 rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj
--no-restore -p:SufficitUseLocalSui=false
--filter 'FullyQualifiedName~MariaDbConcurrentMigrationTests|FullyQualifiedName~MariaDbMigrationRecoveryTests|FullyQualifiedName~MigrationAdvisoryLockTests|FullyQualifiedName~SchemaProvisioningGuardTests|FullyQualifiedName~TestSynchronizationContractTests'
--nologo --verbosity quiet` — **16 passed**.

## Limits and delivery

This establishes overlapping invocations within one test process, not two complete
server processes, distributed startup configuration or Galera behavior. Old-binary
rollback and recovery of production-like data remain open. MarkdownCoverageTests: **8 passed**; `git diff --check`: clean. This record
accompanies the implementation commit on main; commit/push is not deployment.
