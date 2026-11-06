# Migration advisory-lock recovery

Date: 2026-11-06 (America/Sao_Paulo).
Parent: [runtime architecture plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md), F5.2.

## Changes and evidence

Added `MigrationAdvisoryLockTests` using the existing owned disposable MariaDB
10.11 container fixture. Made that fixture internal so the lock rehearsal reuses
its opt-in lifecycle and cleanup. No production code or schema changed.

The real host wrapper acquires the real MariaDB advisory lock. A controlled EF
`IMigrator` callback checks that a second connection cannot acquire the same lock,
then throws an injected exception. The exact exception propagates and the host
connection is closed; the competitor can acquire and release the lock afterward.
A fresh context retries successfully, with the same exclusion and cleanup checks.

Validation: `SUFFICIT_TEST_MARIADB_DOCKER=1 rtk dotnet test
src/tests/Sufficit.Identity.Tests.csproj --no-restore -p:SufficitUseLocalSui=false
--filter 'FullyQualifiedName~MigrationAdvisoryLockTests|FullyQualifiedName~SchemaProvisioningGuardTests|FullyQualifiedName~TestSynchronizationContractTests'
--nologo --verbosity quiet` — **14 passed**, no skipped tests.

## Limits

This verifies lock orchestration with real connections, not EF migration SQL
execution or transactional DDL rollback. Two concurrent full migrator processes,
real migration failure/retry, old-binary compatibility and Galera remain open in
F5.2. No production resources were accessed and no deploy was performed.

## Delivery

MarkdownCoverageTests: **8 passed**. `git diff --check`: clean.
Changes are delivered together in the main-branch commit containing this record;
commit/push do not imply deployment.
