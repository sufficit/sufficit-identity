# Populated migration failure/recovery

Date: 2026-11-06 (America/Sao_Paulo).
Parent: [runtime architecture plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md), F5.2.

## Changes and evidence

Extended `MariaDbMigrationRecoveryTests` with fictional persisted data before the
final canonical migration: user with an actual ASP.NET Identity password hash,
security/concurrency stamps and lockout metadata; generic role and membership;
user claim; Data Protection storage record; OIDC session with opaque binary bytes.

Ordered no-tracking snapshots compare every mapped field in these six entity
sets after the initial SQL failure, failed blind retry, explicit repair/retry
and subsequent no-op invocation. The original password still verifies against
the recovered user. Repair deletes only the two empty tables owned by the
failed fixture migration; it leaves the populated tables intact.

Key XML and session bytes are deliberately synthetic. This checks storage
preservation, not cryptographic key loading or an authenticated browser session.

## Validation

`SUFFICIT_TEST_MARIADB_DOCKER=1 rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj
--no-restore -p:SufficitUseLocalSui=false
--filter 'FullyQualifiedName~MariaDbMigrationRecoveryTests|FullyQualifiedName~MariaDbMigratorProcessTests|FullyQualifiedName~MariaDbConcurrentMigrationTests|FullyQualifiedName~MigrationAdvisoryLockTests|FullyQualifiedName~SchemaProvisioningGuardTests|FullyQualifiedName~TestSynchronizationContractTests'
--nologo --verbosity quiet` — **17 passed**.

## Rollback artifact review and limits

The existing local release archive `20261106-206fbb9.tar.gz` reports revision
`206fbb94d331c3ff37c50ddcb591593fdca8d954`. The `AddTokenMaintenance` introduction
commit `96fccc0` is its ancestor, and its migrations have no diff from the current
revision. It cannot establish compatibility with a binary predating that schema
change. No old-binary rollback result is claimed.

A historical build crossing the migration boundary and broader data/volume
coverage remain pending. No production data was read or modified; no deploy.

## Delivery

MarkdownCoverageTests: **8 passed**. `git diff --check`: clean.
This activity accompanies the implementation commit on main; commit/push does
not constitute deployment.
