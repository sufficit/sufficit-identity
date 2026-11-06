# Dedicated migrator process rehearsal

Date: 2026-11-06 (America/Sao_Paulo).
Parent: [runtime architecture plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md), F5.2.

## Implementation

`MariaDbMigratorProcessTests` launches two real `Sufficit.Identity.Server.dll`
processes with `--migrate-only` before waiting for either to finish. Both target
the same owned disposable MariaDB 10.11 database through the environment secret
boundary and an explicit database-name allow-list.

Each child receives a cleared environment with only the fixture settings and PATH.
An isolated temporary content root prevents loading repository/deployment JSON.
A temporary self-signed signing/encryption certificate avoids modifying the user's
certificate store. Development is intentional, with the explicit
`AllowDevelopmentOnPublicHost` fixture override required by certificate topology
validation. UI surfaces are None, since the embedded management UI otherwise
requires its disabled API. These are test-only settings, not deployment guidance.

Both children exit zero, log dedicated migration completion, and do not log HTTP
listener startup. An independent context verifies the full canonical migration
history and no pending migrations. Timeout cleanup stops only owned children;
certificate/content-root and container cleanup run even on failure.

## Validation

The initial fixture correctly hit the Development certificate guard, then the
management UI/API composition guard. Adjusting only explicit test configuration
allowed the full host path to run; no production guards were weakened.

`SUFFICIT_TEST_MARIADB_DOCKER=1 rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj
--no-build --no-restore
--filter 'FullyQualifiedName~MariaDbMigratorProcessTests|FullyQualifiedName~MariaDbConcurrentMigrationTests|FullyQualifiedName~MariaDbMigrationRecoveryTests|FullyQualifiedName~MigrationAdvisoryLockTests|FullyQualifiedName~SchemaProvisioningGuardTests|FullyQualifiedName~TestSynchronizationContractTests'
--nologo --verbosity quiet` — **17 passed**. The test assembly was built with
`-p:SufficitUseLocalSui=false` for the preceding successful focused process test.

## Limits

The two launches exercise independent operating-system processes; their exact
arrival order at the database is scheduler-dependent. The separate interceptor
rehearsal provides deterministic overlapping host-wrapper calls. This process
test does not claim Production-posture startup, Galera behavior, old-binary
rollback or recovery with production-like data. No production access/deploy.

## Delivery

MarkdownCoverageTests: **8 passed**. `git diff --check`: clean.
This record accompanies the implementation commit on main; commit/push does not
constitute deployment.
