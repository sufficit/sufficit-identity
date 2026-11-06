# Historical host on upgraded schema

Date: 2026-11-06 (America/Sao_Paulo).
Parent: [runtime architecture plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md), F5.2.

## Historical build

Built unchanged revision `4493f97a1057d03a8a47e041465208f13f992f93`, parent of
`96fccc05375d75d6d0127fe1a6421ceb58e2406b` (AddTokenMaintenance), in detached
worktree `/tmp/identity-rollback-4493f97`. Worktree status remained clean.

Commands: `dotnet restore src/server/Sufficit.Identity.Server.csproj --locked-mode
-p:SufficitUseLocalSui=false`, then `dotnet build` for the same project with
`--no-restore -p:SufficitUseLocalSui=false`. Both succeeded. Restore/build reported
six NU1902 warnings for the historical MySqlConnector 2.5.0 dependency. This
artifact is a local fixture, not a deployment candidate.

Server DLL SHA-256:
`37d6af62165de6350b50347a8a32c013b341db25d8dee32f534b218fa96f7e03`.
The source/dependencies were not patched to make the historical build pass.

## Rehearsal

Added opt-in `MariaDbHistoricalHostTests`, reusing the isolated child-process
launcher. The current migrator first applies the canonical schema in an owned
MariaDB 10.11 container. The historical host then runs in Development with its
UI surfaces disabled, a fixture certificate and a cleared environment, on a
loopback ephemeral HTTP port. Readiness is synchronized by its actual listener
log, with bounded timeout and cleanup of the owned process/container.

The old host serves `/health/ready` successfully. An independent current context
then observes identical migration history (including AddTokenMaintenance) and
no pending migrations. No schema downgrade is attempted.

## Validation

Set `SUFFICIT_TEST_MARIADB_DOCKER=1` and
`SUFFICIT_TEST_HISTORICAL_HOST_DLL=/tmp/identity-rollback-4493f97/src/server/bin/Debug/net10.0/Sufficit.Identity.Server.dll`.
Run `dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-build --no-restore`
filtered to MariaDbHistoricalHostTests, MariaDbMigratorProcessTests,
MariaDbConcurrentMigrationTests, MariaDbMigrationRecoveryTests,
MigrationAdvisoryLockTests, SchemaProvisioningGuardTests and
TestSynchronizationContractTests: **18 passed**. Test build used package mode
(`-p:SufficitUseLocalSui=false`).

## Limits and delivery

This proves startup/readiness for this specific historical revision against the
current schema. It does not prove authenticated login, every historical feature,
Production posture, Galera behavior or recovery at production volume. No production
access or deploy. The historical DLL path is explicitly opted in; its revision
and digest must be recorded for each future rehearsal.

MarkdownCoverageTests: **8 passed**. `git diff --check`: clean.
This record accompanies the implementation commit on main; push is not deployment.
