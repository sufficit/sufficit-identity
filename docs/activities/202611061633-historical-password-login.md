# Historical password login on upgraded schema

Date: 2026-11-06 (America/Sao_Paulo).
Parent: [runtime architecture plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md), F5.2.
Historical binary provenance: [unchanged build](202611061555-historical-host-schema-compatibility.md).

## Changes

Extended `MariaDbHistoricalHostTests` to seed a confirmed fictional user with a
real ASP.NET Identity password hash on the upgraded disposable MariaDB. The old
`4493f97` host now enables its public UI while other surfaces remain disabled.
The client reads the real password form's antiforgery token and retains cookies.

- Incorrect password redirects with `invalid_credentials`.
- Correct password redirects to authentication continuation and issues cookies.
- `/manage` returns 200 and renders the expected username using those cookies.
- Readiness and unchanged migration history checks remain in place.

No test-only sign-in endpoint or fake authentication handler is used. This is HTTP
form/SSR coverage, not JavaScript/browser rendering, MFA or a complete OIDC flow.

## Concurrent lock failure found during validation

The focused historical test passed. The first combined run passed 17 tests but
failed the concurrent migration test when `GET_LOCK` returned DBNull and the host
attempted to convert it to Int32. The host requested a 60-second MariaDB lock wait
but inherited the fixture connection's 3-second default command timeout.

Changed only acquisition to use a 65-second command timeout, allowing the requested
server wait to complete. Null/DBNull results now use the existing controlled
acquisition-failure exception. The observed NULL is consistent with interruption
of the wait; no server-side trace was captured to establish its exact cause.

## Validation

With `SUFFICIT_TEST_MARIADB_DOCKER=1` and
`SUFFICIT_TEST_HISTORICAL_HOST_DLL=/tmp/identity-rollback-4493f97/src/server/bin/Debug/net10.0/Sufficit.Identity.Server.dll`,
ran `dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore
-p:SufficitUseLocalSui=false` filtered to MariaDbHistoricalHostTests,
MariaDbMigratorProcessTests, MariaDbConcurrentMigrationTests,
MariaDbMigrationRecoveryTests, MigrationAdvisoryLockTests,
SchemaProvisioningGuardTests and TestSynchronizationContractTests.
After the fix: **18 passed**, including the previously failing concurrency case.

## Limits and delivery

All processes/data were local disposable fixtures. No production access or deploy.
Historical MFA/OIDC behavior, Production posture and volume recovery remain open.
MarkdownCoverageTests: **8 passed**. `git diff --check`: clean.
This record accompanies the implementation commit on main; push is not deployment.
