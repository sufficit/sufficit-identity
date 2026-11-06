# Activity — Production HTTP schema guard

Date: 2026-11-06. Bounded F5.2 coverage and targeted F14 documentation correction.
[Runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Scope choice

The host accepts the deployment-provided Redis connection string; the generic
cache runbook does not establish a specific automatic-election topology.
Automatic HA and production topology verification remain operational work.
This slice advances the independent, explicitly pending schema-startup guard.

## Verified behavior

Nine new cases invoke the real HostBootstrap.ProvisionSchemaAsync entry point
with a lightweight WebApplication and a database-resolution probe:

- Production and Staging with AutoMigrate enabled in HTTP mode throw before any
  database context is resolved, and direct the operator to --migrate-only.
- HTTP mode with the default disabled flag does not resolve a database context.
- Dedicated migrator with either flag value and Development startup reach the
  database boundary. The probe stops there, before secrets, connection or migration.

No connection string is supplied and no schema is mutated. These assertions
prove the guard and branch boundary, not successful migration execution.

DatabaseOptions XML documentation incorrectly described AutoMigrate as enabling
production HTTP migrations. It now explains refusal, the dedicated process and
the independent Development path, preserving the database-name restriction.

## Validation

Standalone guard cases: **9 passed, zero warnings**.
Combined command:
`rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore
-p:SufficitUseLocalSui=false --filter
'FullyQualifiedName~SchemaProvisioningGuardTests|FullyQualifiedName~DatabaseSchemaContractTests|FullyQualifiedName~TestSynchronizationContractTests'
--nologo --verbosity quiet`: **19 passed, zero warnings**.

MarkdownCoverageTests: **8 passed, zero warnings**. `git diff --check`: clean.
All three execution checkpoints completed.

## Limits and delivery

Runtime behavior did not change; this adds coverage and corrects public comments.
F5.2 remains open for two-replica migration startup, failure/retry and old-binary
rollback. Broad F14 comment reconciliation and HA/clock operational evidence
also remain pending. No production deploy or database migration was performed.
Delivery commit title: `Verify production HTTP schema guard and correct migration comments`.
