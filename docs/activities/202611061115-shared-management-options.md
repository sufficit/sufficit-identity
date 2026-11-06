# Shared Management options — F2.2

Completed on 2026-11-06. Scope: remove the duplicated STS options type; no deployment.

## Changes and decisions

STS now consumes `Sufficit.Identity.Management.ManagementOptions` from the existing
Application.Abstractions dependency. Configuration keys and common defaults remain
unchanged; no new project dependency was added. Explicit source/binary consumers
of the removed STS type must adopt the shared type and rebuild.

The [runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md) retains its other pending
items. F2.2 is recorded here rather than left as a completed plan checkbox.
The historical reconciliation links to the old type at its reviewed commit.

## Execution and evidence

1. Completed: inspected both definitions and their consumers; added a binding regression.
2. Completed: removed the duplicate and validated the shared contract.
3. Completed: documented the contract and archived this item; delivery follows the
   repository's direct-main commit/push workflow, traceable through this file's Git history.

The first build without package mode failed with CS1704 because local and NuGet
Sufficit.Blazor.UI assemblies were mixed. No dependency files were changed.
Using the repository-supported `-p:SufficitUseLocalSui=false` resolved the conflict.
The new regression then failed before the implementation: expected the Management
type, received the STS type. After consolidation the targeted suite passed:
**100 tests, zero warnings**.

```sh
dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore -p:SufficitUseLocalSui=false --filter 'FullyQualifiedName~ManagementOptionsBindingTests|FullyQualifiedName~CspHeaderTests|FullyQualifiedName~ManagementApplicationAuthorizationTests|FullyQualifiedName~ProductionPostureCheckTests|FullyQualifiedName~OperationalHardeningTests|FullyQualifiedName~MarkdownCoverageTests' --nologo --verbosity quiet
```

The suite builds the host and tests configuration binding, CSP headers, Management
authorization, production posture and documentation coverage. It does not establish
production deployment or independently exercise downstream binary consumers.
