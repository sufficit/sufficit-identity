# F14 — Security annotation reconciliation

Date: 2026-11-06 (America/Sao_Paulo).
Parent: [runtime architecture](../plans/PLAN-RUNTIME-ARCHITECTURE.md#f14--security-critical-protocol-annotations).

## Targeted review and changes

- Schema template falsely instructed enabling AutoMigrate for production HTTP.
  It now describes refusal outside Development and the dedicated migrator.
  AllowedDatabaseNames text describes the actual nonempty-list comparison,
  without implying an empty list is enforced differently by environment.
- Session-store comments called the wire cookie the raw sid. They now distinguish
  the protected reference ticket from the sid used as store key/ID-token claim.
- Session entity comments promised immediate invalidation. They now describe
  authoritative deletion and bounded stale cache when invalidation fails.
- Credential composition comments implied a single certificate branch. They now
  describe vault-managed signing, bootstrap and auxiliary keys, configured
  certificates, Development fallback and separate encryption selection.
- Removed the obsolete “pure move” assertion in HostBootstrap and dated catalog/
  legacy-grant change narratives. The feature-catalog claim that hooks run for
  enabled and disabled features matches its loops and is preserved.

This closes the targeted F14.1/F14.2 review; it is not an exhaustive security audit
of every source comment. No runtime statements, feature flags or configuration
values changed. Existing rationale was retained where it matches the code.

## Validation

Parsed template JSON before and after, recursively removing underscore-prefixed
documentation entries: all remaining values are identical.

`dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-build --no-restore`
filtered to SchemaProvisioningGuardTests, ProtocolFeature, SessionTicketCacheRaceTests,
ProductionPostureCheckTests and DocumentationContractTests: **64 passed**.
Existing binaries are appropriate here because only comments/template descriptions
changed. MarkdownCoverageTests: **8 passed**; `git diff --check`: clean.

## Delivery boundaries

Parallel modifications to six package lock files were present at turn start and
are preserved outside this change. No deploy or production access. This record
accompanies the review commit on main.
