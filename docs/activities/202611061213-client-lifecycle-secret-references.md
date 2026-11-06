# Activity — Client lifecycle vault references

Date: 2026-11-06. Authorization plan item A2.4 completed in source and tests.

## Changes

- Added optional secret references to primary-secret rotation and credential
  creation HTTP/application commands. `generate=false` is explicit; reference
  plus plaintext or generation is rejected.
- Both operations resolve via the existing Management Vault resolver using the
  caller context, preserving vault authority and journaling. Manifest ownership,
  optimistic versions, credential lifetime and revocation rules remain in place.
- Resolved plaintext never returns in lifecycle responses (`oneTimeSecret` is
  empty). Generated and compatibility-input secrets preserve their response shape.
- Primary provenance is set for references and cleared on generated/plaintext
  replacement. Additional credentials keep hashes and lifecycle metadata without
  changing primary provenance. No schema change or automatic vault synchronization.
- Both HTTP endpoints now apply the existing audited plaintext expiry adapter;
  warnings use `identity.clients.update`, rather than the create capability.

Contract and migration details: [client scopes and references](../usage/USAGE-CLIENT-SCOPE-GRANTS.md).

## Evidence

Two new HTTP reference tests failed before implementation (400 instead of success).
After implementation, `rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj
--no-restore -p:SufficitUseLocalSui=false --filter
'FullyQualifiedName~ClientSecretReferenceTests|FullyQualifiedName~ClientsControllerTests|FullyQualifiedName~InitialManagedCredentialTests'
--nologo --verbosity quiet` passed **70 tests, zero warnings**.

Coverage includes real named-vault resolution and token issuance, replacement vs
additional-secret coexistence, missing/ambiguous references, no response/audit
plaintext, primary provenance, denied vault resolution preserving client state,
and expired plaintext input with generation still available. The denial cases
use a test authorization evaluator that refuses vault resolution; production
authentication is not being asserted by those isolated tests.

`MarkdownCoverageTests`: **8 passed, zero warnings**. `git diff --check`: clean.
All three execution checkpoints completed.

## Delivery and remaining work

Delivered on main under `Support vault references throughout client credential lifecycle`.
No production deployment or credential mutation was performed. A2.1–A2.3 still
require current production telemetry, consumer migration and manifest inventory;
this activity does not claim those operational gates are complete.
