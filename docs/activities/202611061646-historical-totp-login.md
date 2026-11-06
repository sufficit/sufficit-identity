# Historical TOTP sign-in

Date: 2026-11-06 (America/Sao_Paulo).
Parent: [runtime architecture plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md), F5.2.
Binary provenance: [historical build](202611061555-historical-host-schema-compatibility.md).

## Changes

Extended `MariaDbHistoricalHostTests` to exercise the real historical authenticator
form after password sign-in requires MFA. The existing HTTP helper now handles
both recovery-code and authenticator endpoints, preserving cookie isolation and
real form antiforgery extraction.

A malformed authenticator code redirects with `invalid_code`. A current TOTP from
the fixture's known authenticator key succeeds, redirects to authentication
continuation and permits `/manage` to render the expected fictional username.
The generator is reused from AccountTwoFactorServiceTests by making the existing
static helper internal; no new OTP implementation or production behavior changed.

## Validation

With `SUFFICIT_TEST_MARIADB_DOCKER=1` and
`SUFFICIT_TEST_HISTORICAL_HOST_DLL=/tmp/identity-rollback-4493f97/src/server/bin/Debug/net10.0/Sufficit.Identity.Server.dll`,
ran `dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore
-p:SufficitUseLocalSui=false` filtered to MariaDbHistoricalHostTests,
SchemaProvisioningGuardTests and TestSynchronizationContractTests: **14 passed**.
This includes the historical password/recovery scenarios retained in the same test.

## Limits and delivery

This tests current TOTP acceptance and malformed-code rejection, not expired-code
windows or OTP replay policy. The historical Development configuration accepts the
legacy-format fixture key. MariaDB uses the existing opt-in tmpfs fixture; this
is not durability, production secret-protection or OIDC evidence. No production
access or deploy. MarkdownCoverageTests: **8 passed**; `git diff --check`: clean.
This activity accompanies the implementation commit on main; push is not deployment.
