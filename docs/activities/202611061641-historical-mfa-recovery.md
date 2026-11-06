# Historical MFA recovery-code login

Date: 2026-11-06 (America/Sao_Paulo).
Parent: [runtime architecture plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md), F5.2.
Binary provenance: [historical build](202611061555-historical-host-schema-compatibility.md).

## Coverage

Extended the real historical-host HTTP test with a separate fictional user having
MFA enabled, a password hash, an authenticator-key fixture and one recovery code.
The second-factor records use the legacy plaintext format accepted by the
historical Development configuration. This is not production encryption evidence.

The normal password endpoint requires MFA. Real form antiforgery tokens and
cookies are used for recovery completion. An invalid code is rejected; the
valid code grants access to `/manage`, rendering the expected user. A separate
client with fresh cookies logs in with the password again and cannot redeem the
already consumed code or view the user's profile. No test-only sign-in is used.

## Infrastructure observation

Two focused runs timed out before authentication, waiting for disposable MariaDB
startup. On the second, container state was running/exit=0/oom=false, and its
initialization mariadbd was waiting at `jbd2_log_wait_commit`. No readiness line
was present. Added bounded state diagnostics to future readiness timeouts.

The reusable fixture now optionally uses a 512 MiB tmpfs data directory. Only the
historical-host test opts in: it tests live SQL/authentication, not durability.
The default disk-backed restart/outage fixtures are unchanged. No production
process, Docker daemon setting or shared workload was modified.

## Validation

With `SUFFICIT_TEST_MARIADB_DOCKER=1` and
`SUFFICIT_TEST_HISTORICAL_HOST_DLL=/tmp/identity-rollback-4493f97/src/server/bin/Debug/net10.0/Sufficit.Identity.Server.dll`,
focused test after the storage adjustment: **1 passed**.
Then `dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-build --no-restore`
filtered to MariaDbHistoricalHostTests, SchemaProvisioningGuardTests and
TestSynchronizationContractTests: **14 passed**. Build used package mode
(`-p:SufficitUseLocalSui=false`). The full disk-backed migration suite was not
rerun after the observed local I/O stalls.

## Limits and delivery

TOTP, OIDC, Production posture and recovery at volume remain unverified by this
activity. No production access or deploy. MarkdownCoverageTests: **8 passed**;
`git diff --check`: clean. This record accompanies the implementation commit on
main; push is not deployment.
