# Historical OIDC authorization-code flow

Date: 2026-11-06 (America/Sao_Paulo).
Parent: [runtime architecture plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md), F5.2.
Binary provenance: [unchanged historical build](202611061555-historical-host-schema-compatibility.md).

## Coverage

Extended `MariaDbHistoricalHostTests` to seed a fictional public OIDC client using
the real OpenIddict application manager against the current schema. Its callback
is `https://client.example.invalid/callback`, with implicit consent and only the
permissions needed for authorization code, token exchange and openid.

The real password-authenticated historical HTTP session requests authorization
with a random state, nonce and S256 PKCE challenge. The test verifies the callback
address, returned state and authorization code without following the external
callback. It exchanges the code with the verifier and receives access/ID tokens.

ID-token validation uses keys fetched from the old host's discovered JWKS path
and verifies signature, issuer, audience, expiration, subject and nonce. It uses
the repository's existing JsonWebTokenHandler dependency. A second exchange of
the same code returns HTTP 400 with `invalid_grant`.

## Validation

With `SUFFICIT_TEST_MARIADB_DOCKER=1` and
`SUFFICIT_TEST_HISTORICAL_HOST_DLL=/tmp/identity-rollback-4493f97/src/server/bin/Debug/net10.0/Sufficit.Identity.Server.dll`,
ran `dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore
-p:SufficitUseLocalSui=false` filtered to MariaDbHistoricalHostTests,
SchemaProvisioningGuardTests and TestSynchronizationContractTests: **14 passed**.
The historical test retains real password, recovery-code replay rejection and
TOTP assertions on the same upgraded disposable database.

## Limits and delivery

No production access or deploy. The unchanged pre-migration binary now has local
startup, password, MFA and basic OIDC compatibility evidence on the current schema.
The fixture remains Development with tmpfs MariaDB; Production posture,
production-volume data and other client/extension combinations are not established.
The test validates the ID token, not access-token behavior at a resource server.
MarkdownCoverageTests: **8 passed**; `git diff --check`: clean.
This activity accompanies the implementation commit on main; push is not deployment.
