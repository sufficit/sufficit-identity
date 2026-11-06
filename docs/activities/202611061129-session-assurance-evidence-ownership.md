# Conservative assurance and owned session evidence

Completed on 2026-11-06: assurance derivation and session-factory ownership within
A4.1. Remaining work is in the [authorization plan](../plans/PLAN-AUTHORIZATION.md).

## Findings and changes

The resolver promoted standalone passkey/hwk and even face/geo to its strongest
level, and trusted an AAL stamp before inspecting evidence. It now requires MFA
above Loa1, and MFA plus a WebAuthn-family method for the strongest level. It reads
repeated and space-separated methods. A defined lower stamp remains conservative;
a higher or undefined stamp cannot promote the result. This is local assurance
policy, not a claim of standards certification.

The session factory previously appended request methods to account/role claims
and could inherit evidence from the current principal even when its subject/SID
was not reusable. It now removes stored authentication claims before projection.
Renewal requires an authenticated same-subject principal and a matching unexpired
durable session. Fresh request evidence overrides renewal evidence; a fresh factor
clears any old remembered marker. SID generation for new sessions is preserved.

## Validation

1. Completed: new/updated assurance and ownership regressions failed before the
   change: **13 failed, 36 passed**.
2. Completed: targeted authentication suite **262 passed, zero warnings**.
   Added expired-session and unauthenticated-principal boundaries afterwards;
   the projection suite then passed **18 tests, zero warnings**.
   Strengthened the conservative-stamp regression with actual MFA evidence;
   `--filter FullyQualifiedName~SharedSignalsTests` passed **33 tests, zero warnings**.
3. Completed: permanent documentation and pending scope updated, activity recorded.
   Delivery follows direct-main commit/push; this file's Git history identifies it.

```sh
dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore -p:SufficitUseLocalSui=false --filter 'FullyQualifiedName~SharedSignals|FullyQualifiedName~AuthenticationContext|FullyQualifiedName~Passkey|FullyQualifiedName~AuthorizationReauthentication|FullyQualifiedName~Mfa|FullyQualifiedName~RememberedSecondFactor|FullyQualifiedName~CredentialMutationSecurity|FullyQualifiedName~ServerSideSessions|FullyQualifiedName~MarkdownCoverage' --nologo --verbosity quiet
dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore -p:SufficitUseLocalSui=false --filter FullyQualifiedName~AuthenticationContextProjectionTests --nologo --verbosity quiet
```

Tests use the real DI-composed session factory, SQLite account/role and session
storage, and token projector. They cover fresh evidence, retained same-user evidence,
foreign user, absent durable row, expiry, unauthenticated principal, stored claims,
remembered marker and projected ACR/time. They do not exercise a full browser flow.

## Compatibility and limits

No deployment or token/session revocation was performed. Corrected creation and
renewal do not rewrite existing issued cookies or refresh tokens. Direct stamped-AAL
consumers need follow-up, as does passkey evidence ordering around cookie issuance.
Passkey hwk-versus-swk labeling remains unresolved. These explicit remaining items
prevent treating A4.1 or A4.2 as complete.
