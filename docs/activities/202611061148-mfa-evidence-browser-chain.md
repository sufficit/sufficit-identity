# MFA evidence issuance and browser authorization chain — A4 closure

Completed on 2026-11-06. A4.1 and A4.2 from the
[authorization plan](../plans/PLAN-AUTHORIZATION.md) are implemented and validated.
Earlier reader, factor and ownership corrections are recorded in the activities
linked from that plan. This delivery does not deploy or revoke production sessions.

## Defects resolved

- Passkey evidence was set after Identity had already constructed the cookie.
  SufficitSignInManager now sets it from the successfully verified assertion,
  before cookie construction. Framework assertion/counter/sign-in handling is
  retained. Invalid signatures do not issue a session.
- Passkeys emit `passkey` and, only with user verification, `mfa`. The ceremony
  does not establish hardware key protection, so it no longer asserts `hwk`.
- Authorization step-up no longer trusts a stale or undefined AAL stamp above
  the available methods. Cookie security-stamp renewal re-derives AAL/ACR while
  preserving actual methods, authentication time, SID and remembered marker.
- Token projection re-derives ACR for code redemption and refresh rather than
  replaying an older high ACR. The original authentication time is retained.
  The remembered marker survives projection, preserving fresh-factor checks.
- GrantOperations excludes stored authentication claims, preventing account
  claims from being appended after trusted evidence projection.

## Writer and consumer review

| Path | Evidence and result |
|---|---|
| Password, TOTP, recovery code | Interactive sign-in supplies local evidence; successful second-factor paths assert mfa; remembered factor stays marked. Existing regressions retained. |
| External sign-in | Local flow records federated/provider methods and only asserts mfa for the established remembered-factor path; remembered distinction retained. |
| Passkey | Virtual assertion hook runs after cryptographic verification and before cookie construction; actual Chromium ceremony and cross-replica replay tests pass. |
| Cookie creation / renewal | Previous ownership fixes remove account/role authentication claims; renewal hook now normalizes copied AAL/ACR. |
| Authorize step-up | Uses evidence-aware resolver; stale high/numeric stamps cannot bypass requested ACR. |
| Authorization code / refresh | Projection recalculates ACR and keeps auth_time/remembered status. Persisted authentication claims are excluded. |
| Token exchange / delegated credentials | User exchange uses BuildIdentityAsync/projector. Existing exchange/delegated credential regressions pass; fresh-MFA distinction remains. |
| Device/CIBA without ceremony evidence | BuildIdentityAsync does not invent MFA from stored account claims. |
| Management / SCIM | Shared policy; verified browser token allowed, possession-only token denied, before and after refresh. |
| Overview AAL display | Informational display, not an authorization decision. |

The Identity sequencing was checked against the official
[ASP.NET Core SignInManager source](https://github.com/dotnet/aspnetcore/blob/v10.0.0/src/Identity/Core/src/SignInManager.cs):
PasskeySignInAsync invokes the virtual assertion method before constructing the
session. The regression runs against the repository's resolved framework version.

## Browser validation and CI

MfaAuthorizationChainTests starts an isolated SQLite/Kestrel host with real STS,
Management and SCIM modules. Chromium's virtual authenticator generates WebAuthn
credentials and assertions. A test-only authenticated session bootstraps enrollment;
the session is then cleared and the tested login uses the actual signed assertion.
Both cases exercise invalid signatures, cookie round trip, authorization code +
PKCE, API requests and refresh. User-verified evidence produces 200 from both APIs;
non-verified evidence produces 403. No production account or credential is used.

The browser project references the existing test fixture, with transitive locks
updated. CI installs the matching Chromium and runs this self-contained suite
explicitly; live-deployment browser suites keep their existing exclusion.

## Checkpoints and results

1. Completed: three new regressions failed before correction (two old-cookie
   AAL cases and the cross-replica passkey cookie evidence assertion).
2. Completed: issuance and consumer corrections; 147 focused tests passed.
3. Completed: both Chromium cases passed, including failed-signature refusal.
4. Completed: broader regression suite **347 passed, zero warnings**; grant
   suite **100 passed, zero warnings**; Chromium **2 passed, zero warnings**.
   Counts overlap and are not a unique-test total. Locked restore passed for
   15 projects; workflow YAML parsed; final Markdown coverage passed 8 tests.
5. Completed: documentation and remaining plan reconciled, activity recorded.
   Delivery follows direct-main commit/push; this file's Git history identifies
   the delivery. CI configuration validation is not a claim of a remote CI run.

```sh
dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore -p:SufficitUseLocalSui=false --filter 'FullyQualifiedName~AuthenticationContext|FullyQualifiedName~AuthorizationCodeFlow|FullyQualifiedName~Passkey|FullyQualifiedName~AuthorizationReauthentication|FullyQualifiedName~SharedSignals|FullyQualifiedName~RememberedSecondFactor|FullyQualifiedName~Scim|FullyQualifiedName~Mfa|FullyQualifiedName~CredentialMutationSecurity|FullyQualifiedName~ServerSideSessions|FullyQualifiedName~SessionValidity|FullyQualifiedName~UserManagementControllerTests|FullyQualifiedName~SystemUser|FullyQualifiedName~TwoReplica|FullyQualifiedName~MarkdownCoverage' --nologo --verbosity quiet
dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore -p:SufficitUseLocalSui=false --filter 'FullyQualifiedName~AuthorizationCodeFlow|FullyQualifiedName~TokenExchange|FullyQualifiedName~DelegatedCredential|FullyQualifiedName~AuthenticationContext' --nologo --verbosity quiet
dotnet test src/tests/Sufficit.Identity.BrowserTests/Sufficit.Identity.BrowserTests.csproj --no-restore -p:SufficitUseLocalSui=false --filter FullyQualifiedName~MfaAuthorizationChainTests --nologo --verbosity quiet
dotnet restore src/tests/Sufficit.Identity.BrowserTests/Sufficit.Identity.BrowserTests.csproj --locked-mode -p:SufficitUseLocalSui=false
```

## Compatibility and operational limits

Consumers must use actual evidence rather than assume every passkey declares
hardware protection. Custom ACR strings are normalized to the configured provider
vocabulary when tokens are issued. Existing tokens at external resource servers
are not rewritten or revoked. Historical signed mfa assertions cannot reveal
whether an old issuer overstated them; incident response must revoke affected
sessions/tokens and require reauthentication. Deployment and any such revocation
remain operational actions, not implied by commit/push. Other authorization-plan
sections (A2 and D1) remain open.
