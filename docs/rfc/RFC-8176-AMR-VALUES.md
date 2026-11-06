# RFC 8176 — Authentication Method Reference Values

| | |
|---|---|
| Role | OpenID Provider |
| Coverage | **C — Partial** |
| Origin | In-house |
| Spec | https://www.rfc-editor.org/rfc/rfc8176 |

## Implementation

`AuthenticationContextProjection` (`src/sts/AuthenticationContextProjection.cs`)
projects three claims onto the token and the `id_token`: `amr`, `acr`, and
`auth_time` (`:38-40`). Both tokens are the target
(`src/sts/Grants/GrantOperations.cs:293-298`).

The values are written at login time and preserved across principal
refreshes, so that a security-stamp revalidation does not downgrade a session
that already completed MFA (`src/sts/ServiceCollectionExtensions.cs:559-602`).

| Situation | `amr` issued | `acr` |
|---|---|---|
| Password | `pwd` | `{prefix}loa1` |
| Password + device with remembered MFA | `pwd`, `mfa` | `{prefix}loa2` |
| Password + TOTP | `pwd`, `otp`, `mfa` | `{prefix}loa2` |
| Password + recovery code | `pwd`, `rc`, `mfa` | `{prefix}loa2` |
| Passkey with user verification | `passkey`, `mfa` | `{prefix}loa3` |
| Passkey without user verification (opt-in) | `passkey` | `{prefix}loa1` |
| Password grant (legacy) | `pwd` | `{prefix}loa1` |

`{prefix}` is `Sufficit:Identity:AuthenticationContext:AcrPrefix`, default
`urn:identity:acr:`. Every sign-in path spells the level through
`IAuthenticationContextClassMapper` (`src/sts/AuthenticationContextClassMapper.cs`),
so the vocabulary lives in one place. A session with no sign-in evidence gets
the level resolved from its `amr` values, spelled by the same mapper.

## Consumption

Management, STS and SCIM use `MfaEvidencePolicy` in
`src/application/Sufficit.Identity.Application.Abstractions/Security/MfaEvidencePolicy.cs`.
It requires explicit `mfa` or `pwd` plus one of `otp`, `hwk`, `sms`, `vcm`,
`fpt`, `eye`, `voice`, `retina`. The latter list is a compatibility vocabulary
(`eye` is legacy), not a claim that each value is standardized or alone proves MFA.
Single methods and possession-only combinations such as `passkey hwk` are refused.
Other factor combinations require the trusted issuer to assert `mfa` explicitly.
This is a provider acceptance policy; RFC 8176 defines method meanings, not this
particular authorization rule.

`identity:mfa_remembered=true` permits ordinary MFA-protected operations but does
not satisfy the fresh-evidence check used for credential minting. Existing tokens
with only a single-method AMR must authenticate with sufficient evidence before
using MFA-protected surfaces after this change.

## Session assurance and ownership

`AmrBasedAssuranceLevelResolver` derives Loa1 without MFA, Loa2 with MFA,
and the provider's strongest level with MFA plus a WebAuthn-family method
(`passkey`, `fido`, `webauthn`). Claims may be repeated or space-separated.
A pre-existing AAL stamp can lower the result but cannot elevate it; undefined
numeric enum values cannot establish assurance. This mapping is deployment policy,
not a standardized assurance certification.

`OidcSessionClaimsPrincipalFactory` removes stored account/role `amr`, `aal`,
`acr`, `auth_time` and remembered-factor claims before setting session evidence.
Renewal requires an authenticated principal of the same subject with a matching,
non-expired durable session. Fresh request evidence takes precedence and replaces
the remembered marker. The factory derives AAL afresh and maps fallback ACR from it.
`SufficitSignInManager.PerformPasskeyAssertionAsync` records signed, validated
passkey evidence before the framework builds the cookie. Passkeys do not assert
hardware or software key protection; that property is not established here.

AuthenticationContextProjector copies AMR/time and the remembered marker, and
re-derives ACR from evidence for authorization codes, refresh and user token
exchange. GrantOperations excludes persisted authentication claims from token
construction. Cookie security-stamp renewal also normalizes AAL/ACR. The authorize
step-up check uses the evidence-aware resolver instead of trusting an old stamp.

Already-issued tokens are not revoked by this code change. A correctly signed
historical `mfa` assertion cannot reveal whether the old issuer overstated it;
deployments investigating such sessions must revoke the affected sessions/tokens
and require reauthentication. Resource servers holding already-issued access tokens
retain their own validation behavior until expiry or revocation. No rollout or
bulk revocation is implied by these code tests.

## Gaps

- **`acr` uses a deployment vocabulary, not a registered one.** The prefix is
  configurable, but there is no built-in mapping to ISO/IEC 29115 values or to
  `http://schemas.openid.net/pape/policies/2007/06/multi-factor`; a relying
  party must be told what `loa1`–`loa3` mean.
- The provider does not attest a hardware/software distinction for passkeys.
  The private `passkey` method identifies the WebAuthn ceremony without asserting it.
- Recognized `acr_values` above current evidence request bounded reauthentication;
  unsupported values are ignored. The returned ACR states the achieved level.

## Tests

`AuthenticationContextProjectionTests`, `AuthorizationReauthenticationPolicyTests`,
`ManagementApplicationAuthorizationTests`, `ScimMfaEvidenceTests`,
`MfaRequirementTests`, `PasskeyAssurancePolicyTests`, `RememberedSecondFactorTests`,
`TwoReplicaSmokeTests`, and the isolated Chromium
[MfaAuthorizationChainTests](../../src/tests/Sufficit.Identity.BrowserTests/MfaAuthorizationChainTests.cs).

The browser suite starts its own SQLite/Kestrel host and a virtual WebAuthn
authenticator. It checks invalid signatures, verified/unverified sign-in, cookie
round trips, authorization code + PKCE, Management/SCIM responses and refresh.
The dedicated CI step runs this suite without production credentials or a deployed
server. Other browser suites retain their separate live-server requirements.
