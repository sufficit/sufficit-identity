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
| Passkey with user verification | `passkey`, `hwk`, `mfa` | `{prefix}loa3` |
| Passkey without user verification (opt-in) | `passkey`, `hwk` | `{prefix}loa1` |
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
AuthenticationContextProjector copies the resulting AMR/ACR/time into token claims.

Already-issued cookies and tokens are not revoked by this code change. Their
existing evidence and the direct authorization/refresh consumers require separate
review; these tests do not establish a production rollout or full browser ceremony.

## Gaps

- **`acr` uses a deployment vocabulary, not a registered one.** The prefix is
  configurable, but there is no built-in mapping to ISO/IEC 29115 values or to
  `http://schemas.openid.net/pape/policies/2007/06/multi-factor`; a relying
  party must be told what `loa1`–`loa3` mean.
- Passkeys currently emit `hwk` without distinguishing software-backed from
  hardware-backed credentials. Audit issuance ordering through the actual
  passkey cookie ceremony and existing refresh-token evidence (remaining A4.1).
- `acr_values` in the request does not select an authentication policy; only
  `max_age` and `prompt=login` force re-authentication.

## Tests

`AuthenticationContextProjectionTests`, `AuthorizationReauthenticationPolicyTests`,
`ManagementApplicationAuthorizationTests`, `ScimMfaEvidenceTests`,
`MfaRequirementTests`, `PasskeyAssurancePolicyTests`, `RememberedSecondFactorTests`.
