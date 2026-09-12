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
| Passkey | `passkey`, `hwk`, `mfa` | `{prefix}loa3` |
| Password grant (legacy) | `pwd` | `{prefix}loa1` |

`{prefix}` is `Sufficit:Identity:AuthenticationContext:AcrPrefix`, default
`urn:identity:acr:`. Every sign-in path spells the level through
`IAuthenticationContextClassMapper` (`src/sts/AuthenticationContextClassMapper.cs`),
so the vocabulary lives in one place. A session with no sign-in evidence gets
the level resolved from its `amr` values, spelled by the same mapper.

## Consumption

The management plane requires evidence of a second factor: `MfaRequirement`
accepts the values `mfa`, `otp`, `hwk`, `sms`, `vcm`, `fpt`, `eye`, `voice`,
and `retina` (`src/management/ServiceCollectionExtensions.cs:377-380`), all
from the RFC 8176 registry. The same requirement applies to personal token
issuance and SSF stream management.

## Gaps

- **`acr` uses a deployment vocabulary, not a registered one.** The prefix is
  configurable, but there is no built-in mapping to ISO/IEC 29115 values or to
  `http://schemas.openid.net/pape/policies/2007/06/multi-factor`; a relying
  party must be told what `loa1`–`loa3` mean.
- Passkeys do not distinctly emit `hwk` or `swk`; they enter the MFA path as
  a verified factor.
- `acr_values` in the request does not select an authentication policy; only
  `max_age` and `prompt=login` force re-authentication.

## Tests

`AuthenticationContextProjectionTests`, `AuthorizationReauthenticationPolicyTests`,
`ManagementApplicationAuthorizationTests`.
