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
`auth_time` (`:35-37`). Both tokens are the target
(`src/sts/Grants/GrantOperations.cs:289-294`).

The values are written at login time and preserved across principal
refreshes, so that a security-stamp revalidation does not downgrade a session
that already completed MFA (`src/sts/ServiceCollectionExtensions.cs:556-599`).

| Situation | `amr` issued | `acr` |
|---|---|---|
| Password | `pwd` | `urn:sufficit:acr:loa1` |
| Password + device with remembered MFA | `pwd`, `mfa` | `urn:sufficit:acr:loa2` |
| Password + TOTP | `pwd`, `otp`, `mfa` | `urn:sufficit:acr:loa2` |
| Password grant (legacy) | `pwd` | `urn:sufficit:acr:loa1` |

## Consumption

The management plane requires evidence of a second factor: `MfaRequirement`
accepts the values `mfa`, `otp`, `hwk`, `sms`, `vcm`, `fpt`, `eye`, `voice`,
and `retina` (`src/management/ServiceCollectionExtensions.cs:377-380`), all
from the RFC 8176 registry. The same requirement applies to personal token
issuance and SSF stream management.

## Gaps

- **`acr` does not use standardized URNs.** `urn:sufficit:acr:loa1|loa2` is
  in-house vocabulary; there is no mapping to ISO/IEC 29115 values or to
  `http://schemas.openid.net/pape/policies/2007/06/multi-factor`. A
  third-party RP has no way to interpret it. Suggested fix: make the
  vocabulary configurable via `AssuranceLevelOptions`.
- Passkeys do not distinctly emit `hwk` or `swk`; they enter the MFA path as
  a verified factor.
- `acr_values` in the request does not select an authentication policy; only
  `max_age` and `prompt=login` force re-authentication.

## Tests

`AuthenticationContextProjectionTests`, `AuthorizationReauthenticationPolicyTests`,
`ManagementApplicationAuthorizationTests`.
