# RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **B — Substantial** |
| Origin | Mixed |
| Spec | https://www.rfc-editor.org/rfc/rfc9068 |

## Two formats coexisting

The deployment enables `UseReferenceAccessTokens()`
(`src/sts/OpenIddictServerConfiguration.cs:405`), so the **default is
reference tokens** — opaque, validated via introspection. The JWT profile is
applied selectively.

The choice is made per client **and** per resource, decided in
`src/sts/Tokens/AccessTokenFormatPolicy.cs`, triggered by the
`ApplyAccessTokenFormat` handler (`src/sts/OpenIddictServerConfiguration.cs:250`).

| Configuration | Effect |
|---|---|
| `Tokens:AccessTokenFormatsByClient` | Format per `client_id` |
| `Tokens:AccessTokenFormatsByResource` | Format per resource/audience |
| `Tokens:UseReferenceAccessTokens` | Global fallback (`true`) |

Both maps are validated at startup
(`src/sts/ServiceCollectionExtensions.Validation.cs:31-35`), so an invalid
value fails the process instead of silently falling back.

## Claims of the profile

When the format is JWT, the token carries `iss`, `exp`, `aud`, `sub`,
`client_id`, `iat`, `jti` (OpenIddict) and the authorization claims projected
by `GrantOperations.GetDestinations` — `scope`, `roles` when the scope allows
it, and the application claims mapped by `ClaimScopeMap`.

For `client_credentials` tokens, the client registration's *entitlements* are
stamped as an authorization claim explicitly destined for the access token
(`ClientCredentialsGrantHandler`), which is the intended use under §2.2.3.1.

## Requirements

| Requirement | § | Status |
|---|---|---|
| `iss`, `exp`, `aud`, `sub`, `client_id`, `iat`, `jti` | 2.2 | Yes |
| Asymmetric signature | 4 | Yes, `RS256`/`PS256`/`ES256` |
| `typ: at+jwt` in the header | 2.1 | Explicit in CIBA; inherited from OpenIddict elsewhere |
| Identity claims limited by scope | 2.2.3.1 | Yes |
| `scope` claim | 2.2.3 | Yes |
| Authorization claims (`groups`, `roles`, `entitlements`) | 2.2.3.1 | Yes |
| Reject a token without `aud` at the RS | 4 | Resource server's responsibility |

## About `typ: at+jwt`

The only place in the repository that stamps the header explicitly is the
CIBA token generator (`src/sts/Ciba/CibaAccessTokenGenerator.cs:124`), pinned
by `CibaTests.cs:166`. In the other grants the stamp comes from OpenIddict and
**cannot be verified from this repository**, nor is it covered by a dedicated
test.

This is a verification gap, not necessarily a behavioral one: if the
framework ever changes, nothing here would notice. The stamp is what stops a
careless resource server from accepting an `id_token` where it expects an
access token. Cheap fix: a test that decodes the JWT access token header for
each grant and requires `at+jwt`.

## Tests

`AccessTokenFormatPolicyTests`, `TokenIssuancePolicyTests`,
`ClientEntitlementsTests.Issuance`.
