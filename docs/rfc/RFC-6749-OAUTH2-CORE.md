# RFC 6749 — OAuth 2.0 Authorization Framework

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **B — Substantial** |
| Origin | OpenIddict 7.7, configured in `src/sts/OpenIddictServerConfiguration.cs` |
| Spec | https://www.rfc-editor.org/rfc/rfc6749 |

## Implementation

The framework endpoints are registered in
`src/sts/OpenIddictServerConfiguration.cs:43-53` and served in
*passthrough* mode: OpenIddict validates the protocol and the
`AuthorizationController` decides on issuance.

| Endpoint | Path | Handler |
|---|---|---|
| Authorization (§3.1) | `/connect/authorize` | `src/sts/Controllers/AuthorizationController.cs:102-104` |
| Token (§3.2) | `/connect/token` | `src/sts/Controllers/AuthorizationController.cs:366-370` |

The token endpoint does not implement grant logic directly: it delegates to
`TokenGrantDispatcher`, which resolves an `ITokenGrantHandler` by `grant_type`
(`src/sts/Grants/TokenGrants.cs`). Each grant is its own class.

## Grants

Registered in `src/sts/OpenIddictServerConfiguration.cs:243-247`:

| Grant | §  | Status | Handler |
|---|---|---|---|
| `authorization_code` | 4.1 | Enabled | `UserTokenGrantsHandler` |
| `client_credentials` | 4.4 | Enabled | `ClientCredentialsGrantHandler` |
| `refresh_token` | 6 | Enabled, rotating | `UserTokenGrantsHandler` |
| `urn:ietf:params:oauth:grant-type:device_code` | RFC 8628 | Enabled | `DeviceCodeGrantHandler` |
| `urn:ietf:params:oauth:grant-type:token-exchange` | RFC 8693 | Enabled | `TokenExchangeGrantHandler` |
| `password` | 4.3 | **Off by default** | `PasswordGrantHandler` |
| `implicit` | 4.2 | **Not registered** | — |
| `none` / hybrid | — | **Off by default** | — |

`implicit` is not registered anywhere. `password` and `none` only exist under
`Sufficit:Identity:LegacyGrants`, whose two fields are `false` by default
(`src/sts/OpenIddictServerConfiguration.cs:296-300`). The rationale and the risk
are covered in [RFC-9700-OAUTH-SECURITY-BCP.md](RFC-9700-OAUTH-SECURITY-BCP.md).

## Key requirements

| Requirement | § | Status | Evidence |
|---|---|---|---|
| Prior registration of `redirect_uri` | 3.1.2.2 | Yes | `src/management/Clients/ClientUriPolicy.cs` |
| Exact match of `redirect_uri` | 3.1.2.3 | Yes (OpenIddict, plain string) | — |
| `state` passed back unmodified | 4.1.2 | Yes (OpenIddict) | — |
| Confidential client authentication | 2.3 | Yes, multiple methods | [RFC-7523-CLIENT-ASSERTION.md](RFC-7523-CLIENT-ASSERTION.md), [RFC-8705-MUTUAL-TLS.md](RFC-8705-MUTUAL-TLS.md) |
| Single-use authorization code | 4.1.2 | Yes (OpenIddict, with reuse detection) | — |
| `scope` validated against the client | 3.3 | Yes, `oi_scp` permission per client | `src/management/Clients/ClientPermissionPolicy.cs` |
| TLS required | 1.6 | Yes outside Development | `src/sts/OpenIddictServerConfiguration.cs:644-650` |
| Errors per §4.1.2.1 / §5.2 | 4.1.2.1, 5.2 | Yes | `TokenGrantDispatcher.ForbidError` |

## Deliberate deviations

- **No implicit/hybrid.** OAuth 2.1 and RFC 9700 remove them; OpenIddict 5+
  deprecates them. Legacy clients need to migrate to `authorization_code` + PKCE.
- **PKCE required** even for confidential clients when
  `Pkce.RequireForAllClients` (the deployment's default), which goes beyond RFC 6749.
- **Rotating, single-use refresh token**, with family-wide revocation on reuse.
  RFC 6749 §6 only permits this; here it's enforced.

## Configuration

| Key | Default | Effect |
|---|---|---|
| `Sufficit:Identity:LegacyGrants:Password` | `false` | Enables the password grant. |
| `Sufficit:Identity:LegacyGrants:None` | `false` | Enables the `none` flow. |
| `Sufficit:Identity:Tokens:RefreshTokenLifetimeDays` | `14` | Refresh token lifetime. |
| `Sufficit:Identity:Issuer` | empty | Fixes `iss`; empty derives it from the request. |

## Tests

`AuthorizationCodeFlowTests`, `ClientCredentialsTests`, `RefreshTokenTests`,
`PasswordGrantTests`, `DeviceFlowTests`, `TokenExchangeTests`.

## Gaps

- An empty `Sufficit:Identity:Issuer` makes `iss` follow the `Host` header. In
  production it should always be configured.
- No run of the OpenID Conformance Suite is automated in CI, so
  compliance is audited by reading and in-house tests, not certified.
