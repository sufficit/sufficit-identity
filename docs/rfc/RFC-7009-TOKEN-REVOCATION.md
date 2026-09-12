# RFC 7009 — OAuth 2.0 Token Revocation

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **A — Complete** |
| Origin | OpenIddict; endpoint registered in `src/sts/OpenIddictServerConfiguration.cs:48` |
| Spec | https://www.rfc-editor.org/rfc/rfc7009 |

## Implementation

`POST /connect/revocation`, served entirely by OpenIddict. With mTLS
enabled it gains the alias `/connect/revocation/mtls`
(`src/sts/OpenIddictServerConfiguration.cs:75-77`), as required by RFC 8705 §5.

| Requirement | § | Status |
|---|---|---|
| Revokes `refresh_token` and `access_token` | 2.1 | Yes |
| `token_type_hint` accepted and optional | 2.1 | Yes |
| Client authentication required | 2.1 | Yes |
| Client can only revoke its own tokens | 2.1 | Yes |
| `200 OK` for a non-existent token | 2.2 | Yes |
| Cascading revocation of the refresh token | 2.1 | Yes, revokes the associated authorization |

## Revocation outside the endpoint

Besides the RFC, there are three administrative paths that revoke without the client asking:

| Path | Where | Effect |
|---|---|---|
| Credential mutation | `src/sts/CredentialMutationSecurityCoordinator.cs:114-155` | Rotates the security stamp and revokes tokens, authorizations and browser sessions. |
| Session revocation | `src/management/Sessions/` | Ends a user's sessions on all devices. |
| Authorization revocation | `src/management/Authorizations/` | Invalidates the *grant* and the tokens derived from it. |

All three emit a CAEP `session-revoked` signal when SSF is enabled — see
[SPEC-SSF-CAEP-RISC.md](SPEC-SSF-CAEP-RISC.md).

## Tests

`PasswordResetRevocationTests`, `SessionsAndAuthorizationsControllerTests`,
`RefreshTokenTests`.
