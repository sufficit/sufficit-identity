# RFC 7591 — OAuth 2.0 Dynamic Client Registration

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **C — Partial** |
| Origin | In-house — OpenIddict does not implement DCR |
| Spec | https://www.rfc-editor.org/rfc/rfc7591 |

## Implementation

`POST /connect/register`, in `src/sts/Controllers/RegistrationController.cs`.
Off by default (`Sufficit:Identity:Mcp:Dcr:Enabled = false`). When off, it
responds `404` instead of `403`, so as not to reveal the endpoint's existence.

The endpoint is announced in the discovery document only when enabled
(`registration_endpoint`, `src/sts/OpenIddictServerConfiguration.Discovery.cs`).

## Three gates

1. **Enablement** (`Dcr.Enabled`).
2. **Initial access token** (`RequireInitialAccessToken`, default `true`). Tokens
   are issued by an operator, one per registrant, through the management API:

   | Method | Path | Capability |
   |---|---|---|
   | `GET` | `api/registration-tokens` | `identity.clients.read` |
   | `POST` | `api/registration-tokens` (`label`, `lifetimeHours` 1–720, default 24; `singleUse`, default `true`) | `identity.clients.create` |
   | `DELETE` | `api/registration-tokens/{id}` | `identity.clients.create` |

   The token value (`dcr_iat_…`) is returned only by the `POST`. The database
   (`dcrinitialaccesstokens`) keeps its SHA-256 hash, a short hint, the issuing
   operator, expiry, usage count and revocation. Issuance and revocation are
   written to the management audit. An unknown, expired, revoked or used token
   gets `401` with `WWW-Authenticate: Bearer error="invalid_token"`.

   The token is consumed only after the client metadata validated, so a rejected
   request does not burn a single-use token, and consumption is an atomic
   conditional update: of two concurrent registrations with one single-use token,
   one succeeds.
3. **Anonymous profile** (when `RequireInitialAccessToken=false`): public
   client only, no secret, restricted to `AnonymousGrantTypes` and `AnonymousScopes`.

The shared static token (`Sufficit:Identity:Mcp:Dcr:InitialAccessToken`, secret
`identity/dcr/initial-access-token`) is retired. Startup fails while it is still
configured.

## What's validated at registration

| Item | Rule |
|---|---|
| `redirect_uris` | `https` except loopback, without fragment — `ClientUriPolicy` |
| `grant_types` | Only those on the allow-list; `password` and `implicit` rejected |
| `scope` | Reserved scopes (`identity.management`, `scim`) blocked |
| `token_endpoint_auth_method` | `none`, `client_secret_basic`, `client_secret_post` |
| `jwks_uri` | Public HTTPS, validated against SSRF |
| `client_id` supplied by the caller | Rejected unless `AllowCallerSuppliedClientIds` |
| `client_secret` supplied by the caller | Rejected unless `AllowCallerSuppliedSecrets` |

Every client is born with `ConsentType=Explicit` and, if it uses `authorization_code`,
with PKCE required.

## Provenance

Registration records markers in the application's properties — origin, date,
whether it was anonymous, IP, user-agent and the identifier of the initial access
token that authorized it (`DynamicClientRegistrationProperties`), so every
self-registered client traces back to the operator who issued the token.

## Rate limiting

Its own bucket, `client-registration`
(`src/server/IdentityRateLimitPolicy.cs`, method `GetCredentialGroup`).

## Gaps

- **No RFC 7592**: there is no `registration_access_token` nor an endpoint for
  reading/updating/deleting a registered client. The post-registration lifecycle
  is only through the management plane.
- Grant and scope limits are global (`AllowedGrantTypes`, `AllowedScopes`), not
  per initial access token.
- The management console has no page for registration tokens yet; use the API.
- `software_statement` (§2.3) is not accepted.
- The MCP authorization specification **deprecates** DCR in favor of CIMD — see
  [SPEC-OAUTH-CIMD.md](SPEC-OAUTH-CIMD.md).

## Tests

`DcrTests` (in `McpTests.cs`), `RegistrationTokenManagementTests`,
`ProvisioningControllerTests`, `ClientDefinitionPolicyTests`, `IdentityMcpTests`.
