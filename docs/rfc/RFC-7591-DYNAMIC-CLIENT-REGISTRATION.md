# RFC 7591 — OAuth 2.0 Dynamic Client Registration

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **C — Partial** |
| Origin | In-house — OpenIddict does not implement DCR |
| Spec | https://www.rfc-editor.org/rfc/rfc7591 |

## Implementation

`POST /connect/register`, in `src/sts/Controllers/RegistrationController.cs`.
Off by default (`Sufficit:Identity:Mcp:Dcr:Enabled = false`,
`src/sts/Options/McpOptions.cs:87`). When off, it responds `404` instead of
`403`, so as not to reveal the endpoint's existence (`RegistrationController.cs:80-86`).

The endpoint is announced in the discovery document only when enabled
(`src/sts/OpenIddictServerConfiguration.cs:556-565`).

## Three gates

1. **Enablement** (`Dcr.Enabled`).
2. **Initial access token** (`RequireInitialAccessToken`, default `true`):
   constant-time comparison of the `Authorization` header, with mandatory
   expiration; with no token configured the endpoint responds `503`, and does not pass
   (`RegistrationController.cs:88-140`). Optionally single-use.
3. **Anonymous profile** (when `RequireInitialAccessToken=false`): public
   client only, no secret, restricted to `AnonymousGrantTypes` and `AnonymousScopes`
   (`RegistrationController.cs:173-220`).

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
with PKCE required (`RegistrationController.cs:149`).

## Provenance

Registration records markers in the application's properties — origin, date,
whether it was anonymous, IP and user-agent
(`RegistrationController.cs:36-52`), so the console distinguishes a self-registered
client from one created by an operator.

## Rate limiting

Its own bucket, `client-registration`
(`src/server/IdentityRateLimitPolicy.cs`, method `GetCredentialGroup`).

## Gaps

- **No RFC 7592**: there is no `registration_access_token` nor an endpoint for
  reading/updating/deleting a registered client. The post-registration lifecycle
  is only through the management plane.
- The initial access token is a static shared secret, not attributed per
  registrant. A fix has been proposed in the evaluation: issue it as an OpenIddict
  reference token instead.
- `software_statement` (§2.3) is not accepted.
- The MCP authorization specification **deprecates** DCR in favor of CIMD — see
  [SPEC-OAUTH-CIMD.md](SPEC-OAUTH-CIMD.md).

## Tests

`ProvisioningControllerTests`, `ClientDefinitionPolicyTests`, `McpTests`,
`IdentityMcpTests`.
