# RFC 6750 — OAuth 2.0 Bearer Token Usage

| | |
|---|---|
| Role | Authorization Server and Resource Server (in-house APIs) |
| Coverage | **A — Complete** |
| Origin | OpenIddict (issuance and validation), in-house for management challenges |
| Spec | https://www.rfc-editor.org/rfc/rfc6750 |

## Implementation

The token is delivered as `Bearer` in the `token_type` of the token
endpoint's response, except when there's a proof-of-possession binding — then it becomes `DPoP`
(`src/sts/Dpop/DpopTokenHandlers.cs`, handler `AttachDpopTokenType`).

Identity's own APIs (management, SCIM, personal tokens, MCP) consume the
same token via `OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme`,
declared in the policies at `src/management/ServiceCollectionExtensions.cs:211-236`
and `src/scim/ScimServiceCollectionExtensions.cs:52-56`.

## Requirements

| Requirement | § | Status | Evidence |
|---|---|---|---|
| Token in the `Authorization: Bearer` header | 2.1 | Yes | OpenIddict's validation scheme |
| Token **not** accepted in query string | 2.3 | Yes, no reading of `access_token` from the query | — |
| `WWW-Authenticate` on 401 | 3 | Yes | `src/management/Mcp/McpResourceMetadataChallenge.cs` |
| `error="invalid_token"` on invalid token | 3.1 | Yes (OpenIddict) | — |
| `error="insufficient_scope"` on 403 | 3.1 | Yes | `ScopeRequirement` + MCP challenge |
| TLS required | 5.3 | Yes outside Development | — |

## Notable detail

The 401 challenge for the MCP plan adds `resource_metadata` to the
`WWW-Authenticate` header, which is what the MCP authorization specification
requires — see [RFC-9728-PROTECTED-RESOURCE-METADATA.md](RFC-9728-PROTECTED-RESOURCE-METADATA.md).

## Tests

`IntrospectionTests`, `ManagementAuthorizationResponseTests`,
`PublicAuthenticationBoundaryTests`, `McpTests`.
