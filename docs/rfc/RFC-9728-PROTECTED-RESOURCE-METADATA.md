# RFC 9728 — OAuth 2.0 Protected Resource Metadata

| | |
|---|---|
| Role | Protected Resource (Identity's own APIs) |
| Coverage | **B — Substantial** |
| Origin | In-house |
| Spec | https://www.rfc-editor.org/rfc/rfc9728 |

## Why it is here

This RFC targets the **resource server**, not the AS. Identity implements it
because it **is** a resource server too: it exposes the management plane,
SCIM, and the MCP endpoint. An MCP client needs to discover, starting from
the resource, which authorization server to use.

## Implementation

| Component | Role |
|---|---|
| `src/sts/Controllers/ProtectedResourceMetadataController.cs` | Serves `/.well-known/oauth-protected-resource`, anonymous |
| `src/management/Mcp/McpResourceMetadataChallenge.cs` | Emits the `WWW-Authenticate` with `resource_metadata` on 401 |

Controlled by `Sufficit:Identity:Mcp:ProtectedResourceMetadataEnabled`, which
is **`true` by default** (`src/sts/Options/McpOptions.cs:54`) — unlike most
extensions, which are opt-in.

## The full cycle

1. Client calls the resource without a token.
2. The resource returns `401` with
   `WWW-Authenticate: Bearer resource_metadata="https://…/.well-known/oauth-protected-resource"`.
3. The client reads the document and discovers `authorization_servers`.
4. The client discovers the AS via
   [RFC-8414-AUTHORIZATION-SERVER-METADATA.md](RFC-8414-AUTHORIZATION-SERVER-METADATA.md).
5. The client requests a token with `resource=`
   ([RFC-8707-RESOURCE-INDICATORS.md](RFC-8707-RESOURCE-INDICATORS.md)).

## Requirements

| Requirement | § | Status |
|---|---|---|
| `resource` (canonical identifier) | 2 | Yes |
| `authorization_servers` | 2 | Yes |
| `scopes_supported` | 2 | Yes |
| `bearer_methods_supported` | 2 | Yes |
| Anonymous document at `/.well-known/oauth-protected-resource` | 3 | Yes |
| `resource_metadata` in `WWW-Authenticate` | 5.1 | Yes |
| `scope` in the 401/403 challenge | RFC 6750 §3 | Yes, on the MCP path |
| Signed document (`signed_metadata`) | 2 | No |

## Gaps

- No `signed_metadata`; the document is served in cleartext over TLS.
- One document per host, not per mounted resource: distinct resources on the
  same process share the same `/.well-known`.

## Tests

`McpTests`, `IdentityMcpTests`, `ManagementAuthorizationResponseTests`.
