# MCP Authorization

| | |
|---|---|
| Role | Authorization Server **and** Resource Server |
| Coverage | **B — Substantial** |
| Origin | Mixed — composition of other specifications plus the in-house MCP endpoint |
| Spec | https://modelcontextprotocol.io/specification/draft/basic/authorization |

## What the spec requires from the AS

| Requirement | Implementation |
|---|---|
| OAuth 2.1 with PKCE | [RFC-7636-PKCE.md](RFC-7636-PKCE.md); implicit and password out |
| RS implements RFC 9728 | [RFC-9728-PROTECTED-RESOURCE-METADATA.md](RFC-9728-PROTECTED-RESOURCE-METADATA.md) |
| AS publishes RFC 8414 or OIDC Discovery | [RFC-8414-AUTHORIZATION-SERVER-METADATA.md](RFC-8414-AUTHORIZATION-SERVER-METADATA.md) |
| CIMD as preferred registration | [SPEC-OAUTH-CIMD.md](SPEC-OAUTH-CIMD.md) |
| DCR accepted, but deprecated | [RFC-7591-DYNAMIC-CLIENT-REGISTRATION.md](RFC-7591-DYNAMIC-CLIENT-REGISTRATION.md) |
| `resource` required (RFC 8707) | [RFC-8707-RESOURCE-INDICATORS.md](RFC-8707-RESOURCE-INDICATORS.md) |
| `iss` in the response and matching announcement | [RFC-9207-ISSUER-IDENTIFICATION.md](RFC-9207-ISSUER-IDENTIFICATION.md) |
| Token audienced to the resource | Yes, via a resource allow-list |
| `WWW-Authenticate` with `resource_metadata` and `scope` | `src/management/Mcp/McpResourceMetadataChallenge.cs` |
| `403` with `insufficient_scope` for step-up | Yes, `ScopeRequirement` |

No item on the list is missing. That's the reason for level B rather than C.

## The in-house MCP server

Besides authorizing third-party MCP, Identity **is** an MCP server:
`src/management/Controllers/McpController.cs`, protected by the
`sufficit-identity-mcp` policy (scope `identity.mcp`, default in
`src/sts/Options/McpOptions.cs:20`).

It speaks JSON-RPC with `tools/list` and `tools/call` (`McpController.cs:92-101`).
The tool registry is `IdentityMcpToolRegistry`, composed of two sets
(`src/management/Mcp/McpTooling.cs:39`):

| Set | File | Scope |
|---|---|---|
| Personal vault | `VaultMcpTools.cs` | Read, write, list and delete secrets in the `user-<sub>` context |
| Self-service | `SelfServiceMcpTools.cs` | Data of the account's own owner |

Two design properties are worth noting:

1. **Every tool is bound to the authenticated subject.** The vault context is
   forced to `user-<sub>` in the controller
   (`src/management/Controllers/PersonalVaultController.cs:151`), not taken from
   the argument. An agent cannot reach another user's secret.
2. **Deletion requires plaintext confirmation**: the removal tool demands
   `confirmPlaintext` in addition to the name (`VaultMcpTools.cs:69-72`), which
   prevents a model from deleting a secret by inferring intent.

## Scopes and provisioning

`McpScopeProvisioner` creates the required scope at startup and grants it to the
configured first-party clients; `McpScopeGrantPolicy` decides the implicit
grant. Resources accepted as audience come from `Mcp:Resources`, with explicit
registration — an agent cannot invent an audience.

## Gaps against the state of the art

| Item | Status | Comparison |
|---|---|---|
| Agent identity as a first-class principal | No | Enter Agent ID (GA Apr/2026), Auth0 Agent-as-Principal |
| Third-party token vault | **Yes**, in `src/sts/Integrations/` | Equivalent to Auth0's Token Vault |
| On-behalf-of delegation for an agent without a user | No | See [RFC-8693-TOKEN-EXCHANGE.md](RFC-8693-TOKEN-EXCHANGE.md) |
| ID-JAG / Cross-App Access | No | Draft-04, adopted by Anthropic, Atlassian, Slack, Notion |

The first and third rows are the same gap seen from different angles: token
exchange requires the `subject_token` to identify a user, which prevents an
agent from exchanging its own identity for downstream access.

## Tests

`McpTests`, `IdentityMcpTests`, `McpScopeGrantPolicy` via
`PersonalTokenScopeProvisionerTests` and `ScopeEntitlementSecurityTests`.
