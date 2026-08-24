# Genius Identity MCP and personal Vault scope — 2026-08-23

Issue: [#35](https://github.com/sufficit/sufficit-identity/issues/35)

## Decision

The Identity MCP and the subject-bound personal Vault HTTP adapter require the
dedicated OAuth scope `identity.mcp`. It is intentionally distinct from
`identity.management`: it permits self-service operations for the authenticated
subject only and never grants management capabilities or shared Vault contexts.

`sufficit-ai-genius` is the only default trusted client. At server startup,
`McpScopeProvisioner` idempotently creates the scope and reconciles the client's
OpenIddict permission. `McpScopeGrantPolicy` adds the scope during user-token
issuance and refresh, so refresh tokens created before this contract repair
themselves without a new enrollment ceremony.

The trust list is configurable under
`Sufficit:Identity:Mcp:ImplicitClientIds`, but expanding it is a security
decision rather than normal client registration.

## Personal Vault transport

`/api/vault/personal/secrets/{name}` exposes resolve, save and delete for
first-party secret-store clients. The server derives `user-<sub>` internally;
there is no `contextId` parameter and therefore no path to another user's or a
shared context. Plaintext resolution retains the Management audit trail.

The MCP tools continue to use the same named-secret store and personal-context
rule. Both transports share the `identity.mcp` authorization policy.

## Verification

Integration coverage proves missing-scope denial, MCP initialization with the
scope, startup provisioning idempotency, trusted-client-only implicit grants,
legacy device/refresh repair and cross-subject Vault isolation.
