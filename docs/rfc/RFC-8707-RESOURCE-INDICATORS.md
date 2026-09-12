# RFC 8707 — Resource Indicators for OAuth 2.0

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **B — Substantial** |
| Origin | Mixed |
| Spec | https://www.rfc-editor.org/rfc/rfc8707 |

## Implementation

The `resource` parameter is processed by OpenIddict and turned into the
token's audience. The in-house layer is the **explicit registration of
accepted resources**:

```
if (options.Mcp.Resources.Count > 0)
{
    server.RegisterAudiences(options.Mcp.Resources.ToArray());
    server.RegisterResources(options.Mcp.Resources.ToArray());
}
```

`src/sts/OpenIddictServerConfiguration.cs:204-212`.

Three combined controls decide whether a `resource` becomes an audience:

1. The host allow-list above (`Sufficit:Identity:Mcp:Resources`).
2. The per-client `oi_rprm` permission, from OpenIddict.
3. Grant-level resolution in `GrantOperations.ResolveResourcesAsync`.

The effect is that **a client cannot turn an arbitrary URI into an
audience**, which is the defense RFC 8707 §3 exists to provide.

## In token exchange

The attenuation is explicit: a requested resource not authorized by the
`subject_token` returns `invalid_target`; the issued set is the intersection
(see [RFC-8693-TOKEN-EXCHANGE.md](RFC-8693-TOKEN-EXCHANGE.md)).

## Requirements

| Requirement | § | Status |
|---|---|---|
| `resource` in authorize and in token | 2 | Yes |
| Multiple `resource` values | 2 | Yes |
| Token `aud` reflects the `resource` | 2.2 | Yes |
| `invalid_target` | 2 | Yes |
| Absolute URI without a fragment | 2 | Yes, validated at registration |

## Role in MCP

The MCP authorization specification makes `resource` **mandatory** for the
client, and the resource server must reject a token whose audience is not
itself. The AS side is ready here; audience checking at the resource is each
service's own responsibility — see
[SPEC-MCP-AUTHORIZATION.md](SPEC-MCP-AUTHORIZATION.md).

## Tests

`ResourceIndicatorTests`, `AudiencesControllerTests`, `McpTests`.
