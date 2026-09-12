# RFC 6750 — OAuth 2.0 Bearer Token Usage

| | |
|---|---|
| Papel | Authorization Server e Resource Server (APIs próprias) |
| Abrangência | **A — Completa** |
| Origem | OpenIddict (emissão e validação), próprio nos desafios de management |
| Spec | https://www.rfc-editor.org/rfc/rfc6750 |

## Como está implementado

O token é entregue como `Bearer` no `token_type` da resposta do endpoint de
token, salvo quando há vínculo de posse — aí vira `DPoP`
(`src/sts/Dpop/DpopTokenHandlers.cs`, handler `AttachDpopTokenType`).

As APIs próprias do Identity (management, SCIM, personal tokens, MCP) consomem o
mesmo token via `OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme`,
declarado nas policies em `src/management/ServiceCollectionExtensions.cs:211-236`
e `src/scim/ScimServiceCollectionExtensions.cs:52-56`.

## Requisitos

| Requisito | § | Estado | Evidência |
|---|---|---|---|
| Token no cabeçalho `Authorization: Bearer` | 2.1 | Sim | Esquema de validação do OpenIddict |
| Token **não** aceito em query string | 2.3 | Sim, não há leitura de `access_token` na query | — |
| `WWW-Authenticate` em 401 | 3 | Sim | `src/management/Mcp/McpResourceMetadataChallenge.cs` |
| `error="invalid_token"` em token inválido | 3.1 | Sim (OpenIddict) | — |
| `error="insufficient_scope"` em 403 | 3.1 | Sim | `ScopeRequirement` + desafio MCP |
| TLS obrigatório | 5.3 | Sim fora de Development | — |

## Detalhe relevante

O desafio de 401 do plano MCP acrescenta `resource_metadata` ao
`WWW-Authenticate`, que é o que a especificação de autorização do MCP exige —
ver [RFC-9728-PROTECTED-RESOURCE-METADATA.md](RFC-9728-PROTECTED-RESOURCE-METADATA.md).

## Testes

`IntrospectionTests`, `ManagementAuthorizationResponseTests`,
`PublicAuthenticationBoundaryTests`, `McpTests`.
