# MCP Authorization

| | |
|---|---|
| Papel | Authorization Server **e** Resource Server |
| Abrangência | **B — Substancial** |
| Origem | Misto — composição de outras especificações mais o endpoint MCP próprio |
| Spec | https://modelcontextprotocol.io/specification/draft/basic/authorization |

## O que a especificação exige do AS

| Requisito | Como é atendido |
|---|---|
| OAuth 2.1 com PKCE | [RFC-7636-PKCE.md](RFC-7636-PKCE.md); implicit e password fora |
| RS implementa RFC 9728 | [RFC-9728-PROTECTED-RESOURCE-METADATA.md](RFC-9728-PROTECTED-RESOURCE-METADATA.md) |
| AS publica RFC 8414 ou OIDC Discovery | [RFC-8414-AUTHORIZATION-SERVER-METADATA.md](RFC-8414-AUTHORIZATION-SERVER-METADATA.md) |
| CIMD como registro preferencial | [SPEC-OAUTH-CIMD.md](SPEC-OAUTH-CIMD.md) |
| DCR aceito, porém depreciado | [RFC-7591-DYNAMIC-CLIENT-REGISTRATION.md](RFC-7591-DYNAMIC-CLIENT-REGISTRATION.md) |
| `resource` obrigatório (RFC 8707) | [RFC-8707-RESOURCE-INDICATORS.md](RFC-8707-RESOURCE-INDICATORS.md) |
| `iss` na resposta e anúncio correspondente | [RFC-9207-ISSUER-IDENTIFICATION.md](RFC-9207-ISSUER-IDENTIFICATION.md) |
| Token com audiência do recurso | Sim, via allow-list de recursos |
| `WWW-Authenticate` com `resource_metadata` e `scope` | `src/management/Mcp/McpResourceMetadataChallenge.cs` |
| `403` com `insufficient_scope` para step-up | Sim, `ScopeRequirement` |

Nenhuma peça da lista está faltando. É a razão do nível B e não C.

## O servidor MCP próprio

Além de autorizar MCP de terceiros, o Identity **é** um servidor MCP:
`src/management/Controllers/McpController.cs`, protegido pela policy
`sufficit-identity-mcp` (escopo `identity.mcp`, padrão em
`src/sts/Options/McpOptions.cs:20`).

Fala JSON-RPC com `tools/list` e `tools/call` (`McpController.cs:92-101`). O
registro de ferramentas é `IdentityMcpToolRegistry`, composto por dois conjuntos
(`src/management/Mcp/McpTooling.cs:39`):

| Conjunto | Arquivo | Alcance |
|---|---|---|
| Cofre pessoal | `VaultMcpTools.cs` | Ler, gravar, listar e apagar segredos do contexto `user-<sub>` |
| Autosserviço | `SelfServiceMcpTools.cs` | Dados da própria conta |

Duas propriedades de projeto valem registro:

1. **Toda ferramenta é vinculada ao sujeito autenticado.** O contexto do cofre é
   forçado para `user-<sub>` no controller
   (`src/management/Controllers/PersonalVaultController.cs:151`), não vem do
   argumento. Um agente não alcança o segredo de outro usuário.
2. **A exclusão exige confirmação em texto claro**: a ferramenta de remoção pede
   `confirmPlaintext` além do nome (`VaultMcpTools.cs:69-72`), o que evita que um
   modelo apague um segredo por inferência de intenção.

## Escopos e provisionamento

`McpScopeProvisioner` cria o escopo exigido no startup e o concede aos clientes
de primeira parte configurados; `McpScopeGrantPolicy` decide a concessão
implícita. Os recursos aceitos como audiência vêm de `Mcp:Resources`, com
registro explícito — um agente não inventa audiência.

## Lacunas frente ao estado da arte

| Item | Estado | Comparação |
|---|---|---|
| Identidade de agente como princípio de primeira classe | Não | Entra Agent ID (GA abr/2026), Auth0 Agent-as-Principal |
| Cofre de tokens de terceiros | **Sim**, em `src/sts/Integrations/` | Equivale ao Token Vault do Auth0 |
| Delegação on-behalf-of para agente sem usuário | Não | Ver [RFC-8693-TOKEN-EXCHANGE.md](RFC-8693-TOKEN-EXCHANGE.md) |
| ID-JAG / Cross-App Access | Não | Draft-04, adotado por Anthropic, Atlassian, Slack, Notion |

A primeira e a terceira linhas são a mesma lacuna vista de ângulos diferentes: o
token exchange exige que o `subject_token` identifique um usuário, o que impede
um agente de trocar a própria identidade por acesso downstream.

## Testes

`McpTests`, `IdentityMcpTests`, `McpScopeGrantPolicy` via
`PersonalTokenScopeProvisionerTests` e `ScopeEntitlementSecurityTests`.
