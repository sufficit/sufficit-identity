# RFC 8707 — Resource Indicators for OAuth 2.0

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **B — Substancial** |
| Origem | Misto |
| Spec | https://www.rfc-editor.org/rfc/rfc8707 |

## Como está implementado

O parâmetro `resource` é processado pelo OpenIddict e transformado em audiência
do token. A camada própria é o **registro explícito de recursos aceitos**:

```
if (options.Mcp.Resources.Count > 0)
{
    server.RegisterAudiences(options.Mcp.Resources.ToArray());
    server.RegisterResources(options.Mcp.Resources.ToArray());
}
```

`src/sts/OpenIddictServerConfiguration.cs:204-212`.

Três controles somados decidem se um `resource` vira audiência:

1. A allow-list do host acima (`Sufficit:Identity:Mcp:Resources`).
2. A permissão `oi_rprm` por cliente, do OpenIddict.
3. A resolução por grant em `GrantOperations.ResolveResourcesAsync`.

O efeito é que **um cliente não transforma uma URI arbitrária em audiência**, que
é a defesa que o RFC 8707 §3 existe para dar.

## No token exchange

A atenuação é explícita: recurso pedido que não esteja autorizado pelo
`subject_token` devolve `invalid_target`; o conjunto emitido é a interseção
(ver [RFC-8693-TOKEN-EXCHANGE.md](RFC-8693-TOKEN-EXCHANGE.md)).

## Requisitos

| Requisito | § | Estado |
|---|---|---|
| `resource` no authorize e no token | 2 | Sim |
| Múltiplos `resource` | 2 | Sim |
| `aud` do token reflete o `resource` | 2.2 | Sim |
| `invalid_target` | 2 | Sim |
| URI absoluta sem fragmento | 2 | Sim, validado no registro |

## Papel no MCP

A especificação de autorização do MCP torna o `resource` **obrigatório** para o
cliente, e o resource server deve recusar token cuja audiência não seja ele.
Aqui o lado AS está pronto; a checagem de audiência no recurso é de cada
serviço — ver [SPEC-MCP-AUTHORIZATION.md](SPEC-MCP-AUTHORIZATION.md).

## Testes

`ResourceIndicatorTests`, `AudiencesControllerTests`, `McpTests`.
