# RFC 9728 — OAuth 2.0 Protected Resource Metadata

| | |
|---|---|
| Papel | Protected Resource (as APIs do próprio Identity) |
| Abrangência | **B — Substancial** |
| Origem | Próprio |
| Spec | https://www.rfc-editor.org/rfc/rfc9728 |

## Por que existe aqui

Este RFC é dirigido ao **resource server**, não ao AS. O Identity o implementa
porque também **é** um resource server: expõe o plano de management, o SCIM e o
endpoint MCP. Um cliente MCP precisa descobrir, a partir do recurso, qual é o
authorization server.

## Como está implementado

| Componente | Papel |
|---|---|
| `src/sts/Controllers/ProtectedResourceMetadataController.cs` | Serve `/.well-known/oauth-protected-resource`, anônimo |
| `src/management/Mcp/McpResourceMetadataChallenge.cs` | Emite o `WWW-Authenticate` com `resource_metadata` no 401 |

Controlado por `Sufficit:Identity:Mcp:ProtectedResourceMetadataEnabled`, que é
**`true` por padrão** (`src/sts/Options/McpOptions.cs:54`) — ao contrário da
maioria das extensões, que são opt-in.

## O ciclo completo

1. Cliente chama o recurso sem token.
2. Recurso devolve `401` com
   `WWW-Authenticate: Bearer resource_metadata="https://…/.well-known/oauth-protected-resource"`.
3. Cliente lê o documento e descobre `authorization_servers`.
4. Cliente descobre o AS por [RFC-8414-AUTHORIZATION-SERVER-METADATA.md](RFC-8414-AUTHORIZATION-SERVER-METADATA.md).
5. Cliente pede token com `resource=` ([RFC-8707-RESOURCE-INDICATORS.md](RFC-8707-RESOURCE-INDICATORS.md)).

## Requisitos

| Requisito | § | Estado |
|---|---|---|
| `resource` (identificador canônico) | 2 | Sim |
| `authorization_servers` | 2 | Sim |
| `scopes_supported` | 2 | Sim |
| `bearer_methods_supported` | 2 | Sim |
| Documento anônimo em `/.well-known/oauth-protected-resource` | 3 | Sim |
| `resource_metadata` no `WWW-Authenticate` | 5.1 | Sim |
| `scope` no desafio de 401/403 | RFC 6750 §3 | Sim, no caminho MCP |
| Documento assinado (`signed_metadata`) | 2 | Não |

## Lacunas

- Sem `signed_metadata`; o documento é servido em claro sobre TLS.
- Um documento por host, não por recurso montado: recursos distintos do mesmo
  processo compartilham o mesmo `/.well-known`.

## Testes

`McpTests`, `IdentityMcpTests`, `ManagementAuthorizationResponseTests`.
