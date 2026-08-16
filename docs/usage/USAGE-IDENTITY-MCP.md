# USAGE-IDENTITY-MCP — Vault and self-service tools

O Identity expõe um servidor MCP compacto no endpoint `/api/mcp` quando a
superfície opcional de Management está habilitada. O prefixo acompanha
`Sufficit:Identity:Management:RoutePrefix`; portanto, com o prefixo padrão, a
rota é `/api/mcp`.

## Habilitação

O host precisa registrar o Management normalmente:

```json
{
  "Sufficit": {
    "Identity": {
      "Management": {
        "Enabled": true,
        "RequireAuthorization": true
      }
    }
  }
}
```

O MCP exige um access token Bearer autenticado. O token precisa conter `sub`;
esse subject é a única identidade usada pelas ferramentas `me_*` e pelo
contexto pessoal do Vault.

## Handshake

Envie `initialize` com o Bearer token:

```http
POST /api/mcp
Authorization: Bearer <access-token>
Content-Type: application/json

{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}
```

A resposta devolve `mcp-session-id`. Envie esse header em todas as requisições
seguintes. A sessão expira após 30 minutos de inatividade e fica vinculada ao
`sub` que a criou; outro usuário não consegue reutilizá-la.

## Ferramentas

As cinco ferramentas de Vault são `vault_list`, `vault_get_info`, `vault_save`,
`vault_delete` e `vault_resolve`. Sem `contextId`, elas operam no contexto
pessoal `user-<sub>`. Um contexto explícito é uma operação compartilhada e
exige a capability correspondente:

- leitura (`vault_list`, `vault_get_info`): `identity.vault.secrets.read`;
- escrita (`vault_save`, `vault_delete`): `identity.vault.secrets.manage`;
- resolução em texto claro (`vault_resolve`):
  `identity.vault.secrets.resolve`.

`vault_resolve` só responde quando `confirmPlaintext=true`. Toda resolução,
inclusive segredo ausente ou expirado, é registrada na auditoria. Listagem e
metadados nunca incluem valores.

As ferramentas de self-service são `me_get`, `me_update`,
`me_sessions_list`, `me_session_revoke`, `me_authorizations_list` e
`me_authorization_revoke`. Elas só leem ou alteram objetos pertencentes ao
subject autenticado. Troca de senha, e-mail e MFA permanece na UI com
verificação de step-up e não é exposta ao agente.

## Compatibilidade com o sufficit-ai

O sufficit-ai continua podendo consumir seu endpoint MCP durante a transição,
mas seu cliente REST de Vault aponta para o mesmo named-secret store do
Identity. Segredos `ai/<referência>` mantêm o namespace usado pelos agentes;
contextos pessoais continuam no formato `user-<guid>`, sem fallback para um
contexto global.

Para validar a composição local:

```sh
dotnet test src/tests/Sufficit.Identity.Tests.csproj --filter FullyQualifiedName~IdentityMcpTests
```
