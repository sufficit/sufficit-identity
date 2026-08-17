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

## Como as aplicações se conectam

Diferente do sufficit-ai — onde era preciso gerar um token e colar na
configuração — aqui o próprio Identity é o Authorization Server, então o
cliente MCP negocia o acesso sozinho.

### Clientes MCP (Claude Code, VS Code, Claude Desktop)

Basta apontar para a URL; o login abre no navegador:

```sh
claude mcp add --transport http sufficit-identity https://identity.sufficit.com.br/api/mcp
```

O que acontece por baixo (não precisa configurar nada disso):

1. o cliente chama `/api/mcp` sem token e recebe `401` com
   `WWW-Authenticate: Bearer resource_metadata="https://identity.sufficit.com.br/.well-known/oauth-protected-resource"`;
2. lê esse documento (RFC 9728) e descobre o Authorization Server — o próprio
   Identity;
3. lê `/.well-known/openid-configuration` e executa Authorization Code + PKCE
   no navegador;
4. usa o access token resultante em todas as chamadas.

O `sub` desse token é **o seu usuário** — é ele que define o vault pessoal
(`user-<sub>`) e o alvo das ferramentas `me_*`.

Pré-requisito para o passo 3: o cliente precisa existir no Identity. Duas
formas:

- **Registro dinâmico (recomendado para ferramentas de terceiros):** habilite
  `Sufficit:Identity:Mcp:Dcr:Enabled=true` (RFC 7591, `/connect/register`). É
  opt-in e, por padrão, exige um initial access token
  (`Sufficit:Identity:Mcp:Dcr:InitialAccessToken`, resolvido pelo vault) —
  mantenha essa exigência ligada.
- **Client fixo:** registre um client público com PKCE e o redirect URI do
  cliente MCP (Claude Code usa `http://localhost:<porta>/callback`).

### Aplicações de serviço (sem usuário)

Um daemon que só precisa ler segredos compartilhados usa `client_credentials`
e o `Sufficit.Identity.Vault.Client` REST — **não** o MCP. Motivo: nesse fluxo
não existe usuário, então não há vault pessoal nem `me_*`; o client precisa das
capabilities de vault e sempre informa um `contextId` explícito.

### Token manual (depuração)

```sh
curl -s -X POST https://identity.sufficit.com.br/connect/token \
  -d grant_type=client_credentials -d client_id=... -d client_secret=... \
  -d scope=identity.management | jq -r .access_token
```

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

## Auto-registro (DCR) e o console de registros

Habilitar o auto-registro:

```json
{
  "Sufficit": {
    "Identity": {
      "Mcp": {
        "Dcr": {
          "Enabled": true,
          "RequireInitialAccessToken": false
        }
      }
    }
  }
}
```

Com `RequireInitialAccessToken=false` qualquer cliente MCP se registra sozinho,
mas o registro é **anônimo** e o cliente nasce restrito ao perfil de login
interativo — imposto no servidor, não por configuração:

- público (sem client secret) e obrigatoriamente PKCE;
- grants apenas `authorization_code` e `refresh_token`
  (`Sufficit:Identity:Mcp:Dcr:AnonymousGrantTypes`);
- escopos apenas `openid`, `profile`, `offline_access`
  (`Sufficit:Identity:Mcp:Dcr:AnonymousScopes`) — nenhum escopo de API ou
  administrativo, portanto o client não alcança o Management;
- pedidos fora desse perfil são **recusados** (400), nunca reduzidos em
  silêncio.

Mantendo `RequireInitialAccessToken=true`, o registro segue exigindo o token
inicial e pode receber o que a allowlist geral (`AllowedGrantTypes` /
`AllowedScopes`) permitir.

Todo cliente criado por DCR é carimbado com sua procedência (origem, instante,
endereço de origem e user-agent). Consulte em:

- **UI:** *Aplicações → Registros automáticos* (`/clients/registrations`) —
  lista, mostra de onde veio cada registro e permite revogar (remove tokens e
  consentimentos junto, com auditoria).
- **API:** `GET /api/clients?origin=dcr` — a listagem traz `origin`,
  `registeredAtUtc`, `registeredAnonymously`, `registeredFromAddress` e
  `registeredUserAgent`. Revogação: `DELETE /api/clients/{clientId}`.
