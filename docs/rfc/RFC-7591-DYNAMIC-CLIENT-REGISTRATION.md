# RFC 7591 — OAuth 2.0 Dynamic Client Registration

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **C — Parcial** |
| Origem | Próprio — o OpenIddict não implementa DCR |
| Spec | https://www.rfc-editor.org/rfc/rfc7591 |

## Como está implementado

`POST /connect/register`, em `src/sts/Controllers/RegistrationController.cs`.
Desligado por padrão (`Sufficit:Identity:Mcp:Dcr:Enabled = false`,
`src/sts/Options/McpOptions.cs:87`). Quando desligado, responde `404` em vez de
`403`, para não revelar a existência do endpoint (`RegistrationController.cs:80-86`).

O endpoint é anunciado no documento de discovery apenas quando habilitado
(`src/sts/OpenIddictServerConfiguration.cs:556-565`).

## Três portões

1. **Habilitação** (`Dcr.Enabled`).
2. **Initial access token** (`RequireInitialAccessToken`, padrão `true`):
   comparação em tempo constante do cabeçalho `Authorization`, com expiração
   obrigatória; sem token configurado o endpoint responde `503`, e não passa
   (`RegistrationController.cs:88-140`). Opcionalmente de uso único.
3. **Perfil anônimo** (quando `RequireInitialAccessToken=false`): só cliente
   público, sem segredo, restrito a `AnonymousGrantTypes` e `AnonymousScopes`
   (`RegistrationController.cs:173-220`).

## O que é validado no registro

| Item | Regra |
|---|---|
| `redirect_uris` | `https` salvo loopback, sem fragmento — `ClientUriPolicy` |
| `grant_types` | Somente os da allow-list; `password` e `implicit` recusados |
| `scope` | Escopos reservados (`identity.management`, `scim`) bloqueados |
| `token_endpoint_auth_method` | `none`, `client_secret_basic`, `client_secret_post` |
| `jwks_uri` | HTTPS pública, validada contra SSRF |
| `client_id` fornecido pelo chamador | Recusado salvo `AllowCallerSuppliedClientIds` |
| `client_secret` fornecido pelo chamador | Recusado salvo `AllowCallerSuppliedSecrets` |

Todo cliente nasce com `ConsentType=Explicit` e, se usar `authorization_code`,
com PKCE exigido (`RegistrationController.cs:149`).

## Proveniência

O registro grava marcadores nas propriedades da aplicação — origem, data,
se foi anônimo, IP e user-agent
(`RegistrationController.cs:36-52`), de modo que o console distingue cliente
auto-registrado de cliente criado por operador.

## Limite de taxa

Bucket próprio `client-registration`
(`src/server/IdentityRateLimitPolicy.cs`, método `GetCredentialGroup`).

## Lacunas

- **Sem RFC 7592**: não há `registration_access_token` nem endpoint de
  leitura/atualização/exclusão do cliente registrado. O ciclo de vida pós-registro
  é só pelo plano de management.
- O initial access token é um segredo estático compartilhado, sem atribuição por
  registrante. Proposta de correção registrada na avaliação: emiti-lo como token
  de referência do OpenIddict.
- `software_statement` (§2.3) não é aceito.
- A especificação de autorização do MCP **depreca** DCR em favor de CIMD — ver
  [SPEC-OAUTH-CIMD.md](SPEC-OAUTH-CIMD.md).

## Testes

`ProvisioningControllerTests`, `ClientDefinitionPolicyTests`, `McpTests`,
`IdentityMcpTests`.
