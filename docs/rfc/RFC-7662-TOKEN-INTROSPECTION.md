# RFC 7662 — OAuth 2.0 Token Introspection

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **A — Completa** |
| Origem | OpenIddict; endpoint em `src/sts/OpenIddictServerConfiguration.cs:47` |
| Spec | https://www.rfc-editor.org/rfc/rfc7662 |

## Como está implementado

`POST /connect/introspect`, servido pelo OpenIddict. É o caminho principal de
validação porque o padrão do deployment é **access token por referência**
(`UseReferenceAccessTokens()`, `src/sts/OpenIddictServerConfiguration.cs:405`):
o valor entregue ao cliente é opaco e só o AS sabe traduzi-lo.

| Requisito | § | Estado | Observação |
|---|---|---|---|
| Autenticação do chamador | 2.1 | Sim | Cliente confidencial ou token de portador autorizado. |
| `active` como campo obrigatório | 2.2 | Sim | — |
| Resposta mínima para token inativo | 2.2 | Sim, só `active: false` | Evita oráculo de existência. |
| `scope`, `client_id`, `sub`, `exp` | 2.2 | Sim | — |
| `cnf` para tokens vinculados | RFC 8705 §3.2 | Sim | Thumbprint mTLS repassado. |
| Alias mTLS do endpoint | RFC 8705 §5 | Sim | `/connect/introspect/mtls`. |

## Limite de taxa

A introspecção tem bucket próprio de 300 requisições por minuto por IP, separado
do bucket de 30/min dos demais endpoints `POST /connect/*`
(`src/server/IdentityRateLimitPolicy.cs`, `src/sts/Options/RateLimitOptions.cs:39-40`).
Sem essa separação, um resource server chatty consumiria a cota de emissão.

## Introspecção de personal access tokens

Há um endpoint próprio, `POST /api/account/tokens/introspect`
(`src/sts/Controllers/PersonalTokensController.cs:497`), com forma de resposta
semelhante mas escopo diferente: serve para um resource server descobrir se um
token pessoal continua ativo. Devolve `inactive` em qualquer falha, sem
distinguir causa.

## Testes

`IntrospectionTests`, `PersonalTokensTests`, `MtlsPolicyTests`.
