# RFC 9101 — JWT-Secured Authorization Request (JAR)

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **B — Substancial** |
| Origem | Próprio — o OpenIddict não implementa JAR |
| Spec | https://www.rfc-editor.org/rfc/rfc9101 |

## Como está implementado

Dois handlers de evento, registrados só quando `Sufficit:Identity:Jar:Enabled`
(`src/sts/OpenIddictServerConfiguration.cs:287-294`):

| Handler | Ponto |
|---|---|
| `ExtractAuthorizationRequestObject` | `/connect/authorize` |
| `ExtractPushedAuthorizationRequestObject` | `/connect/par` |

Ambos em `src/sts/Jar/JarRequestObjectHandler.cs`. Eles extraem o parâmetro
`request`, validam e mesclam os claims do objeto na requisição.

## Validação, na ordem do código

| # | Verificação | Linha |
|---|---|---|
| 1 | Parse sem validar, só para ler `alg`/`kid` | `:129` |
| 2 | `iat`, `exp` e `jti` obrigatórios; `exp > iat` | `:154-162` |
| 3 | `iat` no máximo 30 s no futuro; janela `exp - iat` limitada | `:170-171` |
| 4 | `alg` na allow-list (`PS256`, `ES256` por padrão) | `:179-183` |
| 5 | `client_id` presente no objeto e igual ao da requisição externa | `:187-200` |
| 6 | Resolução das chaves do cliente via `jwks` ou `jwks_uri` | `:205-241` |
| 7 | Validação de assinatura com `ValidateIssuer` e `ValidateAudience` ligados: `iss` = `client_id`, `aud` = issuer do OP | `:245-252` |

O passo 4 é o que fecha a família de ataques de confusão de algoritmo: `none` e
algoritmos simétricos não estão na lista e não podem ser negociados pelo cliente.

O passo 5 fecha a substituição de cliente: um objeto assinado por A não pode ser
apresentado como requisição de B.

## Chaves remotas

`src/sts/Jar/JarSigningKeyResolver.cs` busca `jwks_uri` através do
`SafeHttpHandlerFactory` (guarda anti-SSRF, sem redirecionamento para rede
interna) e mantém cache com TTL fixo — o comentário no código registra que o
honramento de `Cache-Control` (RFC 9111) foi deliberadamente trocado por TTL
fixo, para que um servidor hostil não force revalidação infinita.

## Discovery

Com JAR ligado, o documento publica `request_parameter_supported: true` e
`request_object_signing_alg_values_supported` com a allow-list ordenada
(`src/sts/OpenIddictServerConfiguration.cs:625-634`).

## Lacunas

- `request_uri` **por valor do cliente** (§5.2.2, buscar o objeto numa URL do
  cliente) não é suportado. O `request_uri` aceito é o do PAR, que é do próprio
  AS — o que é a recomendação do FAPI 2.0 de qualquer modo.
- Request object cifrado (JWE) na entrada não é suportado; só assinado.

## Testes

`JarRequestObjectTests`, `FapiJarmTests.Par`.
