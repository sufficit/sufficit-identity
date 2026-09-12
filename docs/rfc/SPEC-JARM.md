# JARM — JWT Secured Authorization Response Mode

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **B — Substancial** |
| Origem | Próprio |
| Spec | https://openid.net/specs/oauth-v2-jarm.html |

## Como está implementado

Ligado por `Sufficit:Identity:Jarm:Enabled` (padrão `false`). Quando ativo,
quatro modos de resposta são adicionados ao OpenIddict e um handler assume a
escrita da resposta (`src/sts/OpenIddictServerConfiguration.cs:277-285`):

| `response_mode` | Constante |
|---|---|
| `jwt` | `JarmAuthorizationResponseHandler.Jwt` |
| `query.jwt` | `QueryJwt` |
| `fragment.jwt` | `FragmentJwt` |
| `form_post.jwt` | `FormPostJwt` |

`src/sts/Jarm/JarmAuthorizationResponseHandler.cs:16-19`. Um modo fora desses
quatro não é tratado (`:50`), e a resposta segue o caminho normal.

## Conteúdo e assinatura

A resposta vira um JWT assinado pela credencial auxiliar, com vida de 120
segundos por padrão (`src/sts/Options/JarmOptions.cs:19`). O algoritmo é
publicado em `authorization_signing_alg_values_supported`
(`src/sts/OpenIddictServerConfiguration.cs:597-601`).

O que o JARM protege: em `query.jwt` os parâmetros de resposta deixam de trafegar
em claro na URL, e passam a ser um objeto assinado. Isso dá integridade e
autenticação de origem à resposta de autorização — inclusive às respostas de
erro, que sem JARM são forjáveis por quem controla o redirecionamento.

## Cifragem

Opcional (`Jarm:Encryption:Enabled`, padrão `false`). Quando ligada, resolve as
credenciais de cifragem do cliente
(`IJarmClientEncryptionCredentialsResolver`) e produz JWE com:

| Parâmetro | Padrão |
|---|---|
| Gerenciamento de chave RSA | `RSA-OAEP-256` |
| Gerenciamento de chave EC | `ECDH-ES+A256KW` |
| Cifragem de conteúdo | `A256CBC-HS512` |

`src/sts/Options/JarmOptions.cs:59-74`. Os três são publicados em discovery
quando a cifragem está ativa, como pede o perfil FAPI 2.0 Advancing.

## Lacunas

- Sem seleção de algoritmo por cliente: o `alg` é o da credencial auxiliar do OP.
- `authorization_encryption_*` são globais, não por registro de cliente.

## Testes

`FapiJarmTests`, `FapiJarmTests.Jarm`.
