# OpenID Connect Client-Initiated Backchannel Authentication (CIBA) Core 1.0

| | |
|---|---|
| Papel | OpenID Provider |
| Abrangência | **C — Parcial** |
| Origem | Próprio — o OpenIddict não tem primitivas de CIBA |
| Spec | https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html |

## Superfície

`src/sts/Controllers/CibaController.cs`, com estado persistido em
`cibapendingstates`.

| Papel | Caminho | Linha |
|---|---|---|
| Backchannel authentication (§7) | `POST /bc-authorize` | `:101` |
| Aprovação pelo usuário | `GET`/`POST /connect/ciba/complete` | `:191`, `:251` |
| Polling de token (§10) | `POST /connect/ciba/token` | `:343` |

## Modo suportado

Apenas **poll**. `ping` e `push` não são implementados.

| Requisito | § | Estado |
|---|---|---|
| `auth_req_id` opaco | 7.3 | Sim |
| `expires_in` e `interval` na resposta | 7.3 | Sim, de `CibaOptions` |
| `login_hint` resolvendo o usuário | 7.1 | Sim, e-mail ou nome de usuário |
| `binding_message` exibido antes da aprovação | 7.1 | Sim, com limite de tamanho (`:114-119`) |
| `authorization_pending` / `slow_down` | 11 | Sim |
| `expired_token` / `access_denied` | 11 | Sim |
| Permissão de escopo por cliente verificada | 7.1 | Sim (`:160-162`) |
| Política de elegibilidade do cliente | — | Sim, `ICibaClientPolicy` com modo `Observe` reportado pela verificação de postura |
| `user_code` | 7.1 | Não |
| `id_token_hint` como identificador | 7.1 | Não |
| Modo `ping` / `push` | 10.2, 10.3 | Não |

## Desvio arquitetural relevante

A especificação define o polling no **endpoint de token padrão**, com
`grant_type=urn:openid:params:grant-type:ciba`. Aqui o polling acontece em
`/connect/ciba/token`, um endpoint próprio, e a autenticação do cliente é
reimplementada lendo `client_secret` do formulário (`:111`, `:351`).

Três consequências práticas:

1. Um cliente CIBA de prateleira não funciona sem adaptação.
2. `private_key_jwt`, mTLS e a dança de nonce do DPoP **não** se aplicam
   automaticamente a esse caminho, porque não passam pelo pipeline do OpenIddict.
3. Existe uma segunda implementação de autenticação de cliente para revisar e
   manter.

A correção de projeto proposta é registrar o grant com `AllowCustomFlow` e
implementar um `CibaGrantHandler : ITokenGrantHandler`, eliminando o endpoint
próprio e herdando toda a autenticação de cliente já existente.

## Emissão de token

`src/sts/Ciba/CibaAccessTokenGenerator.cs` monta o access token diretamente, e é
o único ponto do repositório que carimba `typ: at+jwt` de forma explícita
(`:124`), fixado por `CibaTests.cs:166`.

## Testes

`CibaTests`.
