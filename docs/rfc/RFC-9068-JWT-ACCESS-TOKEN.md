# RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **B — Substancial** |
| Origem | Misto |
| Spec | https://www.rfc-editor.org/rfc/rfc9068 |

## Dois formatos coexistindo

O deployment liga `UseReferenceAccessTokens()`
(`src/sts/OpenIddictServerConfiguration.cs:405`), portanto o **padrão é token
por referência** — opaco, validado por introspecção. O perfil JWT é aplicado
seletivamente.

A escolha é por cliente **e** por recurso, decidida em
`src/sts/Tokens/AccessTokenFormatPolicy.cs`, acionada pelo handler
`ApplyAccessTokenFormat` (`src/sts/OpenIddictServerConfiguration.cs:250`).

| Configuração | Efeito |
|---|---|
| `Tokens:AccessTokenFormatsByClient` | Formato por `client_id` |
| `Tokens:AccessTokenFormatsByResource` | Formato por recurso/audiência |
| `Tokens:UseReferenceAccessTokens` | Fallback global (`true`) |

Ambos os mapas são validados no startup
(`src/sts/ServiceCollectionExtensions.Validation.cs:31-35`), de modo que um
valor inválido falha o processo em vez de silenciosamente cair no fallback.

## Claims do perfil

Quando o formato é JWT, o token carrega `iss`, `exp`, `aud`, `sub`, `client_id`,
`iat`, `jti` (OpenIddict) e os claims de autorização projetados por
`GrantOperations.GetDestinations` — `scope`, `roles` quando o escopo permite, e
os claims de aplicação mapeados por `ClaimScopeMap`.

Para tokens de `client_credentials`, os *entitlements* do registro do cliente são
carimbados como claim de autorização explicitamente destinada ao access token
(`ClientCredentialsGrantHandler`), o que é o uso previsto no §2.2.3.2.

## Requisitos

| Requisito | § | Estado |
|---|---|---|
| `iss`, `exp`, `aud`, `sub`, `client_id`, `iat`, `jti` | 2.2 | Sim |
| Assinatura assimétrica | 4 | Sim, `RS256`/`PS256`/`ES256` |
| `typ: at+jwt` no cabeçalho | 2.1 | Explícito no CIBA; herdado do OpenIddict nos demais |
| Claims de identidade limitados por escopo | 2.2.3.1 | Sim |
| Claims de autorização (`scope`, `groups`, `roles`, `entitlements`) | 2.2.3.2 | Sim |
| Rejeitar token sem `aud` no RS | 4 | Responsabilidade do resource server |

## Sobre o `typ: at+jwt`

O único ponto do repositório que carimba o cabeçalho explicitamente é o gerador
de token do CIBA (`src/sts/Ciba/CibaAccessTokenGenerator.cs:124`), fixado por
`CibaTests.cs:166`. Nos demais grants o carimbo vem do OpenIddict e **não é
verificável a partir deste repositório** nem coberto por teste próprio.

Isso é uma lacuna de verificação, não necessariamente de comportamento: se um dia
o framework mudar, nada aqui percebe. O carimbo é o que impede um resource server
descuidado de aceitar um `id_token` onde espera um access token. Correção barata:
um teste que decodifica o header do access token JWT em cada grant e exige
`at+jwt`.

## Testes

`AccessTokenFormatPolicyTests`, `TokenIssuancePolicyTests`,
`ClientEntitlementsTests.Issuance`.
