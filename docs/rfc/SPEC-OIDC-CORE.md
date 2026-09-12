# OpenID Connect Core 1.0

| | |
|---|---|
| Papel | OpenID Provider |
| Abrangência | **B — Substancial** |
| Origem | Misto: OpenIddict, com controller e projeções próprias |
| Spec | https://openid.net/specs/openid-connect-core-1_0.html |

## Fluxos

Somente **Authorization Code Flow** (§3.1). Implicit (§3.2) e Hybrid (§3.3) não
são registrados — ver [RFC-9700-OAUTH-SECURITY-BCP.md](RFC-9700-OAUTH-SECURITY-BCP.md).

## Endpoints

| Papel | Caminho |
|---|---|
| Authorization (§3.1.2) | `/connect/authorize` |
| Token (§3.1.3) | `/connect/token` |
| UserInfo (§5.3) | `/connect/userinfo` |
| JWKS (§10) | `/.well-known/openid-configuration/jwks` |

## `id_token`

Emitido pelo OpenIddict com `iss`, `sub`, `aud`, `exp`, `iat`, `nonce` e
`auth_time`. Os claims de identidade entram conforme escopo, decidido em
`GrantOperations.GetDestinations` (`src/sts/Grants/GrantOperations.cs:260-326`):

| Claim | Condição |
|---|---|
| `name`, `preferred_username` | escopo `profile` |
| `email`, `email_verified` | escopo `email` |
| `role` | escopo `roles` |
| `amr`, `acr`, `auth_time` | Sempre, em ambos os tokens |
| `sid` | Apenas no `id_token` |
| `cnf` | Apenas no access token |
| `AspNet.Identity.SecurityStamp` | **Nunca emitido** |

A última linha importa: o security stamp é estado interno do ASP.NET Identity, e
vazá-lo num token daria a um cliente a capacidade de correlacionar invalidações.
O `switch` o descarta explicitamente (`:302-303`).

## UserInfo

`src/sts/Controllers/AuthorizationController.cs:385-390`. Os claims são
recarregados do `UserManager` no momento da chamada — não replicados do token —
e filtrados por escopo (`:437-470`). `email_verified` reflete o estado atual da
conta, não o do instante da emissão.

## `prompt` e `max_age`

| Parâmetro | Comportamento |
|---|---|
| `prompt=none` | Devolve `login_required`, `consent_required` ou `interaction_required` sem interação |
| `prompt=login` | Força reautenticação via `AuthorizationReauthenticationPolicy` |
| `prompt=consent` | Participa da política de consentimento em vez de contorná-la |
| `max_age` | Exige autenticação recente; `max_age=0` usa um recibo assinado para evitar laço |

O tratamento de `prompt=consent` merece nota: a implementação anterior **pulava**
a verificação de consentimento quando o parâmetro estava presente, exatamente o
inverso do pedido. Hoje ele entra na política centralizada
(`AuthorizationController.cs:290-330`).

## Consentimento

`AuthorizationConsentPolicy` avalia o `ConsentType` do cliente (implicit,
explicit, systematic, external). Quando é preciso interagir, o `/connect/authorize`
redireciona para `/consent` repassando a query original; a UI reposta ao mesmo
endpoint com `consent_decision`, e a **antiforgery é validada no servidor**
(`AuthorizationController.cs:260-275`). O host é API-only e não registra o filtro
automático do MVC, portanto o componente Blazor sozinho não bastaria.

A UI pode **estreitar** os escopos na reapresentação; ampliá-los não funciona,
porque a validação de escopo do OpenIddict roda de novo na requisição reposta.

## `sub`

Estável, é o identificador do usuário no ASP.NET Identity. Não há
pairwise/pseudonymous subject identifier (§8.1); o `sub` é o mesmo para todos os
clientes.

## Lacunas

| Item | § | Estado |
|---|---|---|
| Implicit e Hybrid | 3.2, 3.3 | Não, por decisão |
| `claims` parameter | 5.5 | Não |
| `request_uri` apontando para o cliente | 6.2 | Não, só via PAR |
| Pairwise `sub` | 8.1 | Não |
| `id_token` cifrado para o cliente | 10.2 | Não |
| ACR solicitável por `acr_values` | 3.1.2.1 | Não |
| Certificação OpenID | — | Não executada |

## Testes

`AuthorizationCodeFlowTests`, `ConsentFallbackIntegrationTests`,
`AuthorizationConsentPolicyTests`, `AuthorizationReauthenticationIntegrationTests`,
`ClaimScopeMapTests`, `RetiredIdentityScopeTests`.
