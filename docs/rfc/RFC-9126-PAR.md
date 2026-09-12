# RFC 9126 — OAuth 2.0 Pushed Authorization Requests

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **A — Completa** |
| Origem | OpenIddict, com política FAPI e limites próprios |
| Spec | https://www.rfc-editor.org/rfc/rfc9126 |

## Como está implementado

Endpoint `/connect/par`, registrado em
`src/sts/OpenIddictServerConfiguration.cs:53`; com mTLS ganha o alias
`/connect/par/mtls`. O processamento é do OpenIddict.

| Requisito | § | Estado |
|---|---|---|
| `request_uri` opaco de uso único | 2.2 | Sim |
| Vida curta do `request_uri` | 2.2 | Sim, configurável |
| Autenticação do cliente no PAR | 2 | Sim |
| `request_uri` recusado após consumo | 2.2 | Sim, e o erro é humanizado no navegador |
| `require_pushed_authorization_requests` em discovery | 5 | Sim |
| Exigência global de PAR | — | `Par:RequireForAllClients` |
| Exigência por cliente sob FAPI | — | Sim, `ValidateFapiAuthorizationRequest` |

## Tempo de vida

Dois pontos escrevem `RequestTokenLifetime`:

1. FAPI 2.0, quando habilitado, fixa
   `Fapi2:PushedAuthorizationRequestLifetimeSeconds` — global, porque o
   OpenIddict não tem essa configuração por cliente
   (`src/sts/OpenIddictServerConfiguration.cs:272-275`).
2. `Par:RequestUriLifetimeSeconds`, se configurado
   (`:415-419`).

Como ambos escrevem a mesma propriedade, a ordem importa: a configuração de PAR
é aplicada depois e prevalece. Um deployment FAPI que também configure
`Par:RequestUriLifetimeSeconds` está sobrescrevendo o valor do perfil.

## Replay do `request_uri`

Consumir um `request_uri` já usado gera um erro interno do OpenIddict (ID2013)
que, numa navegação de nível superior, chegaria ao usuário como payload cru. O
handler `RenderBrowserFriendlyAuthorizationError`
(`src/sts/ErrorPages/BrowserAuthorizationErrorPage.cs`, registrado em
`src/sts/OpenIddictServerConfiguration.cs:262-265`) converte isso em página
legível, preservando o payload para clientes de máquina.

## Limite de taxa

Bucket próprio `par`: 30 requisições por minuto por IP
(`src/sts/Options/RateLimitOptions.cs:48-50`), separado do bucket de token.

## Testes

`FapiJarmTests.Par`, `ParLoginRoundTripTests`, `BrowserAuthorizationErrorTests`.
