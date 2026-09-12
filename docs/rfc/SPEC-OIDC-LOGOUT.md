# RP-Initiated, Front-Channel e Back-Channel Logout

| | |
|---|---|
| Papel | OpenID Provider |
| Abrangência | **B — Substancial** |
| Origem | Misto |
| Specs | RP-Initiated Logout 1.0, Front-Channel Logout 1.0, Back-Channel Logout 1.0 |

## RP-Initiated Logout

`GET /connect/endsession` (e o alias `/connect/logout`) valida o pedido pelo
OpenIddict e redireciona para a página de confirmação da UI
(`src/sts/Controllers/AuthorizationController.Logout.cs:37-64`).

Detalhe de implementação relevante: a etapa intermediária **não** repassa o
`id_token_hint`. Só `post_logout_redirect_uri` e `state` seguem para a UI. O
motivo está registrado no código — um JWT no cabeçalho `Location` já estourou o
buffer de resposta do nginx e transformou logout válido em 502. O pedido já foi
validado pelo OpenIddict nesse ponto; a UI não precisa do hint.

O `POST` executa a saída (`:66-224`) com antiforgery validada no servidor. Há uma
exceção deliberada: se a validação falhar **e não houver sessão ativa**, o pedido
segue. O ataque que a proteção existe para impedir é forçar o logout de quem
*está* autenticado; recusar quem já não tem sessão só converteria "sair" em erro
de protocolo numa página que o usuário não pode mais usar.

## Back-Channel Logout

Anunciado apenas quando `BackchannelLogout:Enabled`
(`src/sts/OpenIddictServerConfiguration.cs:506-511`). O dispatcher distribui
`logout_token` assinado aos RPs registrados, com limite de 8 segundos e captura
de exceção: um RP lento ou fora do ar **não** impede a saída local
(`AuthorizationController.Logout.cs:150-170`).

| Requisito | Estado |
|---|---|
| `logout_token` assinado com `events` e `sid` | Sim |
| `sub` ou `sid` presente | Sim, ambos quando disponíveis |
| Fan-out só para RPs com sessão | Sim, resolvido antes da saída |
| RP que exige `sid` é pulado quando não há `sid` | Sim (`BackchannelLogoutDistributor.cs:138`) |
| Falha de RP não bloqueia a saída local | Sim |
| Repetição com backoff | Não |

## Front-Channel Logout

Página de fan-out em iframe, `GET /connect/frontchannel-logout`
(`AuthorizationController.Logout.cs:225-227`). O ponto de projeto: as URLs dos RP
**nunca** vêm da query string. O que trafega é um identificador opaco de contexto
(`logout_context`), preparado antes da saída enquanto o sujeito ainda é
conhecido, e resolvido no servidor. Isso remove a classe de open redirect que
essa página normalmente carrega.

## Efeitos colaterais da saída

| Efeito | Onde |
|---|---|
| Sessão server-side removida | `OidcUserSessionTicketStore` |
| Sinal CAEP `session-revoked` | `_sharedSignalsDispatcher.SessionRevokedAsync` |
| Cookie de MFA lembrada descartado quando `force_mfa` | `ForgetTwoFactorClientAsync` |

## Lacunas

- Session Management 1.0 (`check_session_iframe`) não é implementado, por
  decisão: depende de cookies de terceiros, hoje bloqueados por padrão nos
  navegadores. As sessões server-side e o back-channel cobrem o caso.
- Sem repetição de `logout_token` para RP indisponível.

## Testes

`BackchannelLogoutTests`, `FrontchannelLogoutTests`,
`FrontchannelLogoutReplayTests`, `ServerSideSessionsTests`.
