# RFC 8628 — OAuth 2.0 Device Authorization Grant

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **A — Completa** |
| Origem | OpenIddict, com controller de verificação e guarda de replay próprios |
| Spec | https://www.rfc-editor.org/rfc/rfc8628 |

## Endpoints

| Papel | Caminho | Registro |
|---|---|---|
| Device authorization (§3.1) | `/connect/deviceauthorization` | `src/sts/OpenIddictServerConfiguration.cs:49` |
| End-user verification (§3.3) | `/connect/device` | `src/sts/OpenIddictServerConfiguration.cs:50` |
| Token, `grant_type=device_code` | `/connect/token` | `DeviceCodeGrantHandler` |

`src/sts/Controllers/DeviceController.cs` serve a página de verificação
(`GET /connect/device`, `:150`) e processa a aprovação
(`POST /connect/device`, `:289`) com validação de antiforgery no servidor.

## Guarda de replay do device code

`src/sts/Tokens/DeviceCodeReplayGuard.cs` (`RejectRedeemedDeviceCodeReplay`,
registrado em `src/sts/OpenIddictServerConfiguration.cs:257`).

O problema: o cliente faz *polling*. Duas requisições simultâneas podem
apresentar o mesmo `device_code`. A heurística nativa de detecção de roubo do
OpenIddict interpretaria isso como reuso e **revogaria todos os tokens da
autorização** — inclusive os que acabaram de ser emitidos ao vencedor da corrida,
cujo `userinfo` passaria a devolver 401. O handler converte esse caso em
`invalid_grant` simples, que é o que o §3.5 manda.

## Endpoint anônimo de informação

`GET /connect/device/info` (`DeviceController.cs:231-234`) devolve dados do
cliente para a tela de confirmação a partir do `user_code`. Por ser anônimo e
enumerável, tem **bucket de limite próprio**: 12 requisições por minuto por IP
(`src/sts/Options/RateLimitOptions.cs:57-59`), separado dos demais para que uma
tentativa de enumeração não drene a cota de credenciais.

## Requisitos

| Requisito | § | Estado |
|---|---|---|
| `device_code`, `user_code`, `verification_uri`, `expires_in`, `interval` | 3.2 | Sim (OpenIddict) |
| `authorization_pending` enquanto não aprovado | 3.5 | Sim, `DeviceCodeGrantHandler` |
| `slow_down` em polling agressivo | 3.5 | Sim (OpenIddict) |
| `expired_token` e `access_denied` | 3.5 | Sim |
| `user_code` de entropia adequada | 5.1 | Sim (OpenIddict) |
| Limite de tentativa por força bruta no `user_code` | 5.2 | Sim, via bucket `interactive` e o bucket de `device/info` |
| Estado do usuário revalidado na emissão | — | Sim: `CanSignInAsync` e claims reconstruídas do estado atual |

## Encerramento no navegador

Após aprovar, o navegador precisa fechar ou voltar ao app. Isso usa um ticket
protegido em vez de URI na query (`DataProtectionDeviceCloseFallbackTicketService`,
`DeviceFlowCloseReportController`), mesmo padrão de
[RFC-8252-NATIVE-APPS.md](RFC-8252-NATIVE-APPS.md).

## Testes

`DeviceFlowTests`, `DeviceFlowCloseFallbackTests`, `DeviceFlowCloseReportTests`,
`DeviceBrowserLaunchTests`.
