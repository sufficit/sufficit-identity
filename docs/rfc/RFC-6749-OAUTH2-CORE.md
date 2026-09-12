# RFC 6749 — OAuth 2.0 Authorization Framework

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **B — Substancial** |
| Origem | OpenIddict 7.7, configurado em `src/sts/OpenIddictServerConfiguration.cs` |
| Spec | https://www.rfc-editor.org/rfc/rfc6749 |

## Como está implementado

Os endpoints do framework são registrados em
`src/sts/OpenIddictServerConfiguration.cs:43-53` e servidos em modo
*passthrough*: o OpenIddict valida o protocolo e o `AuthorizationController`
decide a emissão.

| Endpoint | Caminho | Handler |
|---|---|---|
| Authorization (§3.1) | `/connect/authorize` | `src/sts/Controllers/AuthorizationController.cs:102-104` |
| Token (§3.2) | `/connect/token` | `src/sts/Controllers/AuthorizationController.cs:366-370` |

O endpoint de token não implementa a lógica de grant diretamente: delega para
`TokenGrantDispatcher`, que resolve um `ITokenGrantHandler` por `grant_type`
(`src/sts/Grants/TokenGrants.cs`). Cada grant é uma classe.

## Grants

Registrados em `src/sts/OpenIddictServerConfiguration.cs:243-247`:

| Grant | §  | Estado | Handler |
|---|---|---|---|
| `authorization_code` | 4.1 | Habilitado | `UserTokenGrantsHandler` |
| `client_credentials` | 4.4 | Habilitado | `ClientCredentialsGrantHandler` |
| `refresh_token` | 6 | Habilitado, rotativo | `UserTokenGrantsHandler` |
| `urn:ietf:params:oauth:grant-type:device_code` | RFC 8628 | Habilitado | `DeviceCodeGrantHandler` |
| `urn:ietf:params:oauth:grant-type:token-exchange` | RFC 8693 | Habilitado | `TokenExchangeGrantHandler` |
| `password` | 4.3 | **Desligado por padrão** | `PasswordGrantHandler` |
| `implicit` | 4.2 | **Não registrado** | — |
| `none` / hybrid | — | **Desligado por padrão** | — |

`implicit` não é registrado em lugar nenhum. `password` e `none` só existem sob
`Sufficit:Identity:LegacyGrants`, cujos dois campos são `false` por padrão
(`src/sts/OpenIddictServerConfiguration.cs:296-300`). A justificativa e o risco
estão em [RFC-9700-OAUTH-SECURITY-BCP.md](RFC-9700-OAUTH-SECURITY-BCP.md).

## Requisitos principais

| Requisito | § | Estado | Evidência |
|---|---|---|---|
| Registro prévio de `redirect_uri` | 3.1.2.2 | Sim | `src/management/Clients/ClientUriPolicy.cs` |
| Comparação exata de `redirect_uri` | 3.1.2.3 | Sim (OpenIddict, string simples) | — |
| `state` repassado sem alteração | 4.1.2 | Sim (OpenIddict) | — |
| Autenticação do cliente confidencial | 2.3 | Sim, múltiplos métodos | [RFC-7523-CLIENT-ASSERTION.md](RFC-7523-CLIENT-ASSERTION.md), [RFC-8705-MUTUAL-TLS.md](RFC-8705-MUTUAL-TLS.md) |
| Código de autorização de uso único | 4.1.2 | Sim (OpenIddict, com detecção de reuso) | — |
| `scope` validado contra o cliente | 3.3 | Sim, permissão `oi_scp` por cliente | `src/management/Clients/ClientPermissionPolicy.cs` |
| TLS obrigatório | 1.6 | Sim fora de Development | `src/sts/OpenIddictServerConfiguration.cs:644-650` |
| Erros conforme §4.1.2.1 / §5.2 | 4.1.2.1, 5.2 | Sim | `TokenGrantDispatcher.ForbidError` |

## Desvios deliberados

- **Sem implicit/hybrid.** OAuth 2.1 e RFC 9700 os removem; o OpenIddict 5+ os
  depreca. Clientes legados precisam migrar para `authorization_code` + PKCE.
- **PKCE obrigatório** mesmo para clientes confidenciais quando
  `Pkce.RequireForAllClients` (padrão do deployment), o que vai além do RFC 6749.
- **Refresh token rotativo e de uso único**, com revogação da família em reuso.
  O RFC 6749 §6 apenas permite; aqui é imposto.

## Configuração

| Chave | Padrão | Efeito |
|---|---|---|
| `Sufficit:Identity:LegacyGrants:Password` | `false` | Habilita o grant de senha. |
| `Sufficit:Identity:LegacyGrants:None` | `false` | Habilita o fluxo `none`. |
| `Sufficit:Identity:Tokens:RefreshTokenLifetimeDays` | `14` | Validade do refresh token. |
| `Sufficit:Identity:Issuer` | vazio | Fixa o `iss`; vazio deriva do request. |

## Testes

`AuthorizationCodeFlowTests`, `ClientCredentialsTests`, `RefreshTokenTests`,
`PasswordGrantTests`, `DeviceFlowTests`, `TokenExchangeTests`.

## Lacunas

- `Sufficit:Identity:Issuer` vazio faz o `iss` seguir o cabeçalho `Host`. Em
  produção deve ser sempre configurado.
- Nenhuma execução da OpenID Conformance Suite está automatizada no CI, logo a
  conformidade é auditada por leitura e testes próprios, não certificada.
