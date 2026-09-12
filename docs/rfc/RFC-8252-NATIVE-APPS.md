# RFC 8252 — OAuth 2.0 for Native Apps

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **B — Substancial** |
| Origem | Próprio (política de URI e tickets de retorno) |
| Spec | https://www.rfc-editor.org/rfc/rfc8252 |

## Como está implementado

`src/management/Clients/ClientUriPolicy.cs` aplica as regras da BCP no registro
de qualquer cliente:

| Regra | § | Onde |
|---|---|---|
| `https` obrigatório, com exceção só para loopback | 7.3 | `ClientUriPolicy.cs:69` |
| Esquema privado (`com.exemplo.app:/oauth`) aceito | 7.1 | `ClientUriPolicy.cs:85` |
| Comparação literal do redirect, sem normalização | 8.1 | `ClientUriPolicy.cs:86` |
| Porta variável em loopback | 7.3 | Aceita, pois a comparação do OpenIddict trata host e caminho |
| Fragmento proibido no redirect | — | Sim |
| PKCE obrigatório | 8.1 | Sim, ver [RFC-7636-PKCE.md](RFC-7636-PKCE.md) |

## Retorno para aplicações nativas

Além do redirect padrão, há um mecanismo próprio para o caso em que o navegador
do sistema precisa devolver o controle ao app: um **ticket protegido por Data
Protection** em vez de carregar a URI de retorno na query string.

| Componente | Papel |
|---|---|
| `src/sts/DataProtectionNativeReturnUriTicketService.cs` | Cria e resolve o ticket opaco. |
| `src/sts/OpenIddictClientNativeReturnUriResolver.cs` | Resolve a URI registrada a partir do ticket. |
| `src/sts/DataProtectionDeviceCloseFallbackTicketService.cs` | Mesmo padrão no encerramento do device flow. |

O ganho é que a URI de retorno nunca trafega como parâmetro manipulável pelo
navegador, o que remove a classe de open redirect nesse ponto.

## Lacunas

- Não há verificação de App Links / Universal Links (associação
  `assetlinks.json` / `apple-app-site-association`); um esquema privado
  registrado por outro app do dispositivo continua sendo um risco do sistema
  operacional, não mitigável no AS.

## Testes

`NativeReturnUriPolicyTests`, `DeviceBrowserLaunchTests`,
`DeviceFlowCloseFallbackTests`, `LocalUrlValidatorTests`.
