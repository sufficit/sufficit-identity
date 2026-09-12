# RFC 7009 — OAuth 2.0 Token Revocation

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **A — Completa** |
| Origem | OpenIddict; endpoint registrado em `src/sts/OpenIddictServerConfiguration.cs:48` |
| Spec | https://www.rfc-editor.org/rfc/rfc7009 |

## Como está implementado

`POST /connect/revocation`, servido inteiramente pelo OpenIddict. Com mTLS
habilitado ganha o alias `/connect/revocation/mtls`
(`src/sts/OpenIddictServerConfiguration.cs:75-77`), como exige o RFC 8705 §5.

| Requisito | § | Estado |
|---|---|---|
| Revoga `refresh_token` e `access_token` | 2.1 | Sim |
| `token_type_hint` aceito e opcional | 2.1 | Sim |
| Autenticação do cliente exigida | 2.1 | Sim |
| Cliente só revoga os próprios tokens | 2.1 | Sim |
| `200 OK` para token inexistente | 2.2 | Sim |
| Revogação em cascata do refresh | 2.1 | Sim, revoga a autorização associada |

## Revogação fora do endpoint

Além do RFC, há três caminhos administrativos que revogam sem o cliente pedir:

| Caminho | Onde | Efeito |
|---|---|---|
| Mutação de credencial | `src/sts/CredentialMutationSecurityCoordinator.cs:114-155` | Rotaciona o security stamp e revoga tokens, autorizações e sessões de navegador. |
| Revogação de sessão | `src/management/Sessions/` | Encerra sessões de um usuário em todos os dispositivos. |
| Revogação de autorização | `src/management/Authorizations/` | Invalida o *grant* e os tokens dele derivados. |

Os três emitem sinal CAEP `session-revoked` quando o SSF está ligado — ver
[SPEC-SSF-CAEP-RISC.md](SPEC-SSF-CAEP-RISC.md).

## Testes

`PasswordResetRevocationTests`, `SessionsAndAuthorizationsControllerTests`,
`RefreshTokenTests`.
