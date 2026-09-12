# RFC 7521 / RFC 7523 — Client assertions com JWT (`private_key_jwt`)

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **B — Substancial** |
| Origem | OpenIddict, com política própria de JWKS do cliente |
| Spec | https://www.rfc-editor.org/rfc/rfc7523 |

## Como está implementado

`private_key_jwt` é habilitado **incondicionalmente** pelo OpenIddict; não há
flag para desligar (nota em `src/sts/OpenIddictServerConfiguration.cs:60-62`).
O cliente autentica no endpoint de token apresentando
`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
e um JWT assinado por chave cuja pública está registrada.

O registro dessas chaves é próprio: `src/management/Clients/ClientJwksPolicy.cs`
valida tanto o JWKS inline quanto o `jwks_uri`.

| Regra aplicada | Onde |
|---|---|
| `jwks_uri` precisa ser HTTPS absoluta, pública, sem user-info nem fragmento | `ClientJwksPolicy.cs:37-50` |
| Somente chaves públicas `RSA` ou `EC` | `ClientJwksPolicy.cs:135-140` |
| `kid` obrigatório e único no conjunto | `ClientJwksPolicy.cs:144-149` |
| Limite de quantidade de chaves | `ClientJwksPolicy.cs:23` |
| Busca remota do `jwks_uri` passa pelo guarda anti-SSRF | `src/sts/SafeHttpHandlerFactory.cs` |

## Onde é exigido

- **FAPI 2.0**: o cliente precisa autenticar com `private_key_jwt` **ou** mTLS;
  segredo compartilhado é recusado
  (`src/sts/Fapi/Fapi2Handlers.cs:151` e `:226`).
- Demais clientes confidenciais podem usar `client_secret_basic` ou
  `client_secret_post`, com o segredo armazenado apenas como hash — ver
  [RFC-6749-OAUTH2-CORE.md](RFC-6749-OAUTH2-CORE.md).

## Correção de segurança herdada

O OpenIddict 7.7 corrigiu a validação do `aud` em client assertions
(GHSA-925x-4h4v-2792) e passou a aceitar `aud` como array JSON. O repositório
está nessa versão (`Directory.Packages.props`), portanto a correção está
presente.

## Lacunas

- O grant `urn:ietf:params:oauth:grant-type:jwt-bearer` (RFC 7523 §2.1,
  *autorização* por assertion, não autenticação) **não** está habilitado. É a
  peça que faltaria para o draft ID-JAG.
- Não há rotação assistida de JWKS do cliente; o operador troca o documento.

## Testes

`ClientsControllerTests.Credentials`, `ClientDefinitionPolicyTests`,
`FapiJarmTests`, `JarRequestObjectTests` (reaproveita a resolução de chaves).
