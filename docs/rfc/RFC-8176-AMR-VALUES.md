# RFC 8176 — Authentication Method Reference Values

| | |
|---|---|
| Papel | OpenID Provider |
| Abrangência | **C — Parcial** |
| Origem | Próprio |
| Spec | https://www.rfc-editor.org/rfc/rfc8176 |

## Como está implementado

`AuthenticationContextProjection` (`src/sts/AuthenticationContextProjection.cs`)
projeta três claims para o token e o `id_token`: `amr`, `acr` e `auth_time`
(`:35-37`). O destino é ambos os tokens
(`src/sts/Grants/GrantOperations.cs:289-294`).

Os valores são gravados no momento do login e preservados na renovação do
principal, para que uma revalidação de security stamp não rebaixe uma sessão que
já fez MFA (`src/sts/ServiceCollectionExtensions.cs:541-560`).

| Situação | `amr` emitido | `acr` |
|---|---|---|
| Senha | `pwd` | `urn:sufficit:acr:loa1` |
| Senha + dispositivo com MFA lembrado | `pwd`, `mfa` | `urn:sufficit:acr:loa2` |
| Senha + TOTP | `pwd`, `otp`, `mfa` | `urn:sufficit:acr:loa2` |
| Grant de senha (legado) | `pwd` | `urn:sufficit:acr:loa1` |

## Consumo

O plano de management exige evidência de segundo fator: `MfaRequirement` aceita
os valores `mfa`, `otp`, `hwk`, `sms`, `vcm`, `fpt`, `eye`, `voice` e `retina`
(`src/management/ServiceCollectionExtensions.cs:377-380`), todos do registro do
RFC 8176. A mesma exigência vale para emissão de personal tokens e gestão de
streams SSF.

## Lacunas

- **`acr` não usa URNs padronizadas.** `urn:sufficit:acr:loa1|loa2` é vocabulário
  próprio; não há mapeamento para os valores do ISO/IEC 29115 nem para
  `http://schemas.openid.net/pape/policies/2007/06/multi-factor`. Um RP de
  terceiro não sabe interpretar. Correção sugerida: tornar o vocabulário
  configurável em `AssuranceLevelOptions`.
- Passkeys não emitem `hwk` nem `swk` distintamente; entram no caminho de MFA
  como fator verificado.
- `acr_values` na requisição não seleciona política de autenticação; só
  `max_age` e `prompt=login` forçam reautenticação.

## Testes

`AuthenticationContextProjectionTests`, `AuthorizationReauthenticationPolicyTests`,
`ManagementApplicationAuthorizationTests`.
