# FAPI 2.0 Security Profile

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **C — Parcial** (implementado, **não certificado**) |
| Origem | Próprio |
| Spec | https://openid.net/specs/fapi-security-profile-2_0-final.html |

O FAPI 2.0 Security Profile é especificação **Final** desde fevereiro de 2025. O
repositório implementa os controles, mas **nunca rodou a suíte de conformidade
da OpenID Foundation**. Por isso o nível é C: o comportamento existe, a prova
externa não.

## Ativação

`Sufficit:Identity:Fapi2:Enabled`, com aplicação por cliente decidida em
`Fapi2Policy.Applies` (`src/sts/Fapi/Fapi2Handlers.cs:14`). Três handlers entram
no pipeline (`src/sts/OpenIddictServerConfiguration.cs:267-276`):

| Handler | Ponto |
|---|---|
| `ValidateFapiAuthorizationRequest` | `/connect/authorize` |
| `ValidateFapiPushedAuthorizationRequest` | `/connect/par` |
| `ValidateFapiTokenRequest` | `/connect/token` |

## O que é recusado

No PAR e no authorize (`Fapi2Handlers.cs:127-182`):

| Condição | Erro |
|---|---|
| Cliente não autenticado por `private_key_jwt` nem mTLS | `invalid_client` |
| `response_type` diferente de `code` | `unsupported_response_type` |
| `redirect_uri` ausente | `invalid_request` |
| `code_challenge` ausente ou método diferente de `S256` | `invalid_request` |
| `SenderConstraint=DPoP` e `dpop_jkt` ausente ou inválido | `invalid_request` |
| Cliente sem PAR quando o perfil exige | `unauthorized_client` |

No token (`:214-232`): autenticação fraca é recusada, e com
`SenderConstraint=Mtls` o certificado precisa estar presente e vinculado.

## Tempos de vida

O perfil encurta dois valores, globalmente, porque o OpenIddict não os expõe por
cliente (`src/sts/OpenIddictServerConfiguration.cs:268-275`):

| Valor | Chave |
|---|---|
| Código de autorização | `Fapi2:AuthorizationCodeLifetimeSeconds` |
| `request_uri` do PAR | `Fapi2:PushedAuthorizationRequestLifetimeSeconds` |

Aplicar globalmente é conservador: encurta também para clientes fora do perfil,
o que é compatível para trás.

## Validação cruzada no startup

`src/sts/ServiceCollectionExtensions.Validation.cs:135-141` recusa configuração
incoerente: `SenderConstraint=DPoP` com `Dpop:Enabled=false` falha o processo,
em vez de rodar um perfil que não pode cumprir o que promete.

## Composição

O FAPI 2.0 aqui é a soma de outras peças, não uma implementação isolada:

- [RFC-9126-PAR.md](RFC-9126-PAR.md) — `request_uri` obrigatório
- [RFC-7636-PKCE.md](RFC-7636-PKCE.md) — `S256`
- [RFC-9449-DPOP.md](RFC-9449-DPOP.md) ou [RFC-8705-MUTUAL-TLS.md](RFC-8705-MUTUAL-TLS.md) — vínculo de posse
- [RFC-7523-CLIENT-ASSERTION.md](RFC-7523-CLIENT-ASSERTION.md) — autenticação forte
- [RFC-9207-ISSUER-IDENTIFICATION.md](RFC-9207-ISSUER-IDENTIFICATION.md) — anti mix-up
- [SPEC-JARM.md](SPEC-JARM.md) — resposta assinada (perfil Advancing)

## Lacunas

| Item | Estado |
|---|---|
| Suíte de conformidade FAPI 2.0 no CI | Não |
| FAPI 2.0 Message Signing | Parcial, via JARM; sem assinatura de requisição HTTP |
| FAPI 1.0 Advanced | Não |
| `request` object obrigatório no perfil | Não imposto; o PAR é o caminho |

## Testes

`FapiJarmTests`, `FapiJarmTests.Par`, `FapiJarmTests.Jarm`, `SenderConstraintTests`,
`MtlsPolicyTests`.
