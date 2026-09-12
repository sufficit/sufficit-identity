# Conformidade com RFCs e especificações

Um documento por especificação: o que o Sufficit Identity implementa, **como**,
e até onde vai. A fonte de verdade é o código; cada afirmação aqui cita
`arquivo:linha`. Quando código e texto divergirem, o código vence e este
documento é que está errado.

## Escala de abrangência

| Nível | Significado |
|---|---|
| **A — Completa** | Todos os `MUST` e os `SHOULD` aplicáveis ao papel exercido, com teste automatizado. |
| **B — Substancial** | Todos os `MUST`; algum `SHOULD` ou recurso opcional ausente, listado no documento. |
| **C — Parcial** | Subconjunto interoperável em produção, com lacunas relevantes declaradas. |
| **D — Mínima** | Apenas o necessário para outra funcionalidade operar; não é uma implementação do perfil. |
| **— Ausente** | Não implementado, por decisão registrada. |

O papel exercido importa: em quase tudo o Identity é **Authorization Server**
(AS) ou **OpenID Provider** (OP). Requisitos dirigidos ao cliente ou ao resource
server não contam contra a nota, e estão marcados como fora de escopo.

## Origem da implementação

| Origem | Significado |
|---|---|
| `OpenIddict` | Comportamento herdado do OpenIddict 7.7 e apenas configurado aqui. |
| `Próprio` | Escrito neste repositório, porque o OpenIddict não cobre. |
| `Misto` | Base do OpenIddict com handlers próprios no pipeline de eventos. |

## Índice — IETF

| RFC | Assunto | Nível | Origem | Documento |
|---|---|---|---|---|
| 6749 | OAuth 2.0 Authorization Framework | B | OpenIddict | [RFC-6749-OAUTH2-CORE.md](RFC-6749-OAUTH2-CORE.md) |
| 6750 | Bearer Token Usage | A | OpenIddict | [RFC-6750-BEARER-TOKEN.md](RFC-6750-BEARER-TOKEN.md) |
| 7009 | Token Revocation | A | OpenIddict | [RFC-7009-TOKEN-REVOCATION.md](RFC-7009-TOKEN-REVOCATION.md) |
| 7519 + JOSE | JWT, JWS, JWE, JWK, JWA | B | Misto | [RFC-7519-JWT-AND-JOSE.md](RFC-7519-JWT-AND-JOSE.md) |
| 7523 | JWT client assertions (`private_key_jwt`) | B | OpenIddict | [RFC-7523-CLIENT-ASSERTION.md](RFC-7523-CLIENT-ASSERTION.md) |
| 7591 | Dynamic Client Registration | C | Próprio | [RFC-7591-DYNAMIC-CLIENT-REGISTRATION.md](RFC-7591-DYNAMIC-CLIENT-REGISTRATION.md) |
| 7636 | PKCE | A | OpenIddict | [RFC-7636-PKCE.md](RFC-7636-PKCE.md) |
| 7643/7644 | SCIM 2.0 | C | Próprio | [RFC-7643-7644-SCIM.md](RFC-7643-7644-SCIM.md) |
| 7662 | Token Introspection | A | OpenIddict | [RFC-7662-TOKEN-INTROSPECTION.md](RFC-7662-TOKEN-INTROSPECTION.md) |
| 8176 | Authentication Method Reference (`amr`) | C | Próprio | [RFC-8176-AMR-VALUES.md](RFC-8176-AMR-VALUES.md) |
| 8252 | OAuth 2.0 for Native Apps | B | Próprio | [RFC-8252-NATIVE-APPS.md](RFC-8252-NATIVE-APPS.md) |
| 8414 | Authorization Server Metadata | A | Misto | [RFC-8414-AUTHORIZATION-SERVER-METADATA.md](RFC-8414-AUTHORIZATION-SERVER-METADATA.md) |
| 8417/8935/8936 | Security Event Token e entrega | B | Próprio | [RFC-8417-SECURITY-EVENT-TOKEN.md](RFC-8417-SECURITY-EVENT-TOKEN.md) |
| 8628 | Device Authorization Grant | A | Misto | [RFC-8628-DEVICE-AUTHORIZATION-GRANT.md](RFC-8628-DEVICE-AUTHORIZATION-GRANT.md) |
| 8693 | Token Exchange | C | Misto | [RFC-8693-TOKEN-EXCHANGE.md](RFC-8693-TOKEN-EXCHANGE.md) |
| 8705 | Mutual-TLS client auth e tokens vinculados | B | Misto | [RFC-8705-MUTUAL-TLS.md](RFC-8705-MUTUAL-TLS.md) |
| 8707 | Resource Indicators | B | Misto | [RFC-8707-RESOURCE-INDICATORS.md](RFC-8707-RESOURCE-INDICATORS.md) |
| 9068 | JWT Profile for Access Tokens | B | Misto | [RFC-9068-JWT-ACCESS-TOKEN.md](RFC-9068-JWT-ACCESS-TOKEN.md) |
| 9101 | JWT-Secured Authorization Request (JAR) | B | Próprio | [RFC-9101-JAR.md](RFC-9101-JAR.md) |
| 9126 | Pushed Authorization Requests (PAR) | A | Misto | [RFC-9126-PAR.md](RFC-9126-PAR.md) |
| 9207 | Authorization Server Issuer Identification | A | OpenIddict | [RFC-9207-ISSUER-IDENTIFICATION.md](RFC-9207-ISSUER-IDENTIFICATION.md) |
| 9449 | DPoP | B | Próprio | [RFC-9449-DPOP.md](RFC-9449-DPOP.md) |
| 9700 | OAuth 2.0 Security Best Current Practice | B | Misto | [RFC-9700-OAUTH-SECURITY-BCP.md](RFC-9700-OAUTH-SECURITY-BCP.md) |
| 9728 | Protected Resource Metadata | B | Próprio | [RFC-9728-PROTECTED-RESOURCE-METADATA.md](RFC-9728-PROTECTED-RESOURCE-METADATA.md) |

## Índice — OpenID Foundation, W3C e drafts

| Especificação | Nível | Origem | Documento |
|---|---|---|---|
| OpenID Connect Core 1.0 | B | Misto | [SPEC-OIDC-CORE.md](SPEC-OIDC-CORE.md) |
| OpenID Connect Discovery 1.0 | A | Misto | [SPEC-OIDC-DISCOVERY.md](SPEC-OIDC-DISCOVERY.md) |
| RP-Initiated, Front-Channel e Back-Channel Logout | B | Misto | [SPEC-OIDC-LOGOUT.md](SPEC-OIDC-LOGOUT.md) |
| CIBA Core 1.0 | C | Próprio | [SPEC-OIDC-CIBA.md](SPEC-OIDC-CIBA.md) |
| JARM | B | Próprio | [SPEC-JARM.md](SPEC-JARM.md) |
| FAPI 2.0 Security Profile | C | Próprio | [SPEC-FAPI-2-0.md](SPEC-FAPI-2-0.md) |
| Shared Signals Framework, CAEP e RISC | C | Próprio | [SPEC-SSF-CAEP-RISC.md](SPEC-SSF-CAEP-RISC.md) |
| WebAuthn Level 2 e passkeys | B | ASP.NET Identity | [SPEC-WEBAUTHN-PASSKEYS.md](SPEC-WEBAUTHN-PASSKEYS.md) |
| OAuth Client ID Metadata Document (draft) | B | Próprio | [SPEC-OAUTH-CIMD.md](SPEC-OAUTH-CIMD.md) |
| MCP Authorization | B | Misto | [SPEC-MCP-AUTHORIZATION.md](SPEC-MCP-AUTHORIZATION.md) |

## Não implementado, por decisão

| Especificação | Motivo |
|---|---|
| SAML 2.0 | Fora do escopo do produto; nenhum consumidor SAML. |
| OpenID Connect Session Management 1.0 (`check_session_iframe`) | Substituído por sessões server-side e back-channel logout; o iframe depende de cookies de terceiros. |
| Identity Assertion JWT Authorization Grant (ID-JAG) | Draft; avaliado como próximo passo para acesso entre aplicações de agentes. |
| OAuth 2.0 Device Posture / RFC 9396 (RAR) | Sem demanda; `scope` + `resource` cobrem os casos atuais. |
| Implicit e Hybrid flow | Removidos deliberadamente — ver [RFC-9700-OAUTH-SECURITY-BCP.md](RFC-9700-OAUTH-SECURITY-BCP.md). |
| Resource Owner Password Credentials | Desligado por padrão, mantido só como compatibilidade migratória. |
