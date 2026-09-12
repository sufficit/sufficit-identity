# RFC 9700 — OAuth 2.0 Security Best Current Practice

| | |
|---|---|
| Papel | Authorization Server |
| Abrangência | **B — Substancial** |
| Origem | Misto — é um documento transversal, não um recurso |
| Spec | https://www.rfc-editor.org/rfc/rfc9700 |

Este documento não descreve um endpoint; audita o repositório contra as
recomendações da BCP. É o resumo de conformidade que um revisor externo pede
primeiro.

## Recomendações principais

| Recomendação | § | Estado | Onde |
|---|---|---|---|
| Não usar implicit grant | 2.1.2 | **Cumprido**, não registrado | `OpenIddictServerConfiguration.cs:243-247` |
| Não usar Resource Owner Password Credentials | 2.4 | **Cumprido por padrão**, desligado | `:296-297` |
| PKCE para todos os clientes de código | 2.1.1 | **Cumprido** | [RFC-7636-PKCE.md](RFC-7636-PKCE.md) |
| Comparação exata de `redirect_uri` | 4.1 | Cumprido | `ClientUriPolicy.cs` |
| Rotação de refresh token ou vínculo ao cliente | 4.14 | **Cumprido**, rotação de uso único com detecção de reuso | `:358-372` |
| `iss` na resposta de autorização (anti mix-up) | 4.4 | Cumprido | [RFC-9207-ISSUER-IDENTIFICATION.md](RFC-9207-ISSUER-IDENTIFICATION.md) |
| Tokens vinculados ao remetente | 4.10 | Cumprido, DPoP e mTLS | [RFC-9449-DPOP.md](RFC-9449-DPOP.md), [RFC-8705-MUTUAL-TLS.md](RFC-8705-MUTUAL-TLS.md) |
| Restringir audiência dos tokens | 4.9 | Cumprido | [RFC-8707-RESOURCE-INDICATORS.md](RFC-8707-RESOURCE-INDICATORS.md) |
| Não colocar credencial em query string | 4.3 | Cumprido | — |
| Proteção CSRF nas etapas interativas | 4.7 | Cumprido, antiforgery validada no servidor em consent, logout e device | `AuthorizationController.cs:260-275` |
| Contramedida a *clickjacking* | 4.5 | Cumprido, CSP e cabeçalhos de segurança | `SecurityHeadersMiddlewareExtensions.cs` |
| Limitar tempo de vida do código | 4.1 | Cumprido, e reduzido sob FAPI | `:270-272` |
| Autenticação forte do cliente | 4.13 | Disponível: `private_key_jwt` e mTLS; obrigatória sob FAPI | [RFC-7523-CLIENT-ASSERTION.md](RFC-7523-CLIENT-ASSERTION.md) |
| Segredos de cliente não armazenados em claro | — | Cumprido, `PasswordHasher` V3 | `src/core/Services/ClientCredentialSecretHasher.cs:24-27` |

## Mitigações adicionais, além da BCP

| Controle | Onde |
|---|---|
| Verificação de postura que recusa subir em produção com achado não reconhecido | `src/sts/Security/ProductionPostureCheck.cs` |
| Limite de taxa por grupo de endpoint, com bucket separado para introspecção, PAR, device-info e administração | `src/server/IdentityRateLimitPolicy.cs` |
| Guarda anti-SSRF em toda saída HTTP (JWKS remoto, CIMD, HIBP, push SSF) | `src/sts/SafeHttpHandlerFactory.cs` |
| Lockout de conta e política de senha de 12 caracteres | `src/sts/Options/AccountPolicyOptions.cs:14-48` |
| Verificação de senha vazada (HIBP, k-anonymity) | `src/sts/BreachedPasswordValidator.cs` |
| Sessões server-side revogáveis por dispositivo | `src/sts/OidcUserSessionTicketStore.cs` |
| Revogação em cascata ao mudar credencial | `src/sts/CredentialMutationSecurityCoordinator.cs:114-155` |

## Pontos de atenção conhecidos

| Item | Risco | Nota |
|---|---|---|
| `Sufficit:Identity:Issuer` vazio | `iss` segue o cabeçalho `Host` | Configurar sempre |
| `RateLimit:FailOnUntrustedProxy = false` | Sem proxies confiáveis, o limite por IP colapsa num bucket só | Ligar em produção |
| `Password:RejectBreached = false` | HIBP desligado por padrão, e falha aberta | Ligar em produção |
| Grant de senha com enumeração por tempo | O hash só é calculado quando o usuário existe | Grant desligado por padrão |
| Vínculo de identidade externa sem `email_verified` | Conta criada e vinculada antes da prova de posse do e-mail | Corrigir antes de abrir registro público |

Os cinco estão detalhados, com cenário e correção, na avaliação independente mais
recente em `docs/evaluations/`.
