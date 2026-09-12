# OpenID Connect Discovery 1.0

| | |
|---|---|
| Papel | OpenID Provider |
| Abrangência | **A — Completa** |
| Origem | Misto |
| Spec | https://openid.net/specs/openid-connect-discovery-1_0.html |

O documento `/.well-known/openid-configuration` e a política de "não anunciar o
que não está ligado" estão descritos em
[RFC-8414-AUTHORIZATION-SERVER-METADATA.md](RFC-8414-AUTHORIZATION-SERVER-METADATA.md),
que é a especificação base. Este documento cobre só o que é específico do OIDC.

## Específico do OIDC

| Metadado | Estado |
|---|---|
| `userinfo_endpoint` | Sim |
| `id_token_signing_alg_values_supported` | Sim (OpenIddict) |
| `subject_types_supported` | `public` |
| `claims_supported` | Publicado a partir do que o controller realmente emite, incluindo os claims de aplicação do `ClaimScopeMap` (`OpenIddictServerConfiguration.cs:216-226`) |
| `scopes_supported` | Inclui os escopos padrão, `identity.management`, o escopo de personal tokens, os de aplicação e os de *entitlement* (`:180-202`) |
| `backchannel_logout_supported` | Reflete a configuração real |
| `frontchannel_logout_supported` | Reflete a configuração real |
| WebFinger (§2) | **Não implementado** |

## Consequência de `claims_supported` ser derivado

A lista não é estática: escopos e claims declarados em
`Sufficit:Identity:ClaimScopeMap` e `ScopeEntitlements` entram no documento
automaticamente. Isso mantém o STS neutro em relação ao vocabulário do produto —
um cliente registra o próprio escopo por configuração, sem alterar o código.

## Testes

`DiscoveryTests` verifica presença **e ausência** condicional de cada metadado.
