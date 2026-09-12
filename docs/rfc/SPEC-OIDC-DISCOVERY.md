# OpenID Connect Discovery 1.0

| | |
|---|---|
| Role | OpenID Provider |
| Coverage | **A — Complete** |
| Origin | Mixed |
| Spec | https://openid.net/specs/openid-connect-discovery-1_0.html |

The `/.well-known/openid-configuration` document and the "don't announce what
isn't wired up" policy are described in
[RFC-8414-AUTHORIZATION-SERVER-METADATA.md](RFC-8414-AUTHORIZATION-SERVER-METADATA.md),
which is the base spec. This document covers only what's specific to OIDC.

## OIDC-specific

| Metadata | Status |
|---|---|
| `userinfo_endpoint` | Yes |
| `id_token_signing_alg_values_supported` | Yes (OpenIddict) |
| `subject_types_supported` | `public` |
| `claims_supported` | Published from what the controller actually issues, including application claims from `ClaimScopeMap` (`OpenIddictServerConfiguration.cs:216-226`) |
| `scopes_supported` | Includes the default scopes, `identity.management`, the personal tokens scope, application scopes and *entitlement* scopes (`:180-202`) |
| `backchannel_logout_supported` | Reflects the actual configuration |
| `frontchannel_logout_supported` | Reflects the actual configuration |
| WebFinger (§2) | **Not implemented** |

## Consequence of `claims_supported` being derived

The list is not static: scopes and claims declared in
`Sufficit:Identity:ClaimScopeMap` and `ScopeEntitlements` are automatically
included in the document. This keeps the STS neutral with respect to the
product's vocabulary — a client registers its own scope through
configuration, without changing code.

## Tests

`DiscoveryTests` verifies presence **and** conditional absence of each
metadata field.
