# Identity Assertion JWT Authorization Grant (ID-JAG)

| | |
|---|---|
| Role | IdP Authorization Server and Resource Authorization Server |
| Coverage | **C — Partial** |
| Origin | In-house on top of OpenIddict's token exchange and custom grant hooks |
| Spec | https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/ (draft-04) |

ID-JAG is the Cross-App Access pattern: a client that holds a user's identity
assertion from an IdP asks that IdP for a signed grant addressed to another
authorization server, then redeems the grant there for an access token,
without a new consent round trip. Both roles are **disabled by default** and
configured under `Sufficit:Identity:IdentityAssertions`
(`src/sts/Options/IdentityAssertionOptions.cs`).

## IdP role — issuing a grant (§4.3)

Token exchange with `requested_token_type=urn:ietf:params:oauth:token-type:id-jag`,
branched from `TokenExchangeGrantHandler` to `IdentityAssertionIssuer`
(`src/sts/Grants/IdentityAssertionGrants.cs`). OpenIddict validates the
subject token; the custom token type is registered in `RequestedTokenTypes`
only when issuance is enabled (`src/sts/OpenIddictServerConfiguration.cs`).

| Rule | Behavior |
|---|---|
| `subject_token_type` | `id_token` or `refresh_token`; anything else is `invalid_request`. |
| Subject binding | An ID Token must list the caller in `aud`; a refresh token must be presented by the caller. Otherwise `invalid_grant`. |
| `audience` | Exactly one, matching a configured `Audiences[].Issuer` or alias; otherwise `invalid_target`. Aliases resolve to the issuer placed in `aud`. The configured values are registered with OpenIddict, which also requires the client permission `aud:<value>` for the value sent. |
| Client allow-list | `AllowedClientIds` per audience; `unauthorized_client` when set and not matched. |
| User status | The user must still exist and be allowed to sign in. |
| `scope`, `resource` | Values from the receiving server's catalog, so `DeferIdentityAssertionRequestValidation` moves them out of OpenIddict's local scope and resource validation (registering them would publish them in this server's discovery). They are passed through, or intersected with `AllowedScopes` / `AllowedResources`; an empty result is `invalid_scope` / `invalid_target`, and each resource must be an absolute URI. |
| `client_id` claim | The caller, or its mapping in `ClientIdMap` (the client's id at the resource authorization server). |
| `authorization_details` | Rejected: RAR is not implemented. |
| `actor_token` | Ignored; the draft leaves its processing out of scope. |

The grant is a JWT with header `typ=oauth-id-jag+jwt`, signed with the STS
signing key (published JWKS), carrying `iss`, `sub`, `aud`, `client_id`, `jti`,
`iat`, `exp`, and when available `scope`, `resource`, `auth_time`, `acr`,
`amr`, the confirmed `email` (`IncludeEmail`) and `cnf.jkt` when the request
carried a DPoP proof. Lifetime is `LifetimeSeconds` (default 300, 60..3600).
The response has `issued_token_type`, `access_token`, `token_type=N_A`,
`expires_in` and the granted `scope`, with `Cache-Control: no-store`.

## Resource authorization server role — redeeming a grant (§4.4)

The RFC 7523 `urn:ietf:params:oauth:grant-type:jwt-bearer` grant, registered
with `AllowCustomFlow` only when redemption is enabled, handled by
`IdentityAssertionGrantHandler`. The client needs the grant-type permission
and must be confidential.

| Rule | Behavior |
|---|---|
| Issuer | `iss` must exactly match a `TrustedIssuers[].Issuer`. |
| `typ` | Must be `oauth-id-jag+jwt`. |
| `aud` | A string or a single-element array equal to this server's issuer. |
| `client_id` | Must equal the authenticated client. |
| Signature and lifetime | Keys from `JwksUri`, or from the issuer's discovery document (whose `issuer` must match), fetched through the public-HTTPS JWKS provider. `jti` and `iat` are required and `exp - iat` is bounded by `MaxAssertionLifetimeSeconds`. |
| Subject | Resolved only through an existing external login named `LoginProvider` whose key equals `sub`. Email is never used, so an IdP cannot claim an arbitrary local account. No just-in-time provisioning. |
| Scopes | Asserted scopes, limited by `AllowedScopes` and the client's scope permissions; `offline_access` is dropped. |
| Resources | Derived from the granted scopes and narrowed to the asserted `resource` values. |
| Authentication context | Foreign `amr`/`acr` are not projected; step-up stays with local authentication. |
| Refresh token | Not issued (§4.4.3). |

Grants are not single-use: the draft lets a client re-submit an unexpired
grant to obtain a new access token.

## Metadata (§7)

When enabled, discovery publishes
`identity_chaining_requested_token_types_supported: ["urn:ietf:params:oauth:token-type:id-jag"]`
(issuance) and `authorization_grant_profiles_supported:
["urn:ietf:params:oauth:grant-profile:id-jag"]` (redemption). The jwt-bearer
grant type appears in `grant_types_supported` through OpenIddict.

## Gaps

- Rich Authorization Requests (`authorization_details`).
- SAML 2.0 assertions as subject tokens and `sub_id` NameID resolution (§3.2, §4.5).
- Multi-tenant claims (`tenant`, `aud_tenant`, `aud_sub`).
- Client metadata `authorization_grant_profiles_supported` in dynamic registration (§8).

## Tests

`IdentityAssertionGrantTests`.
