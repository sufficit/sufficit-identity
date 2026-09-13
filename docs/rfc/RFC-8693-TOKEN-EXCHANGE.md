# RFC 8693 — OAuth 2.0 Token Exchange

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **B — Substantial** |
| Origin | Mixed: OpenIddict grant and token validation, in-house semantics |
| Spec | https://www.rfc-editor.org/rfc/rfc8693 |

## Implementation

Grant enabled in `src/sts/OpenIddictServerConfiguration.cs`
(`AllowTokenExchangeFlow`); the logic lives in `TokenExchangeGrantHandler`
(`src/sts/Grants/TokenGrants.cs`).

Four layers of control, in this order:

1. **Per-client permission** — `Permissions.GrantTypes.TokenExchange` on the
   registration, checked by OpenIddict's pipeline before the handler runs.
2. **Kill switch** — `Sufficit:Identity:TokenExchange:Enabled` (default `true`).
3. **Client allow-list** — `AllowedClientIds`, empty by default.
4. **Provenance policy** — `ISubjectTokenProvenancePolicy`.

## Defense against *confused deputy*

This is the strongest part of the implementation. The policy requires that
the `subject_token` carry an **unambiguous authorized party**
(`azp`/`client_id`/presenter), that the caller be an intended recipient of the
token (its party, audience or resource) and, when an allow-list is configured,
that the party belong to it. The check runs on **every** exchange.

The `Observe` mode exists as a migration escape hatch and is **reported by
`ProductionPostureCheck`** (`src/sts/Security/StsProductionPostureContributor.cs`).

## Subjects

| Subject token identifies | Accepted when |
|---|---|
| A user | The account exists and `CanSignInAsync` still allows it. |
| A client | `TokenExchange:AllowClientSubjectTokens=true` (default `false`), the token's subject is its single authorized party (the client's own token, e.g. from `client_credentials`), and the registration still exists. The issued identity is rebuilt from the registration, as in `client_credentials`, and entitlements go to the access token only. |

A client subject lets a service or agent with its own identity exchange its
token for a downstream resource token, with no user in the chain.

## Actor token

OpenIddict validates `actor_token` (signature, lifetime, type) but disables
audience and presenter validation for token exchange. The handler therefore
requires the actor token to have been **issued to the calling client**: its
single authorized party must equal the caller. A token the caller merely holds
cannot name someone else as actor.

| Actor | Resulting `act` |
|---|---|
| None | `{ "sub": <caller client_id> }` |
| The caller's own client token | `{ "sub": <caller client_id> }` |
| A user token issued to the caller | `{ "sub": <user id>, "client_id": <caller> }`; the user must still be allowed to sign in. |

An `act` already present in the subject token is nested under the new one
(§4.1).

## Attenuation

| Dimension | Rule |
|---|---|
| Scopes | Intersection between the request and the `subject_token`'s scopes; with no request, it inherits all of them. |
| Resources | `invalid_target` if the requested resource is not authorized by the subject token; the result is the intersection. |
| Actor chain | `act` is **nested**, preserving the previous chain instead of overwriting it (§4.1). |
| Subject status | User: `CanSignInAsync` is revalidated. Client: the registration must still exist. |

## Requirements

| Requirement | § | Status |
|---|---|---|
| `subject_token` and `subject_token_type` | 2.1 | Yes |
| `actor_token` / `actor_token_type` | 2.1 | Yes; must be issued to the caller |
| `requested_token_type` | 2.1 | Validated by OpenIddict against `RequestedTokenTypes`; only access tokens are supported |
| `issued_token_type` in the response | 2.2.1 | Inherited from OpenIddict |
| `act` claim with nesting | 4.1 | Yes |
| `may_act` | 4.4 | No |
| `invalid_target` | 2.2.2 | Yes |

## Remaining gaps

- `may_act` (§4.4) is not evaluated.
- Only access tokens can be requested.
- The *Cross-App Access* / ID-JAG pattern
  (draft-ietf-oauth-identity-assertion-authz-grant) is not implemented.

## Tests

`TokenExchangeTests`, `TokenExchangeDelegationTests`,
`TokenExchangeConfusedDeputyTests`, `ResourceIndicatorTests`.
