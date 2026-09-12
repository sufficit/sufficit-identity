# RFC 8693 — OAuth 2.0 Token Exchange

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **C — Partial** |
| Origin | Mixed: OpenIddict grant, in-house semantics |
| Spec | https://www.rfc-editor.org/rfc/rfc8693 |

## Implementation

Grant enabled in `src/sts/OpenIddictServerConfiguration.cs:247`
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
(`azp`/`client_id`/presenter) and, when an allow-list is configured, that
this party belong to it. The check runs on **every** exchange, not only when
the allow-list is configured — a previous behavior that left the default
deployment with no defense at all.

The `Observe` mode exists as a migration escape hatch and is **reported by
`ProductionPostureCheck`**, meaning that running it in production requires
explicit acknowledgment (`src/sts/Security/StsProductionPostureContributor.cs:56-69`).

## Attenuation

| Dimension | Rule |
|---|---|
| Scopes | Intersection between the request and the `subject_token`'s scopes; with no request, it inherits all of them. |
| Resources | `invalid_target` if the requested resource is not authorized by the subject token; the result is the intersection. |
| Actor chain | `act` is **nested**, preserving the previous chain instead of overwriting it (§4.1). |
| User status | `CanSignInAsync` is revalidated; a deactivated account invalidates the exchange. |

## Requirements

| Requirement | § | Status |
|---|---|---|
| `subject_token` and `subject_token_type` | 2.1 | Yes |
| `actor_token` / `actor_token_type` | 2.1 | **Not read** |
| `requested_token_type` | 2.1 | **Not handled**; always issues an access token |
| `issued_token_type` in the response | 2.2.1 | Inherited from OpenIddict |
| `act` claim with nesting | 4.1 | Yes |
| `may_act` | 4.4 | No |
| `invalid_target` | 2.2.2 | Yes |

## Main gap

The `subject_token` must identify a **user**: if `sub` does not resolve to
an account, the exchange is rejected. This blocks:

- an agent or service with its own identity exchanging its token for a
  downstream resource token (service-to-service delegation);
- actor chains with no user at the start;
- the *Cross-App Access* / ID-JAG pattern, currently the emerging consensus
  path for agent access across SaaS applications.

The proposed design fix is to extract `ISubjectTokenResolver` with two
implementations (user and client) and to read `actor_token`.

## Tests

`TokenExchangeTests`, `TokenExchangeConfusedDeputyTests`,
`ResourceIndicatorTests`.
