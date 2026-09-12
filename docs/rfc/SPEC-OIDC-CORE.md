# OpenID Connect Core 1.0

| | |
|---|---|
| Role | OpenID Provider |
| Coverage | **B — Substantial** |
| Origin | Mixed: OpenIddict, with in-house controller and projections |
| Spec | https://openid.net/specs/openid-connect-core-1_0.html |

## Flows

**Authorization Code Flow** (§3.1) only. Implicit (§3.2) and Hybrid (§3.3) are
not registered — see [RFC-9700-OAUTH-SECURITY-BCP.md](RFC-9700-OAUTH-SECURITY-BCP.md).

## Endpoints

| Role | Path |
|---|---|
| Authorization (§3.1.2) | `/connect/authorize` |
| Token (§3.1.3) | `/connect/token` |
| UserInfo (§5.3) | `/connect/userinfo` |
| JWKS (§10) | `/.well-known/openid-configuration/jwks` |

## `id_token`

Issued by OpenIddict with `iss`, `sub`, `aud`, `exp`, `iat`, `nonce` and
`auth_time`. Identity claims are included based on scope, decided in
`GrantOperations.GetDestinations` (`src/sts/Grants/GrantOperations.cs:264-330`):

| Claim | Condition |
|---|---|
| `name`, `preferred_username` | `profile` scope |
| `email`, `email_verified` | `email` scope |
| `role` | `roles` scope |
| `amr`, `acr`, `auth_time` | Always, in both tokens |
| `sid` | Only in the `id_token` |
| `cnf` | Only in the access token |
| `AspNet.Identity.SecurityStamp` | **Never issued** |

The last row matters: the security stamp is ASP.NET Identity internal state,
and leaking it into a token would give a client the ability to correlate
invalidations. The `switch` explicitly discards it (`:306-307`).

## UserInfo

`src/sts/Controllers/AuthorizationController.cs:385-390`. Claims are reloaded
from `UserManager` at call time — not replicated from the token — and filtered
by scope (`:437-470`). `email_verified` reflects the account's current state,
not the state at issuance time.

## `prompt` and `max_age`

| Parameter | Behavior |
|---|---|
| `prompt=none` | Returns `login_required`, `consent_required` or `interaction_required` without interaction |
| `prompt=login` | Forces reauthentication via `AuthorizationReauthenticationPolicy` |
| `prompt=consent` | Participates in the consent policy instead of bypassing it |
| `max_age` | Requires recent authentication; `max_age=0` uses a signed receipt to avoid a loop |

The handling of `prompt=consent` deserves a note: the previous implementation
**skipped** the consent check when the parameter was present, exactly the
opposite of what was requested. Today it goes through the centralized policy
(`AuthorizationController.cs:290-330`).

## Consent

`AuthorizationConsentPolicy` evaluates the client's `ConsentType` (implicit,
explicit, systematic, external). When interaction is needed,
`/connect/authorize` redirects to `/consent` carrying the original query; the
UI posts back to the same endpoint with `consent_decision`, and
**antiforgery is validated on the server**
(`AuthorizationController.cs:260-275`). The host is API-only and doesn't
register MVC's automatic filter, so the Blazor component alone would not be
enough.

The UI can **narrow** scopes on resubmission; widening them doesn't work,
because OpenIddict's scope validation runs again on the resubmitted request.

## `sub`

Stable, it's the user's identifier in ASP.NET Identity. There is no
pairwise/pseudonymous subject identifier (§8.1); `sub` is the same for every
client.

## Gaps

| Item | § | Status |
|---|---|---|
| Implicit and Hybrid | 3.2, 3.3 | No, by decision |
| `claims` parameter | 5.5 | No |
| `request_uri` pointing to the client | 6.2 | No, only via PAR |
| Pairwise `sub` | 8.1 | No |
| `id_token` encrypted for the client | 10.2 | No |
| ACR requestable via `acr_values` | 3.1.2.1 | No |
| OpenID certification | — | Not performed |

## Tests

`AuthorizationCodeFlowTests`, `ConsentFallbackIntegrationTests`,
`AuthorizationConsentPolicyTests`, `AuthorizationReauthenticationIntegrationTests`,
`ClaimScopeMapTests`, `RetiredIdentityScopeTests`.
