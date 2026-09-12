# RFC 7662 — OAuth 2.0 Token Introspection

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **A — Complete** |
| Origin | OpenIddict; endpoint in `src/sts/OpenIddictServerConfiguration.cs:47` |
| Spec | https://www.rfc-editor.org/rfc/rfc7662 |

## Implementation

`POST /connect/introspect`, served by OpenIddict. It is the primary
validation path because the deployment defaults to **reference access
tokens** (`UseReferenceAccessTokens()`, `src/sts/OpenIddictServerConfiguration.cs:405`):
the value handed to the client is opaque, and only the AS can resolve it.

| Requirement | § | Status | Note |
|---|---|---|---|
| Caller authentication | 2.1 | Yes | Confidential client or authorized bearer token. |
| `active` as a mandatory field | 2.2 | Yes | — |
| Minimal response for an inactive token | 2.2 | Yes, only `active: false` | Avoids an existence oracle. |
| `scope`, `client_id`, `sub`, `exp` | 2.2 | Yes | — |
| `cnf` for bound tokens | RFC 8705 §3.2 | Yes | mTLS thumbprint carried through. |
| mTLS alias for the endpoint | RFC 8705 §5 | Yes | `/connect/introspect/mtls`. |

## Rate limit

Introspection has its own bucket of 300 requests per minute per IP, separate
from the 30/min bucket shared by the other `POST /connect/*` endpoints
(`src/server/IdentityRateLimitPolicy.cs`, `src/sts/Options/RateLimitOptions.cs:39-40`).
Without that separation, a chatty resource server could consume the issuance
quota.

## Personal access token introspection

There is a dedicated endpoint, `POST /api/account/tokens/introspect`
(`src/sts/Controllers/PersonalTokensController.cs:497`), with a similar
response shape but a different scope: it lets a resource server discover
whether a personal token is still active. It returns `inactive` on any
failure, without distinguishing the cause.

## Tests

`IntrospectionTests`, `PersonalTokensTests`, `MtlsPolicyTests`.
