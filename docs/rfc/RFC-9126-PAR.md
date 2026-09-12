# RFC 9126 — OAuth 2.0 Pushed Authorization Requests

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **A — Complete** |
| Origin | OpenIddict, with an in-house FAPI policy and limits |
| Spec | https://www.rfc-editor.org/rfc/rfc9126 |

## Implementation

Endpoint `/connect/par`, registered in
`src/sts/OpenIddictServerConfiguration.cs:53`; with mTLS it gains the alias
`/connect/par/mtls`. Processing is handled by OpenIddict.

| Requirement | § | Status |
|---|---|---|
| Single-use opaque `request_uri` | 2.2 | Yes |
| Short lifetime for `request_uri` | 2.2 | Yes, configurable |
| Client authentication at PAR | 2 | Yes |
| `request_uri` rejected after consumption | 2.2 | Yes, and the error is humanized in the browser |
| `require_pushed_authorization_requests` in discovery | 5 | Yes |
| Global PAR requirement | — | `Par:RequireForAllClients` |
| Per-client requirement under FAPI | — | Yes, `ValidateFapiAuthorizationRequest` |

## Lifetime

Two places write `RequestTokenLifetime`:

1. FAPI 2.0, when enabled, sets
   `Fapi2:PushedAuthorizationRequestLifetimeSeconds` — global, because
   OpenIddict has no per-client setting for it
   (`src/sts/OpenIddictServerConfiguration.cs:272-275`).
2. `Par:RequestUriLifetimeSeconds`, if configured
   (`:415-419`).

Since both write to the same property, order matters: the PAR configuration
is applied afterward and takes precedence. A FAPI deployment that also
configures `Par:RequestUriLifetimeSeconds` is overriding the profile's value.

## `request_uri` replay

Consuming an already-used `request_uri` raises an internal OpenIddict error
(ID2013) that, on a top-level navigation, would reach the user as raw
payload. The `RenderBrowserFriendlyAuthorizationError` handler
(`src/sts/ErrorPages/BrowserAuthorizationErrorPage.cs`, registered in
`src/sts/OpenIddictServerConfiguration.cs:262-265`) converts this into a
readable page, while preserving the payload for machine clients.

## Rate limit

A dedicated `par` bucket: 30 requests per minute per IP
(`src/sts/Options/RateLimitOptions.cs:48-50`), separate from the token
bucket.

## Tests

`FapiJarmTests.Par`, `ParLoginRoundTripTests`, `BrowserAuthorizationErrorTests`.
