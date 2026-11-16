# Sufficit.Identity.AspNetCore.Authentication.OAuth2Introspection

ASP.NET Core authentication handler for **reference (opaque) tokens** validated through
[OAuth 2.0 Token Introspection (RFC 7662)](https://www.rfc-editor.org/rfc/rfc7662). It follows the model of
`Duende.AspNetCore.Authentication.OAuth2Introspection` (same registration and option names) and adds two
behaviours Sufficit services need:

- **Coalescing**: concurrent requests carrying the same token share one call to the introspection endpoint.
- **Outage is not an invalid token**: when the endpoint cannot answer (network error, timeout, 5xx, 429 or any
  non-2xx), the request gets **503** with `Retry-After`, never 401. A 401 means only "this token is not active".

## Usage

```csharp
using Sufficit.Identity.AspNetCore.Authentication.OAuth2Introspection;

builder.Services.AddStackExchangeRedisCache(o => o.Configuration = "..."); // optional; in-memory otherwise

builder.Services.AddAuthentication(OAuth2IntrospectionDefaults.AuthenticationScheme)
    .AddOAuth2Introspection(options =>
    {
        options.Authority = "https://identity.sufficit.com.br";
        options.ClientId = "my-api";
        options.ClientSecret = builder.Configuration["Identity:ClientSecret"];
        options.EnableCaching = true;
        options.CacheDuration = TimeSpan.FromMinutes(1);
        options.CacheKeyPrefix = "my-api:introspection:";
    });
```

Audience and scope are authorization concerns: check them with policies (`RequireClaim("scope", ...)`,
`RequireClaim("aud", ...)`), as with Duende.

Pipelines that authenticate outside the handler (DPoP, legacy fallback clients) can register only the
client with `services.AddOAuth2IntrospectionClient()` and call `IOAuth2IntrospectionClient.IntrospectAsync`.

## Cache rules

- Only **active** results are cached, keyed by `CacheKeyPrefix` + SHA-256 of the token (the token is never a key).
- An entry lives for `CacheDuration`, never beyond the token's `exp`.
- Refusals and failures are never cached; a broken cache degrades to calling the endpoint.
- Revocation takes effect within at most `CacheDuration`: keep it short for sensitive resources.
