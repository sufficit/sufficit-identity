# Sufficit Identity

OpenID Connect / OAuth 2.0 Security Token Service (STS) for the Sufficit platform.

Built on [.NET](https://dotnet.microsoft.com/) and [OpenIddict](https://github.com/openiddict/openiddict-core), focused exclusively on the identity service.

## Status

🚧 **Early stage** — actively in development. Not yet production-ready.

This repository is the next-generation identity service for Sufficit, succeeding the
Skoruba/Duende-based implementation that lives in [`sufficit-identity-legacy`](https://github.com/sufficit/sufficit-identity-legacy)
(private) and the database snapshot `identity2` used for isolated testing.

## Goals

- Modern OpenID Connect STS based on OpenIddict (consumed as a NuGet dependency).
- ASP.NET Core Identity for user storage (compatible with the existing user base).
- MySQL as the backing store.
- Reference tokens, introspection, device flow, server-side sessions, PKCE.
- MIT-0 licensed — free for any use, no attribution required.

## License

[MIT-0](./LICENSE) (MIT No Attribution). Use, copy, modify, distribute, sell — no
strings attached.

> Note: third-party dependencies consumed via NuGet (e.g. OpenIddict, Apache 2.0)
> retain their own licenses as required by their respective authors.
