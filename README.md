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

## Architecture

The solution has one executable composition host and three focused modules:

| Project | Role | Runnable |
| --- | --- | --- |
| `src/server` | Composition root for STS, management, UI, middleware and runtime configuration | Yes |
| `src/sts` | OAuth/OIDC identity API, ASP.NET Core Identity and OpenIddict | No |
| `src/management` | Optional management API | No |
| `src/core` | Shared entities and persistence classes | No |

`Program.cs`, launch profiles and `appsettings` belong to `src/server`, the
only project that builds an ASP.NET Core host. Real configuration must be
provided through User Secrets, environment variables or mounted configuration;
`src/server/appsettings.json.template` documents the available keys.

Run the composition host with:

```sh
dotnet run --project src/server/Sufficit.Identity.Server.csproj
```

## License

[MIT-0](./LICENSE) (MIT No Attribution). Use, copy, modify, distribute, sell — no
strings attached.

> Note: third-party dependencies consumed via NuGet (e.g. OpenIddict, Apache 2.0)
> retain their own licenses as required by their respective authors.
