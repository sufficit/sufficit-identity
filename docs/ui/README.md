# Sufficit Identity UI

Blazor Server frontend for the [Sufficit Identity STS](https://github.com/sufficit/sufficit-identity)
(OpenIddict). Provides the interactive OAuth/OIDC screens: login, consent, logout,
device flow verification, and a full self-service "Manage" area.

## Status

🚧 **Early stage** — actively in development.

## Repository boundary

The runtime, APIs and both embedded presentation projects live in the
`sufficit-identity` monorepo. Neither UI project is a standalone application.
Both are compiled into the same Identity host, share its session and are
deployed in its single artifact, while remaining distinct assemblies. See the
[repository architecture and consolidation record](../REPOSITORY-ARCHITECTURE.md).

## Projects

- `src/ui/Sufficit.Identity.UI` — Razor Class Library injected into the STS for
  login, consent and end-user self-service.
- `src/ui/Sufficit.Identity.UI.Management` — administrative Razor Class Library
  injected into the same composition host under `/management`. It reuses the
  host Identity session and consumes the same application contracts used by
  the Management API. See its
  [architecture and status](../../src/ui/Sufficit.Identity.UI.Management/README.md).

## Design goals

- **Blazor Server**, hosted inside the STS app (same origin) for maximum security.
- **Single application source of truth**: UIs and API controllers invoke the
  same versioned use cases; UIs do not query persistence or reimplement rules.
- **Minimal coupling**: the target state removes UI references to Identity
  Core, infrastructure implementations and host configuration.
- **Injectable** via `Add*()` / `Use*()` extension pairs for the public and
  administrative modules, so an OpenIddict-based host can compose the surfaces
  it enables.
- **MIT-0 licensed** — free for any use, no attribution required.

## How to inject into the STS host

```csharp
// In sufficit-identity/src/server/Program.cs:
builder.Services.AddSufficitIdentitySTS(builder.Configuration);
builder.Services.AddSufficitIdentityUI();   // <-- add this
builder.Services.AddSufficitIdentityManagementUI(builder.Configuration);

// pipeline:
app.UseAuthentication();
app.UseAuthorization();
app.UseSufficitIdentityManagementUI();
app.UseSufficitIdentityUI();                // <-- and this
```

Project references in `src/server/Sufficit.Identity.Server.csproj`:
```xml
<ProjectReference Include="..\ui\Sufficit.Identity.UI\Sufficit.Identity.UI.csproj" />
<ProjectReference Include="..\ui\Sufficit.Identity.UI.Management\Sufficit.Identity.UI.Management.csproj" />
```

## Screens

- `/Account/Login` — username/password + external login buttons
- `/Consent` — scope-by-scope accept/deny
- `/Account/Logout` — confirmation with client info from `id_token_hint`
- `/Device/UserCode` — device flow user_code capture
- `/Manage/*` — profile, change password, 2FA (TOTP + recovery codes), passkeys,
  external logins, grants, server-side sessions, personal data (GDPR)

## Why Blazor Server (not a JS SPA)

Tokens and credentials never reach the browser: the auth cookie is issued
server-side via `SignInAsync`, the cookie is `HttpOnly + SameSite=Lax`, and
antiforgery is built-in. Hosting on the same origin as the STS removes every
CORS / cross-origin cookie problem. See [`architecture.md`](architecture.md).

The canonical UI/backend boundary is
[`single-source-ui-architecture.md`](single-source-ui-architecture.md).

## License

[MIT-0](../../LICENSE).
