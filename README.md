# Sufficit Identity UI

Blazor Server frontend for the [Sufficit Identity STS](https://github.com/sufficit/sufficit-identity)
(OpenIddict). Provides the interactive OAuth/OIDC screens: login, consent, logout,
device flow verification, and a full self-service "Manage" area.

## Status

🚧 **Early stage** — actively in development.

## Projects

- `src/Sufficit.Identity.UI` — Razor Class Library injected into the STS for
  login, consent and end-user self-service.
- `src/Sufficit.Identity.UI.Management` — administrative Razor Class Library
  injected into the same composition host under `/management`. It reuses the
  host Identity session and consumes the same application contracts used by
  the Management API. See its
  [architecture and status](src/Sufficit.Identity.UI.Management/README.md).

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

Project reference in `Sufficit.Identity.STS.csproj`:
```xml
<ProjectReference Include="..\..\sufficit-identity-ui\src\Sufficit.Identity.UI\Sufficit.Identity.UI.csproj" />
<ProjectReference Include="..\..\sufficit-identity-ui\src\Sufficit.Identity.UI.Management\Sufficit.Identity.UI.Management.csproj" />
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
CORS / cross-origin cookie problem. See `docs/architecture.md`.

The canonical UI/backend boundary is
[`docs/single-source-ui-architecture.md`](docs/single-source-ui-architecture.md).

## License

[MIT-0](./LICENSE).
