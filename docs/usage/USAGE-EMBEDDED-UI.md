# Embedded Sufficit Identity UIs

Blazor Server frontends for the
[Sufficit Identity runtime](https://github.com/sufficit/sufficit-identity).
They provide interactive OAuth/OIDC screens, account management and provider
management. OpenIddict is the current protocol adapter behind neutral
application contracts.

## Status

**Integrated and deployed in the test environment.** The public/account and
Management assemblies are part of the canonical server artifact. Production
replacement of the legacy service remains governed by the separate cutover
plan.

## Repository boundary

The runtime, APIs and both official presentation projects live in the
`sufficit-identity` monorepo. Their current implementation is embedded: both
are compiled into the same Identity host, share its session and are deployed in
one artifact, while remaining distinct assemblies. Optional standalone hosts
are planned but are not implemented by merely disabling an embedded surface.
See the [repository architecture and consolidation record](../architecture/ARCHITECTURE-REPOSITORY.md).

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
- **Enforced presentation boundary**: architecture tests reject UI references
  to Identity stores, EF Core, protocol managers and host implementations.
- **Injectable** via `Add*()` / `Use*()` extension pairs for the public and
  administrative modules, so the composition host can enable only the surfaces
  it publishes.
- **MIT-0 licensed** — free for any use, no attribution required.

## Hosting mode

Both official surfaces are embedded by default. A deployment that only needs
the runtime/API can omit either surface without changing code:

```json
{
  "Sufficit": {
    "Identity": {
      "UI": {
        "Public": { "Mode": "None" },
        "Management": { "Mode": "None" }
      }
    }
  }
}
```

Supported values are currently `Embedded` and `None`. `None` does not provide
remote login, consent or account pages; interactive browser flows require an
embedded UI until the remote interaction protocol is delivered. An unsupported
numeric value fails startup instead of silently changing topology.

The architecture and remote-host delivery gates are defined in
[`PLAN-PLUGGABLE-USER-INTERFACES.md`](../plans/PLAN-PLUGGABLE-USER-INTERFACES.md).

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
CORS / cross-origin cookie problem. See
[`ARCHITECTURE-PUBLIC-UI.md`](../architecture/ARCHITECTURE-PUBLIC-UI.md).

The canonical UI/backend boundary is
[`ARCHITECTURE-SINGLE-SOURCE-UI.md`](../architecture/ARCHITECTURE-SINGLE-SOURCE-UI.md).

## License

[MIT-0](../../LICENSE).
