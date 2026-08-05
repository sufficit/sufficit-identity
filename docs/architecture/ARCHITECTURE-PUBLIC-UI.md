# Architecture — Sufficit Identity UI

## Why Blazor Server, hosted inside the STS

The single most important security principle for an OAuth/OIDC login UI:

> **Tokens and credentials never reach the browser.**

A Blazor Server component runs on the server and streams UI diffs over a
WebSocket (SignalR). It invokes a canonical authentication use case in the
application layer; that implementation owns `SignInManager` and issues an
`HttpOnly + SameSite=Lax` auth cookie. An HTTP controller may expose the same
use case, but an internal self-call is not required.

A JavaScript SPA (Vue/React) runs in the browser. Even with HTTPS, a XSS
payload in the SPA's bundle, a third-party script, or a compromised dependency
can read the credentials as they're typed, exfiltrate the session cookie (if
not HttpOnly), or rewrite the consent screen to grant extra scopes. The Curity,
Duende, and Microsoft guidance converges: **server-rendered login pages are
materially safer than SPA login pages.**

## Why same-origin (hosted inside the STS)

When the UI is hosted by the STS app itself (same origin), we eliminate:

- **CORS** — no preflight, no `Access-Control-Allow-Credentials`, no origin list.
- **SameSite=None** — we can use `SameSite=Lax` (the safe default) because the
  cookie only needs to travel within `identity.example.com`.
- **Cookie domain games** — no `Domain=.example.com` needed; the cookie is
  scoped to the STS origin naturally.
- **Antiforgery complexity** — Razor tag helpers emit tokens, validated by the
  same-origin cookie, end of story.

## Why a separate UI project

- **Independent assembly boundary** — the UI keeps an explicit project and
  assembly boundary inside the monorepo, while being incorporated and
  published with the STS host.
- **Team separation** — frontend-focused work can happen in parallel.
- **Reusability** — an OAuth/OIDC provider can plug this in through versioned
  application contracts and the `AddSufficitIdentityUI()` /
  `UseSufficitIdentityUI()` pair. OpenIddict and ASP.NET Identity are the
  current runtime adapters, not UI dependencies.
- **Minimal coupling** — the UI references only versioned application
  contracts shared with API controllers. It does not reference the STS host,
  persistence or infrastructure implementations.

## Dependency graph

```
Public/account UI ─┐
Management UI ─────┼── application contracts / use cases ◄── HTTP API controllers
                   │       │
                   │       ├── authorization and validation
                   │       ├── ASP.NET Core Identity / OpenIddict
                   │       └── persistence
                   └── presentation only
```

The UI does **NOT** reference:

- `Sufficit.Identity.Server` (OpenIddict configuration)
- `Sufficit.Identity.STS` (the host web app)
- mutable identity entities or persistence types from `Sufficit.Identity.Core`
- infrastructure implementations from `Sufficit.Identity.Management`
- `UserManager`, `SignInManager` or OpenIddict managers

This boundary is enforced over both UI projects by architecture tests without
legacy exceptions. Runtime adapters remain free to use the current engines
behind the canonical contracts.

## How the STS host injects the UI

```csharp
// sufficit-identity/src/server/Program.cs
builder.Services.AddSufficitIdentitySTS(builder.Configuration);
builder.Services.AddSufficitIdentityUI();   // <-- Razor Components + services

// pipeline
app.UseAuthentication();
app.UseAuthorization();
app.UseSufficitIdentityUI();                // <-- MapRazorComponents + static assets
```

## Screens and flows

| Route | Auth | Purpose |
|---|---|---|
| `/Account/Login` | anonymous | username/password form → canonical interactive sign-in use case → redirect to `ReturnUrl` |
| `/Consent` | authenticated | scope toggles → accept/deny → redirect to `/connect/authorize` |
| `/Account/Logout` | optional | confirm → `SignOutAsync` → redirect to `post_logout_redirect_uri` |
| `/Device/UserCode` | optional | device flow user_code capture → bind to user |
| `/Account/ForgotPassword` | anonymous | email form → generate reset token |
| `/Account/ResetPassword` | anonymous | new password form → `ResetPasswordAsync` |
| `/Account/ConfirmEmail` | anonymous | validate token → `ConfirmEmailAsync` |
| `/Account/AccessDenied` | authenticated | "no permission" page |
| `/Manage` | required | profile overview |
| `/Manage/ChangePassword` | required | old + new password form |
| `/Manage/TwoFactor` | required | TOTP setup (QR), enable/disable, recovery codes |
| `/Manage/Passkeys` | required | list/add/remove WebAuthn passkeys |
| `/Manage/ExternalLogins` | required | list/link/unlink Google/GitHub/AzureAD |
| `/Manage/Grants` | required | list/revoke connected applications |
| `/Manage/Sessions` | required | active server-side sessions (host-dependent) |
| `/Manage/PersonalData` | required | GDPR download/delete |

## Security checklist

- [x] `HttpOnly + Secure + SameSite=Lax` auth cookie (host configures)
- [x] Antiforgery tokens on all POST forms (`<AntiforgeryToken />`)
- [x] Same-origin (no CORS surface)
- [x] Tokens never reach the browser
- [x] Identity lockout enabled (`lockoutOnFailure: true` in `PasswordSignInAsync`)
- [x] CSP baseline emitted by the host in report-only mode
- [ ] Strict CSP enforcement after production report calibration
- [x] Rate limiting configured by the host
- [x] HTTPS redirection and production secure-cookie enforcement

## Interactive sign-in boundary

Password login, external-provider discovery, pending two-factor state,
authenticator verification and recovery-code login use
`IInteractiveSignInService`. The contract contains only immutable commands,
providers and stable result states. The current
`AspNetCoreIdentityInteractiveSignInService` adapter owns `SignInManager`,
cookie issuance and the protected temporary two-factor ticket.

The login pages therefore neither know nor expose ASP.NET Core Identity. The
logout page only submits to the standard end-session endpoint; protocol
validation and cookie termination remain responsibilities of the runtime
controller. Replacing the current identity engine does not require changing
these UI pages or their routes.
