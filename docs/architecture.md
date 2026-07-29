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
  cookie only needs to travel within `identity.sufficit.com.br`.
- **Cookie domain games** — no `Domain=.sufficit.com.br` needed; the cookie is
  scoped to the STS origin naturally.
- **Antiforgery complexity** — Razor tag helpers emit tokens, validated by the
  same-origin cookie, end of story.

## Why a separate project (not in the STS repo)

- **Independent evolution** — UI changes don't require redeploying the STS API.
- **Team separation** — frontend-focused work can happen in parallel.
- **Reusability** — any OpenIddict + ASP.NET Identity STS can plug this in via
  the `AddSufficitIdentityUI()` / `UseSufficitIdentityUI()` pair.
- **Minimal coupling** — the target UI references only versioned application
  contracts shared with API controllers. It does not reference the STS host,
  Core entities, persistence or infrastructure implementations.

## Dependency graph

```
sufficit-identity-ui
    │
    ├── Razor Components / presentation
    └── application contracts / use cases ◄── HTTP API controllers
            │
            ├── authorization and validation
            ├── ASP.NET Core Identity / OpenIddict
            └── persistence
```

The target UI does **NOT** reference:

- `Sufficit.Identity.Server` (OpenIddict configuration)
- `Sufficit.Identity.STS` (the host web app)
- `Sufficit.Identity.Core` (entities and persistence)
- infrastructure implementations from `Sufficit.Identity.Management`
- `UserManager`, `SignInManager` or OpenIddict managers

The current public UI still contains some of these direct dependencies. They
are migration debt under the canonical
[`single-source-ui-architecture.md`](single-source-ui-architecture.md), not the target
architecture.

## How the STS host injects the UI

```csharp
// sufficit-identity/src/sts/Program.cs
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
| `/Account/Login` | anonymous | username/password form → `SignInAsync` → redirect to `ReturnUrl` |
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
| `/Manage/Passkeys` | required | list/add/rename/remove WebAuthn passkeys |
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
- [ ] Strict CSP (to be configured by the host: `default-src 'self'; script-src 'self'`)
- [ ] Rate limiting (host responsibility)
- [ ] HTTPS enforcement (host responsibility)
