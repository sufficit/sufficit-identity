# Sufficit Identity

OAuth 2.0 / OpenID Connect Security Token Service (STS) built on [.NET 10](https://dotnet.microsoft.com/) and [OpenIddict 7.6](https://github.com/openiddict/openiddict-core).

[![CI](https://github.com/sufficit/sufficit-identity/actions/workflows/ci.yml/badge.svg)](https://github.com/sufficit/sufficit-identity/actions/workflows/ci.yml)
[![License: MIT-0](https://img.shields.io/badge/License-MIT--0-blue.svg)](./LICENSE)

**MIT-0 licensed** — free for any use, no attribution required.

## What is this?

A self-hostable, .NET-native identity provider that goes well beyond stock OpenIddict. It hand-implements modern protocol features OpenIddict 7.6 does not have — DPoP, CIBA, FAPI 2.0 enforcement, JARM, JAR, SSF/CAEP — on top of the OpenIddict server/validation core, with ASP.NET Core Identity and MySQL/MariaDB storage.

## Protocol coverage

| Protocol | RFC / Spec | Status |
|---|---|---|
| OAuth 2.0 / OIDC Core | RFC 6749 / OpenID Connect 1.0 | ✅ |
| OAuth 2.1 baseline (PKCE mandatory, implicit/hybrid off) | draft-ietf-oauth-v2-1 | ✅ |
| DPoP (sender-constrained tokens) | RFC 9449 | ✅ Hand-implemented |
| CIBA (decoupled authentication) | RFC 9126 | ✅ Hand-implemented |
| PAR (Pushed Authorization Request) | RFC 9126 | ✅ |
| JAR (JWT-Secured Authorization Request) | RFC 9101 | ✅ Hand-implemented |
| JARM (JWT response mode, signed + encrypted) | JARM | ✅ |
| FAPI 2.0 Security Profile enforcement | FAPI 2.0 Final | ✅ Opt-in boundary |
| mTLS (client auth + sender-constrained tokens) | RFC 8705 | ✅ |
| Token Exchange (delegation) | RFC 8693 | ✅ |
| Device Authorization Grant | RFC 8628 | ✅ |
| OIDC Back-Channel Logout | OIDC BC Logout 1.0 | ✅ |
| OIDC Front-Channel Logout | OIDC FC Logout 1.0 | ✅ |
| SSF / CAEP (Shared Signals) | RFC 8933/8934/8935 + CAEP 1.0 | ✅ Stream mgmt + push + poll |
| SCIM 2.0 (user/group provisioning) | RFC 7643/7644 | ✅ |
| WebAuthn / Passkeys (.NET 10 native) | FIDO2 | ✅ |
| MCP Authorization (resource metadata + DCR) | RFC 9728 + RFC 7591 | ✅ |
| Dynamic Client Registration | RFC 7591 | ✅ Opt-in, token-gated |

## Architecture

10 projects, ~46k LOC, clean layering enforced by CI tests:

```
Application.Abstractions  ← implementation-neutral contracts (NuGet-packable)
        ▲
Core ─────────────────────  AppDbContext, entities, Identity lifecycle, branding
 ▲   ▲
 │   └─ (referenced by every module)
STS ───────────────────────  OpenIddict server+validation, /connect/* controllers,
 │                          DPoP/CIBA/FAPI2/JARM/JAR/SSF hand-rolled on top
Management ────────────────  optional REST API (clients/scopes/users/...), capability authz
SCIM ──────────────────────  optional RFC 7643/7644 Users/Groups
UI (Blazor Server) ────────  public: login/consent/logout/register/manage/device/2FA/passkeys
UI.Management (Blazor) ────  admin dashboard
Server ────────────────────  composition host (the only runnable project / Docker entrypoint)
Tests ─────────────────────  318 integration + unit tests (xUnit, WebApplicationFactory)
```

## Security posture

- **OAuth 2.1 secure-by-default**: PKCE mandatory for all code clients, `plain` removed, implicit/hybrid/password/none grants default-off, token exchange default-off with client allowlist, refresh-token rotation always on
- **Production cert enforcement**: missing signing/encryption PFX is a fatal startup error outside Development
- **Cookie `Secure=Always`**, issuer pinning, antiforgery on every state-changing endpoint
- **Account lockout** on both interactive login and password grant, plus per-IP token-endpoint rate limiting
- **DCR** disabled by default, constant-time-compared initial access token, fail-closed
- **CSP** (tightened `connect-src`, no ws/wss wildcard), Permissions-Policy (deny-all), COOP, CORP
- **Data Protection keys** encrypted at rest with the signing certificate
- **Breached-password validator** (HIBP k-anonymity range API, opt-in)
- **Distributed stores** for CIBA, DPoP nonce, DPoP jti replay (IDistributedCache / Redis-ready)
- **Non-root Docker**, digest-pinned images, multi-stage build, separate liveness/readiness probes

## Quick start

```sh
# Clone
git clone https://github.com/sufficit/sufficit-identity.git
cd sufficit-identity

# Copy the template and fill in your values
cp src/server/appsettings.json.template src/server/appsettings.Development.json

# Run (Development auto-creates the schema with ephemeral certs)
dotnet run --project src/server/Sufficit.Identity.Server.csproj
```

→ **[ONBOARD.md](ONBOARD.md)** for the full setup guide (Docker, first client, certificates, etc.)

## Configuration

Every option is documented in [`src/server/appsettings.json.template`](src/server/appsettings.json.template) with inline explanations. Key sections:

- **Certificates** — PFX paths for token signing/encryption (required in production)
- **TrustedProxies** — CIDR list for reverse-proxy forwarded headers
- **SSF/CAEP** — stream management, push/poll delivery, event types
- **PAR / JAR / JARM / FAPI 2.0** — opt-in protocol enforcement
- **Management / SCIM** — optional REST surfaces with scope-gated authorization

## Testing

318 tests covering every OAuth/OIDC grant type end-to-end over real HTTP, plus unit tests for protocol internals, distributed stores, security hardening, and architecture enforcement.

```sh
dotnet test
```

CI runs on GitHub Actions with real MariaDB 10.4.34, `-warnaserror`, SHA-verified NuGet feed, and migration rehearsal.

## License

[MIT-0](./LICENSE) (MIT No Attribution). The Sufficit.Identity.* code is MIT-0; OpenIddict (Apache 2.0) and other third-party dependencies retain their own licenses.

## Documentation

See the [documentation index](docs/README.md) for architecture, design, runbooks, active plans, and completed work records.
