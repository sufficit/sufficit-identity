# Onboarding — Sufficit Identity

This guide gets you from zero to a running STS with your first OAuth client.

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- [MariaDB](https://mariadb.org/) 10.4+ (or MySQL 8+) — for production; the test suite uses SQLite in-memory
- A reverse proxy (nginx, Envoy, Caddy) — the STS is designed to run behind one

## 1. Clone and build

```sh
git clone https://github.com/sufficit/sufficit-identity.git
cd sufficit-identity
dotnet restore
dotnet build
```

## 2. Configure (Development)

Development mode auto-creates the database schema (`EnsureCreatedAsync`) and uses ephemeral signing/encryption certificates — no PFX files needed.

```sh
cp src/server/appsettings.json.template src/server/appsettings.Development.json
```

Edit `appsettings.Development.json`:

```jsonc
{
  "ConnectionStrings": {
    "DefaultConnection": "server=127.0.0.1;port=3306;database=identity_dev;user=root;SslMode=Disabled"
  },
  "Sufficit": {
    "Identity": {
      "Issuer": "https://localhost:5001/",
      "Certificates": {
        // Leave empty in Development — ephemeral certs are generated automatically.
      }
    }
  }
}
```

> **Never commit `appsettings.json` or `appsettings.*.json`** — they are gitignored. Only `.template` files are tracked.

## 3. Run

```sh
dotnet run --project src/server/Sufficit.Identity.Server.csproj
```

The STS is now live at `https://localhost:5001`. Verify:
- Discovery: `GET /.well-known/openid-configuration`
- Health: `GET /health` (liveness) and `GET /health/ready` (includes DB check)
- Login UI: `https://localhost:5001/account/login`

## 4. Create your first client

The Management API is opt-in. Enable it and create a client:

```jsonc
// In appsettings.Development.json:
"Sufficit": {
  "Identity": {
    "Management": { "Enabled": true }
  }
}
```

Alternatively, seed a client programmatically. The simplest path is an authorization-code + PKCE public client:

```csharp
await appManager.CreateAsync(new OpenIddictApplicationDescriptor
{
    ClientId = "my-app",
    ClientType = OpenIddictConstants.ClientTypes.Public,
    ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
    RedirectUris = { new Uri("https://my-app.example.com/callback") },
    Permissions =
    {
        OpenIddictConstants.Permissions.Endpoints.Authorization,
        OpenIddictConstants.Permissions.Endpoints.Token,
        OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
        OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
        OpenIddictConstants.Permissions.ResponseTypes.Code,
        OpenIddictConstants.Scopes.OpenId,
        OpenIddictConstants.Scopes.Profile,
        OpenIddictConstants.Scopes.Email,
    },
    Requirements =
    {
        OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange,
    },
});
```

Your client can now do the standard authorization-code + PKCE flow:

```
GET /connect/authorize?response_type=code&client_id=my-app&redirect_uri=...&code_challenge=...&code_challenge_method=S256&scope=openid profile
```

## 5. Production checklist

Before deploying to production:

- [ ] **Certificates** — generate two X.509 PFX files (signing + encryption) and configure `Certificates.SigningPath` / `EncryptionPath`
- [ ] **Issuer** — set `Issuer` to the public HTTPS URL (e.g. `https://identity.example.com/`)
- [ ] **TrustedProxies** — list the CIDR ranges of your reverse proxy network so forwarded headers work and rate limiting partitions by real client IP. This now matters for the management API and SCIM too: without it every administrative caller shares the proxy's bucket
- [ ] **Database** — run `dotnet ef database update` (or apply `docs/migration/sql/001-create-empty-database.sql`) against your MariaDB instance
- [ ] **Rate limiting** — verify `RateLimit.Enabled=true` and `FailOnUntrustedProxy=true` so a missing proxy config fails fast instead of self-DoSing. `AdministrativePermitLimit` (600/min) covers the management API and SCIM; `AdministrativeBulkPermitLimit` (30/min) is a separate bucket for whole-collection commands — provisioning manifest inventory/preview/apply and revoking every session of a user — so one cannot exhaust the other's budget
- [ ] **Swagger** — `Swagger.Enabled` is unset by default, which publishes the contract in Development only. Both endpoints are anonymous, so setting it `true` in production hands any caller the full management/SCIM/provisioning/vault route inventory; set it explicitly to `false` if you want that decision recorded rather than implied
- [ ] **Audit retention** — `Management.AuditRetentionDays` defaults to 15. The table is append-only and nothing pruned it before this setting existed, so the first run after upgrading deletes everything older; export the history first if you need it, or set `0` to disable pruning
- [ ] **CSP** — calibrate `Csp.ReportOnly` against the real UI, then flip to `false` (enforce)
- [ ] **Secrets at rest** — deploy readers first, set `Sufficit__Vault__Enabled=true`, migrate os valores `pt1.` e prove zero leituras legadas; `RequireEncryptionInProduction` não desliga o guard e existe apenas por compatibilidade (see [`RUNBOOK-VAULT.md`](docs/runbooks/RUNBOOK-VAULT.md))
- [ ] **Docker** — the included Dockerfile builds a non-root, digest-pinned image. Mount secrets via env vars or files.

## 6. Docker Compose (recommended for local dev)

The included `docker-compose.yml` runs the full stack: MariaDB + STS + nginx (TLS reverse proxy).

```sh
docker compose up --build
```

- **STS direct:** http://localhost:8080 (plain HTTP, bypasses nginx — for debugging)
- **STS via proxy:** https://localhost:5001 (self-signed TLS, realistic topology)

The nginx proxy generates a self-signed cert on first boot. The database is initialized from the checked-in schema SQL. Management API and SCIM are enabled by default in the compose config.

## 7. Docker (standalone)

```sh
docker build -t sufficit-identity .

docker run -p 8080:8080 \
  -e ASPNETCORE_ENVIRONMENT=Production \
  -e ConnectionStrings__DefaultConnection="server=db;port=3306;database=identity;user=identity;password=..." \
  -e Sufficit__Identity__Issuer="https://identity.example.com/" \
  -e Sufficit__Identity__Certificates__SigningPath="/secrets/signing.pfx" \
  -e Sufficit__Identity__Certificates__SigningPassword="..." \
  -v /path/to/secrets:/secrets:ro \
  sufficit-identity
```

## 7. Optional features

All optional features are **off by default** — enable per environment:

| Feature | Config key | What it does |
|---|---|---|
| Management API | `Management:Enabled=true` | REST API for clients/scopes/users/claims/sessions |
| SCIM 2.0 | `Scim:Enabled=true` | RFC 7643/7644 user/group provisioning |
| SSF/CAEP | `SharedSignals:Enabled=true` | Push signed security events to receivers |
| Stream Management | `SharedSignals:StreamManagementEnabled=true` | REST API for RFC 8933 streams + RFC 8934 poll |
| DPoP | `Dpop:Enabled=true` | Sender-constrained access tokens |
| CIBA | `Ciba:Enabled=true` | Decoupled backchannel authentication |
| JARM | `Jarm:Enabled=true` | JWT-secured authorization responses |
| JAR | `Jar:Enabled=true` | Signed authorization requests |
| FAPI 2.0 | `Fapi2:Enabled=true` + `ClientIds` | Profile enforcement for specific clients |
| PAR global | `Par:RequireForAllClients=true` | Require PAR from every client |
| Token Exchange | `TokenExchange:Enabled=true` | RFC 8693 delegation |
| DCR | `Mcp:Dcr:Enabled=true` | Dynamic client registration (token-gated) |
| Breached passwords | `Password:RejectBreached=true` | HIBP k-anonymity check on create/change |

## 8. Running the tests

```sh
dotnet test
```

Tests use SQLite in-memory (no MariaDB needed) and cover:
- Every OAuth/OIDC grant type end-to-end over real HTTP
- Protocol internals (DPoP proof validation, CIBA pending store, JARM signing, JAR extraction)
- Distributed stores (CIBA, DPoP nonce, DPoP replay)
- Security hardening (breached passwords, SCIM authz, CSP headers)
- Architecture enforcement (no layering leaks between projects)

The CI pipeline additionally runs against real MariaDB 10.4.34 with migration rehearsal.

## Where to go next

- [`appsettings.json.template`](src/server/appsettings.json.template) — every configuration key, documented inline
- [`docs/`](docs/README.md) — architecture, design, runbooks, active plans
- [`docs/plans/PLAN-PRODUCTION-READINESS.md`](docs/plans/PLAN-PRODUCTION-READINESS.md) — what's left for production hardening
