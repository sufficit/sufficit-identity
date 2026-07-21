# Avaliação Crítica — sufficit-identity (STS OAuth 2.0/OIDC)

**Data:** 2026-07-21
**Avaliador:** ZCode (GLM-5.2)
**Repo:** `/mnt/sufficit/sufficit-identity`
**Branch auditada:** `feature/eval-p0-remediation` (working tree, NÃO comitada)
**Versão:** `0.2.0-alpha` (`Directory.Build.props`)
**Stack:** .NET 9 + OpenIddict 7.6.0 + ASP.NET Core Identity + EF Core 9 + Pomelo MySQL 9.0.0
**Repo irmão UI:** `/mnt/sufficit/sufficit-identity-ui` (Blazor Server)

> **Importante:** Esta avaliação re-verifica o CÓDIGO atual. Não confia nos `docs/*.md`
> anteriores (que estão staged-para-deleção no working tree). Toda evidência abaixo é
> `file:line` verificada pessoalmente pelo avaliador ou por agente Explore em modo read-only.
>
> **Histórico de avaliações anteriores:** `INVESTIGATION-2026-07-20.md` (C1-C4, I1-I6
> originais), `UPGRADE-PLAN-2026-07-20.md` (modernização F1-F4), `EVALUATION-2026-07-20.md`
> (avaliação pós-F1-F4), implementação P0 (20/20 testes) — todos registrados em memória
> Sufficit AI. Esta é a quarta passagem.

---

## Sumário Executivo

O **sufficit-identity** é um STS OAuth 2.0/OIDC em .NET 9 + OpenIddict 7.6 que substitui o
stack legado Skoruba/Duende (`sufficit-identity-legacy`). Após 4 ciclos de investigação +
remediação (Investigação → F1-F4 → EVAL → P0), o código atingiu um **nível de maturidade
alto para um projeto alpha**: arquitetura limpa, 20 testes E2E, CI com `-warnaserror` +
gitleaks + auditoria de vulnerabilidades, e os 4 achados críticos originais (C1-C4)
parcial ou totalmente resolvidos no código.

**Porém não está pronto para cutover de produção (Onda A, 26 clients, 2.358 usuários):**

1. **CSRF ausente no consent POST `/connect/authorize`** (novo achado desta avaliação) —
   `[IgnoreAntiforgeryToken]` sem `IAntiforgery.ValidateRequestAsync`, justificativa
   incorreta ("Blazor EditForm cuida"). O `DeviceController.Verify` faz certo; o
   `AuthorizationController.Authorize` POST e `LogoutPost` não. **Potencial account-grant
   CSRF**.
2. **Segredos reais ainda expostos** (C4 parcial): working tree tem `appsettings.json`
   com senha MySQL (`4353SDFDF34D3424FDF4536FD`) e `appsettings.Development.json` com
   senha RabbitMQ (`FTrU7phaHJDabSh`); commit `0a56f5a` vazou `ClientSecret=KKwyJC8v...`
   do Google OAuth **na mensagem do commit** (imutável, só `git filter-repo
   --replace-message` limpa); commit `c706b64` expõe topologia interna (jump host IPv6,
   SSH key path).
3. **`backchannel_logout_supported`/`frontchannel_logout_supported` advertised como `true`
   mas são stubs** (`AuthorizationController.cs:651-674`) — distribuição para RPs não é
   implementada, descoberta desonesta.
4. **Sem migrations EF Core** — schema provisionado por SQL ad-hoc que está sendo
   deletado do working tree. Deploy de produção não tem caminho idempotente versionado.
5. **Trabalho P0 inteiro UNTRACKED** — `src/tests/`, `Dockerfile`, `.github/`,
   `DeviceController.cs`, modifications em 6 arquivos não estão committed. A UI pinada
   no CI (`UI_REF=381c9a6`) NÃO inclui os fixes P0 da UI ainda.
6. **`.NET 10` bloqueado** pela cadeia OpenIddict 7.6 → EF Core 10 → Pomelo (sem release
   EF10) → AddPasskeys() (.NET 10 Identity) inacessível. **Passkeys é stub apenas**
   (`Passkeys.razor` renderiza via reflection sobre API inexistente em net9.0).

### Veredito Go/No-Go

| Dimensão | Nota | Comentário |
|---|---|---|
| **Segurança** | **B+** (7.5/10) | C1/C2/C3 resolvidos; C4 parcial (vazamentos residuais); novo CSRF no consent é HIGH; discovery back/frontchannel desonesta |
| **Arquitetura** | **A-** (8.5/10) | 5-projeto limpo acíclico, snake_case correto, Data Protection em MySQL, options pattern idiomático |
| **Qualidade** | **B** (7.0/10) | 20 testes E2E (era 0), CI `-warnaserror`+gitleaks+vuln-audit, mas sem cobertura de UI real, sem SAST, sem coverage |
| **Completude** | **C+** (6.5/10) | Faltam: migrations, NuGet UI package, passkeys reais, DPoP/JAR, backchannel logout real, SCIM, SSF/CAEP |

**Onda A (cutover 26 clients/2.358 usuários): NO-GO.** Falta resolver 2 blockers code-side
(CSRF consent + backchannel stub) e executar o pacote humano-only (rotação de 3 segredos,
`git filter-repo`, provisionar PFX/JWKS reais, ensaio de migração dos 26 clients em clone).
Projeção: **2-3 dias de trabalho focado** para atingir GO condicional.

---

## 1. AVALIAÇÃO — Análise crítica do código atual

### 1.1 Segurança

#### Fluxos OAuth/OIDC implementados

`src/server/ServiceCollectionExtensions.cs:226-236` registra:

- ✅ `authorization_code` + PKCE (sem implicit/hybrid — correto, OAuth 2.1-aligned)
- ✅ `client_credentials`
- ✅ `device_authorization` (RFC 8628) — `DeviceController` completo
- ✅ `refresh_token` (rotação single-use sempre on)
- ✅ `token_exchange` (RFC 8693) — implementação correta com `act` aninhado
- ⚠️ `password` e `none` (legacy, default ON via `LegacyGrantsOptions` — "Onda E" deve
  desligar)
- ❌ DPoP, JAR, PAR-required, CIBA, server-side sessions — **não implementados**

#### Emissão de claims

**BUG HISTÓRICO CORRIGIDO:** O bug `GetUserAsync(result.Principal)` vs `Claims.Subject`
está documentado e corrigido em 3 lugares:

- `AuthorizationController.cs:355` (`ExchangeForDeviceCodeAsync`)
- `AuthorizationController.cs:484` (`ExchangeForTokenExchangeAsync`)
- `AuthorizationController.cs:561` (`Userinfo`)

Cada fix tem comentário explicando o porquê (device flow nunca completava E2E antes do
fix; userinfo sempre retornava null). **Teste de regressão** em
`DeviceFlowTests.cs:59` valida o fluxo completo.

**`directive` claim** (`AuthorizationController.cs:719-733`): emitida via
`AddPersistedClaimsAsync` (lê `AspNetUserClaims`), roteada ao access token via
`GetDestinations` default branch (`:779-796`). **Residual gap #10 documentado**: vai para
TODOS os audiences, não só relevantes. Aceito como follow-up, não blocker.

**`email_verified`**: mapeado do Google (`ServiceCollectionExtensions.cs:430`); Facebook e
GitHub sem `ClaimAction` explícito — `name` funciona, `email_verified`/`picture`
provavelmente não (LOW).

#### Lockout, rate limit, anti-enumeration

- ✅ **Lockout** (C1 RESOLVIDO): `CheckPasswordSignInAsync(..., lockoutOnFailure: true)`
  em `AuthorizationController.cs:410`, NÃO `CheckPasswordAsync`. Política em
  `ServiceCollectionExtensions.cs:102-103` (default 5 tentativas / 5 min, configurável).
- ✅ **Anti-enumeration**: `AuthorizationController.cs:416-426` — usuário inexistente,
  senha errada, locked out, `CanSignInAsync=false` todos colapsam para a MESMA mensagem
  genérica `"Invalid username or password."`.
- ✅ **Rate limiter** em `/connect/token`: `Program.cs:109-152`, fixed window 30/min/IP
  (configurável), `Retry-After` header. **Caveat**: se `TrustedProxies` vazio em prod,
  `RemoteIpAddress` colapsa para o IP do proxy (bucket compartilhado) — warning loggado
  em `Program.cs:156-161`.

#### Certificados e segredos (C3 + C4)

**C3 RESOLVIDO** — `ServiceCollectionExtensions.cs:302-342`:
- `X509CertificateLoader.LoadPkcs12FromFile` para signing E encryption
- Fail-fast `throw new InvalidOperationException` se `SigningPath`/`EncryptionPath`
  vazios E ambiente ≠ Development
- `AddDevelopmentSigningCertificate`/`AddDevelopmentEncryptionCertificate` só alcançáveis
  em Development

**C4 PARCIAL** — verificação pessoal no git:

| Vazamento | Onde | Status |
|---|---|---|
| Senha MySQL `4353SDFDF34D3424FDF4536FD` | working tree `src/sts/appsettings.json:3` | gitignored (não entrou no index), mas presente em plaintext no dev |
| Senha RabbitMQ `FTrU7phaHJDabSh` | working tree `src/sts/appsettings.Development.json:39` | gitignored, plaintext no dev |
| Google `ClientSecret=KKwyJC8v...` | commit `0a56f5a` **mensagem** | 🔴 IMUTÁVEL — só `git filter-repo --replace-message` limpa |
| Google `ClientId=609194959516-...` | commit `0a56f5a` mensagem | 🔴 IMUTÁVEL |
| Topologia jump host IPv6 + SSH key path | commit `c706b64` (`docs/migration/sql/generate_clients_migration.py`) | alcançável no HEAD; senha já redactada em `d29e116` mas host/key path permanecem |
| JWKS kids + lista de clients | commit `c706b64` (`docs/migration/JWKS_KEYS.md`) | sem material privado (verificado), mas deletar por higiene |

**Rotação de credenciais** é **HUMAN-ONLY** (não-code): MySQL, RabbitMQ, Google OAuth
client_secret precisam ser rotacionadas nas respectivas fontes. `gitleaks detect --redact`
CI não pega (commit messages não são default scope).

#### CSRF — NOVO ACHADO HIGH

Esta avaliação identificou um novo problema não coberto pelas investigações anteriores:

```csharp
// AuthorizationController.cs:56-58
[HttpGet("~/connect/authorize")]
[HttpPost("~/connect/authorize")]
[IgnoreAntiforgeryToken]  // ← sem validação server-side
public async Task<IActionResult> Authorize()
```

O POST aceita `consent_decision=allow` SEM chamar `_antiforgery.ValidateRequestAsync()`.
A justificativa em `LogoutPost:628-631` ("Blazor Server `<EditForm>` cuida via
AntiforgeryToken component") está **incorreta para este host**: o STS é API-only e não
registra o filtro MVC antiforgery. A UI vive no repo irmão. Um site malicioso pode POST
`consent_decision=allow&{params originais}` com o cookie SameSite=Lax da vítima e aprovar
um client que ela nunca consentiu.

**Contraste:** `DeviceController.cs:219` faz certo (`await
_antiforgery.ValidateRequestAsync(HttpContext)`).

**Severidade:** HIGH (consent-grant CSRF) e MEDIUM (logout forçado).

#### Cookie, HSTS, headers, host filtering

- ✅ Cookie `SecurePolicy=Always` fora de Development (`ServiceCollectionExtensions.cs:129-131`)
- ✅ SameSite=Lax, paths canonicalizados lowercase
- ✅ HSTS configurado (365d, subdomains, preload) fora de Development (`Program.cs:99-107`)
- ✅ Headers baseline: `X-Content-Type-Options: nosniff`, `Referrer-Policy`,
  `X-Frame-Options: DENY` (`Program.cs:189-195`)
- ❌ **CSP ausente** — comentário admite deferral para Blazor Server (`Program.cs:171-172`)
- ✅ `AllowedHosts` restrito em prod (`appsettings.json:13`)
- ✅ `TrustedProxies` CIDR explícito, warning se vazio (`Program.cs:27-65`)

#### Discovery honesty (parcial)

`ServiceCollectionExtensions.cs:345-373` corretamente **removeu**:
- DPoP signing algos
- JAR request object signing algos
- `request_uri`/`request` parameter support
- `claims_parameter_supported`
- `check_session_iframe`
- `backchannel_logout_url` (não é metadata OP)

**Porém** (`:362-367`) mantém como `true`:
- `backchannel_logout_supported`/`backchannel_logout_session_supported`
- `frontchannel_logout_supported`/`frontchannel_logout_session_supported`

…enquanto `AuthorizationController.cs:651-674` é **stub**: `BackchannelLogout` retorna
`Ok({status:"ok"})` sem fazer nada; `FrontchannelLogout` retorna HTML que fecha a janela.
A distribuição real de logout_token para RPs **não existe**. Um RP que confie no metadata
não será notificado. **Discovery desonesta — corrigir**: ou implementar, ou setar `false`.

#### Token Exchange (RFC 8693) — implementação sólida

`AuthorizationController.cs:442-540`:

- ✅ `act` claim com **nesting** (`:531-535`) — cadeia multi-hop preserva actor anterior
- ✅ Subject via `Claims.Subject` (`:484`) — não `ClaimTypes.NameIdentifier`
- ✅ Scope narrowing por intersecção (`requestedScopes.Intersect(subjectScopes)`, `:517-519`)
- ✅ `GetDestinations` (`:747-798`) gateia `role`/`name`/`email` por scope
- ✅ Allowlist config-driven (`TokenExchangeOptions`, `:452-464`)
- ⚠️ **Default ON** (`:840`) — eval recomendou OFF, mantido ON para não quebrar clients.
  Flag para Onda E.
- ✅ Testes: `TokenExchangeTests` (3 casos) + `TokenExchangeAllowlistTests` (rejeição)

### 1.2 Arquitetura

#### Separação core/server/sts/management

5 projetos, dependência acíclica verificada:

```
src/core       → AppDbContext, Entities, EmailOptions  (referencia nada Sufficit)
src/server     → AddSufficitIdentitySTS, options       (→ core)
src/management → ClientsController (opt-in admin API)  (→ core)
src/sts        → Program.cs + Controllers                (→ server + management + UI sibling)
src/tests      → xUnit + WebApplicationFactory           (→ sts)
```

UI sibling: `sufficit-identity-ui` references **só** `src/core` (correto — UI não vê
server/sts/management). STS references UI in-process. **Sem ciclos.**

#### DbContext e schema snake_case

`src/core/Data/AppDbContext.cs`:
- Tabelas Identity mapeadas para lowercase legacy: `users`, `roles`, `userroles`,
  `userclaims`, `userlogins`, `usertokens`, `roleclaims` (`:56-79`)
- Tabelas OpenIddict: `applications`, `authorizations`, `scopes`, `tokens`, todas colunas
  snake_case via `SnakeCaseColumns(...)` (`:91-171`)
- **Sem prefixo `openiddict_`** (commit `a229cf4`)
- `DataProtectionKey` → `dataprotectionkeys` (`:192`)
- `ApplicationUser.Timestamp` → MySQL `timestamp` com `HasDefaultValueSql("UTC_TIMESTAMP()")`
  — shimmed em testes via SQLite UDF (`SufficitIdentityTestFactory.cs:106`)
- `ConcurrencyToken` presente em todas as tabelas OpenIddict (`:103,124,141,159`)

#### Migrations — AUSENTES

`find . -type d -name Migrations` retorna vazio. Schema é provisionado por SQL ad-hoc em
`docs/migration/sql/01..05_*.sql` — **staged-para-deleção** no working tree desta branch.
Runtime usa `Database.EnsureCreatedAsync()` em Development apenas (`Program.cs:216`).
Dockerfile não roda migrations.

**Gap crítico**: deploy de produção não tem caminho idempotente versionado. Os SQL estão
sendo apagados sem substituição.

#### Data Protection

`ServiceCollectionExtensions.cs:92-94`: persistida em MySQL via
`IDataProtectionKeyContext`. `SetApplicationName("Sufficit.Identity")` hardcoded (com
comentário explicando porquê). **Resolve P0 #B4** (key ring compartilhado entre réplicas).

`TODO(prod, optional hardening)` em `:77`: `.ProtectKeysWithCertificate(...)` deliberadamente
não conectado — keys em plaintext at-rest no MySQL. Apenas 1 TODO em todo o codebase.

### 1.3 Qualidade

#### Testes (src/tests)

| Arquivo | `[Fact]`/`[Theory]` |
|---|---|
| `DiscoveryTests.cs` | 1 |
| `HealthTests.cs` | 1 |
| `PasswordGrantTests.cs` | 4 (incl. lockout 5-tentativas, anti-enumeração) |
| `ClientCredentialsTests.cs` | 1 |
| `TokenExchangeTests.cs` (+`TokenExchangeAllowlistTests`) | 3 |
| `IntrospectionTests.cs` | 1 (directive claim) |
| `AuthorizationCodeFlowTests.cs` | 4 (PKCE verify errado/ausente, consent deny) |
| `DeviceFlowTests.cs` | 3 (incl. E2E que pega sub-resolution bug) |
| `RefreshTokenTests.cs` | 2 (rotation + reuse-leeway) |
| **Total** | **20** |

Todos E2E contra TestServer real. Factory custom (`SufficitIdentityTestFactory`): SQLite
in-memory + UDF `UTC_TIMESTAMP` + `TestOnlyEndpoints` (`/test-only/signin`,
`/test-only/antiforgery`) para suprir o que a UI Blazor normalmente faria. **Não cobre**
UI pages reais (Consent.razor, Login.razor, UserCode.razor), revocation, PAR, back/front
logout, management API, rate limiting.

#### CI (.github/workflows/ci.yml)

2 jobs:
1. **build-and-test**: checkout duplo (identity + UI sibling pinado por SHA
   `381c9a6...`), restore, build **`-warnaserror`**, test, `dotnet list package
   --vulnerable --include-transitive` (falha em High/Critical).
2. **secret-scan**: `gitleaks 8.30.1` instalado direto do tarball upstream, `detect
   --source . --redact --verbose`, `fetch-depth: 0` (histórico completo).

**Fortes:** UI sibling pinado por SHA (não branch móvel); `-warnaserror` override do
`TreatWarningsAsErrors=false` local; gitleaks com `--redact`; vuln audit transitivo.

**Faltantes:** cache NuGet, matrix, Trivy/Snyk image scan, code coverage (sem coverlet),
SAST/CodeQL, build/push Docker image. **Branch protection não verificável** (sem
CODEOWNERS, sem ruleset file) — confirmar no GitHub UI.

#### Docker / deployment

- Multi-stage SDK→runtime, base image `mcr.microsoft.com/dotnet/{sdk,aspnet}:9.0`
  (**floating tag, não SHA digest**)
- ✅ Non-root user (uid/gid 1654, `nologin` shell) — `Dockerfile:75-77`
- ❌ **Sem `HEALTHCHECK`** instruction — depende de probe externo
- ✅ `.dockerignore` exclude `appsettings*.json`, `*.pfx`, `.env*`
- ✅ Dockerfile defensivamente `rm -f` appsettings após COPY (`:76-77`)
- ⚠️ **Não buildável do repo sozinho**: `STS.csproj:31` tem `<ProjectReference
  Include="..\..\..\sufficit-identity-ui\...">` **sem Condition+NuGet fallback** (ao
  contrário de `Sufficit.Communication` que tem). Sem `Sufficit.Identity.UI` NuGet package
  publicado. Build exige `--build-context ui=../sufficit-identity-ui`.

#### Build configuration

`Directory.Build.props`: net9.0, `Nullable=enable`, `ImplicitUsings=enable`,
`ManagePackageVersionsCentrally=true`, **`TreatWarningsAsErrors=false`** (override só no
CI). `Directory.Packages.props`: OpenIddict 7.6.0, EF Core 9.0.18, Pomelo 9.0.0,
SQLitePCLRaw 2.1.12 (CVE-2025-6965 fix).

### 1.4 Dívidas técnicas e blockers conhecidos

| Item | Severidade | Status |
|---|---|---|
| .NET 10 migration blocked | BLOCKER | Pomelo sem EF Core 10 release → cadeia OpenIddict/EF/Caching conflita. AddPasskeys() (.NET 10 Identity) inacessível. net9.0 EOL desde 2026-05-12 |
| Passkeys stub-only | HIGH | `Passkeys.razor` renderiza via reflection sobre API .NET 10 inexistente em net9.0. Sem lib fido2/webauthn |
| No EF migrations | HIGH | SQL ad-hoc sendo deletado, sem substituto |
| UI não é NuGet package | MEDIUM | STS image não buildável do repo sozinho |
| back/frontchannel logout stub | MEDIUM | Advertised true, não implementado |
| `UseReferenceAccessTokens=true` global | MEDIUM | Só 1/26 clients usa reference; flip é migration-contract decision |
| `LegacyGrants.{Password,None}=true` | MEDIUM | OAuth 2.1 remove; default ON para Onda E flip |
| `TokenExchange.Enabled=true` default | MEDIUM | Eval recomendou OFF; mantido ON conservador |
| Persisted claim scope gating | LOW | `directive` vai para todos audiences |
| `.ProtectKeysWithCertificate` | LOW | DP keys plaintext at-rest no MySQL |
| CSP | LOW | Não configurado para Blazor Server |
| Floating Docker tags | LOW | `9.0` não SHA digest |

---

## 2. VERIFICAÇÃO — Status dos problemas C1-C4 e I1-I6

Legenda: ✅ RESOLVED · ⚠️ PARTIAL · ❌ NOT RESOLVED · 🔍 CANNOT VERIFY

### Críticos originais (C1-C4)

| ID | Descrição | Status | Evidência (file:line) |
|---|---|---|---|
| **C1** | Password grant sem lockout (brute-force ilimitado) | ✅ | `AuthorizationController.cs:409-411` (`CheckPasswordSignInAsync(lockoutOnFailure:true)`); `ServiceCollectionExtensions.cs:102-103` (policy); `PasswordGrantTests.cs` (5-tentativas lockout verified) |
| **C2** | `/diagnostics/schema` sem auth | ✅ | Rota **não existe** no fonte (grep vazio); `ClientsController.cs:14` `[Authorize(Policy="sufficit-identity-management")]`; `ServiceCollectionExtensions.cs:47-57` (scope handler); Swagger dev-only (`Program.cs:223-227`) |
| **C3** | Certificados de assinatura dev em produção | ✅ | `ServiceCollectionExtensions.cs:302-342` (`X509CertificateLoader.LoadPkcs12FromFile`, fail-fast `throw` fora Development) |
| **C4** | Senha MySQL vazada em commit público | ⚠️ | Repo limpo (gitleaks CI, gitignore); **mas**: working tree tem senhas plaintext MySQL+RabbitMQ; commit `0a56f5a` vazou Google OAuth secret **na mensagem**; commit `c706b64` vazou topologia infra. Rotação + filter-repo pendentes |

### Importantes originais (I1-I6)

| ID | Descrição | Status | Evidência |
|---|---|---|---|
| **I1** | Token Exchange (RFC 8693) implemented | ✅ | `act` aninhado (`AuthorizationController.cs:531-535`); scope intersection (`:517-519`); allowlist (`:452-464`); subject via `Claims.Subject` (`:484`); `TokenExchangeTests` |
| **I2** | Discovery honesta (DPoP/JAR/sessions) | ⚠️ | DPoP/JAR/check_session/claims_parameter/request_uri **honestamente ausentes** (`ServiceCollectionExtensions.cs:345-373`, `DiscoveryTests:30-55`); PAR registered mas não required (`:163`); **back/frontchannel logout advertised true mas stubs** (`:362-367` + `AuthorizationController.cs:651-674`) |
| **I3** | `email_verified`/`name`/`picture` dos externais | ⚠️ | Google `email_verified` mapped (`ServiceCollectionExtensions.cs:430`); Facebook/GitHub sem `ClaimAction` explícito — `name` funciona, `email_verified`/`picture` provavelmente faltam |
| **I4** | Refresh rotation (reuse invalidation) | ⚠️ | Rotation ON (`ServiceCollectionExtensions.cs:239-248`); **reuse leeway tolerado** dentro da janela OpenIddict (`RefreshTokenTests:76+`) — accepted risk, não é true reuse-detection |
| **I5** | Reference tokens + introspection (audience check) | ✅ | `UseReferenceAccessTokens` (`:277-280`); introspection endpoint (`:158`); exercised por `IntrospectionTests` e `TokenExchangeTests` |
| **I6** | `directive` claim emitida + destino | ✅ (com residual) | Emitida via `AddPersistedClaimsAsync` (`:719-733`); roteada por `GetDestinations` default (`:779-796`); registrada em discovery (`:213`). **Residual**: vai para TODOS audiences (gap #10 acknowledged) |

### Novos achados desta avaliação (não cobertos por C/I anteriores)

| ID | Severidade | Descrição | Evidência |
|---|---|---|---|
| **N1** | HIGH | CSRF no consent POST `/connect/authorize` | `AuthorizationController.cs:56-58, 145-165` — `[IgnoreAntiforgeryToken]` sem `_antiforgery.ValidateRequestAsync()`. Justificativa incorreta. `DeviceController.Verify:219` faz certo |
| **N2** | MEDIUM | CSRF no logout POST `/connect/logout` | `AuthorizationController.cs:621-636` — mesmo padrão (lower-impact: logout forçado) |
| **N3** | MEDIUM | `backchannel_logout_supported`/`frontchannel_logout_supported` advertised true mas stub | `ServiceCollectionExtensions.cs:362-367` + `AuthorizationController.cs:651-674` |
| **N4** | MEDIUM | UI sibling CI pin (`381c9a6`) NÃO inclui fixes P0 da UI | `ci.yml:46` + comentário admitindo; UI worktree tem uncommitted |
| **N5** | HIGH | Trabalho P0 inteiro UNTRACKED | `git status` mostra `src/tests/`, `Dockerfile`, `.github/`, `DeviceController.cs` untracked; 6 modified files |
| **N6** | HIGH | Vazamento de Google OAuth secret em **commit message** `0a56f5a` | `git show --no-patch 0a56f5a` confirma `ClientId=609194959516-...` e `ClientSecret=KKwyJC8v...` no body. Imutável sem `filter-repo --replace-message` |

---

## 3. COMPARAÇÃO — Mercado IdP 2026

### 3.1 Plataformas avaliadas

Fontes consultadas (Jul/2026): sites oficiais, OpenID Foundation, blogs de release,
OpenID certification roster, MarkTechPost, WorkOS, Auth0/Okta newsroom.

### 3.2 Checklist "STS Moderno 2026"

| Requisito | RFC/Spec | Observações 2026 |
|---|---|---|
| OAuth 2.1 aligned defaults (sem implicit, sem password default, PKCE mandatory) | draft-12 | Default esperado; password grant é feature flag |
| OIDC Certification (Basic/Implicit/Hybrid/Config) | OIDC | Tabela oficial openid.net/developers/certified/ |
| FAPI 2.0 Security Profile + Baseline | openid/fapi-2_0-security-02 | **Final spec desde Set/2025**; exige PAR + sender-constraining (mTLS ou DPoP) |
| DPoP (sender-constraining) | RFC 9449 | Adotado por Keycloak 26.4, Duende 7.3, Auth0 |
| PAR | RFC 9126 | Mandatório em FAPI 2.0 |
| Token Exchange | RFC 8693 | OpenIddict 7.0+ nativo; usado para OBO/delegation |
| JAR | RFC 9101 | Opcional, comum em FAPI |
| JARM | oauth-v2-jarm | Resposta de authorization em JWT |
| Backchannel Logout | OIDC Back-Channel 1.0 | Table stakes; precursor do SSF/CAEP |
| Frontchannel Logout | OIDC Front-Channel 1.0 | Table stakes |
| Passkeys/WebAuthn passwordless default | W3C WebAuthn L3 | Default 2026 em Keycloak 26.4, Zitadel, Authentik, Ory, Auth0, Entra |
| Server-side sessions | — | Para revogação imediata |
| Step-up / CIBA | RFC 9106 | Para MFA contextual |
| Token revocation + introspection | RFC 7009 / RFC 7662 | Table stakes |
| WebFinger | RFC 7033 | Para discovery por email |
| Dynamic Client Registration | RFC 7591/7592 | Para multi-tenancy de clients |
| **SSF/CAEP** (Shared Signals / Continuous Access) | OpenID SSF 1.0 (Set/2025) | **Novo standard 2025-2026**; backchannel logout é precursor |
| SCIM 2.0 provisioning | RFC 7643/7644 | Para HR-driven IAM |
| **MCP Authorization** | modelcontextprotocol.io/specification/draft + 2025-11-25 | OAuth 2.1 + PKCE + Resource Indicators (RFC 8707) + RFC 9728 Protected Resource Metadata. Spec update **2026-07-28** com agent auth refinements |
| **Agent Identity / Workload Identity** | (sem RFC ainda) | Auth0/Okta lançaram "Agent Identity Management" Maio/2026 (primeiro enterprise-grade); ID-JAG signatures via JWKS |
| Federation (OIDC/SAML/WS-Fed) | vários | Para enterprise SSO |

### 3.3 Matriz comparativa

Legenda: ✅ native / ⚠️ partial / ❌ missing / — N/A

| Recurso | **sufficit-identity** | Keycloak 26.x | Duende IS 7.3/8α | OpenIddict 7.6 puro | Zitadel | Ory | Authentik | Auth0/Okta | Entra External ID |
|---|---|---|---|---|---|---|---|---|---|
| **Licença** | MIT-0 (código próprio) + Apache 2.0 (OpenIddict) | Apache 2.0 | Comercial (RPL/commercial); free p/ dev | Apache 2.0 | AGPL 3.0 + commercial | Apache 2.0 + OEL | MIT + EE | SaaS | SaaS |
| **Self-host** | ✅ | ✅ | ✅ | ✅ (library) | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Custo prod self-host** | $0 | $0 (ou Red Hat SSO) | $5.7k-25k+/ano (production license) | $0 | Enterprise: contact; Cloud Pro $100/mês | OEL contact; Network $770-9.3k+/mês | $5/user/mo EE; Plus $20k+/ano | $35-240+/mo Essentials/Pro | Free tier p/ MAU; paid tiers |
| **OAuth 2.1 aligned** | ⚠️ (password+none default ON) | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ | ✅ | ✅ |
| **OIDC Certification** | ❌ (ainda não) | ✅ | ✅ | ✅ (pode certificar) | ✅ | ⚠️ | ❌ | ✅ | ✅ |
| **FAPI 2.0** | ❌ | ✅ (26.4) | ✅ (7.3) | ❌ (ainda não) | ❌ | ❌ | ❌ | ✅ | ✅ |
| **DPoP** | ❌ | ✅ (26.4) | ✅ | ❌ (issue aberto) | ⚠️ | ❌ | ❌ | ✅ | ⚠️ |
| **PAR** | ⚠️ endpoint só, não required | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Token Exchange (8693)** | ✅ | ✅ | ✅ | ✅ (7.0+) | ✅ | ⚠️ | ⚠️ | ✅ | ✅ |
| **JAR** | ❌ (removido honestamente) | ✅ | ✅ | ⚠️ | ✅ | ❌ | ⚠️ | ✅ | ✅ |
| **Backchannel Logout** | ⚠️ advertised true, stub | ✅ (GA 2025.10) | ✅ | ⚠️ (precisa implementar) | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Passkeys/WebAuthn** | ❌ (stub só) | ✅ (26.4 GA) | ✅ | ⚠️ (.NET 10 Identity AddPasskeys) | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Server-side sessions** | ❌ | ✅ | ✅ | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **CIBA** | ❌ | ✅ | ✅ | ⚠️ | ✅ | ❌ | ⚠️ | ✅ | ✅ |
| **Revocation/Introspection** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **DCR (7591/7592)** | ❌ | ✅ | ✅ | ⚠️ | ✅ | ⚠️ | ⚠️ | ✅ | ⚠️ |
| **SSF/CAEP** | ❌ | ⚠️ (experimental 2026.07) | ⚠️ | ❌ | ⚠️ | ❌ | ❌ | ⚠️ | ⚠️ |
| **SCIM 2.0** | ❌ | ✅ | ⚠️ | ❌ | ✅ | ⚠️ | ✅ | ✅ | ✅ |
| **MCP Authorization (OAuth 2.1 + RFC 8707 + RFC 9728)** | ⚠️ (PAR teórico, sem RFC 9728) | ✅ (guias práticos) | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ✅ (primeiro enterprise MCP auth, Maio/2026) | ⚠️ |
| **Agent Identity / OBO** | ⚠️ (token exchange) | ✅ | ✅ | ✅ | ⚠️ | ⚠️ | ⚠️ | ✅ (Agent Identity Management 2026) | ⚠️ |
| **SAML federation** | ❌ | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ |
| **Admin UI** | ⚠️ (Skoruba legada separada, sem port) | ✅ nativa | ✅ (BFF template) | ❌ (DIY) | ✅ nativa | ⚠️ (console cloud) | ✅ nativa | ✅ nativa | ✅ nativa |

### 3.4 Posicionamento do sufficit-identity

Em_features paridade_, o sufficit-identity está atrás de Keycloak 26.4 / Duende 7.3 /
Auth0 em praticamente todas as dimensões modernas (FAPI 2.0, DPoP, passkeys, SSF/CAEP,
MCP, SCIM, SAML). **Porém** esse comparativo é injusto para um projeto alpha que está em
remediação ativa. O **posicionamento correto** é:

- **Vs. Duende legado (atual produção):** superior em modelo de licenciamento ($0 vs
  $5.7k-25k/ano), em stack moderna (.NET 9 vs 8/preview), e em clareza arquitetural.
  Inferior em features prontas (Duende tem FAPI 2.0, DPoP, server-side sessions nativos).
- **Vs. Keycloak:** inferior em features (Keycloak 26.4 é o release-marco que uniu passkeys
  + FAPI 2.0 + DPoP), mas superior em alinhamento ao stack Sufficit (.NET) e controle
  fino do código.
- **Vs. OpenIddict puro:** idêntico no núcleo (é OpenIddict 7.6 + UI custom). Diferencial
  do Sufficit é a UI Blazor Server, integração com RabbitMQ email, schema snake_case
  legacy-compatible, e o pensamento de "directive" claim para authz downstream.
- **Vs. Auth0/Entra (SaaS):** perde em TTM (minutos vs semanas), features maduras e escala.
  Ganha em custo ($0 vs per-MAU), privacidade de dados, ausência de vendor lock-in.

**Conclusão:** A escolha OpenIddict-sobre-Duende foi correta dado o contexto Sufficit
(licença, stack .NET, controle). Mas o **roadmap precisa incluir com urgência**:
passkeys (desbloqueia com .NET 10/Pomelo EF10), DPoP + PAR-required, e backchannel logout
real — porque esses viraram table-stakes em 2026 e o ecossistema (Keycloak 26.4) está
muito à frente. **Agent Identity / MCP auth é o diferencial pós-cutover** — Auth0 já
lançou primeiro product em Maio/2026, mas o Sufficit tem abertura natural via token
exchange + directive claim para authz granular de agentes.

---

## 4. VEREDITO

### 4.1 Notas por dimensão

| Dimensão | Nota | Justificativa |
|---|---|---|
| **Segurança** | **B+ (7.5/10)** | C1/C2/C3 RESOLVED; C4 PARTIAL (3 vazamentos residuais em working tree + commit msg); I1 RESOLVED; I2-I4 PARTIAL; I5/I6 RESOLVED. **Novo HIGH**: CSRF no consent. **Novo MEDIUM**: back/front logout stub advertised true. Lockout, rate limit, anti-enumeração, cert fail-fast, refresh rotation — sólidos. |
| **Arquitetura** | **A- (8.5/10)** | 5-projeto limpo acíclico; snake_case legacy-compatible sem prefixo OpenIddict; Data Protection em MySQL; options pattern idiomático; separation of concerns correta (UI → core, STS → UI); paridade com legado preservada. Único gap: UI sem NuGet package, ProjectReference sem fallback Condition. |
| **Qualidade** | **B (7.0/10)** | 20 testes E2E (era 0 pré-F1-F4); CI `-warnaserror`+gitleaks+vuln-audit; só 1 TODO no codebase; comentários explicam o porquê. Faltam: cobertura UI real, SAST/CodeQL, code coverage, cache NuGet, image scan, HEALTHCHECK Docker, branch protection verificável. |
| **Completude** | **C+ (6.5/10)** | Faltam para paridade 2026: migrations EF, passkeys reais, DPoP, PAR-required, back/front logout real, SSF/CAEP, SCIM, MCP RFC 9728. Cutover Onda A ainda bloqueado por N4/N5/N6 (UI pin desatualizado, P0 untracked, vazamento commit msg). |

### 4.2 Gaps priorizados para cutover de produção (Onda A)

**Critério:** Onda A = migrar 26 clients / 2.358 usuários do Duende legado para o novo STS.

#### 🔴 BLOCKERS (GO/NO-GO)

| # | Gap | Esforço | Tipo |
|---|---|---|---|
| **B1** | Rotação de credenciais vazadas: MySQL `identity`, RabbitMQ, Google OAuth ClientSecret | 1-2h humana | Human-only |
| **B2** | `git filter-repo --replace-message --replace-text` p/ limpar commit `0a56f5a` (Google secret msg) + commit `c706b64` (topologia) + JWKS_KEYS.md | 1h + force push | Human-only |
| **B3** | **CSRF no consent POST `/connect/authorize`** — adicionar `_antiforgery.ValidateRequestAsync(HttpContext)` como em `DeviceController.Verify:219` | 30min code | Code-side |
| **B4** | **Back/front logout stub** — ou implementar distribuição real de logout_token para RPs, ou setar `backchannel_logout_supported=false` em discovery | 4h code ou 5min config | Code-side |
| **B5** | **Commit do P0 NÃO-comitado** (`src/tests/`, `Dockerfile`, `.github/`, `DeviceController.cs`, mods) — sem commit, deploy não é reprodutível | 30min + review | Code-side |
| **B6** | UI sibling CI pin (`381c9a6`) **desatualizado** — bumpar para SHA que inclua fixes P0 da UI após commit lá | 15min + re-run CI | Code-side |
| **B7** | Provisionar **PFX/JWKS reais** de produção (signing + encryption) e configurar `Sufficit:Identity:Certificates:*` | 1-2h +.ops | Human-only |
| **B8** | **Ensaio de migração dos 26 clients em clone** do schema `identity2` antes do cutover real (validar `ConsentType`, `requirements`, `redirect_uris`) | 4-8h | Human-only |

#### 🟡 HIGH (pré-Onda A idealmente)

| # | Gap | Esforço |
|---|---|---|
| H1 | Criar EF Core migrations idempotentes (substituir SQL ad-hoc deletado) | 1-2 dias |
| H2 | `.ProtectKeysWithCertificate(cert)` reusing signing PFX | 1-2h |
| H3 | Publicar `Sufficit.Identity.UI` NuGet package + Condition+fallback no `STS.csproj` | 2-4h |
| H4 | Adicionar `HEALTHCHECK` no Dockerfile apontando para `/health` | 5min |
| H5 | Pin Docker base images por SHA digest | 5min |
| H6 | ClaimActions para Facebook/GitHub `email_verified`/`picture` | 1h |

#### 🟢 MEDIUM (Onda B/C/E)

| # | Gap | Esforço |
|---|---|---|
| M1 | Passkeys reais (desbloqueia com .NET 10 + Pomelo EF10) | bloqueado |
| M2 | DPoP + PAR-required (sender-constraining) | 2-3 dias |
| M3 | Server-side sessions + real backchannel logout distribution | 3-5 dias |
| M4 | `LegacyGrants.Password=None=false` (Onda E) | config flip coordenado |
| M5 | `TokenExchange.Enabled=false` default (Onda E) | config flip |
| M6 | Persisted claim scope gating (directive por audience) | 1 dia |
| M7 | SAST/CodeQL job no CI | 2h |
| M8 | Code coverage (coverlet) + badge | 2h |
| M9 | CSP para Blazor Server | 4h |
| M10 | FAPI 2.0 baseline (exige M2 + M3) | 1-2 semanas |

### 4.3 Recomendação GO/NO-GO para Onda A

**🛑 NO-GO.**

Justificativa: 8 blockers code-side e human-only não resolvidos. Os 3 mais críticos:

1. **B1+B2+B7 (segredos)**: sem rotação e limpeza de histórico, qualquer clone do repo
   público continua expondo Google OAuth ClientSecret — credencial ativa de produção.
2. **B3 (CSRF consent)**: vulnerabilidade HIGH nova, código-side, 30min para fixar.
3. **B5+B6 (P0 uncommitted + UI pin)**: deploy não é reprodutível a partir do repo; CI
   testa contra UI desatualizada.

**Projeção para GO condicional:** 2-3 dias de trabalho focado:
- **Dia 1:** B1 (rotação) + B2 (filter-repo) + B7 (PFX) — humano + ops
- **Dia 2:** B3 (CSRF) + B4 (logout stub) + B5 (commit P0) + B6 (UI pin bump) + B8
  (ensaio clients clone) — code + review
- **Dia 3:** H1-H6 paralelo, smoke test final em clone do `identity2`, go/no-go decision

**Condição de GO pós-Onda A:** monitorar por 7 dias em paralelo ( legado + novo ),
comparar contagens de login/token emitidos, validação introspection cross-system, e só
então desligar o legado. **NÃO desligar o legado antes de 7 dias verdes.**

### 4.4 Riscos residuais aceitos

Aceitos pelo time (documentados em código com comentários):
- `UseReferenceAccessTokens=true` global afeta todos os 26 clients (só 1 usa reference
  hoje) — flip é migration-contract, postergado
- `LegacyGrants.{Password,None}=true` default — OAuth 2.1-remove, postergado p/ Onda E
- `TokenExchange.Enabled=true` default — mantido conservador
- `directive` claim vai para todos audiences — gap #10
- Refresh token reuse leeway — accepted OpenIddict default
- DP keys plaintext at-rest MySQL — TODO explícito
- CSP ausente — deferral Blazor
- Floating Docker tags — acceptable com vuln audit
- `.NET 9 EOL` desde 2026-05-12 — bloqueado por Pomelo/EF Core 10

---

## 5. Anexos

### 5.1 Estado do working tree (auditado em 2026-07-21)

```
On branch feature/eval-p0-remediation
Changes not staged for commit:
  modified:   Directory.Build.props
  modified:   Directory.Packages.props
  modified:   Sufficit.Identity.sln
  deleted:    docs/INVESTIGATION-2026-07-20.md
  deleted:    docs/UPGRADE-PLAN-2026-07-20.md
  deleted:    docs/migration/AUDIT.md
  deleted:    docs/migration/CLIENT_MIGRATION_REPORT.md
  deleted:    docs/migration/JWKS_KEYS.md
  deleted:    docs/migration/PLAN.md
  deleted:    docs/migration/inventory-baseline.md
  deleted:    docs/migration/sql/01..05_*.sql
  deleted:    docs/migration/sql/generate_clients_migration.py
  modified:   src/core/Data/AppDbContext.cs
  modified:   src/core/Sufficit.Identity.Core.csproj
  modified:   src/server/ServiceCollectionExtensions.cs
  modified:   src/server/Sufficit.Identity.Server.csproj
  modified:   src/server/SufficitIdentityOptions.cs
  modified:   src/sts/Controllers/AuthorizationController.cs
  modified:   src/sts/Program.cs
  modified:   src/sts/appsettings.json.template

Untracked files:
  .dockerignore
  .github/
  Dockerfile
  src/sts/Controllers/DeviceController.cs
  src/tests/  (9 test files + Infrastructure/)
```

### 5.2 Método da avaliação

- 1 agente Explore (read-only, very thorough) para audit de segurança — verificação file:line
- 1 agente Explore para arquitetura/qualidade/testes/CI/UI integration
- 1 agente general-purpose para pesquisa web mercado (FALHOU em loop, recuperado via
  WebSearch direto pelo avaliador)
- Verificação pessoal do avaliador (GLM-5.2) em: `Program.cs`, `AuthorizationController.cs`,
  `DeviceController.cs`, `ServiceCollectionExtensions.cs`, `SufficitIdentityOptions.cs`,
  `Directory.Build.props`, `Directory.Packages.props`, `Dockerfile`, `.dockerignore`,
  `.github/workflows/ci.yml`, git log/status/history
- Contexto histórico via memória Sufficit AI: 4 checkpoints anteriores (Investigação,
  F1-F4, EVAL-2026-07-20, P0 implementado)

### 5.3 Próximos passos sugeridos

1. **Decisão de commit/push:** com o histórico de incidente de push não-autorizado a
   `origin/main`, recomendar squash + PR review para o bloco P0 + fixes desta avaliação.
2. **Operação humana-only imediata:** iniciar B1+B2+B7 (segredos + filter-repo + PFX)
   independentemente do commit do código.
3. **Após GO condicional:** roadmap Onda B/C = passkeys (desbloqueio .NET 10), DPoP,
   server-side sessions, MCP RFC 9728 — nesse ordenado por valor defensivo.

---

**FIM DO DOCUMENTO**
