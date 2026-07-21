# Avaliação — Sufficit Identity (Fable)

**Data:** 2026-07-21
**Objeto:** `/mnt/sufficit/sufficit-identity` (+ UI irmã `sufficit-identity-ui`) — STS OAuth 2.0/OIDC em **.NET 9** (o TFM real é `net9.0`, apesar do enunciado citar .NET 10 — ver §V.B5) + OpenIddict 7.6.0 + ASP.NET Core Identity + MySQL/Pomelo, substituindo o stack legado Skoruba/Duende.
**Escopo de cutover:** ~26 clients · ~2.358 usuários (Onda A = validação candidata a produção).
**Base de código avaliada:** branch `feature/eval-p0-remediation` em **ambos** os repos; HEAD do STS `7740872` **+ P0 remediation não comitada no worktree** (24 arquivos `+904/−2399`; `src/tests/`, `.github/`, `Dockerfile`, `DeviceController.cs` untracked; `docs/` deletado). UI: 12 arquivos modificados + `LocalUrlValidator.cs` untracked. Versão `0.2.0-alpha`.
**Método:** re-execução crítica direta no código (não confiei nos docs — que aliás não existem mais no worktree). Verificação por leitura de `file:line` + build/test reais + 5 agentes de investigação (2 de segurança, arquitetura, qualidade, pesquisa de mercado). Divergências reconferidas na fonte.

> ⚠️ **Sem commits.** Esta avaliação não altera código nem histórico. Segredos encontrados **não** são reproduzidos aqui.

**Veredito: NO-GO para a Onda A completa** — mas a distância até o GO **encurtou drasticamente** desde a avaliação de 2026-07-20. O que bloqueia agora **não** é mais funcionalidade quebrada (device flow e consent foram consertados e testados); é **entrega/operação**: nada comitado, incidente de segredos aberto, runtime EOL com migração bloqueada, e defaults permissivos. Ver §IV.

---

## I. Sumário executivo

A rodada de remediação P0 é **real e verificável no código**, não só no checkpoint. Dos bloqueadores funcionais que sustentavam o NO-GO anterior, a maioria foi de fato corrigida e coberta por teste:

- **Device flow** agora funciona ponta-a-ponta (`DeviceController` + branch `IsDeviceCodeGrantType` + correção do bug de resolução de subject `sub` vs `NameIdentifier`), com 3 testes E2E (pending/approve/deny).
- **Consent** deixou de ser decorativo: redireciona para `/consent`, `deny` produz `access_denied`, `prompt=consent` força reconsentimento (a inversão de lógica foi corrigida). Testado.
- **Data Protection** persistida em `AppDbContext` (`PersistKeysToDbContext`).
- **Cookie `Secure=Always`** fora de dev, **`SetIssuer`** fixado, **`UseHttpsRedirection`**, **Swagger atrás de `IsDevelopment()`**, **lockout no ROPC** com erro genérico anti-enumeração e rate limit, **token exchange** com kill-switch + allowlist + `act` aninhado + narrowing de claims/scopes.
- **UI** endurecida: `LocalUrlValidator` (open-redirect), account-link só com sessão + `email_verified`, email sender sem log de corpo/token, TOTP SSR.
- **Build limpo** (`-warnaserror` passa, 0 warnings — o CS8601 foi corrigido), **20/20 testes** (era 9/9), **0 pacotes vulneráveis** (Pomelo `9.0.0` estável, SQLitePCLRaw `2.1.12`, OpenIddict `7.6.0`).

Mas o STS **ainda não é candidato de produção para a Onda A completa**. Os bloqueadores agora são de natureza diferente:

1. **Nada está comitado.** Toda a remediação P0 vive num único worktree em disco, no branch `feature/eval-p0-remediation`, em ambos os repos. O HEAD implantável (`7740872`) **não tem** nenhuma dessas correções. A CI (`.github/`) é **untracked** e **nunca rodou**. Um clone/deploy limpo hoje entrega o STS sem device flow, sem consent, sem Data Protection.
2. **Incidente de segredos (C4) não encerrado.** O secret de introspecção continua **no HEAD do git** (`docs/migration/PLAN.md:65`, comitado em `72760d0`); credenciais reais de MySQL e RabbitMQ estão em `appsettings*.json` no disco (gitignored, nunca comitadas, mas vivas). E o job gitleaks da CI **comprovadamente não detecta** o secret em prosa — o controle anunciado para C4 dá falsa confiança.
3. **Runtime .NET 9 no fim da janela de suporte** (política STS 18 meses → EOL 2026-05-12; uma fonte recente cita extensão STS p/ 24 meses → 2026-11-10 — conflito não resolvido, mas em ambos os casos exige migração agora) e a **migração para .NET 10 está bloqueada** por conflito estrutural de dependências (Pomelo sem release EF Core 10), não por um pin simples.
4. **Config ship-a-inseguro:** `TrustedProxies` de produção é placeholder RFC 5737 (nunca casa); ROPC e `none` ligados por default; token exchange `Enabled=true` com allowlist vazia.
5. **Migração dos 26 clients** segue não comprovada — e o runbook SQL foi **deletado do worktree** inteiro.
6. **Novos achados**: CSRF na tela de consent, oráculo anônimo de `user_code` sem rate limit, logout federado ainda stub mas anunciado `true` no discovery.

FAPI 2.0, DPoP, SSF/CAEP e agent identity permanecem gaps de roadmap — não são a causa do NO-GO se nenhum dos 26 clients os exige.

---

## II. Verificação C1–C4 / I1–I6 / B1–B5 + achados #1–#13

**Legenda:** ✅ RESOLVIDO (código + condição satisfeitos, testado quando aplicável) · ⚠️ PARCIAL · ❌ ABERTO. Todas as evidências foram lidas diretamente no worktree.

| ID | Status | Evidência (`file:line`) | Ressalva |
|----|--------|-------------------------|----------|
| **C1** ROPC sem lockout | ✅ | `AuthorizationController.cs:409-411` `CheckPasswordSignInAsync(lockoutOnFailure:true)`; erro genérico `:416-425`; rate limit `Program.cs:131-150`; testado (`PasswordGrantTests` 4 casos) | **ROPC ainda bypassa 2FA** — `CheckPasswordSignInAsync` valida só senha+lockout; usuário com 2FA obtém token com senha. Inerente ao grant (que segue ON, #6). |
| **C2** `/diagnostics/schema` anônimo | ✅ | endpoint removido; Swagger `Program.cs:223-227` atrás de `IsDevelopment()` | `AddSwaggerGen()` (`:91`) é incondicional mas só o middleware `UseSwagger/UI` importa, e está dev-only. |
| **C3** certs de dev em prod | ✅ (código) / ⚠️ operacional | `ServiceCollectionExtensions.cs:304,325` `X509CertificateLoader.LoadPkcs12FromFile`; fail-fast fora de dev `:313-321,334-342` | Loader **não valida** expiração nem `HasPrivateKey`; `ProtectKeysWithCertificate` não ligado (TODO). Provisioning/ACL/rotação/backup ainda humano-only. |
| **C4** segredos em VCS | ❌ **incidente ativo** | secret de introspecção em prosa no **HEAD**: `docs/migration/PLAN.md:65` (comitado em `72760d0`); MySQL/RabbitMQ reais em `appsettings.json`/`appsettings.Development.json` (gitignored, nunca comitados); gitleaks CI `ci.yml:111-141` | **gitleaks NÃO pega** o UUID em prosa (regra `generic-api-key` exige `key=value`) — verificado empiricamente (29 commits, "no leaks"). Deletar `docs/` no worktree **não** limpa histórico. Rotação + purge de histórico pendentes. |
| **I1** claim `directive` não emitida | ⚠️ | emitida via `AddPersistedClaimsAsync` (`:707`), re-sync no refresh (`:303`); `GetDestinations:747-798` gateia `name/email/role` por scope | Claims custom (`directive`) ainda vão ao access token **incondicionalmente** (`default` case `:779-796`) para qualquer audiência (=#10). |
| **I2** discovery anuncia recurso falso | ⚠️ | DPoP/JAR/check_session/claims_parameter removidos (`ServiceCollectionExtensions.cs:344-373`); `DiscoveryTests` pina ausências | **Ainda anuncia `backchannel_logout_supported`/`frontchannel_logout_supported`=true** (`:362-367`) sendo stub (=I4). Mesma classe de defeito. |
| **I3** check-session iframe stub | ✅ | removido; `DiscoveryTests.cs:45` pina ausência | — |
| **I4** logout federado / sessions | ❌ | `BackchannelLogout:653-659` retorna `200 {status:ok}` no-op; `FrontchannelLogout:668-674` HTML estático `window.close()` | Sem propagação server-side a RPs, sem store de sessão, sem fan-out de `logout_token`. |
| **I5** Forwarded Headers confia em tudo | ✅ (código) / ⚠️ config | `Program.cs:27-65` bind CIDR; warning se vazio `:156-161`; prod define lista `appsettings.json:19` | Valor de prod é **placeholder** `203.0.113.0/24` (RFC 5737, nunca casa) → #1. |
| **I6** zero testes / CI | ✅ (existem) / ⚠️ | 10 arquivos em `src/tests/`, **20/20 verde**; `.github/workflows/ci.yml` | **Untracked** (`git ls-files` vazio) → CI nunca rodou; factory não sobe `Program.cs` real; SQLite ≠ MySQL. |
| **B1** device flow quebrado | ✅ | branch `:243-246` → `ExchangeForDeviceCodeAsync:330-378`; `DeviceController.cs` GET `:135`/info `:152`/POST verify `:211`; `UserCode.razor` valida via `/connect/device/info`; **bug `sub` corrigido** `:355` (`GetClaim(Claims.Subject)`) | `slow_down` explícito ausente (delegado ao OpenIddict); `/connect/device/info` anônimo e sem rate limit (achado novo #N2). |
| **B2** `UseReferenceAccessTokens()` global | ⚠️ | flag `ServiceCollectionExtensions.cs:277-280`; default `true` (`SufficitIdentityOptions.cs:138`) | Continua **global** (OpenIddict não tem formato por-client); default preserva reference token → RSs que validam JWT localmente quebram no cutover. |
| **B3** consent quebrado/órfão | ✅ | `:145-208`; `prompt=consent`→interativo `:181,186`; deny→`access_denied` `:156-163`; redirect `/consent` `:206`; `Consent.razor` deny(`value="deny"`)≠allow | Gap menor: `ConsentTypes.Implicit` ignora `prompt=consent` (`:185`) → auto-concede (achado #N3). |
| **B4** Data Protection não persistida | ✅ | `ServiceCollectionExtensions.cs:92-94` `AddDataProtection().SetApplicationName().PersistKeysToDbContext<AppDbContext>()`; `AppDbContext.cs:24,36,190-192` | Chaves **não cifradas em repouso** (`ProtectKeysWithCertificate` não ligado); tabela `dataprotectionkeys` precisa ser criada **manualmente** em prod. |
| **B5** runtime .NET 9 fim-de-suporte | ❌ | todos os `.csproj` em `net9.0`; sem `global.json` (build usa SDK 10 por roll-forward, mas **targeta net9.0**) | EOL 2026 (18 meses→12/05/2026; fonte conflitante cita 24 meses→10/11/2026 — flag). **Migração para .NET 10 BLOQUEADA** (não só adiada): OpenIddict.EFCore net10 exige EF Core ≥10.0.10; **Pomelo não tem release EF Core 10** (topa em 9.0.0 estável); irmãos `Sufficit.Communication`/`Sufficit.EFData` capam Caching <10 (NU1107). Desbloqueio exige trocar provider MySQL (ex. Oracle `MySql.EntityFrameworkCore`), rodar EF Core 9 sobre .NET 10, ou esperar Pomelo. `AddPasskeys()` do .NET 10 (passkeys nativas no Identity) fica bloqueado junto. |
| **#1** `TrustedProxies` vazio/placeholder | ⚠️ | template documenta; prod `appsettings.json:19` = `203.0.113.0/24` | Se ficar, rate limiter particiona pelo IP do proxy (um bucket 30/min p/ todo o deployment) e `X-Forwarded-Proto` é descartado (derruba cookie Secure). Humano deve trocar por CIDR real. |
| **#2** cookie sem `SecurePolicy` | ✅ | `ServiceCollectionExtensions.cs:129-131` `Always` fora de dev | — |
| **#4** token exchange sem policy | ✅ (permissivo) | kill-switch+allowlist `:452-464`; narrowing `:510-521`; `act` aninhado `:531-535` | Ship permissivo: `Enabled=true` (`:840`), `AllowedClientIds` vazio (`:856`) → qualquer client com a permission OpenIddict troca sem allowlist extra. Eval pedia OFF por default. |
| **#5** Swagger incondicional | ✅ | `Program.cs:223-227` `IsDevelopment` | — |
| **#6** ROPC/`none` ON por default | ⚠️ | flags `LegacyGrants` gateiam `:232-236` | Ambos default `true` (`SufficitIdentityOptions.cs:226,231`; template `:41,43`) — legados seguem **ligados** por default (adiado p/ "Onda E"). |
| **#8** issuer/host/https | ✅ | `SetIssuer:181-184`; `AllowedHosts` prod `identity-open.sufficit.com.br` (`appsettings.json:13`); `UseHttpsRedirection Program.cs:186` | Dev `AllowedHosts=*` (intencional). |
| **#9** `act` sobrescreve | ✅ | `:531-535` aninha cadeia de actor prévia (RFC 8693 §4.1) | — |
| **#10** claims sem gating | ⚠️ | `name/email/role` gateados `:751-774` | `directive`/custom → access token incondicional `:779-796` (documentado como follow-up). |
| **#11** só token endpoint tem rate limit | ⚠️ | `Program.cs:131-150` só `POST /connect/token` | `introspect`/`revocation`/`authorize`/`userinfo`/`par`/`device/info` sem throttle. |
| **#12** enumeração por timing | ✅ | `:409-411` sem short-circuit de hash; msg genérica; teste pina | Micro-timing residual (`FindByNameAsync` retorna antes p/ user inexistente), sem bypass. |
| **#13** logout POST `[IgnoreAntiforgeryToken]` | ⚠️ | `:624` confia em `EditForm` Blazor + cookie same-origin | `post_logout_redirect_uri` validado pelo OpenIddict; sem open-redirect no STS. |

**Placar consolidado:** dos 4 críticos e 6 importantes originais + 5 bloqueadores B1–B5, **12 estão RESOLVIDOS no código** (C1, C2, C3-código, I3, B1, B3, B4, #2, #4, #5, #8, #9). **C4 e I4 permanecem ABERTOS.** **B2, B5, I1, I2, I5-config, #1, #6, #10, #11, #13 são PARCIAIS.** O salto real: os dois bloqueadores funcionais que mais pesavam (device flow #B1, consent #B3) foram **de fato consertados e testados**.

---

## III. Achados novos (não vistos na investigação anterior)

**#N1 — CSRF na tela de consent (MÉDIA).** `/connect/authorize` é `[IgnoreAntiforgeryToken]` (`AuthorizationController.cs:58`) e `Consent.razor:50-76` é um form SSR **sem token antiforgery**. Um `POST consent_decision=allow` auto-submetido de outra origem pode aprovar consent silenciosamente para um client cujo `redirect_uri` o atacante controla. **Inconsistência gritante:** `DeviceController.Verify` (`:219`) *valida* antiforgery via `IAntiforgery.ValidateRequestAsync` — o caminho de consent é o mais fraco dos dois. **Corrigir antes de habilitar qualquer client interativo.**

**#N2 — Oráculo anônimo de `user_code` sem rate limit (BAIXA-MÉDIA).** `GET /connect/device/info` é `[AllowAnonymous]` (`DeviceController.cs:151-152`) e fora do escopo do rate limiter (que só cobre `POST /connect/token`). Permite enumerar `user_code`s vivos e vazar `client_id`/`client_name`. Mitigado por códigos de alta entropia/curta vida, mas nada limita a adivinhação.

**#N3 — `prompt=consent` ignorado para clients Implicit-consent (BAIXA).** `AuthorizationController.cs:185`: `ConsentTypes.Implicit => false` independente de `forcesReconsent` — um client Implicit auto-concede sem UI mesmo pedindo reconsent explícito. Não é OIDC-`prompt`-compliant.

**#N4 — Disclosure de existência de conta no login externo (BAIXA).** `ExternalLoginController.cs:139` redireciona com `error=account_link_requires_signin&email=<email refletido>`; combinado com códigos de erro distintos (`:76,79,129,150`) é superfície de enumeração de usuário + reflete o e-mail asserido numa URL.

**#N5 — Over-disclosure de claims persistidas cross-audience (BAIXA-MÉDIA).** `GetDestinations` default (`:779-796`) manda **toda** claim persistida (`directive`, 5000+ no DB) ao access token de **qualquer** audiência, independente de scope. Mesma raiz de I1/#10; reconhecido como residual, não fechado. Mitigado parcialmente por reference tokens + introspection filtrar para não-audiência.

**#N6 — Contrato UI/STS de scopes no device flow (cosmético).** `UserCode.razor:177` (`DeviceInfoResponse`) espera `Scopes`, mas `DeviceController.Info` deliberadamente nunca os retorna — a lista "Permissões solicitadas" fica sempre vazia. Funcional, não segurança.

---

## IV. O que realmente bloqueia o GO (mudou de natureza)

O NO-GO anterior era por **funcionalidade quebrada**. Esse foi resolvido. O NO-GO atual é por **entrega e operação**:

1. **Zero commits / CI nunca rodou.** Tudo é worktree em disco. O HEAD implantável não tem as correções. Sem revisão reproduzível, sem CI verde, não há candidato de produção — só um diff não versionado que qualquer `git checkout` ou clone limpo perde.
2. **C4 aberto de fato.** O secret de introspecção está no HEAD do git; credenciais reais no disco; o controle gitleaks não pega o formato em prosa. É um incidente de segurança **não encerrado**, não um item de roadmap.
3. **Runtime EOL + migração bloqueada.** .NET 9 sem suporte desde maio/2026; o caminho para .NET 10 LTS está **estruturalmente bloqueado** (Pomelo sem EF Core 10). Isso é decisão de plataforma (trocar provider MySQL ou esperar), não um dia de trabalho.
4. **Config insegura-por-default.** `TrustedProxies` placeholder, ROPC/`none` ON, token exchange ON+allowlist-vazia. O que sobe hoje sobe com esses defaults.
5. **Migração dos 26 clients** sem rehearsal, sem matriz de compatibilidade executável, com o runbook SQL agora deletado do worktree.

Nenhum destes é "device flow não funciona". A engenharia dos fluxos está sólida; falta **versionar, encerrar o incidente, resolver plataforma e endurecer defaults**.

---

## V. Arquitetura — nota 6,0

**Positivo:** divisão `core → server → sts` (+ management opcional + UI irmã) com composition root claro; `AppDbContext` único (agora também `IDataProtectionKeyContext`); modelo "STS headless + UI separada" (mesmo do Ory Hydra); Dockerfile novo de boa qualidade (multi-stage, non-root uid 1654, secrets excluídos via `.dockerignore` + `rm` defensivo).

**Dívidas (majoritariamente inalteradas; a remediação priorizou segurança/operação, não dívida arquitetural):**
- **`core` não é framework-independent** — acopla Identity EF + OpenIddict EF + Pomelo + **agora +1** DataProtection EF (`Sufficit.Identity.Core.csproj:11-18`); hardcoda `UTC_TIMESTAMP()` MySQL (`AppDbContext.cs:60`). O nome sugere separação que não existe.
- **Acoplamento circular STS↔UI** — STS→UI ProjectReference incondicional (`STS.csproj:29`); UI→`core` de volta (`Sufficit.Identity.UI.csproj:36`). Imagem Docker **não builda standalone** (exige `--build-context ui=`). CI pina UI por SHA (`ci.yml:43`) — bom — mas o SHA `381c9a6` **precede os fixes P0 da UI não comitados**, então a CI, como pinada, buildaria a UI *sem* as correções.
- **snake_case não é global** — só as 4 tabelas OpenIddict (`AppDbContext.cs:91-171`); Identity = tabelas lowercase mas **colunas PascalCase** (`:52-80`); `dataprotectionkeys` PascalCase. Coluna nova de OpenIddict futuro ficaria PascalCase silenciosamente.
- **Zero EF Migrations** — `EnsureCreatedAsync` (dev/test) + SQL manual (prod). Pior em rastreabilidade: o runbook SQL (`docs/migration/sql/*`) foi **deletado do worktree**, mas `AppDbContext.cs:181-188` ainda manda o ops de prod adicionar `dataprotectionkeys` "conforme o runbook" — referência pendurada.
- **Management API aquém** — só list/get/create/delete de clients (sem update/scopes/users, apesar da Description do csproj); `[Route("api/clients")]` hardcoded torna `RoutePrefix` inefetivo; `RequireAuthorization=false` é incoerente (policy só registrada se `true` → `false` quebra em runtime "policy not found", fail-closed mas incoerente; default agora é `true`, melhoria). Desabilitado por default.
- **Menores:** `ManagementOptions` duplicada entre assemblies; `TokenExchangeOptions`/`TrustedProxies` fora do `SufficitIdentityOptions` (config espalhada em 3 superfícies); `Serilog.AspNetCore` referenciado mas **nunca configurado** (dependência morta); `ServerVersion.AutoDetect` abre handshake MySQL em composition time (forçou workaround na test factory); sem pruning/retention de tokens nem audit estruturado; Dockerfile sem `HEALTHCHECK`.

---

## VI. Qualidade, testes e CI — nota 6,5

**Build & testes (rodados nesta avaliação):**
- `dotnet build -c Release -warnaserror` → **0 erros / 0 warnings** (o CS8601 da UI `ResetPassword.razor` foi corrigido). Passa de verdade agora, não por `TreatWarningsAsErrors=false`.
- `dotnet test` → **20/20 passed, 0 failed, ~1s** (era 9/9).
- `dotnet list package --vulnerable --include-transitive` → **0 vulneráveis** nos 5 projetos. **Pomelo `9.0.0` estável** (era preview.3 — dívida P2 paga); **SQLitePCLRaw `2.1.12`** (advisory GHSA-2m69-gcr7-jv3q resolvido); OpenIddict `7.6.0`.

**Cobertura — matriz:**

| Fluxo | Coberto | Fluxo | Coberto |
|---|---|---|---|
| discovery honesto | ✅ | token exchange (act/no-leak/allowlist) | ✅ |
| health liveness | ✅ | authorization_code + PKCE (+ negativos) | ✅ |
| client_credentials | ✅ | consent **deny** | ✅ |
| password + lockout (4 casos) | ✅ | device flow E2E (pending/approve/deny) | ✅ |
| introspection (directive) | ✅ | refresh **rotation** | ✅ |
| userinfo (indireto) | ✅ | refresh **reuse pós-leeway / revogação família** | ❌ |
| logout / end_session E2E | ❌ | revocation endpoint | ❌ |
| consent **allow via UI real** | ❌ | introspection negativa | ❌ |
| 2FA/passkeys/external via UI real | ❌ | comportamento MySQL/Pomelo | ❌ |

**Infra de teste (limitações):** a factory **não sobe o `Program.cs` real** (`Program` é `internal sealed partial`, invisível ao teste) — replica o wiring mínimo. Logo **rate limiter, forwarded headers, HSTS/HTTPS-redirect, security headers e o fail-fast de cert de produção nunca são exercitados**. **SQLite in-memory** substitui MySQL (com shim `UTC_TIMESTAMP`) — specifics de Pomelo/MySQL não testados. Login/approve via `TestOnlyEndpoints` (nunca registrados em prod). Clients seedados `ConsentTypes.Implicit` para pular a UI.

**Rastreamento:** `git ls-files src/tests .github` → **vazio**. Tudo untracked; a CI **nunca executou**.

**CI (`.github/workflows/ci.yml`, untracked):** todos os 4 itens de hardening presentes — `-warnaserror`, vuln audit (falha em High/Critical), gitleaks (full history), UI pinada por SHA. **PORÉM**, verificado empiricamente: gitleaks 8.30.1 contra o repo → "no leaks found" enquanto o secret de introspecção **está** no HEAD e em toda a história (regra `generic-api-key` exige keyword+operador; UUID em prosa não casa). **O job de secret-scan dá falsa confiança para exatamente o C4 que o comentário diz cobrir.**

---

## VII. Comparação de mercado (atualizada — julho/2026)

> Pesquisa web re-executada nesta avaliação. Preços/versões SaaS mudam — revalidar no momento de uma decisão de compra. Itens marcados *(nv)* = não totalmente verificável / baixa confiança.

### VII.1 Estado por produto

| Produto | Versão jul/2026 | Licença | Custo p/ ~30 clients / ~2.400 users | Veredito p/ quem já tem OpenIddict |
|---|---|---|---|---|
| **Sufficit Identity** | 0.2.0-alpha | MIT-0 / Apache-2.0 (deps) | US$ 0 | — (o objeto desta avaliação) |
| **Keycloak** | **26.7.0** (09/jul/2026) | Apache-2.0 (CNCF) | US$ 0 licença (só custo operacional JVM/Quarkus+DB+HA) | Régua do self-hosted. DPoP GA (26.4), Token Exchange padrão GA (26.2) + Delegation (26.7), **FAPI 2.0 final**, **SSF/Shared Signals (26.7)**, **MCP authorization (26.7)**, AuthZEN, Organizations GA. Troca = replatform Java. |
| **Duende IdentityServer** | **8.0.3** (20/jul/2026; v8 **exige .NET 10**) | Proprietária (source-available) | **Advanced US$ 24.900/ano (30 client IDs)**; +FGSC US$ 7.500/ano p/ FAPI 2.0 | Preço novo modular (jun/2026). 30 clients cai **exatamente** no Advanced. Community grátis só se receita <US$ 1M **e** capital <US$ 3M. Sem ganho funcional decisivo sobre OpenIddict 7.6 (token exchange+mTLS já cobertos). v8 **não roda em .NET 8/9** (ficaria em 7.4.x). |
| **OpenIddict** | **7.6.0** (15/jul/2026); 8.0-preview.2 | Apache-2.0 | US$ 0 (sponsorship opcional) | Token exchange (7.0+), mTLS (7.3). **DPoP: não suporta** (aposta em mTLS+BFF). **DCR (RFC 7591): ainda não** — feature request para 8.0-preview.3. Framework, não IAM pronto. **Bus-factor ≈ 1** (Kévin Chalet, mantenedor único) — o risco a monitorar. |
| **Zitadel** | v3+ (AGPL desde v3, início 2025) | **AGPL-3.0** (SDKs em MIT/Apache) | Self-host US$ 0 (obrigações AGPL) | Passkeys/FIDO2 fortes, OIDC-certified, token exchange (por docs). AGPL **contaminaria** o MIT-0 se linkado. Não é .NET (Go/PostgreSQL/event-sourcing). *(nv: versão exata mid-2026, preço cloud)* |
| **Ory** (Hydra/Kratos/Polis) | Hydra 2.x / Kratos 1.x | Apache-2.0 | OSS US$ 0 (roda 2–3 serviços + UI própria) | AS headless de referência fora do .NET — arquitetura mais próxima de "OpenIddict as a service"; comprou BoxyHQ → **Ory Polis** (SAML/SCIM enterprise). Migrar ganha pouco. *(nv: versões exatas)* |
| **Authentik** | 2026.x (CalVer) | Core MIT / Enterprise source-available | OSS US$ 0; Enterprise **US$ 5/user interno/mês** → 2.400 internos ≈ **US$ 144k/ano (proibitivo)**; externos US$ 0,02/mês → 2.400 ≈ ~US$ 50/mês | Appliance IdP (Python), não STS .NET embutível. Bom como caixa de workforce SSO/proxy ao lado do STS de produto; ruim como substituto. *(nv: versão exata)* |
| **Auth0 (Okta)** | SaaS | Proprietária | Free 25k MAU (2.400 cabem, mas sem essenciais de prod); realista Essentials/Professional ~US$ 150–800+/mês; +~50% p/ AI agents | Passkeys (até no Free), DPoP, **Token Exchange/OBO GA**, FAPI (Enterprise), **MCP auth GA (mai/2026)**, **Auth0 for AI Agents GA (nov/2025) + Token Vault** — o **mais forte em tooling de agente**. Custo/lock-in escala com MAU. Sem SSF/CAEP *(nv)*. |
| **Okta CIC** | SaaS | Proprietária | ~centenas US$/mês @ 2.400 MAU *(nv exato)* | **SSF/CAEP best-in-class** (transmitter+receiver via Identity Threat Protection); **Cross App Access (XAA)** = extensão MCP oficial vendor-neutral (chega ao Auth0 em EA fim jul/2026). |
| **Microsoft Entra External ID** | SaaS | Proprietária | **50k MAU grátis/mês → 2.400 = US$ 0**; US$ 0,03/MAU depois | **Mais barato na sua escala.** **Entra Agent ID GA (abr/2026)** + Conditional Access for Agents (líder em governança de agente); CAE (CAEP). **B2C: sem novos desde 01/mai/2025, P2 descontinuado 15/mar/2026, suporte até ~2030.** DCR limitado; MCP emergente *(nv)*. |
| **WorkOS AuthKit** | SaaS | Proprietária | AuthKit grátis até 1M MAU; **conexões enterprise SSO/SCIM cobradas por-conexão** (US$ 125 cada, escalonado) | **Líder em MCP auth** (OAuth 2.1 + PKCE, **RFC 9728 + 8707 + DCR**). Se os "30 clients" forem 30 federações SSO enterprise → ~US$ 3,4k/mês; se forem 30 apps OAuth comuns → US$ 0. Sem Token Vault/SSF/FAPI *(nv)*. |

**Players novos relevantes:** Logto (OAuth 2.1 + RFC 8693 + guias MCP), Pocket ID (OIDC-certified, passkey-only), Better Auth (→ Vercel, jul/2026), Hanko, Stytch (→ Twilio), Descope/SuperTokens (MCP/B2B). Maioria é lib/SaaS, não STS .NET standalone — pouco aplicável a um self-hosted .NET com MySQL + ASP.NET Identity. *(nv: detalhes por player)*

### VII.2 Checklist "STS moderno 2026"

> **Nota de spec:** OAuth 2.1 ainda é **draft** (draft-15+, mar/2026) — o baseline publicado é o **OAuth 2.0 Security BCP (RFC 9700)**. **FAPI 2.0**: Security Profile **Final (fev/2025)**, Message Signing **Final (set/2025)**. **SSF/CAEP/RISC Final (set/2025)**. **RFC 9728** (Protected Resource Metadata) **abr/2025**. **MCP authorization: revisão 2025-11-25** (OAuth 2.1 + RFC 9728 + RFC 8707) — não equivale a identidade/governança de agentes. **Agent identity:** principal trilho é o draft **ID-JAG / Cross-App Access (XAA)** liderado pela Okta; Entra Agent ID e Auth0 for AI Agents são implementações proprietárias. *(datas de spec confirmadas na pesquisa; ver §VII.3)*

| Capacidade | Estado spec | Quem tem | Status Sufficit |
|---|---|---|---|
| code+PKCE | baseline | Todos | ✅ testado E2E (+ negativos) |
| Proibição implicit/hybrid | baseline | Todos | ⚠️ intenção correta; migração dos 26 clients insegura (§VIII) |
| client_credentials | baseline | Todos | ✅ testado |
| Refresh rotation | baseline | Todos | ✅ rotação testada; ❌ reuse-detection/revogação-família sem teste |
| PAR | maduro | Keycloak, Duende, OpenIddict | ⚠️ configurado, não provado |
| **Device flow** | maduro | Keycloak, OpenIddict | ✅ **funcional + testado E2E** (era ❌) |
| Token exchange RFC 8693 | mainstream | Keycloak, OpenIddict, Duende, Auth0/Okta | ✅ com policy (kill-switch/allowlist/act/narrowing); ⚠️ defaults permissivos |
| **Passkeys/WebAuthn** | consolidado; no .NET vem no Identity do **.NET 10** | Keycloak, Zitadel, Auth0, Entra, Hanko, Pocket ID | ❌ stub — **bloqueado** junto com a migração .NET 10 (Pomelo) |
| MFA/2FA (TOTP) | maduro | Todos | ⚠️ TOTP/recovery existem (SSR corrigido); ROPC bypassa 2FA; sem E2E |
| DPoP (RFC 9449) | RFC 2023, adoção acelerando | Keycloak 26.4, Auth0, Okta | ❌ ausente — **OpenIddict não entrega**; mTLS é a alternativa do stack |
| mTLS / sender-constrained | RFC 8705 | OpenIddict 7.3 (primitives) | ⚠️ primitives do framework, não adotado |
| FAPI 2.0 | **Final** | Keycloak, Duende (add-on), Authlete, Curity | ❌ ausente. Baixa relevância (só se open finance) |
| Logout OIDC / sessions | maduro | Keycloak, Duende | ❌ **stub anunciado `true`** (I4/#N via I2) |
| Rotação de chaves + Data Protection | maduro | Todos maduros | ✅ DP persistida; ⚠️ chaves não cifradas em repouso; JWKS overlap/rotação pendente |
| SSF/CAEP/RISC | **Final set/2025** | Okta (best), Google/Apple, Keycloak (26.7) | ❌ ausente. **Substituto moderno de server-side sessions** — reforça não investir em paridade total de I4 |
| **MCP authorization** | OAuth 2.1 + RFC 9728 + 8707 | WorkOS, Auth0, Keycloak 26.7, Descope | ❌ ausente. **Alta relevância** — maior ROI pós-cutover dado o ecossistema AI/MCP da Sufficit |
| Agent identity / governance | drafts (ID-JAG/XAA); proprietário (Entra Agent ID GA, Auth0 AI Agents GA) | Entra (líder), Okta XAA, Auth0 | ❌ ausente. **Acompanhar, não implementar** — token exchange é a fundação |
| DCR / CIMD | maduro (necessário p/ MCP dinâmico) | Keycloak, WorkOS, Auth0 | ❌ ausente — **OpenIddict ainda não tem DCR** (planejado 8.0) |
| Auditoria/observabilidade | esperado | — | ❌ insuficiente (Serilog morto, sem métricas/alertas) |
| **Runtime suportado** | — | .NET 10 LTS GA 11/nov/2025 (suporte até nov/2028); passkeys nativas no Identity | ❌ **.NET 9 fim-de-suporte em 2026** (12/05 ou 10/11, fontes conflitam) + migração .NET 10 **bloqueada** (Pomelo sem EF Core 10) |

### VII.3 Fontes principais

Runtime/specs: [.NET support policy](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core) (.NET 9 EOL 2026; política STS 18m→12/05/2026 vs. fonte citando 24m→10/11/2026 — flag; **.NET 10 LTS GA 11/nov/2025**) · [.NET 10 release notes](https://github.com/dotnet/core/blob/main/release-notes/10.0/README.md) · [Passkeys no ASP.NET Identity (.NET 10)](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/passkeys/?view=aspnetcore-10.0) · [OAuth 2.1 draft-15 (02/mar/2026, ainda draft)](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) · [RFC 9700 (OAuth 2.0 Security BCP, jan/2025)](https://datatracker.ietf.org/doc/rfc9700/) · [FAPI 2.0 Security Profile Final (22/fev/2025)](https://openid.net/specs/fapi-security-profile-2_0-final.html) · [SSF/CAEP Final (set/2025)](https://openid.net/three-shared-signals-final-specifications-approved/) · [RFC 9728 (abr/2025)](https://datatracker.ietf.org/doc/html/rfc9728) · [RFC 8693 Token Exchange](https://datatracker.ietf.org/doc/rfc8693/) · [MCP Authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) · [ID-JAG / Cross-App Access draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) · [Pomelo NuGet (topa em 9.0.0)](https://www.nuget.org/packages/Pomelo.EntityFrameworkCore.MySql).
Produtos: [Keycloak 26.7.0](https://www.keycloak.org/2026/07/keycloak-2670-released) · [Keycloak DPoP 26.4](https://www.keycloak.org/2025/10/dpop-support-26-4) · [Keycloak Token Exchange 26.2](https://www.keycloak.org/2025/05/standard-token-exchange-kc-26-2) · [Duende pricing](https://duendesoftware.com/pricing) · [Duende v8 launch](https://duendesoftware.com/blog/20260602-your-identity-your-terms-duendes-modular-identity-infrastructure-v8-release) · [OpenIddict NuGet](https://www.nuget.org/packages/OpenIddict) · [OpenIddict DCR #2404](https://github.com/openiddict/openiddict-core/issues/2404) · [Auth0 for AI Agents GA](https://auth0.com/blog/auth0-for-ai-agents-generally-available/) · [Okta Cross App Access](https://www.okta.com/solutions/cross-app-access/) · [Entra External ID pricing](https://learn.microsoft.com/en-us/entra/external-id/external-identities-pricing) · [Entra Agent ID](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-agent-id) · [Azure AD B2C FAQ (sunset)](https://learn.microsoft.com/en-us/azure/active-directory-b2c/faq) · [WorkOS MCP](https://workos.com/docs/authkit/mcp).

---

## VIII. Migração e paridade dos 26 clients — não confiável

**Piorou em rastreabilidade:** o runbook (`docs/migration/sql/01..05` + `generate_clients_migration.py`) foi **deletado do worktree** — existe só no git HEAD. Gaps confirmados (inalterados desde a avaliação anterior):
1. **Token format** (#B2): `UseReferenceAccessTokens()` global; só 1 client legado usava reference; setting SQL `use_reference_tokens` não é lido.
2. **Grants**: SQL descarta implicit/hybrid mas não adiciona corretamente `ept:authorization`+`gt:authorization_code` a todos os afetados.
3. **Lifetimes**: chaves SQL custom que o OpenIddict ignora.
4. **Client claims** legadas sem migração/emissão demonstrada.
5. **Secrets/JWKS**: distribuição das chaves privadas correspondentes ao JWKS público não comprovada.
6. **Persisted grants**: o plano **apaga** grants legados sem dual-read/coexistência/rollback.
7. **Sem matriz de compatibilidade executável** por client (grant, redirect, PKCE, scopes, token format, lifetime, auth method, audience, claims, logout, owner).

**Exigência:** inventário read-only congelado → transformação por código determinístico → validar cada descriptor via APIs OpenIddict → **rehearsal em clone anonimizado** → cleanup destrutivo separado e só após janela de rollback.

---

## IX. Notas por dimensão

Escala: 0 = inexistente/inseguro · 5 = base promissora, não pronta · 8 = produção madura com gaps menores · 10 = excelência comprovada.

| Dimensão | Anterior (2026-07-20) | **Agora (2026-07-21)** | Justificativa |
|---|---:|---:|---|
| **Segurança** | 4,5 | **7,0** | Salto real: consent, device, Data Protection, cookie Secure, issuer, lockout testado, token-exchange com policy, UI endurecida. Puxam pra baixo: **C4 não encerrado** (secret no histórico + creds no disco + gitleaks que não pega), defaults permissivos (ROPC/none/token-exchange ON), logout stub anunciado `true`, e o **CSRF novo no consent** (#N1). |
| **Arquitetura** | 6,0 | **6,0** | Estrutura modular e DbContext unificado são boas bases; Docker/CI novos de boa qualidade. Mas dívidas centrais intactas (core acoplado +1 dep, ciclo STS↔UI, zero migrations com runbook agora deletado, options fragmentadas, Serilog morto). Remediação não pagou dívida arquitetural. |
| **Qualidade** | 4,5 | **6,5** | 20/20 testes reais, `-warnaserror` limpo, 0 vulneráveis, Pomelo estável, CI definida com 4 gates. Docado por: **tudo untracked (CI nunca rodou)**, cobertura sem logout/revocation/reuse-detection/MySQL/Program.cs real, e o **gitleaks que comprovadamente não pega o segredo** (controle que não funciona). |
| **Completude** | 4,0 | **5,5** | Device e consent agora funcionam (grande); grants básicos + token exchange testados. Mas passkeys stub (bloqueado), logout/sessions stub, **runtime EOL + migração .NET 10 bloqueada**, migração dos 26 clients não confiável, reference-token global. |
| **Média** | 4,75 | **≈6,25** | Base de engenharia agora sólida; candidato de produção ainda não — falta entrega, encerramento do incidente e plataforma. |

---

## X. Gaps priorizados e gates de cutover

### P0 — bloqueiam qualquer Onda A candidata a produção
1. **Versionar a remediação P0** em revisão Git reproduzível (comitar `src/tests`, `.github/`, `Dockerfile`, `DeviceController.cs` e o diff dos 2 repos), rodar a CI e obter verde. Sem isto, nada mais conta — o HEAD implantável não tem as correções.
2. **Encerrar o incidente C4:** rotacionar/revogar MySQL, RabbitMQ, secret de introspecção (`PLAN.md`) e credenciais OAuth potencialmente expostas; **purgar histórico** (`git filter-repo` + force-push coordenado); **adicionar regra gitleaks custom** que pegue o formato em prosa (o default não pega); mover segredos p/ user-secrets/env vars.
3. **Resolver a plataforma de runtime** (.NET 9 EOL em 2026 — 12/05 pela política STS 18m, ou 10/11 se a extensão p/ 24m se confirmar; **revalidar a data**). Decidir entre (a) trocar o provider MySQL por um com EF Core 10 (ex. `MySql.EntityFrameworkCore` da Oracle), (b) rodar pacotes EF Core 9 sobre runtime .NET 10 (subindo os irmãos `Sufficit.Communication`/`Sufficit.EFData` para net10), ou (c) aguardar Pomelo shipar EF Core 10 aceitando o risco de janela. Sem isto não há passkeys nativas (`AddPasskeys()` do .NET 10) nem runtime suportado.
4. **Endurecer defaults inseguros:** `TrustedProxies` = CIDR real do cluster; `LegacyGrants.Password`/`None` = `false` (allowlist fechada se algum client exigir ROPC, com telemetria + data de remoção); token exchange `Enabled=false` ou `AllowedClientIds` fechada.
5. **Corrigir #N1 (CSRF no consent)** — antiforgery na tela/POST de consent, alinhando ao que o `DeviceController.Verify` já faz.
6. **Provar operacionalmente C3/B4:** provisioning seguro de PFX (signing+encryption) com ACL/rotação/overlap de JWKS/backup; criar a tabela `dataprotectionkeys` em MySQL; cifrar chaves de Data Protection em repouso; **confirmar que as chaves privadas JWKS de `/tmp` foram salvas.**
7. **Migração dos 26 clients** por APIs/descritores válidos: inventário congelado, grants/lifetimes/claims/secrets corretos, transação, backup, dry-run, diff e rollback. Restaurar o runbook do HEAD ou reescrevê-lo. **Não** apagar tabelas/grants legados na primeira onda.
8. **Preservar formato/contrato de token por client** — o reference-token global quebra RSs que validam JWT localmente.

### P1 — antes do cutover dos 26 clients
- Matriz de compatibilidade executável dos 26 clients + owner/aceite por aplicação.
- Testes: refresh reuse-detection/revogação-família, logout E2E, revocation, consent-allow via UI real, introspection negativa, e um teste que suba o `Program.cs` real (rate limit, forwarded headers, HSTS, cert fail-fast).
- Server-side sessions e back/front-channel logout **reais** se forem requisito anunciado — **senão parar de anunciar `true` no discovery** (I2/I4).
- EF migrations versionadas + testes MariaDB/MySQL do ambiente alvo (não SQLite).
- Rate limit em `introspect`/`revocation`/`authorize`/`userinfo`/`par`/`device/info` (#N2/#11).
- Fechar `directive` cross-audience (#N5/#10) com allowlist claim→scope por client.
- Auditoria estruturada + métricas por endpoint/grant/client + alertas de brute-force.
- OpenID conformance suite + pentest focado em protocolo/UI.

### P2 — roadmap pós-cutover
Passkeys completas (via .NET 10, após desbloqueio) · DPoP ou mTLS sender-constrained · **MCP authorization** (RFC 9728 + 8707 + DCR — **maior ROI**; note que OpenIddict ainda não tem DCR, planejado 8.0) · agent identity sobre o token exchange existente (acompanhar ID-JAG/XAA) · SSF/CAEP como substituto de server-side sessions · FAPI 2.0 só se open finance · aposentar ROPC/`none` (Onda E).

---

## XI. Recomendação final — Onda A

**Decisão: NO-GO para a Onda A completa. Mas a posição é muito mais forte que em 2026-07-20 e o caminho ao GO é agora concreto e curto para um subconjunto.**

A razão do NO-GO **mudou de natureza**. Não é mais "device flow não funciona" — device e consent foram consertados e testados. É que a remediação **não está entregue** (zero commits, CI nunca rodou), o **incidente de segredos segue aberto**, o **runtime está EOL com a migração bloqueada**, e a **config sobe insegura por default**. Nenhum destes exige reescrever fluxos; exige versionar, rotacionar, decidir plataforma e endurecer defaults.

**Caminho construtivo:**
- **Smoke restrito a 1 client `client_credentials` puro** (sem browser/consent/logout/device/passkeys na dependência) torna-se **defensável** assim que P0 itens **1, 2, 4, 6 e 8** fecharem — é o menor escopo com contrato de token verificável.
- **Qualquer client interativo ou device permanece NO-GO** até P0 completo (inclui #N1 CSRF, migração ensaiada e a decisão de plataforma runtime).
- Manter a **pré-onda descartável** (ambiente sem tráfego real) para rodar a migração em **dry-run** sobre clone anonimizado e a suíte de testes ampliada. Não conta como aceite da Onda A.

### Critérios de GO (evidência anexável)
1. P0 fechados em revisão Git reproduzível (não só worktree) + CI verde;
2. device, code+PKCE, consent (allow **e** deny), password legado e refresh (incl. reuse) passam em E2E;
3. clients da Onda A passam contract tests (redirects, scopes, claims, **token format/lifetime**, logout);
4. secrets rotacionados e **histórico higienizado** de forma coordenada, com regra gitleaks que pega o formato em prosa;
5. decisão de plataforma runtime tomada (net10 via troca de provider, ou risco EOL aceito com data), MySQL alvo, certificados e Data Protection ensaiados em topologia equivalente à produção;
6. defaults endurecidos (`TrustedProxies` real, ROPC/none off, token-exchange fechado);
7. backup, rollback e coexistência com o legado testados sem cleanup destrutivo;
8. logs/métricas/alertas e runbook on-call disponíveis;
9. segurança aprovou threat model e testes negativos (incl. #N1 CSRF consent).

---

## XII. Notas de método

Avaliação do worktree em 2026-07-21, branch `feature/eval-p0-remediation` (ambos os repos), **não comitado**. Verificação por leitura direta de `file:line` + `dotnet build -warnaserror`/`dotnet test`/`dotnet list package --vulnerable` reais + agentes paralelos de segurança/arquitetura/qualidade/pesquisa. Onde as fontes divergiram, reconferido no código. Capacidades SaaS, drafts e versões de §VII mudam — revalidar no momento de uma decisão de compra. **Valores secretos encontrados não foram copiados para este documento.**
