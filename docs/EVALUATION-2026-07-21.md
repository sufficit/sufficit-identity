# Avaliação Consolidada — Sufficit Identity (STS OAuth 2.0/OIDC)

**Data:** 2026-07-21
**Avaliadores:** GLM-5.2 (ZCode) + Fable (agente concorrente), consolidados
**Repo:** `/mnt/sufficit/sufficit-identity` (+ sibling UI `/mnt/sufficit/sufficit-identity-ui`)
**Base avaliada:** branch `feature/eval-p0-remediation` em ambos os repos; HEAD `7740872` + remediação P0 no working tree (não comitada no momento da avaliação); versão `0.2.0-alpha`.
**Stack:** .NET 9 + OpenIddict 7.6.0 + ASP.NET Core Identity + EF Core 9 + Pomelo MySQL 9.0.0.
**Escopo de cutover considerado:** Onda A = ~26 clients / ~2.358 usuários.

> **Documento de síntese.** Esta avaliação consolida duas análises independentes executadas em paralelo (GLM via ZCode, Fable via agente concorrente). Cada uma fez leitura direta do código (`file:line`), rodou build/testes reais, e verificou C1-C4 / I1-I6 / B1-B5 contra a fonte. Onde divergiram, este documento apresenta as duas posições e adota um veredito unificado justificado. Não substitui os dois docs originais (`EVALUATION-glm-2026-07-21.md` e `EVALUATION-fable-2026-07-21.md`) — sintetiza-os.

---

## 1. Sumário executivo

O STS OpenIddict completou 4 ciclos de remediação (Investigação → F1-F4 → P0 → pós-avaliação). A base de engenharia dos fluxos OAuth/OIDC está **sólida e testada**:

- Device flow, consent (allow/deny), authorization_code+PKCE, refresh rotation, token exchange (RFC 8693), introspection, password grant com lockout anti-enumeração — todos **implementados e cobertos por testes E2E**.
- Hardening de host: rate limiter em `/connect/token`, HSTS, headers de segurança, TrustedProxies CIDR, cookie Secure, fail-fast de certs X.509 fora de dev, Data Protection persistida em MySQL.
- Build limpo `-warnaserror` (0/0), 32 testes E2E passando (20 pré-existentes + 11 de compatibilidade com produção + 1 de regressão CSRF), 0 pacotes vulneráveis.

**Ainda assim, é NO-GO para a Onda A completa.** Os bloqueadores mudaram de natureza: não são mais funcionalidade quebrada, são **entrega/operação/plataforma**:

1. **Incidente de segredos (C4) não encerrado** — segredos em mensagens de commit (Google OAuth ClientSecret em `0a56f5a`), topologia de jump host em `c706b64`, e working tree com senhas MySQL/RabbitMQ em plaintext. Gitleaks CI **comprovadamente não detecta** o secret em prosa (empiricamente testado: "no leaks").
2. **Back/front logout advertised true mas stub** (`AuthorizationController.cs:651-674`) — distribuição de `logout_token` para RPs não existe.
3. **CSRF no consent POST** (`AuthorizationController.cs:58`) — novo achado identificado independentemente por ambos avaliadores (N1).
4. **Runtime .NET 9 EOL** + **migração .NET 10 estruturalmente bloqueada** (cadeia OpenIddict.EFCore net10 → EF Core 10 → Pomelo sem release EF10 → Sufficit.Communication/EFData capam Caching <10). Bloqueia passkeys nativas (`AddPasskeys()` do .NET 10).
5. **Zero EF Migrations** — schema provisionado por SQL ad-hoc sendo deletado; deploy de produção sem caminho idempotente versionado.
6. **Defaults inseguros-por-ship**: `TrustedProxies` placeholder RFC 5737 (nunca casa em prod), `LegacyGrants.Password/None` default true, `TokenExchange.Enabled=true` com allowlist vazia.
7. **Migração dos 26 clients não ensaiada** — sem matriz de compatibilidade executável, sem rehearsal em clone anonimizado.

**Veredito:** NO-GO para Onda A completa, **mas caminho ao GO é curto e concreto para um subconjunto restrito** (1 client `client_credentials` puro como smoke inicial). Estimativa para GO condicional Onda A: 2-3 dias de trabalho focado após itens P0.

---

## 2. Convergências — o que ambos os avaliadores confirmam independentemente

Estes pontos foram identificados por ambos os avaliadores com a mesma conclusão e evidência:

### 2.1 Status dos problemas originais C1-C4

| ID | Descrição | Status | Evidência |
|----|-----------|--------|-----------|
| **C1** | Password grant sem lockout | ✅ RESOLVIDO | `AuthorizationController.cs:409-411` `CheckPasswordSignInAsync(lockoutOnFailure:true)` + msg genérica anti-enumeração `:416-425` + rate limit em `/connect/token` + testado por `PasswordGrantTests` (4 casos) |
| **C2** | `/diagnostics/schema` anônimo | ✅ RESOLVIDO | Endpoint removido do fonte; `ClientsController` atrás de `[Authorize(Policy="sufficit-identity-management")]`; Swagger dev-only (`Program.cs:223-227`) |
| **C3** | Certificados dev em prod | ✅ RESOLVIDO (código) | `ServiceCollectionExtensions.cs:302-342` `X509CertificateLoader.LoadPkcs12FromFile` + fail-fast `throw` fora de Development |
| **C4** | Segredos em VCS | ⚠️ PARCIAL (incidente ativo) | Repo limpo (gitignore + .dockerignore + Dockerfile rm); **mas**: working tree com senhas MySQL/RabbitMQ em plaintext; commit `0a56f5a` vazou Google OAuth ClientSecret **na mensagem do commit** (imutável sem `filter-repo --replace-message`); commit `c706b64` expõe topologia jump host + SSH key path |

### 2.2 Status dos problemas originais I1-I6

| ID | Status | Evidência |
|----|--------|-----------|
| **I1** Token Exchange implementado | ✅ (com ressalvas) | `act` aninhado + scope narrowing + allowlist + `Claims.Subject` (fix do sub bug); **residual**: directive claim sem audience gating |
| **I2** Discovery honesta | ⚠️ PARCIAL | DPoP/JAR/check_session/claims_parameter honestamente ausentes; **mas** back/front logout advertised true são stubs |
| **I3** email_verified/name/picture externos | ⚠️ PARCIAL | Google `email_verified` mapeado; Facebook/GitHub sem ClaimAction explícito |
| **I4** Refresh rotation | ⚠️ PARCIAL | Rotation ON e testada; reuse leeway tolerado (aceito risk) |
| **I5** Reference tokens + introspection | ✅ | Funcional, testado |
| **I6** directive claim emitida | ✅ (com residual) | Emitida + roteada; gap #10: vai para todos audiences |

### 2.3 Bugs históricos corrigidos (B1-B5)

| ID | Descrição | Status |
|----|-----------|--------|
| **B1** Device flow quebrado | ✅ Corrigido + testado E2E (3 casos); bug `sub` vs `NameIdentifier` corrigido em `AuthorizationController.cs:355` |
| **B2** `UseReferenceAccessTokens()` global | ⚠️ Continua global — OpenIddict não tem formato por-client; só 1/26 clients usa reference hoje; flip é migration-contract decision |
| **B3** Consent quebrado | ✅ Corrigido + testado; deny → access_denied; prompt=consent força reconsentimento |
| **B4** Data Protection não persistida | ✅ Persistida em MySQL via `IDataProtectionKeyContext`; `ProtectKeysWithCertificate` TODO |
| **B5** Runtime .NET 9 EOL | ❌ ABERTO — migração .NET 10 bloqueada por cadeia estrutural Pomelo/EF Core 10 |

### 2.4 Bloqueadores GO/NO-GO — ambos convergem

| Bloqueador | GLM | Fable | Consenso |
|------------|-----|-------|----------|
| C4 incidente ativo (segredos) | B1 blocker | P0 #2 | 🔴 Resolvido no commit `5657622` (P0 + 4 fixes pós-avaliação + fixes CI). **Rotação humana ainda pendente.** |
| Back/front logout stub | N3 MEDIUM | I2/I4 | 🟡 Code fix aplicado (B4: discovery agora `false`) |
| CSRF no consent | N1 HIGH | N1 MÉDIA | 🟢 **Code fix aplicado** (B3: `_antiforgery.ValidateRequestAsync`) |
| .NET 9 EOL + bloqueio .NET 10 | BLOCKER | B5 BLOCKER | 🔴 Pendente — decisão de plataforma (trocar provider MySQL OU esperar Pomelo) |
| Zero EF Migrations | HIGH | Dívida arquitetural | 🔴 Pendente |
| Defaults permissivos | MEDIUM | Config ship-a-inseguro | 🟡 Avaliar por ambiente; ROPC/None/TokenExchange ainda ON |

---

## 3. Divergências — onde os avaliadores discordam

### 3.1 Notas por dimensão

GLM é mais otimista; Fable é mais conservador (especialmente em Arquitetura, onde cita dívidas estruturais não pagas). Veredito unificado adota média ponderada.

| Dimensão | GLM | Fable | **Consolidado** | Justificativa |
|----------|-----|-------|-----------------|---------------|
| **Segurança** | B+ (7.5) | 7.0 | **7.0** | Fable nota empiricamente que gitleaks não pega segredo em prosa (controle falso); GLM identifica CSRF no consent (N1) como HIGH. Média ponderada com conservadorismo. |
| **Arquitetura** | A- (8.5) | 6.0 | **7.0** | Fable identifica dívidas estruturais não pagas pela remediação: core não é framework-independent, ciclo STS↔UI, options fragmentadas, Serilog morto, management API aquém. GLM focou no que funciona. **Adota-se 7.0** — a estrutura é boa mas tem dívidas reais. |
| **Qualidade** | B (7.0) | 6.5 | **7.0** | Ambos validam 32/32 testes (após commit), build limpo, 0 vulneráveis. Fable penalizava pelo "untracked + CI nunca rodou" — **já resolvido** pelo commit `5657622`. Recalibra para cima. |
| **Completude** | C+ (6.5) | 5.5 | **6.0** | Fable penaliza por passkeys stub (bloqueado .NET 10), logout/sessions stub, runtime EOL, migration 26 clients não confiável. GLM alinha com Fable — média. |
| **Média** | ≈7.4 | ≈6.25 | **≈6.75** | Posição de engenharia alpha madura, ainda não pronto para cutover amplo. |

### 3.2 Stance sobre Onda A

**GLM** defende "2-3 dias de trabalho focado para GO condicional Onda A" (blockers code-side rápidos: CSRF, logout stub, commit; + humano-only: rotação, filter-repo, PFX, ensaio clients).

**Fable** é mais cauteloso: defende **subconjunto restrito** inicial — 1 client `client_credentials` puro (sem browser/consent/logout/device) como smoke antes de Onda A completa. Clients interativos e device flow permanecem NO-GO até P0 completo (incluindo #N1 CSRF, migração ensaiada, decisão de plataforma).

**Veredito consolidado:** posição Fable é mais defensável para um cutover de produção real. **Estratégia de ondas progressivas:**
- **Smoke pré-Onda A:** 1 client `client_credentials` isolado após P0 itens code-side. Não conta como aceite.
- **Onda A1:** clients `client_credentials` + `authorization_code` puros (sem device flow interativo).
- **Onda A2:** clients com device flow e/ou logout federado (após back/front logout real implementado).
- **Onda A completa:** 26 clients após rehearsal bem-sucedido em clone anonimizado.

---

## 4. Achados únicos — contribuições complementares de cada avaliador

Estes itens foram identificados por apenas um dos avaliadores. Ambos são válidos e devem ser considerados.

### 4.1 Achados únicos do Fable (não cobertos pelo GLM)

| ID | Severidade | Descrição | Evidência |
|----|-----------|-----------|-----------|
| F-N2 | BAIXA-MÉDIA | **Oráculo anônimo de `user_code` sem rate limit** — `GET /connect/device/info` é `[AllowAnonymous]` e fora do escopo do rate limiter. Permite enumerar user_codes vivos, vaza client_id/client_name. | `DeviceController.cs:151-152` |
| F-N3 | BAIXA | **`prompt=consent` ignorado para clients Implicit-consent** — `ConsentTypes.Implicit => false` independente de `forcesReconsent`. Cliente Implicit auto-concede mesmo pedindo reconsentimento explícito. Não é OIDC-compliant. | `AuthorizationController.cs:185` |
| F-N4 | BAIXA | **Disclosure de existência de conta no login externo** — redireciona com `error=account_link_requires_signin&email=<email refletido>`; códigos distintos permitem enumeração + reflete email na URL. | `ExternalLoginController.cs:139` |
| F-N5 | BAIXA-MÉDIA | **Over-disclosure cross-audience de claims persistidas** — mesma raiz que I1/#10 mas mais explícito: 5000+ claims no DB vão a qualquer audiência. Mitigado por reference+introspection filtrar. | `GetDestinations:779-796` |
| F-arch-1 | — | **`core` não é framework-independent** — acopla Identity EF + OpenIddict EF + Pomelo + DataProtection EF + hardcoda `UTC_TIMESTAMP()` MySQL. Nome sugere separação que não existe. | `Sufficit.Identity.Core.csproj:11-18`, `AppDbContext.cs:60` |
| F-arch-2 | — | **Acoplamento circular STS↔UI** — STS→UI ProjectReference incondicional; UI→core de volta. Imagem Docker não builda standalone. | `STS.csproj:29`, `Sufficit.Identity.UI.csproj:36` |
| F-arch-3 | — | **`snake_case` não é global** — só 4 tabelas OpenIddict; Identity = tabelas lowercase mas colunas PascalCase. | `AppDbContext.cs:52-80,91-171` |
| F-arch-4 | — | **`Serilog.AspNetCore` referenciado mas nunca configurado** (dependência morta). | `Directory.Packages.props:32` |
| F-arch-5 | — | **Management API limitada** — só list/get/create/delete clients (sem update/scopes/users); `[Route("api/clients")]` hardcoded torna `RoutePrefix` inefetivo. | `ClientsController.cs` |
| F-quality-1 | — | **Test factory não sobe `Program.cs` real** — replica wiring mínimo; rate limiter, forwarded headers, HSTS, security headers, cert fail-fast nunca são exercitados. SQLite ≠ MySQL. | `SufficitIdentityTestFactory.cs` |
| F-C4-extra | — | **gitleaks comprovadamente NÃO pega o secret em prosa** — testado empiricamente: "no leaks found" enquanto secret está no HEAD. Regra `generic-api-key` exige `key=value`; UUID em prosa não casa. Controle falso. | CI verificado manualmente |
| F-C1-extra | — | **ROPC bypassa 2FA** — `CheckPasswordSignInAsync` valida só senha+lockout; usuário com 2FA obtém token com senha. Inerente ao grant (segue ON até Onda E). | `AuthorizationController.cs:409-411` |

### 4.2 Achados únicos do GLM (não cobertos pelo Fable)

| ID | Severidade | Descrição | Evidência |
|----|-----------|-----------|-----------|
| G-N6 | HIGH | **Google OAuth ClientSecret vazado em mensagem de commit** — `0a56f5a` traz `ClientSecret=KKwyJC8v...` no body da mensagem. Imutável sem `filter-repo --replace-message`. Rotação é obrigatória. | `git show --no-patch 0a56f5a` |
| G-N4 | HIGH | **UI sibling CI pin (`381c9a6`) não inclui fixes P0 da UI** — comentário admitindo; CI buildava UI desatualizada. **Resolvido após:** bump para `0def296` (commit `071b433`). | `ci.yml:43` |
| G-N5 | HIGH | **P0 inteiro UNTRACKED** (pré-commit) — `src/tests/`, `Dockerfile`, `.github/`, `DeviceController.cs` sem versionar. CI nunca tinha rodado. **Resolvido:** commit `5657622` + push. | `git status` pré-commit |
| G-B8 | HIGH | **Matriz de compatibilidade com produção via fixtures** — implementou `Fixtures/production-requests.json` (15 amostras reais capturadas dos logs nginx de eveo-apps, ~220k amostras) + `ProductionCompatibilityTests.cs` (11 testes de replay). Valida WebForms hybrid/SwaggerUI implicit rejeitados, mobile AppAuth PKCE funcionando, scanners rejeitados. | `src/tests/Fixtures/`, `src/tests/ProductionCompatibilityTests.cs` |
| G-mercado | — | **Checklist STS moderno 2026 completo + matriz comparativa** — inclui Keycloak 26.7 (DPoP 26.4, FAPI 2.0 final, SSF 26.7, MCP 26.7), Duende 8.0.3 (preço modular, v8 exige .NET 10), Auth0 (Agent Identity GA + Token Vault), Entra Agent ID GA, WorkOS (MCP RFC 9728+8707+DCR). MCP spec update 2026-07-28. | `EVALUATION-glm-2026-07-21.md` §3 |

---

## 5. Síntese — gaps priorizados e gates de cutover

### 5.1 P0 — bloqueiam qualquer Onda A candidata a produção

| # | Gap | Tipo | Status (pós-commits) |
|---|-----|------|----------------------|
| 1 | Versionar remediação P0 + CI verde | code + ops | ✅ **RESOLVIDO** (commit `5657622`, CI run `29844363267` verde) |
| 2 | CSRF no consent POST (#N1 ambos) | code | ✅ **RESOLVIDO** (commit `5657622`, teste regressão adicionado) |
| 3 | back/front logout advertised false (I2/I4) | code | ✅ **RESOLVIDO** (commit `5657622`) |
| 4 | Rotacionar 3 credenciais (MySQL/RabbitMQ/Google OAuth) | humano | 🔴 Pendente |
| 5 | `git filter-repo --replace-message` p/ `0a56f5a` + `c706b64` + `JWKS_KEYS.md` | humano | 🔴 Pendente |
| 6 | Provisionar PFX/JWKS reais (signing+encryption) | humano | 🔴 Pendente |
| 7 | Criar tabela `dataprotectionkeys` em MySQL prod + `.ProtectKeysWithCertificate` | humano + code | 🔴 Pendente |
| 8 | Endurecer defaults: `TrustedProxies` real, ROPC/None off (Onda E), TokenExchange closed | config | 🟡 Por ambiente |
| 9 | Ensaio migração 26 clients em clone anonimizado + matriz compatibilidade executável | humano | 🔴 Pendente |
| 10 | Decisão plataforma runtime (.NET 9 EOL → .NET 10 bloqueado) | arquitetura | 🔴 Pendente — trocar provider MySQL OU esperar Pomelo |
| 11 | EF Migrations versionadas (substituir SQL deletado) | code | 🔴 Pendente |
| 12 | Regra gitleaks custom para secret em prosa (default não pega) | code | 🔴 Pendente |

### 5.2 P1 — antes do cutover dos 26 clients

- Matriz de compatibilidade executável por client (grant, redirect, PKCE, scopes, token format, lifetime, auth method, audience, claims, logout, owner) + aceite por aplicação.
- Testes faltantes: refresh reuse-detection / revogação-família, logout E2E, revocation endpoint, consent-allow via UI real, introspection negativa, **teste que suba o `Program.cs` real** (rate limit, forwarded headers, HSTS, cert fail-fast).
- Server-side sessions e back/front-channel logout reais se forem requisito anunciado.
- EF migrations + testes MariaDB/MySQL do ambiente alvo (não SQLite).
- Rate limit em `introspect`/`revocation`/`authorize`/`userinfo`/`par`/`device/info` (F-N2/#11).
- Fechar `directive` cross-audience com allowlist claim→scope por client (F-N5/#10).
- Auditoria estruturada + métricas por endpoint/grant/client + alertas brute-force (configurar Serilog que está morto).
- OpenID conformance suite + pentest focado em protocolo/UI.

### 5.3 P2 — roadmap pós-cutover

- Passkeys completas (via .NET 10, após desbloqueio Pomelo/EF10).
- DPoP (RFC 9449) ou mTLS sender-constrained (OpenIddict ainda não entrega DPoP nativamente — aposta em mTLS+BFF).
- **MCP authorization** (RFC 9728 + RFC 8707 + DCR) — **maior ROI pós-cutover** dado ecossistema AI/MCP Sufficit. Nota: OpenIddict ainda não tem DCR (planejado 8.0-preview.3).
- Agent identity sobre token exchange existente (acompanhar ID-JAG/XAA drafts; Auth0 e Entra já têm produtos proprietary).
- SSF/CAEP como substituto moderno de server-side sessions (Final set/2025).
- FAPI 2.0 só se open finance.
- Aposentar ROPC/`none` (Onda E).

---

## 6. Recomendação final — Onda A

**Decisão: NO-GO para Onda A completa. Mas caminho ao GO é concreto e curto para um subconjunto progressivo.**

A razão do NO-GO **mudou de natureza** desde a avaliação anterior. Não é mais "device flow não funciona" — device e consent foram consertados e testados. É que a remediação ainda tem pendências humano-only (rotação de 3 segredos, filter-repo histórico, provisionamento PFX/JWKS, ensaio 26 clients) e uma decisão de plataforma runtime pendente (.NET 9 EOL + .NET 10 bloqueado).

### Estratégia de ondas progressivas (síntese das duas posições)

| Onda | Escopo | Gates |
|------|--------|-------|
| **Smoke** | 1 client `client_credentials` puro, isolado, em ambiente sem tráfego real | P0 itens 4-7, 10, 12 fechados |
| **A1** | Clients `client_credentials` + `authorization_code` puros (sem device/logout interativo) | + P0 item 9 (ensaio clients A1) + P1 matriz compatibilidade |
| **A2** | Clients com device flow e/ou logout federado | + back/front logout real OU confirmar não-exigência + P1 testes logout E2E |
| **A completa** | 26 clients / 2.358 usuários | + P0 item 9 completo + coexistência legado 7 dias verdes |

### Critérios de GO (evidência anexável)

1. P0 fechados em revisão Git reproduzível + CI verde. ✅ (commit `5657622`, CI verde)
2. Device, code+PKCE, consent (allow e deny), password legado e refresh passam E2E. ✅ (32/32 testes)
3. Clients da onda passam contract tests (redirects, scopes, claims, token format/lifetime, logout).
4. Secrets rotacionados e histórico higienizado com regra gitleaks custom (formato em prosa).
5. Decisão plataforma runtime tomada (net10 via troca provider OU risco EOL aceito com data); MySQL alvo, certs e Data Protection ensaiados em topologia equivalente.
6. Defaults endurecidos (`TrustedProxies` real, ROPC/none off, token-exchange fechado).
7. Backup, rollback e coexistência com legado testados (sem cleanup destrutivo na primeira onda).
8. Logs/métricas/alertas e runbook on-call disponíveis (Serilog configurado — hoje é dependência morta).
9. Segurança aprovou threat model e testes negativos (incl. CSRF consent — já coberto por teste regressão).

---

## 7. Comparativo mercado 2026 (síntese)

Detalhes completos no `EVALUATION-glm-2026-07-21.md` §3. Síntese:

| Produto | Posição relativa ao sufficit-identity |
|---------|---------------------------------------|
| **Keycloak 26.7** | Régua do self-hosted. DPoP GA (26.4), Token Exchange GA (26.2), **FAPI 2.0 final**, **SSF (26.7)**, **MCP authorization (26.7)**. Troca = replatform Java. |
| **Duende IdentityServer 8.0.3** | Preço modular novo (Advanced US$ 24.900/ano p/ 30 client IDs); v8 exige .NET 10. Sem ganho decisivo sobre OpenIddict 7.6. |
| **OpenIddict 7.6 / 8.0-preview.2** | O que estamos usando. Token exchange (7.0+), mTLS (7.3). **Sem DPoP** (aposta mTLS+BFF). **Sem DCR** (planejado 8.0). Bus-factor ≈ 1 (Kévin Chalet). |
| **Zitadel** | AGPL-3.0 — contaminaria MIT-0. Não é .NET. |
| **Ory (Hydra/Kratos)** | Apache-2.0. AS headless de referência fora .NET. Migrar ganha pouco. |
| **Authentik** | Enterprise US$ 5/user/mês → ~US$ 144k/ano (proibitivo na escala). |
| **Auth0/Okta** | Mais forte em agent identity (Auth0 for AI Agents GA + Token Vault; MCP auth GA). Custo/lock-in escala com MAU. |
| **Entra External ID** | Mais barato na escala (50k MAU grátis). Entra Agent ID GA (líder em governança agent). B2C em sunset. |
| **WorkOS AuthKit** | Líder em MCP auth (RFC 9728 + 8707 + DCR). |

**Conclusão:** escolha OpenIddict-sobre-Duende foi correta (licença MIT-0, stack .NET, controle fino). Porém roadmap precisa incluir com urgência: passkeys (desbloqueio .NET 10), DPoP ou mTLS, backchannel logout real, MCP authorization. Esses viraram table-stakes em 2026.

---

## 8. Método

Duas avaliações independentes executadas em paralelo em 2026-07-21:
- **GLM-5.2** (ZCode): 3 agentes paralelos (segurança Explore, arquitetura Explore, pesquisa web general-purpose). Verificação pessoal do avaliador em `Program.cs`, `AuthorizationController.cs`, `DeviceController.cs`, `ServiceCollectionExtensions.cs`, `SufficitIdentityOptions.cs`. Captura de amostras reais dos logs nginx de eveo-apps (produção).
- **Fable** (agente concorrente): 5 agentes de investigação (2 segurança, arquitetura, qualidade, pesquisa mercado). Verificação por leitura `file:line` + build/test reais.

Ambas as avaliações acessaram o mesmo working tree da branch `feature/eval-p0-remediation` em ambos os repos. Onde divergiram, este documento apresenta as duas posições.

Após as avaliações, a remediação code-side foi completada e commitada:
- Commit `5657622` — P0 + B3 (CSRF consent) + B4 (back/front logout false) + H4 (HEALTHCHECK) + H5 (pin Docker)
- Commit `071b433` — bump UI sibling pin para `0def296` (P0 UI pushed)
- Commit `ddf0052` — fix CPM Sufficit.Communication fallback (NU1008/NU1011)
- Commit `2c9c892` — bump actions/checkout + setup-dotnet para v5 (Node.js 24)
- Commit `0def296` (UI repo) — P0 UI fixes (open-redirect, account-takeover, consent/device wiring)

**CI:** run `29844363267` verde (build + testes + vuln audit + gitleaks), sem annotations.
